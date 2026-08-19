# -*- coding: utf-8 -*-
"""TCP 线协议与端到端冒烟测试。

覆盖：
  - PBCS 风格二进制帧往返
  - 临时端口起 PAEEServer，经 TCP 跑完 Reg→Enc→Dec
"""

from __future__ import annotations

import base64
import socket
import threading
import time
from pathlib import Path

from net import messages as M
from net.framing import recv_msg, send_msg, wire_metering
from net.server_api import PAEEServer
from net.wire_codec import encode_message, decode_message
from paee.params import SerKGen, Setup
from paee.protocol import PAEEServerState
from storage.local import LocalStore


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _b64(n: int) -> str:
    return base64.b64encode(b"\x11" * n).decode("ascii")


def test_binary_wire_roundtrip_ext_eval():
    """EXT_EVAL：encode→decode 字段一致。"""
    obj = {"type": M.EXT_EVAL, "a_tilde": _b64(33)}
    raw = encode_message(obj)
    assert raw[0] == 0x23
    back = decode_message(raw)
    assert back["type"] == M.EXT_EVAL
    assert back["a_tilde"] == obj["a_tilde"]


def test_binary_wire_roundtrip_reg_eval():
    """REG_EVAL：K‖X‖ã encode→decode。"""
    obj = {
        "type": M.REG_EVAL,
        "pk": {"K": _b64(33), "X": _b64(33)},
        "a_tilde": _b64(33),
    }
    raw = encode_message(obj)
    assert raw[0] == 0x13
    back = decode_message(raw)
    assert back["type"] == M.REG_EVAL
    assert back["pk"]["K"] == obj["pk"]["K"]
    assert back["pk"]["X"] == obj["pk"]["X"]
    assert back["a_tilde"] == obj["a_tilde"]


def test_message_socket_roundtrip():
    """socketpair 上 REG_BLIND(含 ctx) / REG_EVAL(含 pk) 往返。"""
    a, b = socket.socketpair()
    try:
        send_msg(
            a,
            {
                "type": M.REG_BLIND,
                "id": "bob",
                "a": _b64(33),
                "ctx": _b64(32),
            },
        )
        msg = recv_msg(b)
        assert msg["type"] == M.REG_BLIND
        assert msg["id"] == "bob"
        send_msg(
            b,
            {
                "type": M.REG_EVAL,
                "pk": {"K": _b64(33), "X": _b64(33)},
                "a_tilde": _b64(33),
            },
        )
        ack = recv_msg(a)
        assert ack["type"] == M.REG_EVAL
        assert "pk" in ack and "a_tilde" in ack
    finally:
        a.close()
        b.close()


def test_wire_metering_counts_send_and_recv():
    """wire_metering 应累计二进制收发字节。"""
    a, b = socket.socketpair()
    try:
        with wire_metering() as m:
            n = send_msg(a, {"type": M.EXT_BLIND, "id": "u1", "a": _b64(33)})
            assert m.sent == n
        with wire_metering() as m2:
            send_msg(a, {"type": M.EXT_BLIND, "id": "u2", "a": _b64(33)})
            _ = recv_msg(b)
            send_msg(b, {"type": M.EXT_EVAL, "a_tilde": _b64(33)})
            msg = recv_msg(a)
            assert msg["type"] == M.EXT_EVAL
            assert m2.sent > 0 and m2.recv > 0
            assert m2.total == m2.sent + m2.recv
    finally:
        a.close()
        b.close()


def test_field_too_long_rejected():
    """单字段 >255 应在 encode 时拒绝。"""
    try:
        encode_message({"type": M.EXT_BLIND, "id": "x" * 300, "a": _b64(33)})
        assert False, "expected ValueError"
    except ValueError as e:
        assert "too long" in str(e)


class _TcpHarness:
    """临时端口上的 Fig.1 PAEE TCP 服务器。"""

    def __init__(self, root: Path):
        self.host = "127.0.0.1"
        self.port = _free_port()
        self.pp = Setup(32)
        store = LocalStore(str(root / "server"))
        sk = SerKGen(self.pp)
        store.save_sk(sk)
        self.state = PAEEServerState(self.pp, sk)
        self.srv = PAEEServer(self.state, store)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)

    def _loop(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.listen(8)
            s.settimeout(0.3)
            while not self._stop.is_set():
                try:
                    conn, _ = s.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                threading.Thread(
                    target=self._serve_one, args=(conn,), daemon=True
                ).start()

    def _serve_one(self, conn: socket.socket) -> None:
        with conn:
            try:
                self.srv.handle(conn)
            except Exception:
                pass

    def start(self) -> None:
        self._thread.start()
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                with socket.create_connection((self.host, self.port), timeout=0.2):
                    return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("PAEE TCP server did not start")

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)


def test_tcp_reg_enc_dec_smoke(tmp_path):
    """临时端口起服务器，经长连接跑完 Reg→Enc→Dec。"""
    from net.client_api import PAEEClientSession

    harness = _TcpHarness(tmp_path)
    harness.start()
    try:
        uid = "tcp_wire_test"
        pw = "wire_pw_16chars!!"
        pt = b"tcp smoke plaintext " + b"\xaa\x55" * 50
        with PAEEClientSession(harness.host, harness.port, harness.pp) as sess:
            pk, _ctx = sess.register(uid, pw)
            ct = sess.encrypt(pk, uid, pw, pt)
            out = sess.decrypt(pk, uid, pw, local_ct2=ct.ct2)
        assert out == pt
    finally:
        harness.stop()


def test_tcp_wrong_password_decrypt_fails(tmp_path):
    """TCP 路径：错误口令解密应失败。"""
    from net.client_api import PAEEClientSession

    harness = _TcpHarness(tmp_path)
    harness.start()
    try:
        uid = "tcp_bad_pw"
        pw = "correct_password!!"
        with PAEEClientSession(harness.host, harness.port, harness.pp) as sess:
            pk, _ctx = sess.register(uid, pw)
            ct = sess.encrypt(pk, uid, pw, b"secret")
            try:
                sess.decrypt(
                    pk, uid, "wrong_password!!!", local_ct2=ct.ct2
                )
                assert False, "expected decrypt failure"
            except RuntimeError:
                pass
    finally:
        harness.stop()


def test_tcp_persistent_session_one_connection(tmp_path):
    """Reg+Enc+Dec 全程复用同一 socket（fileno 不变）。"""
    from net.client_api import PAEEClientSession

    harness = _TcpHarness(tmp_path)
    harness.start()
    try:
        uid = "persist_conn"
        pw = "persist_pw_16char!"
        with PAEEClientSession(harness.host, harness.port, harness.pp) as sess:
            fd0 = sess.sock.fileno()
            pk, _ctx = sess.register(uid, pw)
            assert sess.sock.fileno() == fd0
            ct = sess.encrypt(pk, uid, pw, b"abc")
            assert sess.sock.fileno() == fd0
            assert sess.decrypt(pk, uid, pw, local_ct2=ct.ct2) == b"abc"
            assert sess.sock.fileno() == fd0
    finally:
        harness.stop()
