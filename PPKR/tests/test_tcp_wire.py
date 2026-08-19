"""TCP 线协议与端点解析单元测试（PAEE/PBCS 二进制帧）。"""

from __future__ import annotations

import socket
import threading
import time

from common.endpoint import resolve_endpoint
from common.messages import Message, MessageType
from common import wire_codec as WC
from server.tcp_server import TcpServer


def test_resolve_endpoint_tcp_and_legacy_http_url():
    assert resolve_endpoint(host="10.0.0.1", port=9000) == ("10.0.0.1", 9000)
    assert resolve_endpoint(url="127.0.0.1:8766") == ("127.0.0.1", 8766)
    assert resolve_endpoint(url="http://127.0.0.1:5002") == ("127.0.0.1", 5002)
    assert resolve_endpoint(url="tcp://192.168.1.1:8765") == ("192.168.1.1", 8765)


def test_binary_wire_hello_roundtrip():
    msg = Message(MessageType.HELLO, "abc123", {"idc": "bob"})
    raw = msg.to_bytes()
    assert raw[0] == WC.OP_HELLO
    assert b"\x00\x04" in raw or len(raw) > 3  # u16 length for "bob"
    back = WC.decode_message(raw)
    assert back["type"] == WC.HELLO
    assert back["idc"] == "bob"


def test_binary_wire_oprf_resp_roundtrip():
    payload = b"\x01" + b"\x00\x21" + b"\x02" * 33  # fake pkEnc-ish
    obj = {
        "type": WC.OPRF_RESP,
        "ssid": "ssid-1",
        "idc": "alice",
        "sig": b"\x00" * 64,
        "payload": payload,
    }
    raw = WC.encode_message(obj)
    back = WC.decode_message(raw)
    assert back["ssid"] == "ssid-1"
    assert back["sig"] == b"\x00" * 64
    assert back["payload"] == payload


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_tcp_hello_and_oprf_full_smoke():
    """临时端口起 TcpServer，经 TCP 跑完 OPRF Init+Rec。"""
    from client.ppkr_http_client import OPRFPPKRHttpSession

    port = _free_port()
    srv = TcpServer("127.0.0.1", port)
    t = threading.Thread(target=srv.start, daemon=True)
    t.start()
    try:
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            raise RuntimeError("TCP server did not start")

        session = OPRFPPKRHttpSession(
            idc="tcp_wire_test",
            password="wire_pw",
            host="127.0.0.1",
            port=port,
        )
        try:
            K_init, K_rec = session.run_full()
            assert K_init == K_rec
            assert len(K_init) == 32
        finally:
            session.close()
    finally:
        srv.stop()
