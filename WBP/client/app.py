"""
WBP Client — Davies et al. Crypto'23 Figures 4 and 5.

HSM public keys arrive via HELLO_ACK (stand-in for hard-coded pk_HSM in the app).
"""

from __future__ import annotations

import argparse
import logging
import secrets
import socket
import time
import uuid
from dataclasses import dataclass

from common.messages import Message, MessageType, recv_message, send_message
from crypto import opaque_api as opaque
from crypto.primitives import (
    C_AAD,
    K_AAD,
    aesgcm_decrypt,
    aesgcm_encrypt,
    b64d,
    b64e,
    ed25519_verify,
    h3,
    load_ed25519_public_pem,
    load_rsa_public_pem,
    pack_e_payload,
    rsa_encrypt,
)

log = logging.getLogger("wbp.client")

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765

# 轮数对齐 PAEE Fig.1：一次 Client↔Server 交互算 1（不含 HELLO）
INIT_ROUNDS = 2
REC_ROUNDS = 2


@dataclass
class InitResult:
    ok: bool
    backup_key: str | None = None
    aid: str | None = None
    error: str | None = None


@dataclass
class RecResult:
    ok: bool
    backup_key: str | None = None
    deleted: bool = False
    error: str | None = None


class Client:
    def __init__(
        self,
        idc: str,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        password: str = "demo-password",
    ) -> None:
        self.idc = idc
        self.host = host
        self.port = port
        self.password = password
        self.backup_key: str | None = None
        self._sock: socket.socket | None = None
        self._enc_pem: str | None = None
        self._sig_pem: str | None = None
        self._opaque = opaque.OpaqueClient()
        self.comm_bytes: int = 0

    def reset_comm(self) -> None:
        """清零阶段通信量计数（对齐 PPKR：HELLO 不计入 Init/Rec）。"""
        self.comm_bytes = 0

    def connect(self) -> None:
        sock = socket.create_connection((self.host, self.port), timeout=10)
        self._sock = sock
        ssid = uuid.uuid4().hex
        hello = Message(MessageType.HELLO, ssid, {"idc": self.idc})
        send_message(sock, hello, role="client")
        ack = recv_message(sock, role="client")
        if ack.type != MessageType.HELLO_ACK:
            raise RuntimeError(f"expected HELLO_ACK, got {ack.type}")
        self._enc_pem = ack.payload.get("enc_pem")
        self._sig_pem = ack.payload.get("sig_pem")
        if not self._enc_pem or not self._sig_pem:
            raise RuntimeError("HELLO_ACK missing pk_Enc / pk_Sig")
        log.info("connected as IDC=%s (WBP DFG+23)", self.idc)

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def _req(self, msg: Message) -> Message:
        if self._sock is None:
            raise RuntimeError("not connected")
        raw_tx = msg.to_bytes()
        send_message(self._sock, msg, role="client")
        self.comm_bytes += len(raw_tx)
        resp = recv_message(self._sock, role="client")
        self.comm_bytes += len(resp.to_bytes())
        return resp

    def _verify_sigma(self, *parts: str, sigma: str) -> None:
        assert self._sig_pem is not None
        pk = load_ed25519_public_pem(self._sig_pem)
        ed25519_verify(pk, "|".join(parts).encode("utf-8"), b64d(sigma))

    def init(self) -> InitResult:
        """Fig.4 key initialization."""
        ssid = uuid.uuid4().hex
        # Fig.4: K ←$ {0,1}^λ
        backup_key = secrets.token_bytes(32)
        self.backup_key = backup_key.hex()

        try:
            # Fig.4 OPAQUE RegStart → a1
            client_req, reg_state = self._opaque.start_registration(self.password)
            a1 = b64e(client_req.to_bytes())
        except Exception as e:
            return InitResult(ok=False, error=f"OPAQUE RegStart: {e}")

        log.info("Fig.4 INIT_REQ ssid=%s", ssid)
        resp = self._req(Message(MessageType.INIT_REQ, ssid, {"a1": a1}))
        if resp.type == MessageType.INIT_RESULT and not resp.payload.get("ok", True):
            return InitResult(ok=False, error=str(resp.payload.get("error")))
        if resp.type != MessageType.INIT_HSM_RESP:
            return InitResult(ok=False, error=f"unexpected {resp.type}")

        b1 = str(resp.payload.get("b1", ""))
        n1 = str(resp.payload.get("n1", ""))
        sigma = str(resp.payload.get("sigma", ""))
        aid = str(resp.payload.get("aid", ""))
        try:
            # Fig.4: verify σ; OPAQUE RegFinish → K_export
            self._verify_sigma(b1, n1, aid, sigma=sigma)
            server_resp = opaque.RegistrationResponse.from_bytes(b64d(b1))
            result = self._opaque.finish_registration(
                server_resp, reg_state, self.password
            )
            k_export = result.export_key
            # Fig.4: e ← AE.Enc(K_export, K)
            e = aesgcm_encrypt(k_export, backup_key, aad=K_AAD)
            # Fig.4: tr_C ← H3(a1,b1,n1); E ← PKE.Enc(pk_Enc, e∥tr_C)
            tr_c = h3(a1, b1, n1)
            assert self._enc_pem is not None
            e_pke = rsa_encrypt(
                load_rsa_public_pem(self._enc_pem),
                pack_e_payload(e, tr_c),
            )
            opaque_upload = b64e(result.upload.to_bytes())
        except Exception as e:
            return InitResult(ok=False, error=f"Fig.4 client crypto: {e}")

        log.info("Fig.4 INIT_UPLOAD E=PKE(e||trC) ssid=%s", ssid)
        result_msg = self._req(
            Message(
                MessageType.INIT_UPLOAD,
                ssid,
                {"E": b64e(e_pke), "opaque_upload": opaque_upload},
            )
        )
        if result_msg.type != MessageType.INIT_RESULT:
            return InitResult(ok=False, error=f"unexpected {result_msg.type}")
        if not result_msg.payload.get("ok"):
            return InitResult(ok=False, error=str(result_msg.payload.get("error")))
        return InitResult(
            ok=True,
            backup_key=self.backup_key,
            aid=str(result_msg.payload.get("aid")),
        )

    def recover(self, password: str | None = None) -> RecResult:
        """Fig.5 key recovery."""
        pw = password or self.password
        ssid = uuid.uuid4().hex

        try:
            client_req, login_state = self._opaque.start_login(pw)
            a2 = b64e(client_req.to_bytes())
        except Exception as e:
            return RecResult(ok=False, error=f"OPAQUE LoginStart: {e}")

        log.info("Fig.5 REC_REQ ssid=%s", ssid)
        resp = self._req(Message(MessageType.REC_REQ, ssid, {"a2": a2}))
        if resp.type == MessageType.REC_RESULT:
            return RecResult(
                ok=False,
                deleted=bool(resp.payload.get("deleted")),
                error=str(resp.payload.get("error")),
            )
        if resp.type != MessageType.REC_HSM_RESP:
            return RecResult(ok=False, error=f"unexpected {resp.type}")

        b2 = str(resp.payload.get("b2", ""))
        sigma = str(resp.payload.get("sigma", ""))
        aid = str(resp.payload.get("aid", ""))
        try:
            self._verify_sigma(b2, aid, sigma=sigma)
            server_resp = opaque.CredentialResponse.from_bytes(b64d(b2))
            login_result = self._opaque.finish_login(server_resp, login_state, pw)
            k_export = login_result.session_keys.export_key
            shk = login_result.session_keys.session_key
            finish_msg = b64e(login_result.finalization.to_bytes())
        except Exception as e:
            return RecResult(ok=False, error=f"Fig.5 client crypto: {e}")

        log.info("Fig.5 REC_CONFIRM ssid=%s", ssid)
        key_msg = self._req(
            Message(MessageType.REC_CONFIRM, ssid, {"t_c": finish_msg})
        )
        if key_msg.type == MessageType.REC_RESULT:
            return RecResult(
                ok=False,
                deleted=bool(key_msg.payload.get("deleted")),
                error=str(key_msg.payload.get("error")),
            )
        if key_msg.type != MessageType.REC_KEY or not key_msg.payload.get("ok"):
            return RecResult(
                ok=False, error=str(key_msg.payload.get("error", key_msg.type))
            )

        try:
            # Fig.5: e ← AE.Dec(shk, c); K ← AE.Dec(K_export, e)
            e = aesgcm_decrypt(
                shk, b64d(str(key_msg.payload.get("c", ""))), aad=C_AAD
            )
            backup_key = aesgcm_decrypt(k_export, e, aad=K_AAD)
        except Exception as e:
            return RecResult(ok=False, error=f"Fig.5 unwrap K: {e}")

        self.backup_key = backup_key.hex()
        return RecResult(ok=True, backup_key=self.backup_key)

    def init_metrics(self) -> tuple[InitResult, dict]:
        """执行 Init 并返回 (结果, {latency_ms, comm_bytes, rounds, success})。"""
        self.reset_comm()
        t0 = time.perf_counter()
        result = self.init()
        elapsed = (time.perf_counter() - t0) * 1000
        metrics = {
            "latency_ms": elapsed,
            "comm_bytes": self.comm_bytes,
            "rounds": INIT_ROUNDS,
            "success": result.ok,
        }
        return result, metrics

    def recover_metrics(self, password: str | None = None) -> tuple[RecResult, dict]:
        """执行 Rec 并返回 (结果, {latency_ms, comm_bytes, rounds, success})。"""
        self.reset_comm()
        t0 = time.perf_counter()
        result = self.recover(password=password)
        elapsed = (time.perf_counter() - t0) * 1000
        metrics = {
            "latency_ms": elapsed,
            "comm_bytes": self.comm_bytes,
            "rounds": REC_ROUNDS,
            "success": result.ok,
        }
        return result, metrics


def main() -> None:
    parser = argparse.ArgumentParser(description="WBP Client (DFG+23 Fig.4/5)")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--idc", default="user-demo")
    parser.add_argument("--password", default="demo-password")
    parser.add_argument(
        "--mode", choices=("init", "recover", "both"), default="both"
    )
    args = parser.parse_args()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    client = Client(args.idc, args.host, args.port, args.password)
    client.connect()
    try:
        if args.mode in ("init", "both"):
            r = client.init()
            log.info("init result: %s", r)
            if not r.ok:
                raise SystemExit(1)
        if args.mode in ("recover", "both"):
            r = client.recover()
            log.info("recover result: %s", r)
            if not r.ok:
                raise SystemExit(1)
    finally:
        client.close()


if __name__ == "__main__":
    main()
