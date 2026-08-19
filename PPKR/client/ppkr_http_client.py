"""基于 TCP 的 PPKR 客户端会话 — π_encPw+ 与 π_OPRF-PPKR。

经 ``PPKRTcpTransport`` 以 PAEE/PBCS 风格二进制帧与 ``server/tcp_server.py`` 通信。
"""

from __future__ import annotations

import time

from client.tcp_transport import PPKRTcpTransport
from common.endpoint import DEFAULT_HOST, DEFAULT_PORT, resolve_endpoint
from common.payload_codec import decode_payload
from config import IDC, SID
from crypto.group import GROUP
from crypto.schnorr import SchnorrPublicKey
from hsm.attest import AttestedMessage
from logging_config import setup_logger
from protocols.encpw_plus import EncPwPlusClient
from protocols.oprf_ppkr import OPRFPPKRClient

log = setup_logger("CLIENT")


def _hsm_pk_from_wire(pk_wire: bytes | str) -> SchnorrPublicKey:
    """将 HELLO_ACK 返回的 HSM 公钥（raw bytes，兼容旧 Base64/hex）反序列化。"""
    if isinstance(pk_wire, bytes):
        raw = pk_wire
    else:
        from common.wire_codec import b64d

        try:
            raw = b64d(pk_wire)
        except Exception:
            raw = bytes.fromhex(pk_wire)
    return SchnorrPublicKey(y=GROUP.deserialize_point(raw))


class EncPwPlusHttpSession:
    """通过 TCP 与 ``server/tcp_server.py`` 交互的 π_encPw+ 客户端会话。"""

    def __init__(
        self,
        idc: str,
        password: str,
        host: str | None = None,
        port: int | None = None,
        base_url: str | None = None,
        url: str | None = None,
        sid: str = "server-1",
    ) -> None:
        self.idc = idc
        self.password = password
        h, p = resolve_endpoint(host=host, port=port, url=url, base_url=base_url)
        self.host, self.port = h, p
        self.transport = PPKRTcpTransport(h, p, idc=idc)
        pk = self.transport.connect(idc)
        self.client = EncPwPlusClient(
            sid=SID(sid),
            idc=IDC(idc),
            hsm_pk=_hsm_pk_from_wire(pk),
        )
        log.info("EncPw+ 会话就绪 idc=%s tcp=%s:%d", idc, h, p)

    def close(self) -> None:
        self.transport.close()

    def run_init(self) -> bytes:
        K, _ = self.run_init_metrics()
        return K

    def run_init_metrics(self) -> tuple[bytes, dict]:
        log.info("=== Init 开始 idc=%s (TCP) ===", self.idc)
        self.transport.reset_comm()
        t0 = time.perf_counter()
        ssid = self.client.new_ssid()
        r1 = self.transport.post_encpw(self.client.init_start(ssid))
        msg2, K, _ = self.client.init_on_pk(
            self.transport.attested_bytes(r1), ssid, self.password
        )
        r2 = self.transport.post_encpw(msg2)
        result, _ = self.client.init_finish(
            self.transport.attested_bytes(r2), ssid, K
        )
        if result == "Fail":
            raise RuntimeError("Init 失败")
        elapsed = (time.perf_counter() - t0) * 1000
        metrics = {
            "latency_ms": elapsed,
            "comm_bytes": self.transport.comm_bytes,
            "success": True,
        }
        log.info(
            "=== Init 成功 idc=%s K=%s... 耗时=%.2f ms 通信=%d bytes ===",
            self.idc,
            K.hex()[:16],
            elapsed,
            metrics["comm_bytes"],
        )
        return K, metrics

    def run_rec(self) -> bytes:
        K, _ = self.run_rec_metrics()
        return K

    def run_rec_metrics(self) -> tuple[bytes, dict]:
        log.info("=== Rec 开始 idc=%s (TCP) ===", self.idc)
        self.transport.reset_comm()
        t0 = time.perf_counter()
        ssid = self.client.new_ssid()
        r1 = self.transport.post_encpw(self.client.rec_start(ssid))
        msg2, ksym, _ = self.client.rec_on_pk(
            self.transport.attested_bytes(r1), ssid, self.password
        )
        r2 = self.transport.post_encpw(msg2)
        result, _ = self.client.rec_finish(
            self.transport.attested_bytes(r2), ssid, ksym
        )
        if isinstance(result, str):
            raise RuntimeError(f"Rec 失败: {result}")
        elapsed = (time.perf_counter() - t0) * 1000
        metrics = {
            "latency_ms": elapsed,
            "comm_bytes": self.transport.comm_bytes,
            "success": True,
        }
        log.info(
            "=== Rec 成功 idc=%s K=%s... 耗时=%.2f ms 通信=%d bytes ===",
            self.idc,
            result.hex()[:16],
            elapsed,
            metrics["comm_bytes"],
        )
        return result, metrics

    def run_full(self) -> tuple[bytes, bytes]:
        t0 = time.perf_counter()
        K_init = self.run_init()
        K_rec = self.run_rec()
        match = K_init == K_rec
        log.info(
            "=== 完整流程 idc=%s 密钥一致=%s 总耗时=%.2f ms ===",
            self.idc,
            match,
            (time.perf_counter() - t0) * 1000,
        )
        return K_init, K_rec


class OPRFPPKRHttpSession:
    """通过 TCP 与 ``server/tcp_server.py`` 交互的 π_OPRF-PPKR 客户端会话。"""

    def __init__(
        self,
        idc: str,
        password: str,
        host: str | None = None,
        port: int | None = None,
        base_url: str | None = None,
        url: str | None = None,
        sid: str = "server-1",
    ) -> None:
        self.idc = idc
        self.password = password
        h, p = resolve_endpoint(host=host, port=port, url=url, base_url=base_url)
        self.host, self.port = h, p
        self.transport = PPKRTcpTransport(h, p, idc=idc)
        pk = self.transport.connect(idc)
        self.client = OPRFPPKRClient(
            sid=SID(sid),
            idc=IDC(idc),
            hsm_pk=_hsm_pk_from_wire(pk),
        )
        log.info("OPRF-PPKR 会话就绪 idc=%s tcp=%s:%d", idc, h, p)

    def close(self) -> None:
        self.transport.close()

    def run_init(self) -> bytes:
        K, _ = self.run_init_metrics()
        return K

    def run_init_metrics(self) -> tuple[bytes, dict]:
        log.info("=== Init 开始 idc=%s (TCP) ===", self.idc)
        self.transport.reset_comm()
        t0 = time.perf_counter()
        ssid = self.client.new_ssid()
        msg1, state, K, _ = self.client.init_blind(ssid, self.password)
        r1 = self.transport.post_oprf(msg1)
        msg2, K, _ = self.client.init_on_oprf_response(
            self.transport.attested_bytes(r1), ssid, state, K
        )
        r2 = self.transport.post_oprf(msg2)
        result, _ = self.client.init_finish(
            self.transport.attested_bytes(r2), ssid, K
        )
        if result == "Fail":
            raise RuntimeError("Init 失败")
        elapsed = (time.perf_counter() - t0) * 1000
        metrics = {
            "latency_ms": elapsed,
            "comm_bytes": self.transport.comm_bytes,
            "success": True,
        }
        log.info(
            "=== Init 成功 idc=%s 耗时=%.2f ms 通信=%d bytes ===",
            self.idc,
            elapsed,
            metrics["comm_bytes"],
        )
        return K, metrics

    def run_rec(self) -> bytes:
        K, _ = self.run_rec_metrics()
        return K

    def run_rec_metrics(self) -> tuple[bytes, dict]:
        log.info("=== Rec 开始 idc=%s (TCP) ===", self.idc)
        self.transport.reset_comm()
        t0 = time.perf_counter()
        ssid = self.client.new_ssid()
        msg1, state, _ = self.client.rec_blind(ssid, self.password)
        r1 = self.transport.post_oprf(msg1)

        K_rec, sk_c, a_prime, b_prime, _ = self.client.rec_on_oprf_response(
            self.transport.attested_bytes(r1), ssid, state
        )
        if K_rec is None:
            raise RuntimeError("Rec 解密失败")

        att = AttestedMessage.deserialize(self.transport.attested_bytes(r1))
        payload = decode_payload(att.payload)
        msg2, _ = self.client.rec_sign(ssid, a_prime, b_prime, payload["c"], sk_c)
        r2 = self.transport.post_oprf(msg2)
        final, _ = self.client.rec_finish(
            self.transport.attested_bytes(r2), ssid, K_rec
        )
        if isinstance(final, str):
            raise RuntimeError(f"Rec 失败: {final}")
        elapsed = (time.perf_counter() - t0) * 1000
        metrics = {
            "latency_ms": elapsed,
            "comm_bytes": self.transport.comm_bytes,
            "success": True,
        }
        log.info(
            "=== Rec 成功 idc=%s 耗时=%.2f ms 通信=%d bytes ===",
            self.idc,
            elapsed,
            metrics["comm_bytes"],
        )
        return final, metrics

    def run_full(self) -> tuple[bytes, bytes]:
        t0 = time.perf_counter()
        K_init = self.run_init()
        K_rec = self.run_rec()
        match = K_init == K_rec
        log.info(
            "=== 完整流程 idc=%s 密钥一致=%s 总耗时=%.2f ms ===",
            self.idc,
            match,
            (time.perf_counter() - t0) * 1000,
        )
        return K_init, K_rec


EncPwPlusTcpSession = EncPwPlusHttpSession
OPRFPPKRTcpSession = OPRFPPKRHttpSession
