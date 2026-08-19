"""PPKR Client TCP 传输层 — PAEE/PBCS 风格二进制帧。

长连接：HELLO 取 HSM 公钥后，在同一 TCP 上收发 ENCPW/OPRF。
"""

from __future__ import annotations

import time
import uuid
from typing import Any
from urllib.parse import urlparse

import socket

from common.attested_wire import attested_raw
from common.messages import Message, MessageType, recv_message, send_message
from common import wire_codec as WC
from logging_config import setup_logger
from protocols.messages import ProtocolMessage

log = setup_logger("CLIENT")

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765


def parse_endpoint(url_or_host: str, port: int | None = None) -> tuple[str, int]:
    """解析 ``host:port``、``tcp://host:port`` 或 ``http://host:port``。"""
    s = url_or_host.strip()
    if "://" in s:
        u = urlparse(s)
        host = u.hostname or DEFAULT_HOST
        p = u.port if u.port is not None else (port or DEFAULT_PORT)
        return host, p
    if ":" in s and not s.startswith("["):
        host, _, port_s = s.rpartition(":")
        if host and port_s.isdigit():
            return host, int(port_s)
    return s or DEFAULT_HOST, port if port is not None else DEFAULT_PORT


class PPKRTcpTransport:
    """PPKR TCP 客户端传输：长连接，计量应用层通信量。"""

    def __init__(
        self,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        idc: str = "client",
    ) -> None:
        self.host = host
        self.port = port
        self.idc = idc
        self._sock: socket.socket | None = None
        self._hsm_pk: bytes | None = None
        self.comm_bytes: int = 0
        log.info("TCP 传输层初始化 %s:%d idc=%s", host, port, idc)

    def reset_comm(self) -> None:
        self.comm_bytes = 0

    def connect(self, idc: str | None = None) -> bytes:
        """建立 TCP 并完成 HELLO / HELLO_ACK；返回 HSM 公钥 raw 字节。"""
        if idc is not None:
            self.idc = idc
        if self._sock is not None and self._hsm_pk is not None:
            return self._hsm_pk
        try:
            sock = socket.create_connection((self.host, self.port), timeout=30)
        except OSError as e:
            raise RuntimeError(
                f"无法连接 TCP Server {self.host}:{self.port}，请先启动: python serve.py\n原因: {e}"
            ) from e
        self._sock = sock
        ssid = uuid.uuid4().hex
        hello = Message(MessageType.HELLO, ssid, {"idc": self.idc})
        n = send_message(sock, hello, role="client")
        self.comm_bytes += n
        ack = recv_message(sock, role="client")
        self.comm_bytes += len(ack.to_bytes())
        if ack.type != MessageType.HELLO_ACK:
            raise RuntimeError(f"expected HELLO_ACK, got {ack.type}")
        pk = ack.payload.get("pk")
        if not pk:
            raise RuntimeError("HELLO_ACK missing pk")
        self._hsm_pk = pk if isinstance(pk, bytes) else bytes(pk)
        log.info("TCP 已连接并取得 HSM 公钥 (%d B)", len(self._hsm_pk))
        return self._hsm_pk

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def get_hsm_pubkey_hex(self) -> bytes:
        """兼容旧名：返回 HELLO_ACK 中 HSM 公钥 raw bytes。"""
        return self.connect()

    def post_encpw(self, msg: ProtocolMessage) -> dict[str, Any]:
        return self._rpc(MessageType.ENCPW, MessageType.ENCPW_RESP, msg)

    def post_oprf(self, msg: ProtocolMessage) -> dict[str, Any]:
        return self._rpc(MessageType.OPRF, MessageType.OPRF_RESP, msg)

    def _rpc(
        self,
        req_type: str,
        resp_type: str,
        msg: ProtocolMessage,
    ) -> dict[str, Any]:
        self.connect()
        assert self._sock is not None
        payload: dict[str, Any] = {
            "phase": msg.phase,
            "sid": str(msg.sid),
            "ssid": str(msg.ssid),
            "idc": str(msg.idc),
        }
        payload.update(msg.body or {})
        wire = Message(req_type, str(msg.ssid), payload)
        t0 = time.perf_counter()
        n = send_message(self._sock, wire, role="client")
        self.comm_bytes += n
        resp = recv_message(self._sock, role="client")
        self.comm_bytes += len(resp.to_bytes())
        elapsed = (time.perf_counter() - t0) * 1000
        if resp.type == MessageType.ERROR:
            raise RuntimeError(resp.payload.get("error", "server error"))
        if resp.type != resp_type:
            raise RuntimeError(f"expected {resp_type}, got {resp.type}")
        log.info(
            "TCP %s phase=%s 耗时=%.2f ms",
            req_type,
            msg.phase,
            elapsed,
        )
        return dict(resp.payload)

    def attested_bytes(self, response: dict[str, Any]) -> bytes:
        return attested_raw(response)


class PPKRHttpTransport(PPKRTcpTransport):
    """兼容别名。"""

    def __init__(
        self,
        base_url: str = "tcp://127.0.0.1:8765",
        idc: str = "client",
        host: str | None = None,
        port: int | None = None,
    ) -> None:
        if host is not None:
            h, p = host, port if port is not None else DEFAULT_PORT
        else:
            h, p = parse_endpoint(base_url, port)
        super().__init__(host=h, port=p, idc=idc)
