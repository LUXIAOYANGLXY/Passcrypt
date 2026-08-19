"""
WBP framing (Client↔Server) — PBCS/E2SE-inspired binary wire.

Format: opcode(1) ‖ [u16BE len ‖ field]* ‖ 少量 u8
(No outer length header, no JSON/Base64 on the wire.)

HELLO stands in for Noise+SMS IDC auth (Davies et al. Crypto'23).
"""

from __future__ import annotations

import logging
import socket
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from . import wire_codec as WC

log = logging.getLogger("wbp.wire")


class MessageType(str, Enum):
    HELLO = "HELLO"
    HELLO_ACK = "HELLO_ACK"

    INIT_REQ = "INIT_REQ"
    INIT_HSM_RESP = "INIT_HSM_RESP"
    INIT_UPLOAD = "INIT_UPLOAD"
    INIT_RESULT = "INIT_RESULT"
    REC_REQ = "REC_REQ"
    REC_HSM_RESP = "REC_HSM_RESP"
    REC_CONFIRM = "REC_CONFIRM"
    REC_KEY = "REC_KEY"
    REC_RESULT = "REC_RESULT"
    ERROR = "ERROR"


@dataclass
class Message:
    type: MessageType
    ssid: str
    payload: dict[str, Any] = field(default_factory=dict)

    def to_bytes(self) -> bytes:
        return WC.encode_fields(self.type.value, self.ssid, self.payload)

    @classmethod
    def from_bytes(cls, data: bytes) -> Message:
        msg_type, ssid, payload = WC.decode_fields(data)
        return cls(type=MessageType(msg_type), ssid=ssid, payload=payload)


def _payload_summary(payload: dict[str, Any]) -> str:
    parts: list[str] = []
    for k, v in payload.items():
        if isinstance(v, str) and len(v) > 48:
            parts.append(f"{k}=<{len(v)} chars>")
        else:
            parts.append(f"{k}={v!r}")
    return "{" + ", ".join(parts) + "}"


def send_message(sock: socket.socket, msg: Message, *, role: str = "") -> int:
    """Encode and send one binary message; return wire byte count."""
    prefix = f"{role} " if role else ""
    log.info(
        "%sTX %s ssid=%s %s",
        prefix,
        msg.type.value,
        msg.ssid[:8] if msg.ssid else "-",
        _payload_summary(msg.payload),
    )
    data = msg.to_bytes()
    sock.sendall(data)
    return len(data)


def _recvexact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("socket closed while receiving")
        buf.extend(chunk)
    return bytes(buf)


def recv_message(sock: socket.socket, *, role: str = "") -> Message:
    """
    Stream-read one complete binary message (opcode first, then layout fields).
    No outer total-length header — same style as PAEE framing.
    """
    raw = bytearray()
    op_b = _recvexact(sock, 1)
    raw.extend(op_b)
    op = op_b[0]
    if op not in WC.OP_TO_TYPE:
        raise ValueError(f"unknown opcode: 0x{op:02x}")
    msg_type = WC.OP_TO_TYPE[op]
    layout = WC.RECV_LAYOUT[msg_type]

    def take_lv() -> None:
        lb = _recvexact(sock, 2)
        raw.extend(lb)
        (n,) = struct.unpack(">H", lb)
        if n:
            raw.extend(_recvexact(sock, n))

    def take_u8() -> None:
        raw.extend(_recvexact(sock, 1))

    for step in layout:
        if step in ("ssid", "lv"):
            take_lv()
        elif step == "u8":
            take_u8()
        else:
            raise ValueError(f"unknown layout step: {step}")

    msg = Message.from_bytes(bytes(raw))
    prefix = f"{role} " if role else ""
    log.info(
        "%sRX %s ssid=%s %s",
        prefix,
        msg.type.value,
        msg.ssid[:8] if msg.ssid else "-",
        _payload_summary(msg.payload),
    )
    return msg
