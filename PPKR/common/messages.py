"""PPKR TCP 成帧 — 对齐 PAEE/PBCS：opcode + u16 长度前缀字段。

线格式见 ``common.wire_codec``；无外层 4B 总长度头、无 JSON/Base64。
"""

from __future__ import annotations

import logging
import socket
import struct
from dataclasses import dataclass, field
from typing import Any

from common import wire_codec as WC

log = logging.getLogger("ppkr.wire")


# 兼容旧 MessageType 枚举名的别名（测试 / 文档）
class MessageType:
    HELLO = WC.HELLO
    HELLO_ACK = WC.HELLO_ACK
    ENCPW = WC.ENCPW_REQ
    ENCPW_RESP = WC.ENCPW_RESP
    OPRF = WC.OPRF_REQ
    OPRF_RESP = WC.OPRF_RESP
    STATS = WC.STATS
    STATS_RESP = WC.STATS_RESP
    LEAK = WC.LEAK
    LEAK_RESP = WC.LEAK_RESP
    ERROR = WC.ERR


@dataclass
class Message:
    """一条 TCP 业务消息（dict 视图）；``.type`` 为字符串 opcode 名。"""

    type: str
    ssid: str = ""
    payload: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """合并为 wire_codec 可编码的 dict。"""
        t = self.type
        d: dict[str, Any] = {"type": t}
        if t == WC.HELLO:
            d["idc"] = self.payload.get("idc", "")
        elif t == WC.HELLO_ACK:
            d["idc"] = self.payload.get("idc", "")
            d["pk"] = self.payload["pk"]
        elif t == WC.ENCPW_REQ:
            d["phase"] = self.payload["phase"]
            d["sid"] = self.payload.get("sid", "server-1")
            d["ssid"] = self.ssid or self.payload.get("ssid", "")
            d["idc"] = self.payload.get("idc", "")
            if "C" in self.payload:
                d["C"] = self.payload["C"]
        elif t == WC.ENCPW_RESP:
            d["ssid"] = self.ssid or self.payload.get("ssid", "")
            d["idc"] = self.payload.get("idc") or ""
            d["sig"] = self.payload["sig"]
            d["payload"] = self.payload["payload"]
        elif t == WC.OPRF_REQ:
            d["phase"] = self.payload["phase"]
            d["sid"] = self.payload.get("sid", "server-1")
            d["ssid"] = self.ssid or self.payload.get("ssid", "")
            d["idc"] = self.payload.get("idc", "")
            for k in ("a", "C", "a_prime", "b_prime", "c", "sigma"):
                if k in self.payload:
                    d[k] = self.payload[k]
        elif t == WC.OPRF_RESP:
            d["ssid"] = self.ssid or self.payload.get("ssid", "")
            d["idc"] = self.payload.get("idc") or ""
            d["sig"] = self.payload["sig"]
            d["payload"] = self.payload["payload"]
        elif t == WC.ERR:
            d["code"] = self.payload.get("code", "")
            d["msg"] = self.payload.get("msg") or self.payload.get("error", "")
        elif t == WC.STATS:
            pass
        elif t == WC.STATS_RESP:
            d["stats"] = {
                k: v
                for k, v in self.payload.items()
                if k != "type"
            }
        elif t == WC.LEAK:
            pass
        elif t == WC.LEAK_RESP:
            d["leaked_count"] = self.payload.get("leaked_count", 0)
        else:
            raise ValueError(f"unsupported message type: {t}")
        return d

    def to_bytes(self) -> bytes:
        return WC.encode_message(self.to_dict())

    @classmethod
    def from_dict(cls, obj: dict[str, Any]) -> Message:
        t = obj["type"]
        if t == WC.HELLO:
            return cls(t, "", {"idc": obj["idc"]})
        if t == WC.HELLO_ACK:
            return cls(t, "", {"idc": obj["idc"], "pk": obj["pk"]})
        if t == WC.ENCPW_REQ:
            p = {
                "phase": obj["phase"],
                "sid": obj["sid"],
                "ssid": obj["ssid"],
                "idc": obj["idc"],
            }
            if "C" in obj:
                p["C"] = obj["C"]
            return cls(t, obj["ssid"], p)
        if t in (WC.ENCPW_RESP, WC.OPRF_RESP):
            return cls(
                t,
                obj["ssid"],
                {
                    "ssid": obj["ssid"],
                    "idc": obj.get("idc"),
                    "sig": obj["sig"],
                    "payload": obj["payload"],
                },
            )
        if t == WC.OPRF_REQ:
            p = {
                "phase": obj["phase"],
                "sid": obj["sid"],
                "ssid": obj["ssid"],
                "idc": obj["idc"],
            }
            for k in ("a", "C", "a_prime", "b_prime", "c", "sigma"):
                if k in obj:
                    p[k] = obj[k]
            return cls(t, obj["ssid"], p)
        if t == WC.ERR:
            return cls(t, "", {"code": obj.get("code", ""), "error": obj.get("msg", "")})
        if t == WC.STATS:
            return cls(t, "", {})
        if t == WC.STATS_RESP:
            payload = {k: v for k, v in obj.items() if k != "type"}
            return cls(t, "", payload)
        if t == WC.LEAK:
            return cls(t, "", {})
        if t == WC.LEAK_RESP:
            return cls(t, "", {"leaked_count": obj.get("leaked_count", 0)})
        raise ValueError(f"unsupported type: {t}")


def _recvexact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("socket closed while receiving")
        buf.extend(chunk)
    return bytes(buf)


def _take_lv(sock: socket.socket, raw: bytearray) -> None:
    lb = _recvexact(sock, 2)
    raw.extend(lb)
    (n,) = struct.unpack(">H", lb)
    if n:
        raw.extend(_recvexact(sock, n))


def send_message(sock: socket.socket, msg: Message, *, role: str = "") -> int:
    """编码并发送一条二进制消息；返回 wire 字节数。"""
    data = msg.to_bytes()
    prefix = f"{role} " if role else ""
    log.info(
        "%sTX %s ssid=%s fields=%s (%d B)",
        prefix,
        msg.type,
        (msg.ssid[:8] if msg.ssid else "-"),
        list(msg.payload.keys()),
        len(data),
    )
    sock.sendall(data)
    return len(data)


def recv_message(sock: socket.socket, *, role: str = "") -> Message:
    """流式接收一条完整二进制消息并解码。"""
    raw = bytearray()
    op_b = _recvexact(sock, 1)
    raw.extend(op_b)
    op = op_b[0]
    if op not in WC.OP_TO_TYPE:
        raise ValueError(f"unknown opcode: 0x{op:02x}")
    t = WC.OP_TO_TYPE[op]

    if t in (WC.STATS, WC.LEAK):
        pass
    elif t == WC.HELLO:
        _take_lv(sock, raw)
    elif t == WC.HELLO_ACK:
        _take_lv(sock, raw)
        _take_lv(sock, raw)
    elif t == WC.ENCPW_REQ:
        # phase, sid, ssid, idc
        for _ in range(4):
            _take_lv(sock, raw)
        # peek phase from raw (skip opcode)
        phase, _ = WC._get_str(bytes(raw), 1)
        if phase in ("Init", "Rec"):
            _take_lv(sock, raw)
    elif t == WC.OPRF_REQ:
        for _ in range(4):
            _take_lv(sock, raw)
        phase, _ = WC._get_str(bytes(raw), 1)
        if phase in ("Init", "InitFinish", "Rec"):
            _take_lv(sock, raw)
        elif phase == "RecSign":
            for _ in range(4):
                _take_lv(sock, raw)
        else:
            raise ValueError(f"unknown OPRF phase on wire: {phase}")
    elif t in (WC.ENCPW_RESP, WC.OPRF_RESP):
        for _ in range(4):
            _take_lv(sock, raw)
    elif t == WC.ERR:
        _take_lv(sock, raw)
        _take_lv(sock, raw)
    elif t in (WC.STATS_RESP, WC.LEAK_RESP):
        _take_lv(sock, raw)
    else:
        raise ValueError(f"recv not implemented for {t}")

    obj = WC.decode_message(bytes(raw))
    msg = Message.from_dict(obj)
    prefix = f"{role} " if role else ""
    log.info(
        "%sRX %s ssid=%s (%d B)",
        prefix,
        msg.type,
        (msg.ssid[:8] if msg.ssid else "-"),
        len(raw),
    )
    return msg
