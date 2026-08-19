"""PBCS/PAEE 风格二进制线编解码（PPKR）。

线格式::
    opcode(1) ‖ [u16_be len ‖ field]* …

无外层总长度头、无 JSON/Base64；群元/密文为原始字节。
字段长度用 u16（DHIES 密文常接近或超过 255）。

业务层仍用 dict（type 字符串 + bytes/str 字段）；本模块负责 ↔ 原始字节。
"""

from __future__ import annotations

import base64
import struct
from typing import Any

# -------- 兼容旧代码的 Base64 辅助（HTTP 遗留 / 本地调试）--------


def b64e(data: bytes) -> str:
    """bytes → URL-safe Base64 ASCII（无换行）。"""
    return base64.urlsafe_b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    """URL-safe Base64 ASCII → bytes。"""
    return base64.urlsafe_b64decode(text.encode("ascii"))


# -------- opcodes --------
OP_HELLO = 0x01
OP_HELLO_ACK = 0x02
OP_ENCPW_REQ = 0x10
OP_ENCPW_RESP = 0x11
OP_OPRF_REQ = 0x20
OP_OPRF_RESP = 0x21
OP_ERR = 0x07
OP_STATS = 0x30
OP_STATS_RESP = 0x31
OP_LEAK = 0x32
OP_LEAK_RESP = 0x33

HELLO = "HELLO"
HELLO_ACK = "HELLO_ACK"
ENCPW_REQ = "ENCPW_REQ"
ENCPW_RESP = "ENCPW_RESP"
OPRF_REQ = "OPRF_REQ"
OPRF_RESP = "OPRF_RESP"
ERR = "ERR"
STATS = "STATS"
STATS_RESP = "STATS_RESP"
LEAK = "LEAK"
LEAK_RESP = "LEAK_RESP"

TYPE_TO_OP: dict[str, int] = {
    HELLO: OP_HELLO,
    HELLO_ACK: OP_HELLO_ACK,
    ENCPW_REQ: OP_ENCPW_REQ,
    ENCPW_RESP: OP_ENCPW_RESP,
    OPRF_REQ: OP_OPRF_REQ,
    OPRF_RESP: OP_OPRF_RESP,
    ERR: OP_ERR,
    STATS: OP_STATS,
    STATS_RESP: OP_STATS_RESP,
    LEAK: OP_LEAK,
    LEAK_RESP: OP_LEAK_RESP,
}

OP_TO_TYPE: dict[int, str] = {v: k for k, v in TYPE_TO_OP.items()}

# 各类型字段个数（recv 流式读取用）；ENCPW/OPRF REQ 含 phase 决定的尾部字段
# HELLO: idc
# HELLO_ACK: idc, pk
# ENCPW_REQ: phase, sid, ssid, idc, [C?]  — 变长，见 encode
# ENCPW_RESP: ssid, idc, sig, payload
# OPRF_REQ: phase, sid, ssid, idc, ...
# OPRF_RESP: ssid, idc, sig, payload
# ERR: code, msg
# STATS: (empty)
# STATS_RESP: json_blob (1 field, utf-8 json for simplicity)
# LEAK: (empty)
# LEAK_RESP: count u32 as 4 bytes field


def _put(buf: bytearray, data: bytes) -> None:
    if len(data) > 0xFFFF:
        raise ValueError(f"wire field too long ({len(data)} > 65535)")
    buf.extend(struct.pack(">H", len(data)))
    buf.extend(data)


def _put_str(buf: bytearray, s: str) -> None:
    _put(buf, s.encode("utf-8"))


def _get(data: bytes, i: int) -> tuple[bytes, int]:
    if i + 2 > len(data):
        raise ValueError("truncated wire: missing length")
    (n,) = struct.unpack_from(">H", data, i)
    i += 2
    if i + n > len(data):
        raise ValueError("truncated wire: short field")
    return data[i : i + n], i + n


def _get_str(data: bytes, i: int) -> tuple[str, int]:
    raw, i = _get(data, i)
    return raw.decode("utf-8"), i


def _as_bytes(v: Any) -> bytes:
    if isinstance(v, bytes):
        return v
    if isinstance(v, str):
        # 兼容误传 Base64 的旧路径
        try:
            return b64d(v)
        except Exception:
            return v.encode("utf-8")
    raise TypeError(f"expected bytes|str, got {type(v)}")


def encode_message(obj: dict[str, Any]) -> bytes:
    """业务 dict → 二进制消息（含 opcode）。"""
    t = obj.get("type")
    if t not in TYPE_TO_OP:
        raise ValueError(f"unknown message type for binary wire: {t!r}")
    op = TYPE_TO_OP[t]
    buf = bytearray([op])

    if t == HELLO:
        _put_str(buf, str(obj["idc"]))
    elif t == HELLO_ACK:
        _put_str(buf, str(obj["idc"]))
        _put(buf, _as_bytes(obj["pk"]))
    elif t == ENCPW_REQ:
        phase = str(obj["phase"])
        _put_str(buf, phase)
        _put_str(buf, str(obj["sid"]))
        _put_str(buf, str(obj["ssid"]))
        _put_str(buf, str(obj["idc"]))
        if phase in ("Init", "Rec"):
            _put(buf, _as_bytes(obj["C"]))
    elif t == ENCPW_RESP:
        _put_str(buf, str(obj["ssid"]))
        _put_str(buf, str(obj.get("idc") or ""))
        _put(buf, _as_bytes(obj["sig"]))
        _put(buf, _as_bytes(obj["payload"]))
    elif t == OPRF_REQ:
        phase = str(obj["phase"])
        _put_str(buf, phase)
        _put_str(buf, str(obj["sid"]))
        _put_str(buf, str(obj["ssid"]))
        _put_str(buf, str(obj["idc"]))
        if phase == "Init":
            _put(buf, _as_bytes(obj["a"]))
        elif phase == "InitFinish":
            _put(buf, _as_bytes(obj["C"]))
        elif phase == "Rec":
            _put(buf, _as_bytes(obj["a_prime"]))
        elif phase == "RecSign":
            _put(buf, _as_bytes(obj.get("a_prime") or b""))
            _put(buf, _as_bytes(obj.get("b_prime") or b""))
            _put(buf, _as_bytes(obj["c"]))
            _put(buf, _as_bytes(obj["sigma"]))
        else:
            raise ValueError(f"unknown OPRF phase: {phase}")
    elif t == OPRF_RESP:
        _put_str(buf, str(obj["ssid"]))
        _put_str(buf, str(obj.get("idc") or ""))
        _put(buf, _as_bytes(obj["sig"]))
        _put(buf, _as_bytes(obj["payload"]))
    elif t == ERR:
        _put_str(buf, str(obj.get("code", "")))
        _put_str(buf, str(obj.get("msg", obj.get("error", ""))))
    elif t == STATS:
        pass
    elif t == STATS_RESP:
        import json

        blob = json.dumps(obj.get("stats") or obj, separators=(",", ":")).encode()
        _put(buf, blob)
    elif t == LEAK:
        pass
    elif t == LEAK_RESP:
        _put(buf, struct.pack(">I", int(obj.get("leaked_count", 0))))
    else:
        raise ValueError(f"encode not implemented: {t}")

    return bytes(buf)


def decode_message(data: bytes) -> dict[str, Any]:
    """二进制消息 → 业务 dict（bytes 字段）。"""
    if not data:
        raise ValueError("empty wire message")
    op = data[0]
    if op not in OP_TO_TYPE:
        raise ValueError(f"unknown opcode: 0x{op:02x}")
    t = OP_TO_TYPE[op]
    i = 1

    if t == HELLO:
        idc, i = _get_str(data, i)
        return {"type": t, "idc": idc}
    if t == HELLO_ACK:
        idc, i = _get_str(data, i)
        pk, i = _get(data, i)
        return {"type": t, "idc": idc, "pk": pk}
    if t == ENCPW_REQ:
        phase, i = _get_str(data, i)
        sid, i = _get_str(data, i)
        ssid, i = _get_str(data, i)
        idc, i = _get_str(data, i)
        out: dict[str, Any] = {
            "type": t,
            "phase": phase,
            "sid": sid,
            "ssid": ssid,
            "idc": idc,
        }
        if phase in ("Init", "Rec"):
            C, i = _get(data, i)
            out["C"] = C
        return out
    if t == ENCPW_RESP:
        ssid, i = _get_str(data, i)
        idc, i = _get_str(data, i)
        sig, i = _get(data, i)
        payload, i = _get(data, i)
        return {
            "type": t,
            "ssid": ssid,
            "idc": idc or None,
            "sig": sig,
            "payload": payload,
        }
    if t == OPRF_REQ:
        phase, i = _get_str(data, i)
        sid, i = _get_str(data, i)
        ssid, i = _get_str(data, i)
        idc, i = _get_str(data, i)
        out = {
            "type": t,
            "phase": phase,
            "sid": sid,
            "ssid": ssid,
            "idc": idc,
        }
        if phase == "Init":
            a, i = _get(data, i)
            out["a"] = a
        elif phase == "InitFinish":
            C, i = _get(data, i)
            out["C"] = C
        elif phase == "Rec":
            a_prime, i = _get(data, i)
            out["a_prime"] = a_prime
        elif phase == "RecSign":
            a_prime, i = _get(data, i)
            b_prime, i = _get(data, i)
            c, i = _get(data, i)
            sigma, i = _get(data, i)
            out["a_prime"] = a_prime
            out["b_prime"] = b_prime
            out["c"] = c
            out["sigma"] = sigma
        else:
            raise ValueError(f"unknown OPRF phase: {phase}")
        return out
    if t == OPRF_RESP:
        ssid, i = _get_str(data, i)
        idc, i = _get_str(data, i)
        sig, i = _get(data, i)
        payload, i = _get(data, i)
        return {
            "type": t,
            "ssid": ssid,
            "idc": idc or None,
            "sig": sig,
            "payload": payload,
        }
    if t == ERR:
        code, i = _get_str(data, i)
        msg, i = _get_str(data, i)
        return {"type": t, "code": code, "msg": msg, "error": msg}
    if t == STATS:
        return {"type": t}
    if t == STATS_RESP:
        import json

        blob, i = _get(data, i)
        stats = json.loads(blob.decode())
        return {"type": t, **stats}
    if t == LEAK:
        return {"type": t}
    if t == LEAK_RESP:
        raw, i = _get(data, i)
        (n,) = struct.unpack(">I", raw)
        return {"type": t, "leaked_count": n}

    raise ValueError(f"decode not implemented: {t}")


def field_layout(t: str, phase: str | None = None) -> list[str]:
    """返回该消息类型的字段读取序列（用于 framing 流式 recv）。"""
    if t == HELLO:
        return ["lv"]
    if t == HELLO_ACK:
        return ["lv", "lv"]
    if t == ENCPW_REQ:
        # phase,sid,ssid,idc 已读；若 Init/Rec 再读 C — framing 需特殊处理
        base = ["lv", "lv", "lv", "lv"]
        if phase in ("Init", "Rec"):
            base.append("lv")
        return base
    if t in (ENCPW_RESP, OPRF_RESP):
        return ["lv", "lv", "lv", "lv"]  # ssid, idc, sig, payload
    if t == OPRF_REQ:
        base = ["lv", "lv", "lv", "lv"]
        if phase == "Init":
            base.append("lv")
        elif phase == "InitFinish":
            base.append("lv")
        elif phase == "Rec":
            base.append("lv")
        elif phase == "RecSign":
            base.extend(["lv", "lv", "lv", "lv"])
        return base
    if t == ERR:
        return ["lv", "lv"]
    if t in (STATS, LEAK):
        return []
    if t in (STATS_RESP, LEAK_RESP):
        return ["lv"]
    raise ValueError(f"unknown layout for {t}")
