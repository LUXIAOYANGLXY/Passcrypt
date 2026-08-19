# -*- coding: utf-8 -*-
"""
net/wire_codec.py
=================
PBCS/E2SE 风格二进制线编解码。

线格式（对齐 E2SE AuthServer）：
  opcode(1) ‖ [len(1) ‖ payload]* … ‖ 少量定长字段

上层仍使用 dict（type 字符串 + Base64 字段），本模块负责 ↔ 原始字节。
字段长度 ≤ 255（与 PBCS 一致）；ct2 本体不上线，仅传 ct2_len(uint64 BE)。
"""

from __future__ import annotations

import base64
import struct
from typing import Any, Dict, List, Tuple

from net import messages as M

# -------- opcodes（与 messages 字符串 type 双向映射）--------
OP_REG_REQ = 0x10
OP_REG_CTX = 0x11
OP_REG_BLIND = 0x12
OP_REG_EVAL = 0x13
OP_REG_COMMIT = 0x14
OP_REG_ACK = 0x15

OP_EXT_REQ = 0x20
OP_EXT_CTX = 0x21
OP_EXT_BLIND = 0x22
OP_EXT_EVAL = 0x23

OP_ENC_COMMIT = 0x30
OP_ENC_ACK = 0x31

OP_DEC_REQ = 0x40
OP_DEC_RESP = 0x41

OP_ERR = 0x07  # 对齐 PBCS RESP_TYPE_ERROR

TYPE_TO_OP: Dict[str, int] = {
    M.REG_REQ: OP_REG_REQ,
    M.REG_CTX: OP_REG_CTX,
    M.REG_BLIND: OP_REG_BLIND,
    M.REG_EVAL: OP_REG_EVAL,
    M.REG_COMMIT: OP_REG_COMMIT,
    M.REG_ACK: OP_REG_ACK,
    M.EXT_REQ: OP_EXT_REQ,
    M.EXT_CTX: OP_EXT_CTX,
    M.EXT_BLIND: OP_EXT_BLIND,
    M.EXT_EVAL: OP_EXT_EVAL,
    M.ENC_COMMIT: OP_ENC_COMMIT,
    M.ENC_ACK: OP_ENC_ACK,
    M.DEC_REQ: OP_DEC_REQ,
    M.DEC_RESP: OP_DEC_RESP,
    M.ERR: OP_ERR,
}

OP_TO_TYPE: Dict[int, str] = {v: k for k, v in TYPE_TO_OP.items()}


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _as_bytes(v: Any) -> bytes:
    """dict 字段可能是 raw bytes 或 Base64 str。"""
    if isinstance(v, bytes):
        return v
    if isinstance(v, str):
        return base64.b64decode(v.encode("ascii"))
    raise TypeError(f"expected bytes|b64 str, got {type(v)}")


def _put(buf: bytearray, data: bytes) -> None:
    if len(data) > 255:
        raise ValueError(f"wire field too long ({len(data)} > 255)")
    buf.append(len(data) & 0xFF)
    buf.extend(data)


def _put_str(buf: bytearray, s: str) -> None:
    _put(buf, s.encode("utf-8"))


def _get(data: bytes, i: int) -> Tuple[bytes, int]:
    if i >= len(data):
        raise ValueError("truncated wire: missing length")
    n = data[i]
    i += 1
    if i + n > len(data):
        raise ValueError("truncated wire: short field")
    return data[i : i + n], i + n


def _get_str(data: bytes, i: int) -> Tuple[str, int]:
    raw, i = _get(data, i)
    return raw.decode("utf-8"), i


def encode_message(obj: Dict[str, Any]) -> bytes:
    """业务 dict → 二进制消息（含 opcode）。"""
    t = obj.get("type")
    if t not in TYPE_TO_OP:
        raise ValueError(f"unknown message type for binary wire: {t!r}")
    op = TYPE_TO_OP[t]
    buf = bytearray([op])

    if t == M.REG_REQ:
        _put_str(buf, str(obj["id"]))
    elif t == M.REG_CTX:
        pk = obj["pk"]
        _put(buf, _as_bytes(pk["K"]))
        _put(buf, _as_bytes(pk["X"]))
        _put(buf, _as_bytes(obj["ctx"]))
    elif t == M.REG_BLIND:
        _put_str(buf, str(obj["id"]))
        _put(buf, _as_bytes(obj["a"]))
        _put(buf, _as_bytes(obj["ctx"]))
    elif t == M.REG_EVAL:
        # pk 上线但统计时可剔除；仅 Reg 应答含 pk
        pk = obj["pk"]
        _put(buf, _as_bytes(pk["K"]))
        _put(buf, _as_bytes(pk["X"]))
        _put(buf, _as_bytes(obj["a_tilde"]))
    elif t == M.REG_COMMIT:
        _put_str(buf, str(obj["id"]))
        _put(buf, _as_bytes(obj["c"]))
    elif t == M.REG_ACK:
        buf.append(1 if obj.get("ok") else 0)
    elif t == M.EXT_REQ:
        _put_str(buf, str(obj["id"]))
    elif t == M.EXT_CTX:
        _put(buf, _as_bytes(obj["ctx"]))
    elif t == M.EXT_BLIND:
        _put_str(buf, str(obj["id"]))
        _put(buf, _as_bytes(obj["a"]))
    elif t == M.EXT_EVAL:
        _put(buf, _as_bytes(obj["a_tilde"]))
    elif t == M.ENC_COMMIT:
        ct = obj["ct"]
        _put_str(buf, str(obj["id"]))
        _put(buf, _as_bytes(obj["c_prime"]))
        _put(buf, _as_bytes(ct["ct0"]))
        _put(buf, _as_bytes(ct["ct1"]))
        _put(buf, _as_bytes(ct["tau"]))
        # ct2 不上线；只传长度
        ct2_len = int(ct.get("ct2_len", 0))
        buf.extend(struct.pack(">Q", ct2_len))
    elif t == M.ENC_ACK:
        buf.append(1 if obj.get("ok") else 0)
    elif t == M.DEC_REQ:
        _put_str(buf, str(obj["id"]))
    elif t == M.DEC_RESP:
        ct = obj["ct"]
        _put(buf, _as_bytes(ct["ct0"]))
        _put(buf, _as_bytes(ct["ct1"]))
        _put(buf, _as_bytes(ct["tau"]))
        ct2_len = int(ct.get("ct2_len", 0))
        buf.extend(struct.pack(">Q", ct2_len))
        _put(buf, _as_bytes(obj["d"]))
    elif t == M.ERR:
        _put_str(buf, str(obj.get("code", "")))
        _put_str(buf, str(obj.get("msg", "")))
    else:
        raise ValueError(f"encode not implemented: {t}")

    return bytes(buf)


def decode_message(data: bytes) -> Dict[str, Any]:
    """二进制消息 → 业务 dict（Base64 字段，兼容现有 client/server_api）。"""
    if not data:
        raise ValueError("empty wire message")
    op = data[0]
    if op not in OP_TO_TYPE:
        raise ValueError(f"unknown opcode: 0x{op:02x}")
    t = OP_TO_TYPE[op]
    i = 1

    if t == M.REG_REQ:
        uid, i = _get_str(data, i)
        return {"type": t, "id": uid}
    if t == M.REG_CTX:
        K, i = _get(data, i)
        X, i = _get(data, i)
        ctx, i = _get(data, i)
        return {
            "type": t,
            "pk": {"K": _b64e(K), "X": _b64e(X)},
            "ctx": _b64e(ctx),
        }
    if t == M.REG_BLIND:
        uid, i = _get_str(data, i)
        a, i = _get(data, i)
        ctx, i = _get(data, i)
        return {"type": t, "id": uid, "a": _b64e(a), "ctx": _b64e(ctx)}
    if t == M.REG_EVAL:
        K, i = _get(data, i)
        X, i = _get(data, i)
        a_tilde, i = _get(data, i)
        return {
            "type": t,
            "pk": {"K": _b64e(K), "X": _b64e(X)},
            "a_tilde": _b64e(a_tilde),
        }
    if t == M.REG_COMMIT:
        uid, i = _get_str(data, i)
        c, i = _get(data, i)
        return {"type": t, "id": uid, "c": _b64e(c)}
    if t == M.REG_ACK:
        if i >= len(data):
            raise ValueError("truncated REG_ACK")
        return {"type": t, "ok": bool(data[i])}
    if t == M.EXT_REQ:
        uid, i = _get_str(data, i)
        return {"type": t, "id": uid}
    if t == M.EXT_CTX:
        ctx, i = _get(data, i)
        return {"type": t, "ctx": _b64e(ctx)}
    if t == M.EXT_BLIND:
        uid, i = _get_str(data, i)
        a, i = _get(data, i)
        return {"type": t, "id": uid, "a": _b64e(a)}
    if t == M.EXT_EVAL:
        a_tilde, i = _get(data, i)
        return {"type": t, "a_tilde": _b64e(a_tilde)}
    if t == M.ENC_COMMIT:
        uid, i = _get_str(data, i)
        c_prime, i = _get(data, i)
        ct0, i = _get(data, i)
        ct1, i = _get(data, i)
        tau, i = _get(data, i)
        if i + 8 > len(data):
            raise ValueError("truncated ENC_COMMIT ct2_len")
        (ct2_len,) = struct.unpack(">Q", data[i : i + 8])
        return {
            "type": t,
            "id": uid,
            "c_prime": _b64e(c_prime),
            "ct": {
                "ct0": _b64e(ct0),
                "ct1": _b64e(ct1),
                "ct2": _b64e(b""),
                "tau": _b64e(tau),
                "ct2_len": ct2_len,
                "omit_ct2": True,
            },
        }
    if t == M.ENC_ACK:
        if i >= len(data):
            raise ValueError("truncated ENC_ACK")
        return {"type": t, "ok": bool(data[i])}
    if t == M.DEC_REQ:
        uid, i = _get_str(data, i)
        return {"type": t, "id": uid}
    if t == M.DEC_RESP:
        ct0, i = _get(data, i)
        ct1, i = _get(data, i)
        tau, i = _get(data, i)
        if i + 8 > len(data):
            raise ValueError("truncated DEC_RESP ct2_len")
        (ct2_len,) = struct.unpack(">Q", data[i : i + 8])
        i += 8
        d, i = _get(data, i)
        return {
            "type": t,
            "ct": {
                "ct0": _b64e(ct0),
                "ct1": _b64e(ct1),
                "ct2": _b64e(b""),
                "tau": _b64e(tau),
                "ct2_len": ct2_len,
                "omit_ct2": True,
            },
            "d": _b64e(d),
        }
    if t == M.ERR:
        code, i = _get_str(data, i)
        msg, i = _get_str(data, i)
        return {"type": t, "code": code, "msg": msg}

    raise ValueError(f"decode not implemented: {t}")


def message_byte_length(obj: Dict[str, Any]) -> int:
    """编码后字节数（供测试）。"""
    return len(encode_message(obj))
