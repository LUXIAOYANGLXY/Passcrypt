"""HSM attested payload 二进制编解码（签名覆盖的内容）。

替代旧版 JSON+Base64 载荷。Client / HSM 共用；验签后解析为 dict（bytes 字段）。

线格式（payload 本体）::
    tag(1) ‖ [u16_be len ‖ field]*

Tags:
    0x01 pkEnc          — pk
    0x02 InitRes        — result (1B: 0=Fail, 1=Succ)
    0x03 RecRes         — result (1B: 0=Fail, 1=Succ, 2=DelRec) ‖ [C_prime?]
    0x04 oprf_eval      — b ‖ pkEnc
    0x05 oprf_rec_eval  — b_prime ‖ c
"""

from __future__ import annotations

import struct
from typing import Any

TAG_PK_ENC = 0x01
TAG_INIT_RES = 0x02
TAG_REC_RES = 0x03
TAG_OPRF_EVAL = 0x04
TAG_OPRF_REC_EVAL = 0x05

_RESULT = {"Fail": 0, "Succ": 1, "DelRec": 2}
_RESULT_INV = {v: k for k, v in _RESULT.items()}


def _put(buf: bytearray, data: bytes) -> None:
    if len(data) > 0xFFFF:
        raise ValueError(f"payload field too long ({len(data)})")
    buf.extend(struct.pack(">H", len(data)))
    buf.extend(data)


def _get(data: bytes, i: int) -> tuple[bytes, int]:
    if i + 2 > len(data):
        raise ValueError("truncated payload")
    (n,) = struct.unpack_from(">H", data, i)
    i += 2
    if i + n > len(data):
        raise ValueError("truncated payload field")
    return data[i : i + n], i + n


def encode_pk_enc(pk: bytes) -> bytes:
    buf = bytearray([TAG_PK_ENC])
    _put(buf, pk)
    return bytes(buf)


def encode_init_res(result: str) -> bytes:
    code = _RESULT.get(result, 0)
    return bytes([TAG_INIT_RES, code])


def encode_rec_res(result: str, c_prime: bytes | None = None) -> bytes:
    buf = bytearray([TAG_REC_RES, _RESULT.get(result, 0)])
    if result == "Succ" and c_prime is not None:
        _put(buf, c_prime)
    return bytes(buf)


def encode_oprf_eval(b: bytes, pk_enc: bytes) -> bytes:
    buf = bytearray([TAG_OPRF_EVAL])
    _put(buf, b)
    _put(buf, pk_enc)
    return bytes(buf)


def encode_oprf_rec_eval(b_prime: bytes, c: bytes) -> bytes:
    buf = bytearray([TAG_OPRF_REC_EVAL])
    _put(buf, b_prime)
    _put(buf, c)
    return bytes(buf)


def decode_payload(data: bytes) -> dict[str, Any]:
    """binary payload → dict（字段为 bytes / str result）。"""
    if not data:
        raise ValueError("empty payload")
    tag = data[0]
    i = 1
    if tag == TAG_PK_ENC:
        pk, i = _get(data, i)
        return {"type": "pkEnc", "pk": pk}
    if tag == TAG_INIT_RES:
        if i >= len(data):
            raise ValueError("truncated InitRes")
        return {"type": "InitRes", "result": _RESULT_INV.get(data[i], "Fail")}
    if tag == TAG_REC_RES:
        if i >= len(data):
            raise ValueError("truncated RecRes")
        result = _RESULT_INV.get(data[i], "Fail")
        i += 1
        out: dict[str, Any] = {"type": "RecRes", "result": result}
        if result == "Succ" and i < len(data):
            c_prime, i = _get(data, i)
            out["C_prime"] = c_prime
        return out
    if tag == TAG_OPRF_EVAL:
        b, i = _get(data, i)
        pk_enc, i = _get(data, i)
        return {"type": "oprf_eval", "b": b, "pkEnc": pk_enc}
    if tag == TAG_OPRF_REC_EVAL:
        b_prime, i = _get(data, i)
        c, i = _get(data, i)
        return {"type": "oprf_rec_eval", "b_prime": b_prime, "c": c}
    raise ValueError(f"unknown payload tag: 0x{tag:02x}")
