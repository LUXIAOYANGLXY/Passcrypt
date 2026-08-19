"""
PBCS/E2SE-inspired binary wire codec for WBP.

Line format (aligned with PAEE net/wire_codec.py):
  opcode(1) ‖ [u16BE len ‖ field]* … ‖ 少量定长 u8

Uses **u16** length prefixes (not PBCS u8≤255) because WBP carries
RSA-2048 ciphertext (256 B) and OPAQUE CredentialResponse (~320 B).

Application layer still uses Message + Base64/hex strings in payload;
this module maps ↔ raw bytes on the wire.
"""

from __future__ import annotations

import struct
from typing import Any

from crypto.primitives import b64d, b64e

# -------- opcodes（WBP 专用 0x50+；ERROR 对齐 PAEE 0x07）--------
OP_ERROR = 0x07
OP_HELLO = 0x50
OP_HELLO_ACK = 0x51
OP_INIT_REQ = 0x52
OP_INIT_HSM_RESP = 0x53
OP_INIT_UPLOAD = 0x54
OP_INIT_RESULT = 0x55
OP_REC_REQ = 0x56
OP_REC_HSM_RESP = 0x57
OP_REC_CONFIRM = 0x58
OP_REC_KEY = 0x59
OP_REC_RESULT = 0x5A

TYPE_TO_OP: dict[str, int] = {
    "HELLO": OP_HELLO,
    "HELLO_ACK": OP_HELLO_ACK,
    "INIT_REQ": OP_INIT_REQ,
    "INIT_HSM_RESP": OP_INIT_HSM_RESP,
    "INIT_UPLOAD": OP_INIT_UPLOAD,
    "INIT_RESULT": OP_INIT_RESULT,
    "REC_REQ": OP_REC_REQ,
    "REC_HSM_RESP": OP_REC_HSM_RESP,
    "REC_CONFIRM": OP_REC_CONFIRM,
    "REC_KEY": OP_REC_KEY,
    "REC_RESULT": OP_REC_RESULT,
    "ERROR": OP_ERROR,
}

OP_TO_TYPE: dict[int, str] = {v: k for k, v in TYPE_TO_OP.items()}

# Streaming layout after opcode (for framing recv).
# "ssid" and "lv" are u16-LV; "u8" is one byte.
RECV_LAYOUT: dict[str, tuple[str, ...]] = {
    "HELLO": ("ssid", "lv"),
    "HELLO_ACK": ("ssid", "lv", "lv", "lv"),
    "INIT_REQ": ("ssid", "lv"),
    "INIT_HSM_RESP": ("ssid", "lv", "lv", "lv", "lv"),
    "INIT_UPLOAD": ("ssid", "lv", "lv"),
    "INIT_RESULT": ("ssid", "u8", "lv", "lv"),
    "REC_REQ": ("ssid", "lv"),
    "REC_HSM_RESP": ("ssid", "lv", "lv", "lv"),
    "REC_CONFIRM": ("ssid", "lv"),
    "REC_KEY": ("ssid", "u8", "lv", "lv"),
    "REC_RESULT": ("ssid", "u8", "u8", "lv"),
    "ERROR": ("ssid", "lv"),
}


def _put_lv(buf: bytearray, data: bytes) -> None:
    if len(data) > 0xFFFF:
        raise ValueError(f"wire field too long ({len(data)} > 65535)")
    buf.extend(struct.pack(">H", len(data)))
    buf.extend(data)


def _put_str(buf: bytearray, s: str) -> None:
    _put_lv(buf, s.encode("utf-8"))


def _put_ssid(buf: bytearray, ssid_hex: str) -> None:
    raw = bytes.fromhex(ssid_hex) if ssid_hex else b"\x00" * 16
    if len(raw) != 16:
        raise ValueError(f"ssid must be 16 bytes, got {len(raw)}")
    _put_lv(buf, raw)


def _put_b64(buf: bytearray, b64: str) -> None:
    _put_lv(buf, b64d(b64) if b64 else b"")


def _put_n1(buf: bytearray, n1_hex: str) -> None:
    raw = bytes.fromhex(n1_hex) if n1_hex else b"\x00" * 16
    if len(raw) != 16:
        raise ValueError(f"n1 must be 16 bytes, got {len(raw)}")
    _put_lv(buf, raw)


def _get_lv(data: bytes, i: int) -> tuple[bytes, int]:
    if i + 2 > len(data):
        raise ValueError("truncated wire: missing length")
    (n,) = struct.unpack(">H", data[i : i + 2])
    i += 2
    if i + n > len(data):
        raise ValueError("truncated wire: short field")
    return data[i : i + n], i + n


def _get_str(data: bytes, i: int) -> tuple[str, int]:
    raw, i = _get_lv(data, i)
    return raw.decode("utf-8"), i


def _get_ssid(data: bytes, i: int) -> tuple[str, int]:
    raw, i = _get_lv(data, i)
    if len(raw) != 16:
        raise ValueError(f"ssid must be 16 bytes, got {len(raw)}")
    return raw.hex(), i


def _get_b64(data: bytes, i: int) -> tuple[str, int]:
    raw, i = _get_lv(data, i)
    return b64e(raw) if raw else "", i


def _get_n1(data: bytes, i: int) -> tuple[str, int]:
    raw, i = _get_lv(data, i)
    if len(raw) != 16:
        raise ValueError(f"n1 must be 16 bytes, got {len(raw)}")
    return raw.hex(), i


def _bool_u8(v: Any) -> int:
    return 1 if v else 0


def encode_fields(msg_type: str, ssid: str, payload: dict[str, Any]) -> bytes:
    """type + ssid + payload → binary wire (opcode + fields)."""
    if msg_type not in TYPE_TO_OP:
        raise ValueError(f"unknown message type: {msg_type!r}")
    op = TYPE_TO_OP[msg_type]
    buf = bytearray([op])
    p = payload

    if msg_type == "HELLO":
        _put_ssid(buf, ssid)
        _put_str(buf, str(p.get("idc", "")))
    elif msg_type == "HELLO_ACK":
        _put_ssid(buf, ssid)
        _put_str(buf, str(p.get("idc", "")))
        _put_str(buf, str(p.get("enc_pem", "")))
        _put_str(buf, str(p.get("sig_pem", "")))
    elif msg_type == "INIT_REQ":
        _put_ssid(buf, ssid)
        _put_b64(buf, str(p.get("a1", "")))
    elif msg_type == "INIT_HSM_RESP":
        _put_ssid(buf, ssid)
        _put_str(buf, str(p.get("aid", "")))
        _put_b64(buf, str(p.get("b1", "")))
        _put_n1(buf, str(p.get("n1", "")))
        _put_b64(buf, str(p.get("sigma", "")))
    elif msg_type == "INIT_UPLOAD":
        _put_ssid(buf, ssid)
        _put_b64(buf, str(p.get("E", "")))
        _put_b64(buf, str(p.get("opaque_upload", "")))
    elif msg_type == "INIT_RESULT":
        _put_ssid(buf, ssid)
        buf.append(_bool_u8(p.get("ok", False)))
        _put_str(buf, str(p.get("aid", "") or ""))
        _put_str(buf, str(p.get("error", "") or ""))
    elif msg_type == "REC_REQ":
        _put_ssid(buf, ssid)
        _put_b64(buf, str(p.get("a2", "")))
    elif msg_type == "REC_HSM_RESP":
        _put_ssid(buf, ssid)
        _put_str(buf, str(p.get("aid", "")))
        _put_b64(buf, str(p.get("b2", "")))
        _put_b64(buf, str(p.get("sigma", "")))
    elif msg_type == "REC_CONFIRM":
        _put_ssid(buf, ssid)
        _put_b64(buf, str(p.get("t_c", "")))
    elif msg_type == "REC_KEY":
        _put_ssid(buf, ssid)
        buf.append(_bool_u8(p.get("ok", False)))
        _put_str(buf, str(p.get("aid", "") or ""))
        _put_b64(buf, str(p.get("c", "") or ""))
    elif msg_type == "REC_RESULT":
        _put_ssid(buf, ssid)
        buf.append(_bool_u8(p.get("ok", False)))
        buf.append(_bool_u8(p.get("deleted", False)))
        _put_str(buf, str(p.get("error", "") or ""))
    elif msg_type == "ERROR":
        _put_ssid(buf, ssid)
        _put_str(buf, str(p.get("error", "") or ""))
    else:
        raise ValueError(f"encode not implemented: {msg_type}")

    return bytes(buf)


def decode_fields(data: bytes) -> tuple[str, str, dict[str, Any]]:
    """Binary wire → (type, ssid, payload)."""
    if not data:
        raise ValueError("empty wire message")
    op = data[0]
    if op not in OP_TO_TYPE:
        raise ValueError(f"unknown opcode: 0x{op:02x}")
    msg_type = OP_TO_TYPE[op]
    i = 1
    ssid, i = _get_ssid(data, i)

    if msg_type == "HELLO":
        idc, i = _get_str(data, i)
        return msg_type, ssid, {"idc": idc}
    if msg_type == "HELLO_ACK":
        idc, i = _get_str(data, i)
        enc_pem, i = _get_str(data, i)
        sig_pem, i = _get_str(data, i)
        return msg_type, ssid, {"idc": idc, "enc_pem": enc_pem, "sig_pem": sig_pem}
    if msg_type == "INIT_REQ":
        a1, i = _get_b64(data, i)
        return msg_type, ssid, {"a1": a1}
    if msg_type == "INIT_HSM_RESP":
        aid, i = _get_str(data, i)
        b1, i = _get_b64(data, i)
        n1, i = _get_n1(data, i)
        sigma, i = _get_b64(data, i)
        return msg_type, ssid, {"aid": aid, "b1": b1, "n1": n1, "sigma": sigma}
    if msg_type == "INIT_UPLOAD":
        e, i = _get_b64(data, i)
        upload, i = _get_b64(data, i)
        return msg_type, ssid, {"E": e, "opaque_upload": upload}
    if msg_type == "INIT_RESULT":
        if i >= len(data):
            raise ValueError("truncated INIT_RESULT")
        ok = bool(data[i])
        i += 1
        aid, i = _get_str(data, i)
        err, i = _get_str(data, i)
        payload: dict[str, Any] = {"ok": ok}
        if aid:
            payload["aid"] = aid
        if err:
            payload["error"] = err
        return msg_type, ssid, payload
    if msg_type == "REC_REQ":
        a2, i = _get_b64(data, i)
        return msg_type, ssid, {"a2": a2}
    if msg_type == "REC_HSM_RESP":
        aid, i = _get_str(data, i)
        b2, i = _get_b64(data, i)
        sigma, i = _get_b64(data, i)
        return msg_type, ssid, {"aid": aid, "b2": b2, "sigma": sigma}
    if msg_type == "REC_CONFIRM":
        t_c, i = _get_b64(data, i)
        return msg_type, ssid, {"t_c": t_c}
    if msg_type == "REC_KEY":
        if i >= len(data):
            raise ValueError("truncated REC_KEY")
        ok = bool(data[i])
        i += 1
        aid, i = _get_str(data, i)
        c, i = _get_b64(data, i)
        payload = {"ok": ok, "c": c}
        if aid:
            payload["aid"] = aid
        return msg_type, ssid, payload
    if msg_type == "REC_RESULT":
        if i + 2 > len(data):
            raise ValueError("truncated REC_RESULT")
        ok = bool(data[i])
        deleted = bool(data[i + 1])
        i += 2
        err, i = _get_str(data, i)
        payload = {"ok": ok, "deleted": deleted}
        if err:
            payload["error"] = err
        return msg_type, ssid, payload
    if msg_type == "ERROR":
        err, i = _get_str(data, i)
        return msg_type, ssid, {"error": err}

    raise ValueError(f"decode not implemented: {msg_type}")
