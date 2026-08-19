"""Wire codec roundtrip tests (PBCS-inspired u16 LV)."""

from __future__ import annotations

import uuid

from common.messages import Message, MessageType
from common.wire_codec import decode_fields, encode_fields
from crypto.primitives import b64e


def _ssid() -> str:
    return uuid.uuid4().hex


def _roundtrip(msg: Message) -> Message:
    raw = msg.to_bytes()
    back = Message.from_bytes(raw)
    assert back.type == msg.type
    assert back.ssid == msg.ssid
    return back


def test_hello_roundtrip():
    ssid = _ssid()
    msg = Message(MessageType.HELLO, ssid, {"idc": "user-demo"})
    back = _roundtrip(msg)
    assert back.payload["idc"] == "user-demo"


def test_hello_ack_roundtrip():
    ssid = _ssid()
    msg = Message(
        MessageType.HELLO_ACK,
        ssid,
        {
            "idc": "u1",
            "enc_pem": "-----BEGIN PUBLIC KEY-----\nABC\n-----END PUBLIC KEY-----\n",
            "sig_pem": "-----BEGIN PUBLIC KEY-----\nXYZ\n-----END PUBLIC KEY-----\n",
        },
    )
    back = _roundtrip(msg)
    assert back.payload["enc_pem"].startswith("-----BEGIN")
    assert back.payload["sig_pem"].startswith("-----BEGIN")


def test_init_upload_long_fields():
    """E=256 B and upload>255 must fit u16 LV (not PBCS u8)."""
    ssid = _ssid()
    e = b64e(b"\xab" * 256)
    upload = b64e(b"\xcd" * 320)
    msg = Message(
        MessageType.INIT_UPLOAD,
        ssid,
        {"E": e, "opaque_upload": upload},
    )
    raw = msg.to_bytes()
    assert len(raw) > 256 + 320
    back = _roundtrip(msg)
    assert back.payload["E"] == e
    assert back.payload["opaque_upload"] == upload


def test_init_hsm_resp_n1_hex():
    ssid = _ssid()
    n1 = "a1" * 16  # 32 hex chars = 16 bytes
    b1 = b64e(b"\x11" * 64)
    sigma = b64e(b"\x22" * 64)
    msg = Message(
        MessageType.INIT_HSM_RESP,
        ssid,
        {"aid": "deadbeef" * 4, "b1": b1, "n1": n1, "sigma": sigma},
    )
    back = _roundtrip(msg)
    assert back.payload["n1"] == n1
    assert back.payload["b1"] == b1
    assert back.payload["sigma"] == sigma


def test_rec_hsm_resp_b2_over_255():
    ssid = _ssid()
    b2 = b64e(b"\x33" * 320)
    sigma = b64e(b"\x44" * 64)
    msg = Message(
        MessageType.REC_HSM_RESP,
        ssid,
        {"aid": "aid1", "b2": b2, "sigma": sigma},
    )
    back = _roundtrip(msg)
    assert back.payload["b2"] == b2


def test_init_result_ok_and_error():
    ssid = _ssid()
    ok_msg = Message(MessageType.INIT_RESULT, ssid, {"ok": True, "aid": "abc"})
    back = _roundtrip(ok_msg)
    assert back.payload["ok"] is True
    assert back.payload["aid"] == "abc"

    err_msg = Message(
        MessageType.INIT_RESULT, ssid, {"ok": False, "error": "boom"}
    )
    back2 = _roundtrip(err_msg)
    assert back2.payload["ok"] is False
    assert back2.payload["error"] == "boom"


def test_rec_result_deleted():
    ssid = _ssid()
    msg = Message(
        MessageType.REC_RESULT,
        ssid,
        {"ok": False, "deleted": True, "error": "ctr exhausted"},
    )
    back = _roundtrip(msg)
    assert back.payload["deleted"] is True
    assert back.payload["error"] == "ctr exhausted"


def test_rec_key():
    ssid = _ssid()
    c = b64e(b"\x55" * 88)
    msg = Message(
        MessageType.REC_KEY, ssid, {"ok": True, "aid": "a1", "c": c}
    )
    back = _roundtrip(msg)
    assert back.payload["c"] == c


def test_error():
    ssid = _ssid()
    msg = Message(MessageType.ERROR, ssid, {"error": "not authenticated"})
    back = _roundtrip(msg)
    assert back.payload["error"] == "not authenticated"


def test_no_outer_length_header():
    """First byte is opcode, not a JSON '{' or length MSB of huge JSON."""
    ssid = _ssid()
    msg = Message(MessageType.INIT_REQ, ssid, {"a1": b64e(b"\x01" * 32)})
    raw = msg.to_bytes()
    assert raw[0] == 0x52  # OP_INIT_REQ
    t, s, p = decode_fields(raw)
    assert t == "INIT_REQ"
    assert s == ssid
    assert encode_fields(t, s, p) == raw
