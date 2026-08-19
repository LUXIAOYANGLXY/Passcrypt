"""Attested 响应解包 — 扁平 binary 字段（PAEE/PBCS 线风格）。"""

from __future__ import annotations

from typing import Any

from hsm.attest import AttestedMessage


def attested_raw(response: dict[str, Any]) -> bytes:
    """从 Server/Transport 响应得到可供 ``AttestedMessage.deserialize`` 的字节。

    新格式：``{"sig", "payload", "ssid", "idc"}``（raw bytes）。
    """
    if "sig" in response and "payload" in response:
        return AttestedMessage.from_wire_fields(response).serialize()
    # 兼容旧嵌套 attested dict（仅进程内过渡）
    a = response.get("attested")
    if isinstance(a, dict) and "sig" in a:
        return AttestedMessage.from_wire_fields(a).serialize()
    if isinstance(a, dict) and "signature" in a:
        # 极旧 Base64 嵌套
        from common.wire_codec import b64d

        msg = AttestedMessage(
            payload=b64d(a["payload"]) if isinstance(a["payload"], str) else a["payload"],
            signature=b64d(a["signature"]) if isinstance(a["signature"], str) else a["signature"],
            ssid=a["ssid"],
            idc=a.get("idc"),
        )
        return msg.serialize()
    raise TypeError(f"unexpected attested response keys: {list(response.keys())}")


def wrap_attested(msg: AttestedMessage) -> dict[str, Any]:
    """Server 统一响应：扁平字段，供 ENCPW_RESP / OPRF_RESP 编码。"""
    return msg.to_wire_fields()
