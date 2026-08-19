"""HSM 消息认证模块 — 实现论文中的 ↪ x（带签名的 HSM 输出）。

签名覆盖 ``payload || SSID || IDC``。payload 为 ``common.payload_codec`` 二进制，
TCP 线上以扁平字段 ssid|idc|sig|payload 传输（无 JSON/Base64）。
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from config import CostCounter, IDC, SSID
from crypto.schnorr import Schnorr, SchnorrPublicKey, SchnorrSecretKey, deserialize_schnorr_sig
from hsm.key_store import HSMKeyStore


@dataclass(frozen=True)
class AttestedMessage:
    """HSM 输出的带 Schnorr 签名的认证消息（论文 ↪ x）。

    Attributes:
        payload:   二进制协议响应体（见 payload_codec）。
        signature: Schnorr 签名序列化字节（64B）。
        ssid:      绑定的会话标识。
        idc:       绑定的客户端身份（可选）。
    """

    payload: bytes
    signature: bytes
    ssid: SSID
    idc: IDC | None = None

    def to_wire_fields(self) -> dict:
        """TCP 响应扁平字段（raw bytes）。"""
        return {
            "ssid": self.ssid,
            "idc": self.idc or "",
            "sig": self.signature,
            "payload": self.payload,
        }

    @staticmethod
    def from_wire_fields(obj: dict) -> AttestedMessage:
        """从扁平线字段还原。"""
        idc = obj.get("idc") or None
        if idc == "":
            idc = None
        return AttestedMessage(
            payload=obj["payload"] if isinstance(obj["payload"], bytes) else bytes(obj["payload"]),
            signature=obj["sig"] if isinstance(obj["sig"], bytes) else bytes(obj["sig"]),
            ssid=obj["ssid"],
            idc=idc,
        )

    def serialize(self) -> bytes:
        """本地打包：u16|payload || u16|sig || u16|ssid || u16|idc（进程内/测试用）。"""
        import struct

        def put(b: bytes) -> bytes:
            return struct.pack(">H", len(b)) + b

        idc_b = (self.idc or "").encode()
        return (
            put(self.payload)
            + put(self.signature)
            + put(self.ssid.encode())
            + put(idc_b)
        )

    @staticmethod
    def deserialize(data: bytes) -> AttestedMessage:
        """从 serialize() 字节还原。"""
        import struct

        def get(buf: bytes, i: int) -> tuple[bytes, int]:
            (n,) = struct.unpack_from(">H", buf, i)
            i += 2
            return buf[i : i + n], i + n

        i = 0
        payload, i = get(data, i)
        sig, i = get(data, i)
        ssid_b, i = get(data, i)
        idc_b, i = get(data, i)
        idc = idc_b.decode() if idc_b else None
        return AttestedMessage(
            payload=payload,
            signature=sig,
            ssid=ssid_b.decode(),
            idc=idc,
        )


class HSMAttestation:
    """HSM 长期 Schnorr 认证密钥管理器。"""

    def __init__(
        self,
        schnorr: Schnorr | None = None,
        key_dir: Path | None = None,
    ) -> None:
        self._schnorr = schnorr or Schnorr()
        store = HSMKeyStore(key_dir)
        self._pk, self._sk = store.load_or_create(self._schnorr)

    @property
    def public_key(self) -> SchnorrPublicKey:
        return self._pk

    def attest(
        self, payload: bytes, ssid: SSID, idc: IDC | None = None
    ) -> tuple[AttestedMessage, CostCounter]:
        """对 HSM 输出载荷生成 Schnorr 签名（↪ x）。"""
        sig, cost = self._schnorr.sign(
            self._sk, self._pk, payload + ssid.encode() + (idc or "").encode()
        )
        msg = AttestedMessage(payload=payload, signature=sig.serialize(), ssid=ssid, idc=idc)
        return msg, cost

    def verify(
        self,
        msg: AttestedMessage,
        verifier_pk: SchnorrPublicKey | None = None,
        expected_ssid: SSID | None = None,
        expected_idc: IDC | None = None,
    ) -> tuple[bool, CostCounter]:
        """验证 HSM 认证消息的 Schnorr 签名及会话绑定。"""
        if expected_ssid and msg.ssid != expected_ssid:
            return False, CostCounter()
        if expected_idc is not None and msg.idc != expected_idc:
            return False, CostCounter()
        pk = verifier_pk or self._pk
        sig = deserialize_schnorr_sig(msg.signature)
        return self._schnorr.verify(
            pk, msg.payload + msg.ssid.encode() + (msg.idc or "").encode(), sig
        )
