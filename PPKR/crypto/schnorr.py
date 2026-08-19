"""Schnorr 数字签名。

对应 Faller 等 (CCS 2024) Table 4 中 Signature (Schnorr)：
  KeyGen 1 Exp；Sign 1 Exp + 1 Hash；Verify 2 Exp + 1 Mult + 1 Hash。
Fig. 4 OPRF-PPKR 中客户端 pk_C 用于恢复阶段消息认证；
HSM 长期认证密钥 (attest) 亦采用 Schnorr。

线格式 (SchnorrSignature.serialize)：
  e (32 字节大端) || s (32 字节大端)
公钥线格式：SEC1 压缩点 (33 字节)。
"""

from __future__ import annotations

from dataclasses import dataclass

from config import CostCounter
from crypto.group import GROUP, GroupElement, Scalar


# ── 密钥与签名类型 ────────────────────────────────────────────────────


@dataclass(frozen=True)
class SchnorrPublicKey:
    """Schnorr 公钥 y = g^x。"""

    y: GroupElement

    def serialize(self) -> bytes:
        """返回 33 字节 SEC1 压缩公钥。"""
        return self.y.serialize()


@dataclass(frozen=True)
class SchnorrSecretKey:
    """Schnorr 私钥 x。"""

    x: Scalar


@dataclass(frozen=True)
class SchnorrSignature:
    """Schnorr 签名 (e, s)。"""

    e: Scalar
    s: Scalar

    def serialize(self) -> bytes:
        """线格式：e (32 字节) || s (32 字节)。"""
        return (
            self.e.value.to_bytes(32, "big")
            + self.s.value.to_bytes(32, "big")
        )


def deserialize_schnorr_sig(data: bytes) -> SchnorrSignature:
    """从 64 字节线格式解析签名。"""
    return SchnorrSignature(
        e=Scalar(int.from_bytes(data[:32], "big")),
        s=Scalar(int.from_bytes(data[32:64], "big")),
    )


# ── 签名方案 ──────────────────────────────────────────────────────────


class Schnorr:
    """Schnorr 签名方案：挑战 e = H(R || Y || m) mod q。"""

    def keygen(self) -> tuple[SchnorrPublicKey, SchnorrSecretKey, CostCounter]:
        """生成密钥对。"""
        x = GROUP.random_scalar()
        y, c = GROUP.exp(GROUP.g, x)
        return SchnorrPublicKey(y=y), SchnorrSecretKey(x=x), c

    def _challenge(self, r_point: GroupElement, pk: SchnorrPublicKey, message: bytes) -> tuple[Scalar, CostCounter]:
        """计算 Fiat-Shamir 挑战 e。"""
        return GROUP.hash_to_scalar(r_point.serialize() + pk.y.serialize() + message)

    def sign(self, sk: SchnorrSecretKey, pk: SchnorrPublicKey, message: bytes) -> tuple[SchnorrSignature, CostCounter]:
        """签名消息 m；Table 4 计 1 Exp + 1 Hash。"""
        # R = g^k，e = H(R || Y || m)，s = k + x·e (mod q)
        k = GROUP.random_scalar()
        r_point, c_exp = GROUP.exp(GROUP.g, k)
        e, c_hash = self._challenge(r_point, pk, message)
        s_val = (k.value + sk.x.value * e.value) % GROUP.q
        return SchnorrSignature(e=e, s=Scalar(s_val)), c_exp + c_hash + CostCounter(sig=1)

    def verify(
        self, pk: SchnorrPublicKey, message: bytes, sig: SchnorrSignature
    ) -> tuple[bool, CostCounter]:
        """验证 g^s · y^{-e} 重构的 R 与挑战 e 一致；Table 4 计 2 Exp + 1 Mult + 1 Hash。"""
        # R' = g^s · y^{-e}，检验 H(R' || Y || m) == e
        g_s, c1 = GROUP.exp(GROUP.g, sig.s)
        y_neg_e, c2 = GROUP.exp(pk.y, Scalar((GROUP.q - sig.e.value) % GROUP.q))
        r_point, c_mult = GROUP.mult(g_s, y_neg_e)
        e_check, c_hash = self._challenge(r_point, pk, message)
        ok = e_check.value == sig.e.value
        return ok, c1 + c2 + c_mult + c_hash + CostCounter(sig=1)
