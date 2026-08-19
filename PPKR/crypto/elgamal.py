"""ElGamal CPA 公钥加密。

对应 Faller 等 (CCS 2024) Table 4 中 CPA Enc (ElGamal)：
  KeyGen 1 Exp；Enc 2 Exp + 1 Hash；Dec 1 Exp + 1 Hash。
DHIES 密钥生成复用本模块；ElGamal 本身提供 IND-CPA 语义。

线格式 (ElGamalCiphertext.serialize)：
  c1 (33 字节 SEC1 压缩点) || c2 长度 (2 字节大端) || c2 (XOR 掩码密文)
"""

from __future__ import annotations

from dataclasses import dataclass

from config import CostCounter
from crypto.group import GROUP, GroupElement, Scalar
from crypto.kdf import HKDF
from crypto.openssl_p256 import POINT_LEN_COMPRESSED, POINT_LEN_UNCOMPRESSED

POINT_SIZE = POINT_LEN_COMPRESSED


def _c1_len(data: bytes) -> int:
    """根据首字节判定 c1 线长（兼容旧非压缩密文）。"""
    if not data:
        raise ValueError("elgamal ciphertext empty")
    if data[0] in (0x02, 0x03):
        return POINT_LEN_COMPRESSED
    if data[0] == 0x04:
        return POINT_LEN_UNCOMPRESSED
    raise ValueError("invalid ElGamal c1 point prefix")


# ── 密钥与密文类型 ────────────────────────────────────────────────────


@dataclass(frozen=True)
class ElGamalPublicKey:
    """ElGamal 公钥 y = g^x。"""

    y: GroupElement


@dataclass(frozen=True)
class ElGamalSecretKey:
    """ElGamal 私钥 x。"""

    x: Scalar


@dataclass(frozen=True)
class ElGamalCiphertext:
    """ElGamal 密文 (c1, c2)：c1 = g^r，c2 = m XOR KDF(shared secret)。"""

    c1: GroupElement
    c2: bytes

    def serialize(self) -> bytes:
        """线格式：c1 (33 字节压缩) || c2 长度 (2 字节大端) || c2。"""
        c1_bytes = self.c1.serialize()
        if len(c1_bytes) != POINT_SIZE:
            raise ValueError(f"expected {POINT_SIZE}-byte compressed point")
        return c1_bytes + len(self.c2).to_bytes(2, "big") + self.c2


def deserialize_elgamal(data: bytes) -> ElGamalCiphertext:
    """从线格式解析 ElGamal 密文。"""
    n = _c1_len(data)
    if len(data) < n + 2:
        raise ValueError("elgamal ciphertext too short")
    c1 = GROUP.deserialize_point(data[:n])
    clen = int.from_bytes(data[n : n + 2], "big")
    c2_start = n + 2
    c2_end = c2_start + clen
    if len(data) < c2_end:
        raise ValueError("elgamal ciphertext truncated")
    c2 = data[c2_start:c2_end]
    return ElGamalCiphertext(c1=c1, c2=c2)


# ── ElGamal 加解密 ────────────────────────────────────────────────────


class ElGamal:
    """ElGamal 加密：共享秘密经 HKDF 派生一次性流密钥，与明文 XOR。"""

    def __init__(self) -> None:
        self._hkdf = HKDF()

    def keygen(self) -> tuple[ElGamalPublicKey, ElGamalSecretKey, CostCounter]:
        """生成密钥对；Table 4 计 1 Exp (y = g^x)。"""
        x = GROUP.random_scalar()
        y, c = GROUP.exp(GROUP.g, x)
        return ElGamalPublicKey(y=y), ElGamalSecretKey(x=x), c

    def enc(self, pk: ElGamalPublicKey, plaintext: bytes) -> tuple[ElGamalCiphertext, CostCounter]:
        """加密明文；Table 4 计 2 Exp + 1 Hash。"""
        # c1 = g^r，共享秘密 y^r 经 HKDF 派生流密钥，c2 = m XOR key
        r = GROUP.random_scalar()
        c1, c1_cost = GROUP.exp(GROUP.g, r)
        shared, c2_cost = GROUP.exp(pk.y, r)
        key, kdf_cost = self._hkdf.derive(shared.serialize(), b"elgamal", b"enc", len(plaintext))
        c2 = bytes(a ^ b for a, b in zip(plaintext, key))
        return ElGamalCiphertext(c1=c1, c2=c2), c1_cost + c2_cost + kdf_cost

    def dec(self, sk: ElGamalSecretKey, ct: ElGamalCiphertext) -> tuple[bytes, CostCounter]:
        """解密并返回明文；Table 4 计 1 Exp + 1 Hash。"""
        shared, c1_cost = GROUP.exp(ct.c1, sk.x)
        key, kdf_cost = self._hkdf.derive(shared.serialize(), b"elgamal", b"enc", len(ct.c2))
        pt = bytes(a ^ b for a, b in zip(ct.c2, key))
        return pt, c1_cost + kdf_cost
