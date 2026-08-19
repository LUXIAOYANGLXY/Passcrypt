"""secp256r1 (NIST P-256) 椭圆曲线群运算。

对应 Faller 等 (CCS 2024) Table 4 中的 Exp / Mult / Hash 原语计数基础。
群元素线格式为 SEC1 **压缩点** (0x02/0x03 || x，33 字节)；
读入兼容旧非压缩 65 字节并规范化为压缩。
标量模曲线阶 q。hash_to_group 实现 RFC 9380，供 OPRF 的 H1 随机预言机使用。

后端：OpenSSL libcrypto（``crypto.openssl_p256``）。
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from config import CostCounter
from crypto.hash_to_curve import PPKR_H1_DST, hash_to_curve_p256, point_to_compressed
from crypto.openssl_p256 import P256_ORDER, POINT_LEN_COMPRESSED, get_p256


@dataclass(frozen=True)
class GroupElement:
    """群元素：SEC1 压缩点字节串 (33 字节)。"""

    value: bytes  # 0x02/0x03 || x(32)

    def serialize(self) -> bytes:
        """返回 SEC1 压缩点字节串。"""
        return self.value


@dataclass(frozen=True)
class Scalar:
    """标量：整数，运算时模曲线阶 q。"""

    value: int


class GroupContext:
    """P-256 群运算上下文；Exp/Mult 由 OpenSSL 执行。"""

    def __init__(self) -> None:
        self._p256 = get_p256()
        self.q = self._p256.order
        assert self.q == P256_ORDER
        self.g = GroupElement(self._p256.generator_bytes)
        assert len(self.g.value) == POINT_LEN_COMPRESSED

    def random_scalar(self) -> Scalar:
        """均匀采样非零标量 r ∈ {1, …, q−1}。"""
        import secrets

        while True:
            val = int.from_bytes(secrets.token_bytes(32), "big") % self.q
            if val != 0:
                return Scalar(val)

    def exp(self, base: GroupElement, exponent: Scalar) -> tuple[GroupElement, CostCounter]:
        """标量乘法：base^exponent（Table 4 计 1 Exp）；OpenSSL EC_POINT_mul。"""
        e = exponent.value % self.q
        if base.value == self.g.value:
            raw = self._p256.generator_scalarmult(e)
        else:
            raw = self._p256.scalarmult(base.value, e)
        return GroupElement(raw), CostCounter(exp=1)

    def mult(self, a: GroupElement, b: GroupElement) -> tuple[GroupElement, CostCounter]:
        """点加：a + b（Table 4 计 1 Mult）；OpenSSL EC_POINT_add。"""
        raw = self._p256.point_add(a.value, b.value)
        return GroupElement(raw), CostCounter(mult=1)

    def hash_to_scalar(self, data: bytes) -> tuple[Scalar, CostCounter]:
        """SHA-256 哈希后模 q 得标量；零值映射为 1（Table 4 计 1 Hash）。"""
        digest = hashlib.sha256(data).digest()
        val = int.from_bytes(digest, "big") % self.q
        if val == 0:
            val = 1
        return Scalar(val), CostCounter(hash=1)

    def hash_to_group(self, data: bytes) -> tuple[GroupElement, CostCounter]:
        """RFC 9380 hash_to_curve (P256_XMD:SHA-256_SSWU_RO_) — OPRF 的 H1 映射。"""

        def _add(p1: tuple[int, int], p2: tuple[int, int]) -> tuple[int, int]:
            ge1 = GroupElement(point_to_compressed(p1[0], p1[1]))
            ge2 = GroupElement(point_to_compressed(p2[0], p2[1]))
            summed, _ = self.mult(ge1, ge2)
            return self._p256.affine_coords(summed.value)

        x, y = hash_to_curve_p256(data, dst=PPKR_H1_DST, add_fn=_add)
        return GroupElement(point_to_compressed(x, y)), CostCounter(hash=1, mult=1)

    def inverse_scalar(self, s: Scalar) -> Scalar:
        """模 q 求标量逆元。"""
        return Scalar(pow(s.value, -1, self.q))

    def mul_scalars(self, a: Scalar, b: Scalar) -> Scalar:
        """标量乘法模 q。"""
        return Scalar((a.value * b.value) % self.q)

    def deserialize_point(self, data: bytes) -> GroupElement:
        """校验点并规范化为压缩 33 字节。"""
        self._p256.validate_point(data)
        return GroupElement(self._p256.canonicalize_point(data))


GROUP = GroupContext()
