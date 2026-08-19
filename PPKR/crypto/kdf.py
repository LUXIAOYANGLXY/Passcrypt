"""HKDF 与 HMAC 密钥派生 / 消息认证。

对应 Faller 等 (CCS 2024) Table 4：
  KDF (HKDF) 输出 n 个密钥块时计 (2n+2) Hash；
  MAC (HMAC-SHA256) 计 2 Hash。
ElGamal、DHIES 等原语通过 HKDF 从共享秘密派生对称密钥。
"""

from __future__ import annotations

import hashlib
import hmac as hmac_lib
import math

from config import CostCounter


class HKDF:
    """RFC 5869 HKDF-Extract + HKDF-Expand (SHA-256)。"""

    def derive(
        self, ikm: bytes, salt: bytes, info: bytes, length: int
    ) -> tuple[bytes, CostCounter]:
        """从 ikm 派生 length 字节 OKM；返回 (okm, cost)。"""
        hash_len = 32
        n = math.ceil(length / hash_len)
        # HKDF-Extract: PRK = HMAC(salt, IKM)
        prk = hmac_lib.new(salt, ikm, hashlib.sha256).digest()
        # HKDF-Expand: T_i = HMAC(PRK, T_{i-1} || info || i)
        okm = b""
        t = b""
        for i in range(1, n + 1):
            t = hmac_lib.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
            okm += t
        cost = CostCounter(hash=2 * n + 2)
        return okm[:length], cost


class HMAC:
    """HMAC-SHA256 消息认证。"""

    def mac(self, key: bytes, data: bytes) -> tuple[bytes, CostCounter]:
        """计算 MAC 标签。"""
        tag = hmac_lib.new(key, data, hashlib.sha256).digest()
        return tag, CostCounter(hash=2)

    def verify(self, key: bytes, data: bytes, tag: bytes) -> tuple[bool, CostCounter]:
        """常数时间比较验证 MAC。"""
        expected = hmac_lib.new(key, data, hashlib.sha256).digest()
        return hmac_lib.compare_digest(expected, tag), CostCounter(hash=2)
