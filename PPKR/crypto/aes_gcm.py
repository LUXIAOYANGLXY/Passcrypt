"""AES-256-GCM 认证加密 (AE)。

对应 Faller 等 (CCS 2024) Table 4 中 AE 原语：Enc/Dec 各计 1 AES。
用于 DHIES 对称层、OPRF-PPKR 恢复阶段对 K 的二次加密等。

线格式 (AESCiphertext.serialize)：
  1 字节 nonce 长度 || nonce (12 字节) || 密文 || 16 字节 GCM 认证标签

安全注记：nonce 每次随机生成；解密失败时静默返回 None，避免侧信道泄露。
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM as AESGCMPrimitive

from config import AE_KEY_BYTES, AE_NONCE_BYTES, CostCounter

GCM_TAG_BYTES = 16
MIN_AES_SERIALIZED = 1 + AE_NONCE_BYTES + GCM_TAG_BYTES


# ── 密文类型 ──────────────────────────────────────────────────────────


@dataclass(frozen=True)
class AESCiphertext:
    """AES-GCM 密文：nonce + (ciphertext || tag)。"""

    nonce: bytes
    ct: bytes  # ciphertext || tag

    def serialize(self) -> bytes:
        """格式：1 字节 nonce 长度 || nonce || (ciphertext || tag)。"""
        return len(self.nonce).to_bytes(1, "big") + self.nonce + self.ct


def deserialize_aes(data: bytes) -> AESCiphertext:
    """从格式解析 AESCiphertext；长度或 nonce 非法则抛 ValueError。"""
    if len(data) < MIN_AES_SERIALIZED:
        raise ValueError("aes ciphertext too short")
    nlen = data[0]
    if nlen != AE_NONCE_BYTES:
        raise ValueError("invalid aes nonce length")
    if len(data) < 1 + nlen + GCM_TAG_BYTES:
        raise ValueError("aes ciphertext truncated")
    nonce = data[1 : 1 + nlen]
    ct = data[1 + nlen :]
    return AESCiphertext(nonce=nonce, ct=ct)


# ── 加解密 ────────────────────────────────────────────────────────────


class AESGCMCipher:
    """AES-256-GCM 封装；支持 enc/dec 及 XOR 掩码（encPw+ 存储 K 时使用）。"""

    def enc(self, key: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[AESCiphertext, CostCounter]:
        """加密；可选 AAD 用于绑定上下文（如 DHIES 临时公钥）。"""
        if len(key) != AE_KEY_BYTES:
            raise ValueError(f"AES-256-GCM requires {AE_KEY_BYTES}-byte key, got {len(key)}")
        nonce = os.urandom(AE_NONCE_BYTES)  # 每次加密随机 nonce，禁止复用
        ct = AESGCMPrimitive(key).encrypt(nonce, plaintext, aad)
        return AESCiphertext(nonce=nonce, ct=ct), CostCounter(aes=1)

    def dec(
        self, key: bytes, ciphertext: AESCiphertext, aad: bytes = b""
    ) -> tuple[bytes | None, CostCounter]:
        """解密并验证 GCM 标签；验证失败返回 (None, cost)。"""
        if len(key) != AE_KEY_BYTES:
            return None, CostCounter(aes=1)
        try:
            pt = AESGCMPrimitive(key).decrypt(ciphertext.nonce, ciphertext.ct, aad)
            return pt, CostCounter(aes=1)
        except Exception:
            # 标签验证失败统一返回 None，不向调用方泄露失败原因（侧信道防护）
            return None, CostCounter(aes=1)

    def xor_mask(self, key: bytes, data: bytes) -> bytes:
        """密钥 XOR 掩码：实现 Fig. 3 中 K XOR H(s2, pw) 式存储，非 AEAD。"""
        mask = key.ljust(len(data), b"\x00")[: len(data)]
        return bytes(a ^ b for a, b in zip(data, mask))