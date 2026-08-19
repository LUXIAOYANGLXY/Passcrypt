"""文件备份实验用 AES-256-GCM（对齐 PPKRv1 crypto.aes_gcm 的线格式）。

WBP 的 backup key K 为 32 字节，直接作为 AES-256-GCM 密钥。
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

AE_KEY_BYTES = 32
AE_NONCE_BYTES = 12
GCM_TAG_BYTES = 16
MIN_AES_SERIALIZED = 1 + AE_NONCE_BYTES + GCM_TAG_BYTES


@dataclass(frozen=True)
class AESCiphertext:
    nonce: bytes
    ct: bytes  # ciphertext || tag

    def serialize(self) -> bytes:
        return len(self.nonce).to_bytes(1, "big") + self.nonce + self.ct


def deserialize_aes(data: bytes) -> AESCiphertext:
    if len(data) < MIN_AES_SERIALIZED:
        raise ValueError("aes ciphertext too short")
    nlen = data[0]
    if nlen != AE_NONCE_BYTES:
        raise ValueError("invalid aes nonce length")
    nonce = data[1 : 1 + nlen]
    ct = data[1 + nlen :]
    return AESCiphertext(nonce=nonce, ct=ct)


class AESGCMCipher:
    """AES-256-GCM；与 PPKR 文件实验同一接口风格。"""

    def enc(self, key: bytes, plaintext: bytes, aad: bytes = b"") -> AESCiphertext:
        if len(key) != AE_KEY_BYTES:
            key = key[:AE_KEY_BYTES].ljust(AE_KEY_BYTES, b"\x00")
        nonce = os.urandom(AE_NONCE_BYTES)
        ct = AESGCM(key).encrypt(nonce, plaintext, aad)
        return AESCiphertext(nonce=nonce, ct=ct)

    def dec(
        self, key: bytes, ciphertext: AESCiphertext, aad: bytes = b""
    ) -> bytes | None:
        if len(key) != AE_KEY_BYTES:
            key = key[:AE_KEY_BYTES].ljust(AE_KEY_BYTES, b"\x00")
        try:
            return AESGCM(key).decrypt(ciphertext.nonce, ciphertext.ct, aad)
        except Exception:
            return None
