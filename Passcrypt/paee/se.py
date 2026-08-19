# -*- coding: utf-8 -*-
"""
paee/se.py
==========
对称加密：

  ct1 ← SE.Enc(kek, dek)     # AES-256-GCM（Rust/OpenSSL AEAD 快路径）
  ct2 ← SE.Enc_CTR(dek, m)   # AES-256-CTR

CTR 默认 ``cryptography.Cipher``（本机实测快于 cryptogram）。

可选 ``PAEE_AES_CTR_BACKEND``：

  - ``cryptography``（默认）：pyca Cipher AES-CTR
  - ``cryptogram``：https://github.com/ankit-chaubey/cryptogram（可选，一般更慢）
  - ``openssl``：ctypes EVP（一般不更快）

线格式不变：IV(16) ‖ ciphertext。
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CTR_IV_LEN = 16

# cryptography | cryptogram | openssl（auto 视为 cryptography）
_CTR_BACKEND = os.environ.get("PAEE_AES_CTR_BACKEND", "cryptography").strip().lower()
if not _CTR_BACKEND or _CTR_BACKEND == "auto":
    _CTR_BACKEND = "cryptography"


def SE_Enc(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """
    SE.Enc：AES-256-GCM（用于封装 dek → ct1）。
    输出：12 字节 nonce ‖ ciphertext‖tag。
    """
    if len(key) != 32:
        raise ValueError(f"AES-256-GCM requires 32-byte key, got {len(key)}")
    nonce = os.urandom(12)
    out = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce + out


def SE_Dec(key: bytes, blob: bytes, aad: bytes = b"") -> bytes | None:
    """SE.Dec：AES-256-GCM 解密；失败返回 None。"""
    if len(key) != 32:
        return None
    if len(blob) < 12 + 16:
        return None
    nonce, ct = blob[:12], blob[12:]
    try:
        return AESGCM(key).decrypt(nonce, ct, aad)
    except Exception:
        return None


def _ctr_cryptography(key: bytes, iv: bytes, data: bytes, *, encrypt: bool) -> bytes:
    """cryptography Cipher AES-CTR（OpenSSL AES-NI，一次 update）。"""
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    eng = cipher.encryptor() if encrypt else cipher.decryptor()
    if not data:
        return eng.finalize()
    return eng.update(data) + eng.finalize()


def _ctr_openssl(key: bytes, iv: bytes, data: bytes, *, encrypt: bool) -> bytes:
    from crypto_backend.aes_ctr_openssl import (
        aes_256_ctr_decrypt,
        aes_256_ctr_encrypt,
    )

    if encrypt:
        return aes_256_ctr_encrypt(key, iv, data)
    return aes_256_ctr_decrypt(key, iv, data)


def _ctr_cryptogram(key: bytes, iv: bytes, data: bytes, *, encrypt: bool) -> bytes:
    """
    cryptogram AES-256-CTR（C + OpenSSL/AES-NI）。
    iv/state 会被原地更新；此处每次传入拷贝，不改变调用方的 IV。
    """
    import cryptogram

    iv_buf = bytearray(iv)
    state = bytearray(1)  # Telegram-style CTR state; start at 0
    if encrypt:
        return cryptogram.ctr256_encrypt(data, key, iv_buf, state)
    return cryptogram.ctr256_decrypt(data, key, iv_buf, state)


def _ctr(key: bytes, iv: bytes, data: bytes, *, encrypt: bool) -> bytes:
    backend = _CTR_BACKEND
    if backend == "cryptogram":
        try:
            return _ctr_cryptogram(key, iv, data, encrypt=encrypt)
        except Exception:
            pass
    elif backend == "openssl":
        try:
            return _ctr_openssl(key, iv, data, encrypt=encrypt)
        except Exception:
            pass
    return _ctr_cryptography(key, iv, data, encrypt=encrypt)


def SE_Enc_CTR(key: bytes, plaintext: bytes) -> bytes:
    """
    AES-256-CTR 加密（用于明文 m → ct2）。
    输出：16 字节 IV ‖ ciphertext（无 tag；完整性由 τ=H5 承担）。
    """
    if len(key) != 32:
        raise ValueError(f"AES-256-CTR requires 32-byte key, got {len(key)}")
    iv = os.urandom(CTR_IV_LEN)
    return iv + _ctr(key, iv, plaintext, encrypt=True)


def SE_Dec_CTR(key: bytes, blob: bytes) -> bytes | None:
    """AES-256-CTR 解密；格式错误返回 None。"""
    if len(key) != 32:
        return None
    if len(blob) < CTR_IV_LEN:
        return None
    iv, ct = blob[:CTR_IV_LEN], blob[CTR_IV_LEN:]
    try:
        return _ctr(key, iv, ct, encrypt=False)
    except Exception:
        return None


def ctr_backend_name() -> str:
    """当前生效的 CTR 后端名（便于基准日志）。"""
    return _CTR_BACKEND
