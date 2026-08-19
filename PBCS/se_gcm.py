# -*- coding: utf-8 -*-
"""
明文 m 的 AES-256-GCM 文件加解密（与 AES-CTR 对照实验用）。

  密钥：32 字节（MSK）
  线格式：nonce(12) ‖ ciphertext ‖ tag(16)
  后端：cryptography Cipher / OpenSSL（可流式大文件）
"""

from __future__ import annotations

import os
import time
from typing import Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

GCM_NONCE_LEN = 12
GCM_TAG_LEN = 16
GCM_KEY_LEN = 32
_CHUNK = 1024 * 1024


def _require_key(key: bytes) -> None:
    if len(key) != GCM_KEY_LEN:
        raise ValueError(f"AES-256-GCM requires {GCM_KEY_LEN}-byte key, got {len(key)}")


def se_enc_gcm(key: bytes, plaintext: bytes) -> bytes:
    """AES-256-GCM：输出 nonce(12)‖ciphertext‖tag(16)。"""
    _require_key(key)
    nonce = os.urandom(GCM_NONCE_LEN)
    enc = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    ct = enc.update(plaintext) + enc.finalize()
    return nonce + ct + enc.tag


def se_dec_gcm(key: bytes, blob: bytes) -> Optional[bytes]:
    """AES-256-GCM 解密；失败返回 None。"""
    if len(key) != GCM_KEY_LEN or len(blob) < GCM_NONCE_LEN + GCM_TAG_LEN:
        return None
    nonce = blob[:GCM_NONCE_LEN]
    tag = blob[-GCM_TAG_LEN:]
    ct = blob[GCM_NONCE_LEN:-GCM_TAG_LEN]
    try:
        dec = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
        return dec.update(ct) + dec.finalize()
    except Exception:
        return None


def encrypt_file_gcm(source_path: str, dest_path: str, key: bytes) -> float:
    """大文件 AES-256-GCM 加密；写 nonce‖密文‖tag。返回耗时（秒）。"""
    _require_key(key)
    t0 = time.time()
    nonce = os.urandom(GCM_NONCE_LEN)
    enc = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    with open(source_path, "rb") as fin, open(dest_path, "wb") as fout:
        fout.write(nonce)
        while True:
            chunk = fin.read(_CHUNK)
            if not chunk:
                break
            fout.write(enc.update(chunk))
        fout.write(enc.finalize())
        fout.write(enc.tag)
    return time.time() - t0


def decrypt_file_gcm(source_path: str, dest_path: str, key: bytes) -> None:
    """大文件 AES-256-GCM 解密（读 nonce(12)‖密文‖tag(16)）。"""
    _require_key(key)
    size = os.path.getsize(source_path)
    if size < GCM_NONCE_LEN + GCM_TAG_LEN:
        raise ValueError("GCM ciphertext file too short")
    with open(source_path, "rb") as fin:
        nonce = fin.read(GCM_NONCE_LEN)
        if len(nonce) != GCM_NONCE_LEN:
            raise ValueError("Invalid GCM nonce length")
        fin.seek(size - GCM_TAG_LEN)
        tag = fin.read(GCM_TAG_LEN)
        ct_len = size - GCM_NONCE_LEN - GCM_TAG_LEN
        fin.seek(GCM_NONCE_LEN)
        dec = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
        with open(dest_path, "wb") as fout:
            left = ct_len
            while left > 0:
                chunk = fin.read(min(_CHUNK, left))
                if not chunk:
                    break
                left -= len(chunk)
                fout.write(dec.update(chunk))
            fout.write(dec.finalize())
