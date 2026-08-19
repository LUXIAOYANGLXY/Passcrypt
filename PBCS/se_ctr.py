# -*- coding: utf-8 -*-
"""
对称加密（cryptography / OpenSSL AES-CTR）：

  - 明文 m（文件）：AES-256-CTR，密钥 32 B；线格式 IV(16)‖ciphertext
  - MSK 封装（Give/Take）：AES-CTR，密钥为 k1（本协议 16 B → AES-128-CTR）；
    线格式 IV(16)‖ciphertext（无 GCM tag；完整性由 τ=H4 保证）
"""

from __future__ import annotations

import os
from typing import BinaryIO, Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

CTR_IV_LEN = 16
CTR_KEY_LEN = 32  # 文件加密 MSK
_CHUNK = 1024 * 1024


def _require_file_key(key: bytes) -> None:
    if len(key) != CTR_KEY_LEN:
        raise ValueError(f"AES-256-CTR requires {CTR_KEY_LEN}-byte key, got {len(key)}")


def _require_wrap_key(key: bytes) -> None:
    if len(key) not in (16, 32):
        raise ValueError(f"AES-CTR key wrap requires 16- or 32-byte key, got {len(key)}")


def wrap_key_ctr(key: bytes, plaintext: bytes) -> bytes:
    """Give：用 k1 封装 MSK。输出 IV(16)‖ciphertext。"""
    _require_wrap_key(key)
    iv = os.urandom(CTR_IV_LEN)
    enc = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    return iv + enc.update(plaintext) + enc.finalize()


def unwrap_key_ctr(key: bytes, blob: bytes) -> bytes:
    """Take：解封装 MSK。blob = IV(16)‖ciphertext。"""
    _require_wrap_key(key)
    if len(blob) < CTR_IV_LEN:
        raise ValueError("Wrapped key blob too short")
    iv, ct = blob[:CTR_IV_LEN], blob[CTR_IV_LEN:]
    dec = Cipher(algorithms.AES(key), modes.CTR(iv)).decryptor()
    return dec.update(ct) + dec.finalize()


def se_enc_ctr(key: bytes, plaintext: bytes) -> bytes:
    """AES-256-CTR：输出 IV(16) ‖ ciphertext（与 PAEE SE_Enc_CTR 一致）。"""
    _require_file_key(key)
    iv = os.urandom(CTR_IV_LEN)
    enc = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    return iv + enc.update(plaintext) + enc.finalize()


def se_dec_ctr(key: bytes, blob: bytes) -> Optional[bytes]:
    """AES-256-CTR 解密；格式错误返回 None。"""
    if len(key) != CTR_KEY_LEN or len(blob) < CTR_IV_LEN:
        return None
    iv, ct = blob[:CTR_IV_LEN], blob[CTR_IV_LEN:]
    try:
        dec = Cipher(algorithms.AES(key), modes.CTR(iv)).decryptor()
        return dec.update(ct) + dec.finalize()
    except Exception:
        return None

def encrypt_file_ctr(source_path: str, dest_path: str, key: bytes) -> float:
    """大文件 AES-256-CTR 加密；写 IV‖密文。返回耗时（秒）。"""
    import time

    _require_file_key(key)
    t0 = time.time()
    iv = os.urandom(CTR_IV_LEN)
    enc = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    with open(source_path, "rb") as fin, open(dest_path, "wb") as fout:
        fout.write(iv)
        while True:
            chunk = fin.read(_CHUNK)
            if not chunk:
                break
            fout.write(enc.update(chunk))
        fout.write(enc.finalize())
    return time.time() - t0


def decrypt_file_ctr(source_path: str, dest_path: str, key: bytes) -> None:
    """大文件 AES-256-CTR 解密（读 IV(16)‖密文）。"""
    _require_file_key(key)
    with open(source_path, "rb") as fin, open(dest_path, "wb") as fout:
        iv = fin.read(CTR_IV_LEN)
        if len(iv) != CTR_IV_LEN:
            raise ValueError("Invalid IV length in encrypted file.")
        dec = Cipher(algorithms.AES(key), modes.CTR(iv)).decryptor()
        while True:
            chunk = fin.read(_CHUNK)
            if not chunk:
                break
            fout.write(dec.update(chunk))
        fout.write(dec.finalize())


def ctr_encrypt_chunk(key: bytes, iv: bytes, data: bytes) -> bytes:
    """单块 AES-256-CTR（多分片 EncThread 用；调用方提供 16B IV）。"""
    _require_file_key(key)
    if len(iv) != CTR_IV_LEN:
        raise ValueError(f"CTR IV must be {CTR_IV_LEN} bytes")
    enc = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    return enc.update(data) + enc.finalize()


def ctr_decrypt_stream(key: bytes, iv: bytes, input_stream: BinaryIO, output: BinaryIO) -> None:
    """从流解密并写入 output。"""
    _require_file_key(key)
    dec = Cipher(algorithms.AES(key), modes.CTR(iv)).decryptor()
    while True:
        buf = input_stream.read(1024)
        if not buf:
            break
        output.write(dec.update(buf))
    output.write(dec.finalize())
