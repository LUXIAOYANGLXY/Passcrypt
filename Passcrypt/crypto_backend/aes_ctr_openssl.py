# -*- coding: utf-8 -*-
"""
crypto_backend/aes_ctr_openssl.py
=================================
AES-256-CTR via OpenSSL libcrypto EVP（AES-NI）。

尽量零额外拷贝：输入直接引用 ``bytes`` 缓冲，输出写入预分配 ``bytearray``。
"""

from __future__ import annotations

import ctypes
from ctypes import (
    POINTER,
    byref,
    c_char_p,
    c_int,
    c_void_p,
    cast,
)
from functools import lru_cache

from crypto_backend.backends.openssl_p256 import OpenSSLError, _lib


@lru_cache(maxsize=1)
def _bind_evp() -> ctypes.CDLL:
    lib = _lib()

    lib.EVP_CIPHER_CTX_new.restype = c_void_p
    lib.EVP_CIPHER_CTX_new.argtypes = []
    lib.EVP_CIPHER_CTX_free.restype = None
    lib.EVP_CIPHER_CTX_free.argtypes = [c_void_p]
    lib.EVP_aes_256_ctr.restype = c_void_p
    lib.EVP_aes_256_ctr.argtypes = []

    lib.EVP_EncryptInit_ex.restype = c_int
    lib.EVP_EncryptInit_ex.argtypes = [
        c_void_p, c_void_p, c_void_p, c_char_p, c_char_p
    ]
    lib.EVP_EncryptUpdate.restype = c_int
    lib.EVP_EncryptUpdate.argtypes = [
        c_void_p, c_void_p, POINTER(c_int), c_void_p, c_int
    ]
    lib.EVP_EncryptFinal_ex.restype = c_int
    lib.EVP_EncryptFinal_ex.argtypes = [c_void_p, c_void_p, POINTER(c_int)]

    lib.EVP_DecryptInit_ex.restype = c_int
    lib.EVP_DecryptInit_ex.argtypes = [
        c_void_p, c_void_p, c_void_p, c_char_p, c_char_p
    ]
    lib.EVP_DecryptUpdate.restype = c_int
    lib.EVP_DecryptUpdate.argtypes = [
        c_void_p, c_void_p, POINTER(c_int), c_void_p, c_int
    ]
    lib.EVP_DecryptFinal_ex.restype = c_int
    lib.EVP_DecryptFinal_ex.argtypes = [c_void_p, c_void_p, POINTER(c_int)]

    return lib


def _ptr_bytes(data: bytes):
    """指向 Python bytes 底层缓冲（调用期间须保持 data 存活）。"""
    if not data:
        return None
    return cast(c_char_p(data), c_void_p)


def _ptr_bytearray(buf: bytearray):
    if not buf:
        return None
    return (ctypes.c_char * len(buf)).from_buffer(buf)


def aes_256_ctr_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    if len(key) != 32 or len(iv) != 16:
        raise ValueError("AES-256-CTR requires 32-byte key and 16-byte IV")
    lib = _bind_evp()
    ctx = lib.EVP_CIPHER_CTX_new()
    if not ctx:
        raise OpenSSLError("EVP_CIPHER_CTX_new failed")
    try:
        cipher = lib.EVP_aes_256_ctr()
        if lib.EVP_EncryptInit_ex(ctx, cipher, None, key, iv) != 1:
            raise OpenSSLError("EVP_EncryptInit_ex failed")
        n = len(plaintext)
        out = bytearray(n)
        outl = c_int(0)
        if n:
            if (
                lib.EVP_EncryptUpdate(
                    ctx, _ptr_bytearray(out), byref(outl), _ptr_bytes(plaintext), n
                )
                != 1
            ):
                raise OpenSSLError("EVP_EncryptUpdate failed")
        # CTR Final 通常写 0 字节；预留 16B 尾缓冲
        tail = bytearray(16)
        outl2 = c_int(0)
        if lib.EVP_EncryptFinal_ex(ctx, _ptr_bytearray(tail), byref(outl2)) != 1:
            raise OpenSSLError("EVP_EncryptFinal_ex failed")
        if outl2.value:
            out.extend(tail[: outl2.value])
        if outl.value != n and outl2.value == 0:
            # 少数实现 Update 未写满时以 outl 为准
            return bytes(out[: outl.value])
        return bytes(out) if outl2.value == 0 else bytes(out)
    finally:
        lib.EVP_CIPHER_CTX_free(ctx)


def aes_256_ctr_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    if len(key) != 32 or len(iv) != 16:
        raise ValueError("AES-256-CTR requires 32-byte key and 16-byte IV")
    lib = _bind_evp()
    ctx = lib.EVP_CIPHER_CTX_new()
    if not ctx:
        raise OpenSSLError("EVP_CIPHER_CTX_new failed")
    try:
        cipher = lib.EVP_aes_256_ctr()
        if lib.EVP_DecryptInit_ex(ctx, cipher, None, key, iv) != 1:
            raise OpenSSLError("EVP_DecryptInit_ex failed")
        n = len(ciphertext)
        out = bytearray(n)
        outl = c_int(0)
        if n:
            if (
                lib.EVP_DecryptUpdate(
                    ctx, _ptr_bytearray(out), byref(outl), _ptr_bytes(ciphertext), n
                )
                != 1
            ):
                raise OpenSSLError("EVP_DecryptUpdate failed")
        tail = bytearray(16)
        outl2 = c_int(0)
        if lib.EVP_DecryptFinal_ex(ctx, _ptr_bytearray(tail), byref(outl2)) != 1:
            raise OpenSSLError("EVP_DecryptFinal_ex failed")
        if outl2.value:
            out.extend(tail[: outl2.value])
        return bytes(out[: outl.value + outl2.value]) if outl2.value else bytes(out)
    finally:
        lib.EVP_CIPHER_CTX_free(ctx)
