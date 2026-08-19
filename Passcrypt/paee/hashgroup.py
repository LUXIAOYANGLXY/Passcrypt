# -*- coding: utf-8 -*-
"""
paee/hashgroup.py
=================
Fig.1 Setup 中的哈希与 KDF。

  H1 / H3 / H4 : SHA-256（域分离标签）
  H2           : RFC 9380 ``P256_XMD:SHA-256_SSWU_RO_``（``bg.hash_to_g``）
  H5           : HMAC-SHA256（密钥 = kMAC）
  KDF1 / KDF2  : PBKDF2-HMAC-SHA256，iters=``KDF_HASH_REPETITIONS``（对齐 PBCS Utils.kdf）
"""

from __future__ import annotations

import hashlib
import hmac

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from crypto_backend import group as bg

# 与 E2SE/PBCS Constants.KDF_HASH_REPETITIONS 对齐（仅 KDF1/KDF2）
KDF_HASH_REPETITIONS = 1


def _as_pw_bytes(pw: bytes | str) -> bytes:
    if isinstance(pw, str):
        return pw.encode("utf-8")
    return pw


def kdf_pbcs(
    passphrase: bytes | str,
    key: bytes,
    salt: bytes,
    length_bytes: int,
    iterations: int = KDF_HASH_REPETITIONS,
) -> bytes:
    """
    PBCS ``Utils.kdf`` 同构（供 KDF1/KDF2）：
      salt_full = salt ‖ key
      OKM = PBKDF2-HMAC-SHA256(passphrase, salt_full, iterations, length_bytes)
    """
    pw = _as_pw_bytes(passphrase)
    salt_full = salt + key
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length_bytes,
        salt=salt_full,
        iterations=iterations,
    ).derive(pw)


def H1(id: str, ctx: bytes) -> int:
    """
    H1(id, ctx) ∈ ℤ_p*。
    SHA-256 → hash_to_zp。
    """
    msg = b"PAEE|H1|" + id.encode("utf-8") + b"|" + ctx
    return bg.hash_to_zp(msg)


def H2(pw: bytes | str):
    """
    H2(pw) ∈ G。
    RFC 9380 hash-to-curve：P256_XMD:SHA-256_SSWU_RO_。
    """
    pw_b = _as_pw_bytes(pw)
    return bg.hash_to_g(b"PAEE|H2|" + pw_b)


def _h34(tag: bytes, id: str, ctx: bytes, pw: bytes | str, sigma, lambda_bytes: int) -> bytes:
    """H3/H4：SHA-256(tag ‖ id ‖ ctx ‖ pw ‖ σ) 取前 λ 字节。"""
    pw_b = _as_pw_bytes(pw)
    data = (
        tag
        + id.encode("utf-8")
        + b"|"
        + ctx
        + b"|"
        + pw_b
        + b"|"
        + bg.g_to_bytes(sigma)
    )
    return hashlib.sha256(data).digest()[:lambda_bytes]


def H3(id: str, ctx: bytes, pw: bytes | str, sigma, lambda_bytes: int = 32) -> bytes:
    """tk := H3(id, ctx, pw, σ) — SHA-256。"""
    return _h34(b"PAEE|H3|", id, ctx, pw, sigma, lambda_bytes)


def H4(id: str, ctx: bytes, pw: bytes | str, sigma, lambda_bytes: int = 32) -> bytes:
    """c := H4(id, ctx, pw, σ) — SHA-256。"""
    return _h34(b"PAEE|H4|", id, ctx, pw, sigma, lambda_bytes)


def H5(
    kMAC: bytes,
    ct0,
    ct1: bytes,
    ct2: bytes = b"",
    lambda_bytes: int = 32,
    *,
    bind_ct2: bool = True,
) -> bytes:
    """
    τ := H5(kMAC, (ct0, ct1[, ct2])) — HMAC-SHA256。
    密钥 = kMAC；消息带域分离前缀，流式 update 避免大文件整段拼接。
    """
    mac = hmac.new(kMAC, digestmod=hashlib.sha256)
    mac.update(b"PAEE|H5|")
    mac.update(bg.g_to_bytes(ct0))
    mac.update(b"|")
    mac.update(ct1)
    if bind_ct2:
        mac.update(b"|")
        mac.update(ct2)
    return mac.digest()[:lambda_bytes]


def H5_fast(kMAC: bytes, ct0, ct1: bytes, ct2: bytes, lambda_bytes: int = 32) -> bytes:
    """
    大文件优化：HMAC 消息用 SHA-256(ct2) ‖ |ct2| 代替整段 ct2。
    非 Fig.1 字面定义。
    """
    mac = hmac.new(kMAC, digestmod=hashlib.sha256)
    mac.update(b"PAEE|H5|fast|")
    mac.update(bg.g_to_bytes(ct0))
    mac.update(b"|")
    mac.update(ct1)
    mac.update(b"|")
    mac.update(hashlib.sha256(ct2).digest())
    mac.update(b"|")
    mac.update(len(ct2).to_bytes(8, "big"))
    return mac.digest()[:lambda_bytes]


def KDF1(pw: bytes | str, tk: bytes, Xr, key_len: int = 32) -> bytes:
    """kek := KDF1(pw, tk, X^r) — PBKDF2-HMAC-SHA256。"""
    material = tk + b"|" + bg.g_to_bytes(Xr)
    return kdf_pbcs(_as_pw_bytes(pw), material, b"PAEE|KDF1|", key_len)


def KDF2(pw: bytes | str, tk: bytes, Xr, key_len: int = 32) -> bytes:
    """kMAC := KDF2(pw, tk, X^r) — PBKDF2-HMAC-SHA256。"""
    material = tk + b"|" + bg.g_to_bytes(Xr)
    return kdf_pbcs(_as_pw_bytes(pw), material, b"PAEE|KDF2|", key_len)
