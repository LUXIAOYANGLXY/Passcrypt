# -*- coding: utf-8 -*-
"""
crypto_backend/group.py
=======================
Fig.1 素数阶循环群 (p, G, g) 的统一门面。

实际运算委托给 pairing 加载的后端（默认 secp256r1 / OpenSSL）。
协议代码应只依赖本模块符号，不直接 import backends。
"""

from __future__ import annotations

import hashlib

from crypto_backend import pairing as _bg
from crypto_backend import codec as _codec

# Fig.1：(p, G, g) — 生成元与阶来自当前后端
g = _bg.g1  # 生成元 g ∈ G
p = _bg.p  # 群阶

# 群运算别名（G1 在素数阶群方案中即 G）
g_mul = _bg.g1_mul  # 标量乘：P^e
g_add = _bg.g1_add  # 点加：P·Q（乘法记号写作乘）
g_eq = _bg.g1_eq
is_in_g = _bg.is_in_g1
hash_to_g = _bg.hash_to_g1  # H2 底层：hash-to-curve
g_to_bytes = _bg.g1_to_bytes  # 内存 → 线格式
g_from_bytes = _bg.g1_from_bytes  # 线格式 → 内存

CURVE_NAME = _bg.CURVE_NAME
BACKEND_NAME = _bg.BACKEND_NAME
ACTIVE_BACKEND = _bg.ACTIVE_BACKEND
SER_VER = getattr(_bg, "SER_VER", _codec.SER_VER)
CURVE_ID = getattr(_bg, "CURVE_ID", CURVE_NAME)


def g_inv_pow(P, exp: int):
    """
    计算 P^{1/exp mod p}（先求标量逆再标量乘）。
    用于 ã = a^{1/kid}、σ = ã^{1/r}。
    """
    inv = pow(int(exp) % p, -1, p)  # exp^{-1} mod p
    return g_mul(P, inv)


def hash_to_zp(msg: bytes) -> int:
    """
    Hash-to-scalar：{0,1}* → ℤ_p*。
    SHA-256("PAEE|Zp|" ‖ msg) 再模 p；若为 0 则映到 1。
    """
    digest = hashlib.sha256(b"PAEE|Zp|" + msg).digest()
    x = int.from_bytes(digest, "big") % p
    return x if x != 0 else 1
