# -*- coding: utf-8 -*-
"""
paee/params.py
==============
Fig.1：pp ← Setup(1^λ)；(sk, pk) ← SerKGen(pp)。
群 (p, G, g) 由 crypto_backend.group 按配置实例化（默认 secp256r1）。
"""

from __future__ import annotations

import secrets

from crypto_backend import group as bg
from paee.types import PublicParams, ServerKey


def Setup(lambda_bytes: int = 32) -> PublicParams:
    """
    Setup(1^λ)：
      - 取素数阶循环群 (p, G, g)（此处 g、运算在 group 模块中）
      - Hi / KDFi / DLEQ / SE 由其它模块提供，不装进 pp 对象
    返回公开参数 pp（阶 p、λ、曲线名）。
    """
    return PublicParams(p=bg.p, lambda_bytes=lambda_bytes, curve=bg.CURVE_NAME)


def SerKGen(pp: PublicParams) -> ServerKey:
    """
    SerKGen(pp)：
      k, x ←$ ℤ_p^*          # 非零均匀采样
      K := g^k；X := g^x
      sk := (k, x)；pk := (K, X)
    """
    # randbelow(n) ∈ [0,n)；+1 并避开 0，得到 {1,…,p-1}
    k = secrets.randbelow(pp.p - 1) + 1
    x = secrets.randbelow(pp.p - 1) + 1
    K = bg.g_mul(bg.g, k)  # K = g^k
    X = bg.g_mul(bg.g, x)  # X = g^x
    return ServerKey(k=k, x=x, K=K, X=X)
