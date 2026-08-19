# -*- coding: utf-8 -*-
"""
paee/oprf.py
============
3HashSDHI-based POPRF（Reg / Ext 共用同一求值逻辑）。

工程口径（相对 Fig.1 基线的可验证变体）：
  **不传输、不生成、不验证** π_reg / π_ext（DLEQ）。
  服务器只返回 ã；客户端直接去盲派生 σ / tk / c。
  DLEQ 原语仍保留在 ``paee/dleq.py``（单测 / 可选扩展），不进入 wire。

客户端：
  r ←$ ℤ_p*；a := H2(pw)^r

服务器：
  k_{id,ctx} := k + H1(id, ctx)
  ã := a^{1/k_{id,ctx}}

客户端：
  σ := ã^{1/r}
  tk := H3(id, ctx, pw, σ)
  c  := H4(id, ctx, pw, σ)   # Reg 提交；Enc 再算 c'
"""

from __future__ import annotations

import secrets
from typing import Optional

from crypto_backend import group as bg
from paee import hashgroup
from paee.types import BlindState, ExtState, ServerKey


def blind(pw: bytes | str) -> BlindState:
    """客户端盲化：采样 r，计算 a = H2(pw)^r。"""
    r = secrets.randbelow(bg.p - 1) + 1  # r ∈ ℤ_p*
    a = bg.g_mul(hashgroup.H2(pw), r)  # a = H2(pw)^r
    return BlindState(r=r, a=a)


def server_eval(
    sk: ServerKey,
    id: str,
    ctx: bytes,
    a,
) -> Optional[object]:
    """
    服务器 POPRF 求值。
    返回 ã；输入非法或 kid=0 时返回 None。
    **不**生成 DLEQ 证明 π。
    """
    # 拒绝非群元素（防恶意 a）
    if not bg.is_in_g(a):
        return None

    h1 = hashgroup.H1(id, ctx)  # H1(id,ctx) ∈ ℤ_p
    kid = (sk.k + h1) % bg.p  # k_{id,ctx}
    if kid == 0:
        # 逆元不存在，协议失败（概率可忽略）
        return None

    return bg.g_inv_pow(a, kid)  # ã = a^{1/kid}


def finalize(
    id: str,
    ctx: bytes,
    pw: bytes | str,
    st: BlindState,
    a_tilde,
    K=None,  # 保留签名兼容；无 π 时不使用 K
    lambda_bytes: int = 32,
) -> Optional[ExtState]:
    """
    客户端：去盲得 σ → 派生 tk。
    无 DLEQ 验证（π 不上线）。
    """
    del K  # unused in no-π mode
    if a_tilde is None or not bg.is_in_g(a_tilde):
        return None

    sigma = bg.g_inv_pow(a_tilde, st.r)  # σ = ã^{1/r}
    tk = hashgroup.H3(id, ctx, pw, sigma, lambda_bytes)
    return ExtState(sigma=sigma, tk=tk, ctx=ctx)


def derive_c(
    id: str,
    ctx: bytes,
    pw: bytes | str,
    sigma,
    lambda_bytes: int = 32,
) -> bytes:
    """c := H4(id, ctx, pw, σ) — Reg 写入 rec；Enc 时再算 c' 比对。"""
    return hashgroup.H4(id, ctx, pw, sigma, lambda_bytes)
