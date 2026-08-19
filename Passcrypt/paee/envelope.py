# -*- coding: utf-8 -*-
"""
paee/envelope.py
================
Fig.1 Enc / Dec：DHIES 风格信封加密。

Enc：
  parse estext = (σ', tk')；非法则 ⊥
  c' := H4(id, ctx, pw, σ')
  dek ←$ K；r ←$ ℤ_p*；ct0 := g^r
  kek := KDF1(pw, tk, X^r)；kMAC := KDF2(pw, tk, X^r)
  ct1 ← SE.Enc(kek, dek)；ct2 ← SE.Enc_CTR(dek, m)
  τ := H5(kMAC, (ct0, ct1, ct2))；ct := (ct0, ct1, ct2, τ)

Dec（v2）：
  服务器：d := ct0^x，明文返回 (ct, d)（不再用 c 密封）
  客户端：用 d(=X^r) 派生 kMAC/kek，验 τ 后解 dek 与 m
"""

from __future__ import annotations

import os
import secrets
import time
from typing import Optional, Tuple

from crypto_backend import group as bg
from paee import hashgroup
from paee.se import SE_Dec, SE_Dec_CTR, SE_Enc, SE_Enc_CTR
from paee.types import BOTTOM, Ciphertext, ExtState, PublicParams, ServerKey


def Wrap(
    pp: PublicParams,
    pk: ServerKey,
    id: str,
    pw: bytes | str,
    tk: bytes,
) -> Tuple[bytes, object, bytes, bytes, object]:
    """
    Wrap：生成 dek、ct0、ct1，并派生 kMAC 与共享秘密 X^r。
    返回 (dek, ct0, ct1, kMAC, X^r)。
    """
    del id  # Fig.1 Enc(pk,id,…) 签名占位；Wrap 数学上不用 id
    dek = os.urandom(32)  # 随机数据加密密钥
    r = secrets.randbelow(pp.p - 1) + 1  # DH 临时指数
    ct0 = bg.g_mul(bg.g, r)  # ct0 = g^r
    Xr = bg.g_mul(pk.X, r)  # X^r = g^{x r}（客户端侧 ECDH）
    kek = hashgroup.KDF1(pw, tk, Xr)  # 封 dek 的密钥
    kMAC = hashgroup.KDF2(pw, tk, Xr)  # 算 τ 的密钥材料
    ct1 = SE_Enc(kek, dek)
    return dek, ct0, ct1, kMAC, Xr


def Encm(dek: bytes, m: bytes) -> bytes:
    """ct2 ← AES-256-CTR(dek, m)；协议基准可用空 m。"""
    return SE_Enc_CTR(dek, m)


def Decm(dek: bytes, ct2: bytes) -> bytes | None:
    """m ← AES-256-CTR 解密 ct2。"""
    return SE_Dec_CTR(dek, ct2)


def Enc(
    pp: PublicParams,
    pk: ServerKey,
    id: str,
    pw: bytes | str,
    estext: ExtState,
    m: bytes,
    ctx: bytes | None = None,
    *,
    tau_bind_ct2: bool = True,
) -> Tuple[bytes, Ciphertext] | None:
    """
    Enc(pk, id, pw, tk, m; ctx, estext) → (c', ct) 或 ⊥。
    tk 取自 estext.tk；ctx 优先显式参数，否则 estext.ctx。
    tau_bind_ct2=False：τ := H5(kMAC,(ct0,ct1))，不含 ct2。
    """
    # 必须先有合法 Ext 状态
    if estext is None or estext.tk is BOTTOM or estext.tk is None:
        return None
    use_ctx = ctx if ctx is not None else estext.ctx
    if not use_ctx:
        return None

    tk = estext.tk
    # c' 须与服务器 rec.c 一致，否则 Enc_store 拒绝
    c_prime = hashgroup.H4(id, use_ctx, pw, estext.sigma, pp.lambda_bytes)

    dek, ct0, ct1, kMAC, _Xr = Wrap(pp, pk, id, pw, tk)
    ct2 = Encm(dek, m)
    tau = hashgroup.H5(
        kMAC, ct0, ct1, ct2, pp.lambda_bytes, bind_ct2=tau_bind_ct2
    )
    ct = Ciphertext(ct0=ct0, ct1=ct1, ct2=ct2, tau=tau)
    return c_prime, ct


def server_dec_response(sk: ServerKey, ct: Ciphertext):
    """
    SDec 核心：d := ct0^x，返回明文 (ct, d)。
    客户端用 d 代替 Enc 时的 X^r 做 KDF。
    """
    if not bg.is_in_g(ct.ct0):
        return None
    d = bg.g_mul(ct.ct0, sk.x)  # d = ct0^x = g^{r x} = X^r
    return ct, d


def client_dec(
    pp: PublicParams,
    pw: bytes | str,
    estext: ExtState,
    ct: Ciphertext,
    d,
    *,
    tau_bind_ct2: bool = True,
) -> Optional[bytes]:
    """客户端完整解密：成功返回明文 m，失败 None。"""
    parts = client_dec_parts(
        pp, pw, estext, ct, d, tau_bind_ct2=tau_bind_ct2
    )
    return None if parts is None else parts[0]


def client_dec_parts(
    pp: PublicParams,
    pw: bytes | str,
    estext: ExtState,
    ct: Ciphertext,
    d,
    *,
    tau_bind_ct2: bool = True,
) -> Optional[Tuple[bytes, bytes, float, float]]:
    """
    带计时分解的解密（供基准使用）。
    返回 (m, dek, open_ms, dec_m_ms)；失败 None。
    open_ms：验 τ + 解 ct1；dec_m_ms：解 ct2。
    tau_bind_ct2=False：验 τ 时 H5 不含 ct2（须与 Enc 一致）。
    """
    if estext is None or estext.tk is BOTTOM or estext.tk is None:
        return None
    if not bg.is_in_g(d):
        return None

    tk = estext.tk
    t0 = time.perf_counter()

    # 用服务器给的 d(=X^r) 重算 kMAC，校验 τ
    kMAC = hashgroup.KDF2(pw, tk, d)
    tau_check = hashgroup.H5(
        kMAC,
        ct.ct0,
        ct.ct1,
        ct.ct2,
        pp.lambda_bytes,
        bind_ct2=tau_bind_ct2,
    )
    if tau_check != ct.tau:
        return None  # 完整性失败

    kek = hashgroup.KDF1(pw, tk, d)
    dek = SE_Dec(kek, ct.ct1)
    if dek is None:
        return None
    open_ms = (time.perf_counter() - t0) * 1000.0

    t1 = time.perf_counter()
    m = Decm(dek, ct.ct2)
    dec_m_ms = (time.perf_counter() - t1) * 1000.0
    if m is None:
        return None
    return m, dek, open_ms, dec_m_ms
