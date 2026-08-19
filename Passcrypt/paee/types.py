# -*- coding: utf-8 -*-
"""
paee/types.py
=============
Fig.1（v2）核心数据结构。字段名与论文符号对齐，便于对照实现。

Setup / SerKGen:
  pp = (p, G, g, …)；sk = (k, x)，pk = (K, X)，其中 K = g^k，X = g^x

Reg / Ext（3HashSDHI POPRF）:
  a = H2(pw)^r ∈ G
  k_{id,ctx} = k + H1(id, ctx)
  ã = a^{1/k_{id,ctx}}
  σ = ã^{1/r} = H2(pw)^{1/(k+H1(id,ctx))}
  tk = H3(…)；c = H4(…)；estext = (σ, tk)

Enc / Dec:
  ct = (ct0, ct1, ct2, τ)；服务器返回明文 (ct, d)，d = ct0^x
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional


@dataclass
class PublicParams:
    """Fig.1：pp ← Setup(1^λ)。公开参数（群阶与安全字节长度）。"""

    p: int  # 群阶 |G| = p（secp256r1 曲线阶）
    lambda_bytes: int  # λ：tk/c/τ/ctx 等比特串字节长度（默认 32）
    curve: str = "secp256r1"  # 曲线标识，写入磁盘元数据防混用


@dataclass
class ServerKey:
    """
    服务器长期密钥。
    sk := (k, x)；对外只公布 pk := (K, X) = (g^k, g^x)。
    """

    k: int  # POPRF 主密钥（参与 k_{id,ctx}）
    x: int  # DHIES 解密指数（Dec 时算 d = ct0^x）
    K: Any  # 公钥分量 g^k ∈ G
    X: Any  # 公钥分量 g^x ∈ G


@dataclass
class PasswordRecord:
    """
    服务器侧口令记录 rec := (id, ctx, c)。
    c 为注册时客户端提交的半边承诺 H4(id,ctx,pw,σ)，用于 Enc 时比对 c'。
    """

    id: str  # 用户标识
    ctx: bytes  # Reg 时服务器采样的新鲜上下文（λ 字节）
    c: bytes  # 记录半边 c = H4(...)


@dataclass
class BlindState:
    """
    客户端盲化中间态（不上传 r）。
    r ←$ ℤ_p*；a := H2(pw)^r。
    """

    r: int  # 盲化随机数（仅客户端持有）
    a: Any  # 盲化点 a ∈ G，发给服务器求值


@dataclass
class ExtState:
    """
    Fig.1 estext := (σ, tk)：Ext 成功后的短暂客户端状态。
    用于后续 Enc / Dec 派生 kek、kMAC 与 c'。
    """

    sigma: Any  # σ ∈ G：去盲后的 POPRF 输出
    tk: bytes  # tk ∈ {0,1}^λ：认证令牌材料
    ctx: bytes = b""  # 工程保留：Enc 算 c' 时需要与 rec 相同的 ctx


@dataclass
class DLEQProof:
    """
    π ← DLEQ.Prove((g, Y, ã, a), kid)。
    Schnorr 型同群证明：log_g Y = log_ã a (= kid)。
    """

    A1: Any  # 承诺 A1 = g^v
    A2: Any  # 承诺 A2 = ã^v
    z: int  # 响应 z = v + c·kid（c 为 Fiat–Shamir 挑战）


@dataclass
class Ciphertext:
    """
    Fig.1 信封密文 ct := (ct0, ct1, ct2, τ)。
    ct0 = g^r；ct1 封 dek；ct2 封明文 m；τ 绑定完整性。
    """

    ct0: Any  # ∈ G
    ct1: bytes  # SE.Enc(kek, dek)
    ct2: bytes  # SE.Enc(dek, m)
    tau: bytes  # τ = H5(kMAC, (ct0,ct1,ct2))


# 论文中的“⊥ / 失败”在 Python 侧用 None 表示
BOTTOM: None = None
