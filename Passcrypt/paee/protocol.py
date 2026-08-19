# -*- coding: utf-8 -*-
"""
paee/protocol.py
================
Fig.1 交互过程的纯逻辑层（不含 socket；TCP 封装在 net/）。

  CReg / SReg，CExt / SExt，Enc 提交，CDec / SDec

工程补全（不改变原语语义）：
  - Reg：Client 采样 ctx，随 REG_BLIND 提交；Server 写入 rec
  - pk 带外分发；Ext 使用 Client 本地 ctx（不上线）
"""

from __future__ import annotations

import os
from typing import Dict, Optional, Tuple

from paee import envelope, oprf
from paee.params import PublicParams
from paee.types import BlindState, Ciphertext, ExtState, PasswordRecord, ServerKey


class PAEEServerState:
    """
    服务器内存状态：长期密钥 + 口令记录 + 已存密文。
    对应 Fig.1 服务器侧 SReg / SExt / Enc_store / SDec。
    """

    def __init__(self, pp: PublicParams, sk: ServerKey):
        self.pp = pp
        self.sk = sk
        self.records: Dict[str, PasswordRecord] = {}  # id → rec=(id,ctx,c)
        self.ciphertexts: Dict[str, Ciphertext] = {}  # id → ct
        # Reg 两阶段之间暂存尚未 commit 的 ctx（由 Client 提供）
        self._reg_ctx: Dict[str, bytes] = {}

    def SReg_accept_ctx(self, id: str, ctx: bytes) -> bool:
        """若 id 已注册则 ⊥；否则暂存 Client 提供的 ctx。"""
        if id in self.records or id in self._reg_ctx:
            return False
        if len(ctx) != self.pp.lambda_bytes:
            return False
        self._reg_ctx[id] = ctx
        return True

    def SReg_issue_ctx(self, id: str) -> Optional[bytes]:
        """兼容旧测试：服务器采样 ctx（线上路径改用 SReg_accept_ctx）。"""
        if id in self.records:
            return None
        ctx = os.urandom(self.pp.lambda_bytes)
        self._reg_ctx[id] = ctx
        return ctx

    def SReg_eval(self, id: str, a):
        """Reg 阶段 POPRF 求值：使用暂存 ctx。"""
        ctx = self._reg_ctx.get(id)
        if ctx is None:
            return None
        return oprf.server_eval(self.sk, id, ctx, a)

    def SReg_store(self, id: str, c: bytes) -> bool:
        """Reg commit：弹出暂存 ctx，写入 rec=(id,ctx,c)。"""
        ctx = self._reg_ctx.pop(id, None)
        if ctx is None:
            return False
        if id in self.records:
            return False
        self.records[id] = PasswordRecord(id=id, ctx=ctx, c=c)
        return True

    def SExt_ctx(self, id: str) -> Optional[bytes]:
        """Ext：把注册时的 ctx 回传给客户端。"""
        rec = self.records.get(id)
        return None if rec is None else rec.ctx

    def SExt_eval(self, id: str, a):
        """Ext：对已注册用户用 rec.ctx 做 POPRF 求值。"""
        rec = self.records.get(id)
        if rec is None or rec.id != id:
            return None
        return oprf.server_eval(self.sk, id, rec.ctx, a)

    def Enc_store(self, id: str, c_prime: bytes, ct: Ciphertext) -> bool:
        """
        接受 Enc 提交：要求 c' == rec.c（口令/记录绑定检查），再存 ct。
        """
        rec = self.records.get(id)
        if rec is None:
            return False
        if c_prime != rec.c:
            return False  # 半边不匹配
        self.ciphertexts[id] = ct
        return True

    def SDec(self, id: str) -> Optional[Tuple[Ciphertext, object]]:
        """
        Fig.1 SDec：基线无检索授权，仅凭 id 返回 (ct, d)。
        """
        ct = self.ciphertexts.get(id)
        if ct is None:
            return None
        return envelope.server_dec_response(self.sk, ct)


def CReg_blind(pw: bytes | str) -> BlindState:
    """客户端 Reg/Ext 第一步：盲化口令。"""
    return oprf.blind(pw)


def CReg_finalize_c(
    pp: PublicParams,
    id: str,
    pw: bytes | str,
    ctx: bytes,
    st: BlindState,
    a_tilde,
    K=None,
) -> Optional[bytes]:
    """Reg：去盲（无 π），派生并返回要提交的 c。"""
    est = oprf.finalize(id, ctx, pw, st, a_tilde, K, pp.lambda_bytes)
    if est is None:
        return None
    return oprf.derive_c(id, ctx, pw, est.sigma, pp.lambda_bytes)


def CExt(
    pp: PublicParams,
    id: str,
    pw: bytes | str,
    ctx: bytes,
    st: BlindState,
    a_tilde,
    K=None,
) -> Optional[ExtState]:
    """Ext：返回 estext=(σ,tk) 或 ⊥（无 π / 无 DLEQ.Vf）。"""
    return oprf.finalize(id, ctx, pw, st, a_tilde, K, pp.lambda_bytes)


def CEnc(
    pp: PublicParams,
    pk: ServerKey,
    id: str,
    pw,
    estext: ExtState,
    m: bytes,
):
    """Enc：本地算 (c', ct)；随后由 net 层 ENC_COMMIT 上传。"""
    return envelope.Enc(pp, pk, id, pw, estext, m, ctx=estext.ctx)


def CDec(
    pp: PublicParams,
    pw,
    estext: ExtState,
    ct: Ciphertext,
    d,
) -> Optional[bytes]:
    """Dec：用服务器返回的 (ct,d) 在本地解出 m。"""
    return envelope.client_dec(pp, pw, estext, ct, d)
