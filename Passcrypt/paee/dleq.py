# -*- coding: utf-8 -*-
"""
paee/dleq.py
=============
Fig.1 同群 DLEQ.Prove / DLEQ.Vf（Schnorr + Fiat–Shamir）。

语句：π ← DLEQ.Prove((g, Y, ã, a), kid)
  证明 log_g Y = log_ã a (= kid)
  即 Y = g^{kid} 且 a = ã^{kid}（等价于 ã = a^{1/kid}）。

客户端验证时构造：
  Y' := g^{H1(id,ctx)} · K   （应等于 g^{kid}，因 K=g^k）
  DLEQ.Vf((g, Y', ã, a), π)
"""

from __future__ import annotations

import hashlib
import secrets

from crypto_backend import group as bg
from paee.types import DLEQProof


def _fs_challenge(g, Y, a_tilde, a, A1, A2) -> int:
    """
    Fiat–Shamir 挑战 c ∈ ℤ_p：
    c = SHA-256("PAEE|DLEQ|v2|" ‖ g ‖ Y ‖ ã ‖ a ‖ A1 ‖ A2) mod p。
    群元素均以线格式（压缩点）编码进哈希。
    """
    h = hashlib.sha256(b"PAEE|DLEQ|v2|")
    for el in (g, Y, a_tilde, a, A1, A2):
        h.update(bg.g_to_bytes(el))
    return int.from_bytes(h.digest(), "big") % bg.p


def Prove(g, Y, a_tilde, a, kid: int) -> DLEQProof:
    """
    π ← DLEQ.Prove((g, Y, ã, a), kid)。
    1) v ←$ ℤ_p*；A1 = g^v；A2 = ã^v
    2) c ← FS(g,Y,ã,a,A1,A2)
    3) z = v + c·kid mod p
    """
    v = secrets.randbelow(bg.p - 1) + 1  # 随机预言机见证
    A1 = bg.g_mul(g, v)  # A1 = g^v
    A2 = bg.g_mul(a_tilde, v)  # A2 = ã^v
    c = _fs_challenge(g, Y, a_tilde, a, A1, A2)
    z = (v + c * (kid % bg.p)) % bg.p
    return DLEQProof(A1=A1, A2=A2, z=z)


def Vf(g, Y, a_tilde, a, pi: DLEQProof) -> bool:
    """
    DLEQ.Vf((g, Y, ã, a), π) ∈ {0,1}。
    检查：
      g^z  == A1 · Y^c
      ã^z  == A2 · a^c
    """
    c = _fs_challenge(g, Y, a_tilde, a, pi.A1, pi.A2)

    # 第一等式：g^z ?== A1 · Y^c
    lhs1 = bg.g_mul(g, pi.z)
    rhs1 = bg.g_add(pi.A1, bg.g_mul(Y, c))
    if not bg.g_eq(lhs1, rhs1):
        return False

    # 第二等式：ã^z ?== A2 · a^c
    lhs2 = bg.g_mul(a_tilde, pi.z)
    rhs2 = bg.g_add(pi.A2, bg.g_mul(a, c))
    return bg.g_eq(lhs2, rhs2)
