"""2HashDH 不经意伪随机函数 (OPRF)。

对应 Faller 等 (CCS 2024) Sec. 4.3 / Fig. 4 (JKKX16 风格)：
  Client：a = H1(pw||IDC)^r
  HSM：   b = a^k_OPRF
  Client：ρ = H2(pw||IDC, b^(1/r))

线格式：盲化/求值输入输出均为 SEC1 压缩点 (33 字节)。
安全注记：客户端持有盲化因子 r，服务器仅见 a 与 a^k，无法关联 pw。
"""

from __future__ import annotations

from dataclasses import dataclass

from config import CostCounter, IDC
from crypto.group import GROUP, GroupElement, Scalar
from crypto.random_oracle import RandomOracleH1, RandomOracleH2


# ── OPRF 密钥与状态 ───────────────────────────────────────────────────


@dataclass(frozen=True)
class OPRFKey:
    """服务器 OPRF 密钥 k_OPRF。"""

    k: Scalar


@dataclass
class OPRFClientState:
    """客户端盲化会话状态：保存 r、pw、idc 供 finalize 使用。"""

    r: Scalar
    pw: str
    idc: IDC


@dataclass(frozen=True)
class OPRFBlindedInput:
    """客户端→服务器的盲化输入 a。"""

    a: GroupElement

    def serialize(self) -> bytes:
        """返回 33 字节盲化输入 a。"""
        return self.a.serialize()


@dataclass(frozen=True)
class OPRFEvaluated:
    """服务器→客户端的求值结果 b = a^k。"""

    b: GroupElement

    def serialize(self) -> bytes:
        """返回 33 字节求值结果 b。"""
        return self.b.serialize()


# ── 2HashDH OPRF ──────────────────────────────────────────────────────


class OPRF2HashDH:
    """2HashDH OPRF 三阶段：client_blind → server_evaluate → client_finalize。"""

    def __init__(self) -> None:
        self._h1 = RandomOracleH1()
        self._h2 = RandomOracleH2()

    def generate_key(self) -> tuple[OPRFKey, CostCounter]:
        """生成服务器 OPRF 密钥。"""
        return OPRFKey(k=GROUP.random_scalar()), CostCounter()

    def client_blind(
        self, pw: str, idc: IDC, r: Scalar | None = None
    ) -> tuple[OPRFBlindedInput, OPRFClientState, CostCounter]:
        """客户端盲化：采样 r，计算 a = H1(pw||IDC)^r。"""
        if r is None:
            r = GROUP.random_scalar()
        # H1(pw||IDC) 映射到群，再盲化 a = base^r；服务器只见 a，不知 pw
        base, c_h1 = self._h1.hash_to_group(pw, idc)
        a, c_exp = GROUP.exp(base, r)
        state = OPRFClientState(r=r, pw=pw, idc=idc)  # 保存 r 供 finalize 去盲
        return OPRFBlindedInput(a=a), state, c_h1 + c_exp

    def server_evaluate(
        self, blinded: OPRFBlindedInput, key: OPRFKey
    ) -> tuple[OPRFEvaluated, CostCounter]:
        """服务器求值：b = a^k_OPRF（Fig. 4 灰色 HSM 框）。"""
        b, c = GROUP.exp(blinded.a, key.k)
        return OPRFEvaluated(b=b), c

    def client_finalize(
        self, evaluated: OPRFEvaluated, state: OPRFClientState
    ) -> tuple[bytes, CostCounter]:
        """客户端去盲并计算 ρ = H2(pw||IDC, b^(1/r))。"""
        # 去盲：b^(1/r) = (a^k)^(1/r) = H1(pw||IDC)^k（服务器不知 pw）
        r_inv = GROUP.inverse_scalar(state.r)
        unblinded, c_exp = GROUP.exp(evaluated.b, r_inv)
        rho, c_h2 = self._h2.eval(state.pw, state.idc, unblinded)
        return rho, c_exp + c_h2
