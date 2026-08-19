"""PPKR 全局密码学参数与实验开销计数类型。

本模块集中定义与论文 (Faller et al., CCS 2024) 对齐的安全参数、
曲线/哈希/AES 常量，以及实验用的 ``CostCounter`` 逻辑操作计数器。

``CostCounter`` 用于 benchmark 与 ``benchmark/cost_tracker`` 的成本审计：
记录 Exp / Mult / Hash / AES / Sig 等抽象操作次数（非 wall-clock）。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import NewType

# 安全参数 λ = 128（论文 Sec. 2, Fig. 1-4）
LAMBDA = 128
# CTR 模式计数器上限（防重放/溢出）
CTR_MAX = 10

# 论文 Sec. 5：基于 secp256r1 的 (N, Q)-OMDH 群 G
CURVE_NAME = "secp256r1"

HASH_ALG = "sha256"
# AES-256-GCM 密钥长度（与 PAEE/WBP 实验对齐；论文 Fig 常用 λ=128 截断，本仓库实验统一 256-bit 密钥）
AE_KEY_BYTES = 32
AE_NONCE_BYTES = 12
# 盐 s1, s2 ← {0,1}^λ
SALT_BYTES = LAMBDA // 8

# 类型别名：增强 IDC/SSID/SID 等标识符的类型安全
Bytes = NewType("Bytes", bytes)
SSID = NewType("SSID", str)  # 单次协议会话 ID
IDC = NewType("IDC", str)    # 客户端/用户标识
SID = NewType("SID", str)    # 服务器长期 ID


@dataclass(frozen=True)
class CostCounter:
    """逻辑密码学操作计数（对齐论文 Table 3/4）。

    各字段含义：
        exp   — 群指数运算（椭圆曲线标量乘等）
        mult  — 群乘法/点加
        hash  — 哈希函数调用（含 KDF 抽象计数）
        aes   — 对称加解密（AEAD）
        sig   — Schnorr 签名/验签
    """

    exp: int = 0
    mult: int = 0
    hash: int = 0
    aes: int = 0
    sig: int = 0

    def __add__(self, other: CostCounter) -> CostCounter:
        """合并两次阶段的计数（实验汇总用）。"""
        return CostCounter(
            exp=self.exp + other.exp,
            mult=self.mult + other.mult,
            hash=self.hash + other.hash,
            aes=self.aes + other.aes,
            sig=self.sig + other.sig,
        )

    def to_dict(self) -> dict:
        """序列化为 JSON/CSV 友好的字典。"""
        return {
            "exp": self.exp,
            "mult": self.mult,
            "hash": self.hash,
            "aes": self.aes,
            "sig": self.sig,
        }


def format_cost_latency(cost: CostCounter, real_ms: float) -> str:
    """统一实验输出格式：wall-clock 延迟 + 逻辑操作计数。"""
    return (
        f"real_ms={real_ms:.2f} exp={cost.exp} hash={cost.hash} "
        f"sig={cost.sig} mult={cost.mult} aes={cost.aes}"
    )
