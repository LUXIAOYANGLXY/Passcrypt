# -*- coding: utf-8 -*-
"""
crypto_backend/backends/py_ecc_bn254.py
=======================================
Fig.1 BGGen 的 py_ecc.optimized_bn128（Ethereum BN254）实现。
保留作为对照后端；默认请使用 mcl_bn254 或 secp256r1 / BLS12-381。

编码约定（本后端自管长度，不经 codec 定长断言）：
  G1=64B（x||y 各 32B 大端），G2=128B（FQ2 坐标），GT 为 12×32 或 24×32。
由 pairing.py 在选中 py_ecc / bn254 时加载。
"""

from __future__ import annotations

import hashlib  # 用于 RO→Zp（hash_to_g*）
import sys  # 调整递归上限（配对库内部仍可能较深）

# 某些环境下配对最终幂仍较吃递归栈，预先抬高上限
if sys.getrecursionlimit() < 5000:
    sys.setrecursionlimit(5000)

# ---- 从 optimized_bn128 导入曲线与运算原语 ----
from py_ecc.optimized_bn128 import (
    G1,  # G1 生成元
    G2,  # G2 生成元
    Z1,  # G1 无穷远点（单位元）
    Z2,  # G2 无穷远点
    add,  # 点加
    curve_order,  # 群阶 p
    multiply,  # 标量乘
    normalize,  # Jacobian → 仿射，便于编码
    pairing,  # 双线性配对
    eq,  # 点相等
)
from py_ecc.optimized_bn128 import FQ, FQ2, FQ12, b, b2, is_on_curve  # 域元素与曲线方程

# Fig.1 符号：生成元与阶
g1 = G1  # g1 ∈ G1
g2 = G2  # g2 ∈ G2
p = int(curve_order)  # |G| = p，指数运算模 p
CURVE_NAME = "bn254-py_ecc"
BACKEND_NAME = "py_ecc"


def e(P, Q) -> FQ12:
    """
    Fig.1 配对：e : G1 × G2 → GT。
    py_ecc 的 API 为 pairing(Q∈G2, P∈G1)，故参数顺序为 (P,Q)→pairing(Q,P)。
    """
    return pairing(Q, P)


def g1_mul(P, exp: int):
    """G1 标量乘：返回 [exp]P；exp≡0 时返回单位元 Z1。"""
    exp %= p  # 指数模阶
    if exp == 0:
        return Z1
    return multiply(P, exp)


def g2_mul(Q, exp: int):
    """G2 标量乘：返回 [exp]Q；exp≡0 时返回单位元 Z2。"""
    exp %= p
    if exp == 0:
        return Z2
    return multiply(Q, exp)


def g1_add(P, Q):
    """G1 点加。"""
    return add(P, Q)


def g1_eq(P, Q) -> bool:
    """G1 点相等。"""
    return bool(eq(P, Q))


def gt_mul(a, b):
    """GT 乘法。"""
    return a * b


def gt_eq(a, b) -> bool:
    """GT 相等。"""
    return a == b


def _gt_one() -> FQ12:
    """GT 的乘法单位元（用于幂运算初始化）。"""
    return FQ12.one()


def gt_pow(a_tilde: FQ12, exp: int) -> FQ12:
    """
    GT 幂运算 ã^exp。
    使用迭代平方乘，避免对超大指数调用可能有问题的 ** 递归实现。
    """
    exp %= p
    if exp == 0:
        return _gt_one()
    result = _gt_one()  # 累乘结果，初值 1
    base = a_tilde  # 当前基数
    while exp > 0:
        if exp & 1:  # 当前最低位为 1 则乘上 base
            result = result * base
        base = base * base  # 平方
        exp >>= 1  # 右移处理下一位
    return result


def gt_inv_pow(b_tilde: FQ12, r: int) -> FQ12:
    """
    Fig.1 去盲：tk := b̃^{1/r} = b̃^{r^{-1} mod p}。
    """
    inv = pow(r % p, -1, p)  # 模逆
    return gt_pow(b_tilde, inv)


def _as_affine_g1(P):
    """
    将可能的 Jacobian 点规范为仿射形式，便于稳定编码。
    单位元保持 Z1。
    """
    if P is None or P == Z1:
        return Z1
    try:
        return normalize(P)
    except Exception:
        return P  # 已是仿射或无法规范化时原样返回


def is_in_g1(P) -> bool:
    """检查点是否在 G1 曲线上（含单位元）。"""
    if P is None:
        return False
    if P == Z1:
        return True
    try:
        return bool(is_on_curve(P, b))  # b 为 G1 曲线常数项
    except Exception:
        return False


def is_in_g2(a) -> bool:
    """
    检查 a 是否在 G2 上。
    Fig.1：服务器仅当 a ∈ G2 时才继续求值。
    """
    if a is None or a == Z2:
        return False  # 拒绝单位元作为盲化输入（无意义/危险）
    try:
        return bool(is_on_curve(a, b2))
    except Exception:
        return False


def _hash_to_zp(*parts: bytes) -> int:
    """
    长度前缀拼接后做 SHA-256，再映射到 Zp。
    用作 hash-to-curve 的标量来源。
    """
    h = hashlib.sha256()
    for part in parts:
        h.update(len(part).to_bytes(4, "big"))  # 防拼接歧义
        h.update(part)
    return int.from_bytes(h.digest(), "big") % p


def hash_to_g1(msg: bytes):
    """
    实例化 Fig.1 H1 的值域映射：消息 → G1。
    方法：RO→Zp 后计算 g1^s（落在正确子群，实现简单稳健）。
    """
    return g1_mul(g1, _hash_to_zp(b"H1", msg))


def hash_to_g2(msg: bytes):
    """
    实例化 Fig.1 H2 的值域映射：消息 → G2。
    方法：RO→Zp 后计算 g2^s。
    """
    return g2_mul(g2, _hash_to_zp(b"H2", msg))


def g1_to_bytes(P) -> bytes:
    """
    G1 点 → 64 字节（x||y，各 32 字节大端）。
    单位元编码为 64 个 0x00。
    """
    P = _as_affine_g1(P)
    if P is None or P == Z1:
        return b"\x00" * 64
    x, y = P[0], P[1]  # 仿射坐标
    return int(x).to_bytes(32, "big") + int(y).to_bytes(32, "big")


def g1_from_bytes(data: bytes):
    """64 字节 → G1 点（Jacobian 形式 (x,y,1)）。"""
    if len(data) != 64:
        raise ValueError("G1 encoding must be 64 bytes")
    if data == b"\x00" * 64:
        return Z1
    x = FQ(int.from_bytes(data[:32], "big"))
    y = FQ(int.from_bytes(data[32:], "big"))
    P = (x, y, FQ(1))  # 仿射嵌入 Jacobian
    if not is_in_g1(P):
        raise ValueError("invalid G1 point")
    return P


def g2_to_bytes(Q) -> bytes:
    """
    G2 点 → 128 字节：
      x.c0||x.c1||y.c0||y.c1  （各 32 字节）
    """
    Qn = normalize(Q)  # 转仿射
    x, y = Qn[0], Qn[1]
    return (
        int(x.coeffs[0]).to_bytes(32, "big")
        + int(x.coeffs[1]).to_bytes(32, "big")
        + int(y.coeffs[0]).to_bytes(32, "big")
        + int(y.coeffs[1]).to_bytes(32, "big")
    )


def g2_from_bytes(data: bytes):
    """128 字节 → G2 点（Jacobian (x,y,1)）；解码后校验 on-curve。"""
    if len(data) != 128:
        raise ValueError("G2 encoding must be 128 bytes")
    # 还原 FQ2 坐标：x.c0||x.c1||y.c0||y.c1
    x = FQ2(
        [
            int.from_bytes(data[0:32], "big"),
            int.from_bytes(data[32:64], "big"),
        ]
    )
    y = FQ2(
        [
            int.from_bytes(data[64:96], "big"),
            int.from_bytes(data[96:128], "big"),
        ]
    )
    Q = (x, y, FQ2([1, 0]))  # Z=1 ∈ FQ2
    if not is_in_g2(Q):
        raise ValueError("invalid G2 point")
    return Q


def gt_to_bytes(z: FQ12) -> bytes:
    """
    GT=FQ12 元素展平为定长字节串，供 H3 与 DLEQ Fiat–Shamir 使用。
    兼容 coeffs 为 FQ 或嵌套 FQ2 的两种布局（各系数 32B 大端）。
    """
    out = bytearray()
    for item in z.coeffs:
        if hasattr(item, "coeffs"):
            # 该项是 FQ2：再展开两个 FQ
            for c in item.coeffs:
                out.extend(int(c).to_bytes(32, "big"))
        else:
            out.extend(int(item).to_bytes(32, "big"))
    return bytes(out)


def gt_from_bytes(data: bytes) -> FQ12:
    """
    字节串 → FQ12。
    支持 12*32=384（12 个 FQ）或 24*32=768（12 个 FQ2）两种编码长度。
    """
    if len(data) == 12 * 32:
        # 扁平 12×FQ
        return FQ12([FQ(int.from_bytes(data[i : i + 32], "big")) for i in range(0, 384, 32)])
    if len(data) == 24 * 32:
        # 嵌套：每项 64B → 一个 FQ2
        parts = []
        for i in range(12):
            off = i * 64
            parts.append(
                FQ2(
                    [
                        int.from_bytes(data[off : off + 32], "big"),
                        int.from_bytes(data[off + 32 : off + 64], "big"),
                    ]
                )
            )
        return FQ12(parts)
    raise ValueError(f"invalid GT encoding length {len(data)}")
