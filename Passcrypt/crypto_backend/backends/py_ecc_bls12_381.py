# -*- coding: utf-8 -*-
"""
crypto_backend/backends/py_ecc_bls12_381.py
===========================================
Fig.1 BGGen 实例：BLS12-381（py_ecc.optimized_bls12_381，纯 Python 对照）

- 配对 / 群运算：optimized_bls12_381（Jacobian 坐标）
- Hash-to-curve：RFC9380 风格（py_ecc 实现 draft-irtf-cfrg-hash-to-curve
  ciphersuite BLS12381G*_XMD:SHA-256_SSWU_RO_），DST 带 PAEE 前缀
- 点压缩：py_ecc.bls.point_compression（G1=48B, G2=96B）；GT 展平为 12×48B=576B
- SER_VER=2：ZCash/IETF 压缩字节与 pymcl/mcl（SER_VER=3）不互通

由 pairing.py 在选中 py_ecc_bls12_381 时加载。
"""

from __future__ import annotations

import hashlib
import sys

# pairing / FQ12 幂可能较深，抬高递归上限
if sys.getrecursionlimit() < 10000:
    sys.setrecursionlimit(10000)

from py_ecc.bls.hash_to_curve import hash_to_G1, hash_to_G2
from py_ecc.bls.point_compression import (
    compress_G1,
    compress_G2,
    decompress_G1,
    decompress_G2,
)
from py_ecc.optimized_bls12_381 import (
    G1,
    G2,
    Z1,
    Z2,
    add,
    curve_order,
    eq,
    is_on_curve,
    multiply,
    normalize,
    pairing,
    b,
    b2,
)
from py_ecc.optimized_bls12_381 import FQ, FQ2, FQ12

from crypto_backend import codec

# ---- Fig.1 符号 ----
g1 = G1
g2 = G2
p = int(curve_order)  # 群阶（标量域）

CURVE_NAME = "BLS12-381"
BACKEND_NAME = "py_ecc_bls12_381"
# ZCash/IETF 压缩字节与 pymcl/mcl 不同，保持独立版本
SER_VER = 2

# RFC9380 / CFRG hash-to-curve DST（带 PAEE 域分离前缀，避免与其它套件串扰）
_DST_G1 = b"PAEE_V2_BLS12381G1_XMD:SHA-256_SSWU_RO_"
_DST_G2 = b"PAEE_V2_BLS12381G2_XMD:SHA-256_SSWU_RO_"


def _j1(P):
    """G1 坐标规范：仿射 (x,y) → Jacobian (x,y,1)；None → 无穷远 Z1。"""
    if P is None:
        return Z1
    if len(P) == 2:
        return (P[0], P[1], FQ.one())
    return P


def _j2(Q):
    """G2 坐标规范：仿射 (x,y) → Jacobian (x,y,1)；None → 无穷远 Z2。"""
    if Q is None:
        return Z2
    if len(Q) == 2:
        return (Q[0], Q[1], FQ2.one())
    return Q


def e(P, Q):
    """Fig.1 配对：e : G1 × G2 → GT。py_ecc API = pairing(Q∈G2, P∈G1)。"""
    return pairing(_j2(Q), _j1(P))


def g1_mul(P, exp: int):
    """G1 标量乘：[exp]P；exp≡0 返回单位元 Z1。"""
    exp %= p
    if exp == 0:
        return Z1
    return multiply(_j1(P), exp)


def g2_mul(Q, exp: int):
    """G2 标量乘：[exp]Q；exp≡0 返回单位元 Z2。"""
    exp %= p
    if exp == 0:
        return Z2
    return multiply(_j2(Q), exp)


def g1_add(P, Q):
    """G1 点加。"""
    return add(_j1(P), _j1(Q))


def g1_eq(P, Q) -> bool:
    """G1 点相等（Jacobian 下 eq）。"""
    return bool(eq(_j1(P), _j1(Q)))


def gt_mul(a, b):
    """GT 乘法。"""
    return a * b


def gt_eq(a, b) -> bool:
    """GT 相等。"""
    return a == b


def _gt_one() -> FQ12:
    """GT 乘法单位元（幂运算初值）。"""
    return FQ12.one()


def gt_pow(a_tilde: FQ12, exp: int) -> FQ12:
    """GT 幂 ã^exp：迭代平方乘，避免 ** 递归过深。"""
    exp %= p
    if exp == 0:
        return _gt_one()
    result = _gt_one()
    base = a_tilde
    while exp > 0:
        if exp & 1:
            result = result * base
        base = base * base
        exp >>= 1
    return result


def gt_inv_pow(b_tilde: FQ12, r: int) -> FQ12:
    """去盲：b̃^{1/r} = b̃^{r^{-1} mod p}。"""
    inv = pow(int(r) % p, -1, p)
    return gt_pow(b_tilde, inv)


def is_in_g1(P) -> bool:
    """检查是否在 G1 曲线上（含无穷远）。"""
    if P is None:
        return False
    Pj = _j1(P)
    if Pj == Z1 or (len(P) == 3 and P[2] == FQ.zero()):
        return True
    try:
        return bool(is_on_curve(Pj, b))
    except Exception:
        return False


def is_in_g2(a) -> bool:
    """检查是否在 G2 上；拒绝无穷远（协议中盲化输入不应为单位元）。"""
    if a is None:
        return False
    Aj = _j2(a)
    # 拒绝无穷远
    try:
        if Aj == Z2 or Aj[2] == FQ2.zero():
            return False
        return bool(is_on_curve(Aj, b2))
    except Exception:
        return False


def hash_to_g1(msg: bytes):
    """RFC9380 风格 hash_to_G1（XMD:SHA-256_SSWU_RO_），输出规范为 Jacobian。"""
    return _j1(hash_to_G1(msg, _DST_G1, hashlib.sha256))


def hash_to_g2(msg: bytes):
    """RFC9380 风格 hash_to_G2，输出规范为 Jacobian。"""
    return _j2(hash_to_G2(msg, _DST_G2, hashlib.sha256))


def g1_to_bytes(P) -> bytes:
    """G1 → 定长 48 字节压缩（ZCash/IETF）；无穷远编码为全零哨兵。"""
    Pj = _j1(P)
    if Pj == Z1 or Pj[2] == FQ.zero():
        # 压缩无穷远：全零（非标准点；仅作内部哨兵，正常协议不用单位元作公钥）
        return b"\x00" * codec.G1_SIZE
    c = int(compress_G1(Pj))
    return codec.assert_g1_bytes(c.to_bytes(codec.G1_SIZE, "big"))


def g1_from_bytes(data: bytes):
    """48 字节 → G1；全零还原为 Z1，否则 decompress_G1。"""
    data = codec.assert_g1_bytes(data)
    if data == b"\x00" * codec.G1_SIZE:
        return Z1
    c = int.from_bytes(data, "big")
    return _j1(decompress_G1(c))


def g2_to_bytes(Q) -> bytes:
    """G2 → 定长 96 字节：compress_G2 得 (c0,c1)，各 48B 大端拼接。"""
    Qj = _j2(Q)
    c0, c1 = compress_G2(Qj)
    out = int(c0).to_bytes(48, "big") + int(c1).to_bytes(48, "big")
    return codec.assert_g2_bytes(out)


def g2_from_bytes(data: bytes):
    """96 字节 → G2：拆成两个 48B 整数后 decompress_G2。"""
    data = codec.assert_g2_bytes(data)
    c0 = int.from_bytes(data[:48], "big")
    c1 = int.from_bytes(data[48:], "big")
    return _j2(decompress_G2((c0, c1)))


def gt_to_bytes(z: FQ12) -> bytes:
    """GT → 定长 576 字节：12 个 FQ 各 48B 大端；若嵌套 FQ2 则展平。"""
    out = bytearray()
    for item in z.coeffs:
        if hasattr(item, "coeffs"):
            # 若为 FQ2，展平两个 FQ（本曲线 FQ12 通常直接 12×FQ）
            for c in item.coeffs:
                out.extend(int(c).to_bytes(48, "big"))
        else:
            out.extend(int(item).to_bytes(48, "big"))
    if len(out) != codec.GT_SIZE:
        # 若得到 24×FQ（FQ2 布局），再规范：只允许 576
        raise ValueError(f"unexpected GT flatten size {len(out)}")
    return codec.assert_gt_bytes(bytes(out))


def gt_from_bytes(data: bytes) -> FQ12:
    """576 字节 → FQ12：每 48B 还原一个 FQ 系数。"""
    data = codec.assert_gt_bytes(data)
    coeffs = [FQ(int.from_bytes(data[i : i + 48], "big")) for i in range(0, codec.GT_SIZE, 48)]
    return FQ12(coeffs)
