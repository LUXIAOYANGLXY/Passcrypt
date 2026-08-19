# -*- coding: utf-8 -*-
"""
crypto_backend/backends/pymcl_bls12_381.py
==========================================
对照后端：BLS12-381（pymcl / herumi mcl，原生 C++）。

用途：第一版配对 2HashDH / 需要 e:G1×G2→GT 时选用；
Fig.1 v2 默认请用 secp256r1，不要与本后端混用同一 data/。

编码：
  - mcl serialize：G1=48、G2=96、GT=576 → ser_ver=3
  - Hash：mcl hashAndMapTo，消息前加 PAEE DST 做域分离
"""

from __future__ import annotations

import pymcl

from crypto_backend import codec

# 库内置生成元与群阶
g1 = pymcl.g1
g2 = pymcl.g2
r = int(pymcl.r)
p = r  # PublicParams / pairing 门面读 p

CURVE_NAME = "BLS12-381"
BACKEND_NAME = "pymcl_bls12_381"
SER_VER = 3  # 与 py_ecc 压缩字节不兼容，故独立版本

# hashAndMapTo 域分离前缀（写入曲线哈希输入）
_DST_G1 = b"PAEE_V3_BLS12381G1_MCL_HASHANDMAP_"
_DST_G2 = b"PAEE_V3_BLS12381G2_MCL_HASHANDMAP_"


def _fr(exp: int) -> pymcl.Fr:
    """
    Python int → 标量域 Fr。
    mcl Fr.deserialize 使用 little-endian 32 字节。
    """
    x = int(exp) % r
    return pymcl.Fr.deserialize(x.to_bytes(32, "little"))


def e(P, Q):
    """双线性配对 e : G1 × G2 → GT。"""
    return pymcl.pairing(P, Q)


def g1_mul(P, exp: int):
    """G1 标量乘 P^exp。"""
    return P * _fr(exp)


def g2_mul(Q, exp: int):
    """G2 标量乘 Q^exp。"""
    return Q * _fr(exp)


def g1_add(P, Q):
    """G1 点加。"""
    return P + Q


def g1_eq(P, Q) -> bool:
    return P == Q


def gt_mul(a, b):
    """GT 乘法。"""
    return a * b


def gt_eq(a, b) -> bool:
    return a == b


def gt_pow(a_tilde, exp: int):
    """GT 幂 a^exp。"""
    return a_tilde ** _fr(exp)


def gt_inv_pow(b_tilde, exp: int):
    """b̃^(1/exp mod r)；参数勿命名为 r，以免遮蔽群阶。"""
    inv = pow(int(exp) % r, -1, r)
    return gt_pow(b_tilde, inv)


def is_in_g1(P) -> bool:
    """序列化再反序列化校验；无穷远允许。"""
    if P is None:
        return False
    try:
        return pymcl.G1.deserialize(P.serialize()) == P
    except Exception:
        return False


def is_in_g2(a) -> bool:
    """G2 成员检测；零元视为非法（与旧 py_ecc 约定对齐）。"""
    if a is None:
        return False
    try:
        if a.is_zero():
            return False
        return pymcl.G2.deserialize(a.serialize()) == a
    except Exception:
        return False


def hash_to_g1(msg: bytes):
    """mcl hashAndMapTo(G1)：DST ‖ msg。"""
    return pymcl.G1.hash(_DST_G1 + msg)


def hash_to_g2(msg: bytes):
    """mcl hashAndMapTo(G2)：DST ‖ msg。"""
    return pymcl.G2.hash(_DST_G2 + msg)


def g1_to_bytes(P) -> bytes:
    """G1 → 定长 48B。"""
    return codec.assert_g1_bytes(P.serialize())


def g1_from_bytes(data: bytes):
    data = codec.assert_g1_bytes(data)
    return pymcl.G1.deserialize(data)


def g2_to_bytes(Q) -> bytes:
    """G2 → 定长 96B。"""
    return codec.assert_g2_bytes(Q.serialize())


def g2_from_bytes(data: bytes):
    data = codec.assert_g2_bytes(data)
    return pymcl.G2.deserialize(data)


def gt_to_bytes(z) -> bytes:
    """GT → 定长 576B。"""
    return codec.assert_gt_bytes(z.serialize())


def gt_from_bytes(data: bytes):
    data = codec.assert_gt_bytes(data)
    return pymcl.GT.deserialize(data)
