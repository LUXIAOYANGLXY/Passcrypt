# -*- coding: utf-8 -*-
"""
crypto_backend/backends/mcl_bn254.py
====================================
Fig.1 BGGen 遗留后端：BN254（mclbn256 / herumi）。

Windows 注意：mclbn256 导入时会把 DLL 解压到 TemporaryDirectory；
进程退出时 cleanup 可能因路径已失效抛出 NotADirectoryError。
因此在 import mclbn256 之前先给 TemporaryDirectory.cleanup 打补丁吞掉异常。

由 pairing.py 在选中 mcl / mclbn256 时加载。
"""

from __future__ import annotations

import hashlib
import tempfile

# ---- Windows DLL tempfile 清理绕过（必须在 import mclbn256 之前执行）----
_orig_td_cleanup = tempfile.TemporaryDirectory.cleanup


def _safe_td_cleanup(self):  # type: ignore[no-untyped-def]
    """包装原 cleanup：任何异常静默忽略，避免 Windows 上 DLL 临时目录清理崩溃。"""
    try:
        _orig_td_cleanup(self)
    except Exception:
        pass


tempfile.TemporaryDirectory.cleanup = _safe_td_cleanup  # type: ignore[method-assign]

from mclbn256 import Fr, G1, G2, GT  # noqa: E402

# herumi BN254 群阶（mcl 文档：BN254）
# r = 0x2523648240000001ba344d8000000007ff9f800000000010a10000000000000d
p = int("2523648240000001ba344d8000000007ff9f800000000010a10000000000000d", 16)

# 库内置基点作为 Fig.1 生成元
g1 = G1.base_point()
g2 = G2.base_point()

CURVE_NAME = "bn254-mcl"
BACKEND_NAME = "mclbn256"


def _fr(exp: int) -> Fr:
    """int → Fr：指数按群阶取模；little-endian 32 字节反序列化。"""
    x = int(exp) % p
    return Fr.deserialize(x.to_bytes(32, "little"))


def _fr_to_int(f: Fr) -> int:
    """Fr → 无符号 int（不要用 int(Fr)，库可能按有符号解释）。"""
    return int.from_bytes(f.serialize(), "little") % p


def e(P, Q):
    """Fig.1 配对：e : G1 × G2 → GT。"""
    return P.pairing(Q)


def g1_mul(P, exp: int):
    """G1 标量乘：[exp]P。"""
    return P.mul(_fr(exp))


def g2_mul(Q, exp: int):
    """G2 标量乘：[exp]Q。"""
    return Q.mul(_fr(exp))


def g1_add(P, Q):
    """G1 点加。"""
    return P.add(Q)


def g1_eq(P, Q) -> bool:
    """G1 点相等。"""
    return P.equals(Q)


def gt_mul(a, b):
    """GT 乘法。"""
    return a.mul(b)


def gt_eq(a, b) -> bool:
    """GT 相等。"""
    return a.equals(b)


def gt_pow(a_tilde, exp: int):
    """GT 幂：ã^exp。"""
    return a_tilde.pow(_fr(exp))


def gt_inv_pow(b_tilde, r: int):
    """去盲：b̃^{1/r} = b̃^{r^{-1} mod p}。"""
    inv = pow(int(r) % p, -1, p)
    return gt_pow(b_tilde, inv)


def is_in_g1(P) -> bool:
    """检查 P 是否为合法 G1 点（优先 valid + valid_order）。"""
    try:
        return bool(P.valid()) and bool(P.valid_order())
    except Exception:
        try:
            return bool(P.valid())
        except Exception:
            return False


def is_in_g2(a) -> bool:
    """检查 a 是否为合法非单位元 G2 点。"""
    try:
        if not a.valid():
            return False
        # 拒绝单位元（盲化输入无意义）
        z = G2()
        z.clear()
        if a.equals(z):
            return False
        return bool(a.valid_order()) if hasattr(a, "valid_order") else True
    except Exception:
        return False


def hash_to_g1(msg: bytes):
    """H1 值域：G1.fromhash（mcl hashAndMapTo）。"""
    return G1.fromhash(msg)


def hash_to_g2(msg: bytes):
    """H2 值域：G2.fromhash。"""
    return G2.fromhash(msg)


def g1_to_bytes(P) -> bytes:
    """G1 → mcl 压缩序列化（约 32 字节）。"""
    # mcl 压缩序列化约 32 字节；统一再包一层长度无关的规范哈希可选
    return bytes(P.serialize())


def g1_from_bytes(data: bytes):
    """字节 → G1。"""
    return G1.deserialize(data)


def g2_to_bytes(Q) -> bytes:
    """G2 → mcl serialize。"""
    return bytes(Q.serialize())


def g2_from_bytes(data: bytes):
    """字节 → G2。"""
    return G2.deserialize(data)


def gt_to_bytes(z) -> bytes:
    """GT → mcl serialize。"""
    return bytes(z.serialize())


def gt_from_bytes(data: bytes):
    """字节 → GT。"""
    return GT.deserialize(data)
