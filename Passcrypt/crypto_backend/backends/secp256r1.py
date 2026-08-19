# -*- coding: utf-8 -*-
"""
crypto_backend/backends/secp256r1.py
====================================
Fig.1 素数阶群 G：secp256r1（NIST P-256），OpenSSL libcrypto 加速。

表示约定：
  - 内存：SEC1 非压缩 65 字节（0x04‖x‖y）——群运算快路径
  - 线/盘：SEC1 压缩 33 字节（0x02/0x03‖x）——仅 g1_to_bytes 出口压缩；
    g1_from_bytes 入口解为非压缩

Hash-to-curve：RFC 9380 P256_XMD:SHA-256_SSWU_RO_（协议 H2 经 ``paee.hashgroup.H2`` → ``hash_to_g1``）。
"""

from __future__ import annotations

from crypto_backend import codec
from crypto_backend.backends.openssl_p256 import (
    P256_ORDER,
    POINT_LEN_UNCOMPRESSED,
    get_p256,
)
from crypto_backend.hash_to_curve_p256 import (
    PAEE_H2_DST,
    hash_to_curve_p256,
    point_to_uncompressed,
)

# 进程内单例 OpenSSL P-256 上下文
_ctx = get_p256()

g1 = _ctx.generator_bytes  # 标准基点（非压缩 65B）
g2 = None  # 本方案无 G2
r = int(_ctx.order)  # 曲线阶
p = r
assert p == P256_ORDER
assert len(g1) == POINT_LEN_UNCOMPRESSED and g1[0] == 0x04

CURVE_NAME = "secp256r1"
BACKEND_NAME = "secp256r1_openssl"
SER_VER = 10  # 与 codec.SER_VER 一致

_DST = PAEE_H2_DST  # H2 域分离字符串


def _as_bytes(P) -> bytes:
    """规范为内存非压缩点；已是 65B/0x04 则零开销返回。"""
    if not isinstance(P, (bytes, bytearray)):
        raise TypeError(f"expected bytes point, got {type(P)}")
    data = bytes(P)
    if len(data) == POINT_LEN_UNCOMPRESSED and data[0] == 0x04:
        return data
    return _ctx.to_uncompressed(data)


def e(P, Q):  # noqa: ARG001
    """配对：secp256r1 方案不使用。"""
    raise NotImplementedError("secp256r1 backend has no pairing")


def g1_mul(P, exp: int):
    """标量乘 P^exp；生成元走更快的 generator_scalarmult。"""
    data = _as_bytes(P)
    e = int(exp) % r
    if e == 0:
        raise ValueError("scalar 0 yields infinity; not encodable")
    if data == g1:
        return _ctx.generator_scalarmult(e)
    return _ctx.scalarmult(data, e)


def g2_mul(Q, exp: int):  # noqa: ARG001
    raise NotImplementedError("secp256r1 has no G2")


def g1_add(P, Q):
    """椭圆曲线点加。"""
    return _ctx.point_add(_as_bytes(P), _as_bytes(Q))


def g1_eq(P, Q) -> bool:
    """字节相等比较（均规范为非压缩后）。"""
    try:
        return _as_bytes(P) == _as_bytes(Q)
    except Exception:
        return False


def gt_mul(a, b):  # noqa: ARG001
    raise NotImplementedError("secp256r1 has no GT")


def gt_eq(a, b) -> bool:  # noqa: ARG001
    raise NotImplementedError("secp256r1 has no GT")


def gt_pow(a_tilde, exp: int):  # noqa: ARG001
    raise NotImplementedError("secp256r1 has no GT")


def gt_inv_pow(b_tilde, exp: int):  # noqa: ARG001
    raise NotImplementedError("secp256r1 has no GT")


def is_in_g1(P) -> bool:
    """OpenSSL 校验点在曲线上。"""
    try:
        _ctx.validate_point(_as_bytes(P))
        return True
    except Exception:
        return False


def is_in_g2(a) -> bool:  # noqa: ARG001
    return False


def hash_to_g1(msg: bytes):
    """
    RFC 9380 hash_to_curve → 非压缩点。
    add_fn 用 OpenSSL 点加合并两次 SSWU 输出。
    """

    def _add(p1: tuple[int, int], p2: tuple[int, int]) -> tuple[int, int]:
        out = _ctx.point_add(point_to_uncompressed(*p1), point_to_uncompressed(*p2))
        # 非压缩：0x04 ‖ x(32) ‖ y(32)
        return int.from_bytes(out[1:33], "big"), int.from_bytes(out[33:65], "big")

    x, y = hash_to_curve_p256(msg, dst=_DST, add_fn=_add)
    return point_to_uncompressed(x, y)


def hash_to_g2(msg: bytes):  # noqa: ARG001
    raise NotImplementedError("secp256r1 has no G2")


def g1_to_bytes(P) -> bytes:
    """内存非压缩 → 线格式压缩 33 字节（供 JSON/TCP）。"""
    return codec.assert_g_bytes(_ctx.to_compressed(_as_bytes(P)))


def g1_from_bytes(data: bytes):
    """线格式压缩 → 内存非压缩 65 字节。"""
    data = codec.assert_g_bytes(data)
    return _ctx.to_uncompressed(data)


def g2_to_bytes(Q):  # noqa: ARG001
    raise NotImplementedError("secp256r1 has no G2")


def g2_from_bytes(data: bytes):  # noqa: ARG001
    raise NotImplementedError("secp256r1 has no G2")


def gt_to_bytes(z):  # noqa: ARG001
    raise NotImplementedError("secp256r1 has no GT")


def gt_from_bytes(data: bytes):  # noqa: ARG001
    raise NotImplementedError("secp256r1 has no GT")
