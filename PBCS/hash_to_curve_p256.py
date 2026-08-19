"""RFC 9380 hash_to_curve：NIST P-256 (P256_XMD:SHA-256_SSWU_RO_)。

供 PBCS IB-OPRF 的 H1（口令 → 曲线点）使用。
"""

from __future__ import annotations

import hashlib
from typing import Callable

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
Z = P - 10
C2_SQRT_NEG_Z = pow(10, (P + 1) // 4, P)
assert pow(C2_SQRT_NEG_Z, 2, P) == 10

PBCS_H1_DST = b"PBCS-H1-v1-P256_XMD:SHA-256_SSWU_RO_"
RFC9380_TEST_DST = b"QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_"

L = 48


def _mod(x: int) -> int:
    return x % P


def _cmov(a: int, b: int, cond: bool) -> int:
    return b if cond else a


def _sgn0(x: int) -> int:
    return x & 1


def _expand_message_xmd(msg: bytes, dst: bytes, len_in_bytes: int) -> bytes:
    b_in_bytes = 32
    s_in_bytes = 64
    if len(dst) >= 256 or len_in_bytes > 65535:
        raise ValueError("invalid expand_message_xmd parameters")
    ell = (len_in_bytes + b_in_bytes - 1) // b_in_bytes
    if ell > 255:
        raise ValueError("len_in_bytes too large")
    dst_prime = dst + bytes([len(dst)])
    z_pad = b"\x00" * s_in_bytes
    msg_prime = z_pad + msg + len_in_bytes.to_bytes(2, "big") + b"\x00" + dst_prime
    b0 = hashlib.sha256(msg_prime).digest()
    b1 = hashlib.sha256(b0 + b"\x01" + dst_prime).digest()
    blocks = [b1]
    for i in range(2, ell + 1):
        bi = hashlib.sha256(
            bytes(a ^ b for a, b in zip(b0, blocks[-1])) + bytes([i]) + dst_prime
        ).digest()
        blocks.append(bi)
    return b"".join(blocks)[:len_in_bytes]


def _hash_to_field(msg: bytes, count: int, dst: bytes) -> list[int]:
    uniform = _expand_message_xmd(msg, dst, count * L)
    return [int.from_bytes(uniform[i * L : (i + 1) * L], "big") % P for i in range(count)]


def _sqrt_ratio_3mod4(u: int, v: int) -> tuple[bool, int]:
    tv1 = _mod(v * v)
    tv2 = _mod(u * v)
    tv1 = _mod(tv1 * tv2)
    y1 = _mod(pow(tv1, (P - 3) // 4, P) * tv2)
    y2 = _mod(y1 * C2_SQRT_NEG_Z)
    tv3 = _mod(_mod(y1 * y1) * v)
    is_qr = tv3 == u % P
    y = _cmov(y2, y1, is_qr)
    return is_qr, y


def _map_to_curve_simple_swu(u: int) -> tuple[int, int]:
    u = u % P
    tv1 = _mod(Z * _mod(u * u))
    tv2 = _mod(_mod(tv1 * tv1) + tv1)
    tv3 = _mod(B * _mod(tv2 + 1))
    tv4 = _mod(A * _cmov(Z, _mod(P - tv2), tv2 != 0))
    tv2 = _mod(tv3 * tv3)
    tv6 = _mod(tv4 * tv4)
    tv5 = _mod(A * tv6)
    tv2 = _mod(_mod(tv2 + tv5) * tv3)
    tv6 = _mod(tv6 * tv4)
    tv2 = _mod(tv2 + _mod(B * tv6))
    x = _mod(tv1 * tv3)
    is_gx1_square, y1 = _sqrt_ratio_3mod4(tv2, tv6)
    y = _mod(_mod(tv1 * u) * y1)
    x = _cmov(x, tv3, is_gx1_square)
    y = _cmov(y, y1, is_gx1_square)
    e1 = _sgn0(u) == _sgn0(y)
    y = _cmov(_mod(P - y), y, e1)
    x = _mod(x * pow(tv4, P - 2, P))
    return x, y


def _point_add(
    p1: tuple[int, int],
    p2: tuple[int, int],
    add_fn: Callable | None = None,
) -> tuple[int, int]:
    if add_fn is not None:
        return add_fn(p1, p2)
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and y1 == y2:
        lam = _mod((3 * x1 * x1 + A) * pow(_mod(2 * y1), P - 2, P))
    else:
        lam = _mod((y2 - y1) * pow(_mod(x2 - x1), P - 2, P))
    x3 = _mod(lam * lam - x1 - x2)
    y3 = _mod(lam * _mod(x1 - x3) - y1)
    return x3, y3


def hash_to_curve_p256(
    msg: bytes,
    dst: bytes = PBCS_H1_DST,
    add_fn: Callable | None = None,
) -> tuple[int, int]:
    u = _hash_to_field(msg, 2, dst)
    return _point_add(
        _map_to_curve_simple_swu(u[0]),
        _map_to_curve_simple_swu(u[1]),
        add_fn,
    )
