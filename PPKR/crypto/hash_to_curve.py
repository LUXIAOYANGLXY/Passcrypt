"""RFC 9380 hash_to_curve：NIST P-256 (P256_XMD:SHA-256_SSWU_RO_)。

对应 Faller 等 (CCS 2024) Fig. 4 中 OPRF 盲化基 H1(pw||IDC) 的底层映射：
将任意字节串可证明地映射到 P-256 曲线点，供 RandomOracleH1 / GroupContext.hash_to_group 调用。

算法概要 (RFC 9380 §6.6.2)：
  1. expand_message_xmd — 将消息扩展为均匀域元素字节
  2. hash_to_field       — 解析为两个域元素 u₀, u₁
  3. map_to_curve_simple_swu — SSWU 映射各得候选点 Q₀, Q₁
  4. 椭圆曲线点加         — Q₀ + Q₁ 得最终输出点

安全注记：使用域分离字符串 (DST) 防止跨协议/跨用途哈希碰撞；
P-256 余因子为 1，无需额外清余因子步骤。
"""

from __future__ import annotations

import hashlib
from typing import Callable

# ── P-256 曲线常量 (short Weierstrass: y² = x³ + Ax + B) ─────────────
# 以下常量与 RFC 9380 / NIST SP 800-186 一致，用于 SSWU 映射

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3  # P-256 标准参数 a = -3 mod p
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
Z = P - 10  # SSWU 辅助常数：-10 mod p（RFC 9380 推荐）
C2_SQRT_NEG_Z = pow(10, (P + 1) // 4, P)  # sqrt(-Z) = sqrt(10) mod p（p≡3 mod 4）
assert pow(C2_SQRT_NEG_Z, 2, P) == 10

# OPRF H1 专用 DST；RFC 9380 附录测试向量用 DST
PPKR_H1_DST = b"PPKR-OPRF-H1-v1-P256_XMD:SHA-256_SSWU_RO_"
RFC9380_TEST_DST = b"QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_"

L = 48  # 每个域元素占 48 字节 (128-bit 安全级别，ceil((ceil(log2(p))+k)/8))
K = 128  # expand_message 安全参数（比特）


def _mod(x: int) -> int:
    """域元素归约 mod p。"""
    return x % P


def _cmov(a: int, b: int, cond: bool) -> int:
    """常量时间条件选择：cond 为真返回 b，否则返回 a。"""
    return b if cond else a


def _sgn0(x: int) -> int:
    """RFC 9380 sgn0：返回 x 的最低有效位。"""
    return x & 1


def _expand_message_xmd(msg: bytes, dst: bytes, len_in_bytes: int) -> bytes:
    """RFC 9380 §5.3.1 expand_message_xmd (SHA-256)。

    将 msg 扩展为 len_in_bytes 字节均匀伪随机串，供 hash_to_field 使用。
    """
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
    # 迭代生成 b2..b_ell，XOR 链保证扩展字节伪随机
    for i in range(2, ell + 1):
        bi = hashlib.sha256(bytes(a ^ b for a, b in zip(b0, blocks[-1])) + bytes([i]) + dst_prime).digest()
        blocks.append(bi)
    uniform_bytes = b"".join(blocks)
    return uniform_bytes[:len_in_bytes]


def _hash_to_field(msg: bytes, count: int, dst: bytes) -> list[int]:
    """RFC 9380 §5.2 hash_to_field：将消息映射为 count 个域元素。"""
    len_in_bytes = count * L
    uniform = _expand_message_xmd(msg, dst, len_in_bytes)
    out: list[int] = []
    for i in range(count):
        chunk = uniform[i * L : (i + 1) * L]
        out.append(int.from_bytes(chunk, "big") % P)
    return out


def _sqrt_ratio_3mod4(u: int, v: int) -> tuple[bool, int]:
    """RFC 9380 §4.6.2 sqrt_ratio_3mod4：判定 u/v 是否为二次剩余并求平方根。

    P-256 素域满足 p ≡ 3 (mod 4)，可使用快速平方根算法。
    """
    tv1 = _mod(v * v)
    tv2 = _mod(u * v)
    tv1 = _mod(tv1 * tv2)
    c1 = (P - 3) // 4
    y1 = pow(tv1, c1, P)
    y1 = _mod(y1 * tv2)
    y2 = _mod(y1 * C2_SQRT_NEG_Z)
    tv3 = _mod(y1 * y1)
    tv3 = _mod(tv3 * v)
    is_qr = tv3 == u % P
    y = _cmov(y2, y1, is_qr)
    return is_qr, y


def _map_to_curve_simple_swu(u: int) -> tuple[int, int]:
    """RFC 9380 §6.6.2 map_to_curve_simple_swu：单域元素 → 曲线点 (x, y)。"""
    u = u % P
    tv1 = _mod(u * u)
    tv1 = _mod(Z * tv1)
    tv2 = _mod(tv1 * tv1)
    tv2 = _mod(tv2 + tv1)
    tv3 = _mod(tv2 + 1)
    tv3 = _mod(B * tv3)
    tv4 = _cmov(Z, _mod(P - tv2), tv2 != 0)
    tv4 = _mod(A * tv4)
    tv2 = _mod(tv3 * tv3)
    tv6 = _mod(tv4 * tv4)
    tv5 = _mod(A * tv6)
    tv2 = _mod(tv2 + tv5)
    tv2 = _mod(tv2 * tv3)
    tv6 = _mod(tv6 * tv4)
    tv5 = _mod(B * tv6)
    tv2 = _mod(tv2 + tv5)
    x = _mod(tv1 * tv3)
    is_gx1_square, y1 = _sqrt_ratio_3mod4(tv2, tv6)
    y = _mod(tv1 * u)
    y = _mod(y * y1)
    x = _cmov(x, tv3, is_gx1_square)
    y = _cmov(y, y1, is_gx1_square)
    e1 = _sgn0(u) == _sgn0(y)
    y = _cmov(_mod(P - y), y, e1)
    inv_tv4 = pow(tv4, P - 2, P)
    x = _mod(x * inv_tv4)
    return x, y


def _point_add(
    p1: tuple[int, int],
    p2: tuple[int, int],
    add_fn: Callable[[tuple[int, int], tuple[int, int]], tuple[int, int]] | None = None,
) -> tuple[int, int]:
    """椭圆曲线点加 P₁ + P₂。

    若提供 add_fn（如 GroupContext.mult 桥接），则委托外部群运算以计入 Table 4 Mult 成本。
    """
    if add_fn is not None:
        return add_fn(p1, p2)
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and y1 == y2:
        lam = _mod(3 * x1 * x1 + A)
        lam = _mod(lam * pow(_mod(2 * y1), P - 2, P))
    else:
        lam = _mod((y2 - y1) * pow(_mod(x2 - x1), P - 2, P))
    x3 = _mod(lam * lam - x1 - x2)
    y3 = _mod(lam * _mod(x1 - x3) - y1)
    return x3, y3


def hash_to_curve_p256(
    msg: bytes,
    dst: bytes = PPKR_H1_DST,
    add_fn: Callable[[tuple[int, int], tuple[int, int]], tuple[int, int]] | None = None,
) -> tuple[int, int]:
    """RFC 9380 §3 hash_to_curve (random oracle 模式)；P-256 余因子为 1。

    流程：hash_to_field → 两次 SSWU 映射 → 点加合并。
    """
    # 1. 消息 → 两个域元素 u₀, u₁
    u = _hash_to_field(msg, 2, dst)
    # 2. 各自 SSWU 映射为曲线点 Q₀, Q₁
    q0 = _map_to_curve_simple_swu(u[0])
    q1 = _map_to_curve_simple_swu(u[1])
    # 3. Q₀ + Q₁ 得最终输出（余因子 h=1，无需 clear cofactor）
    return _point_add(q0, q1, add_fn)


def point_to_uncompressed(x: int, y: int) -> bytes:
    """曲线坐标 → SEC1 非压缩点编码 (0x04 || x || y，各 32 字节)。"""
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def point_to_compressed(x: int, y: int) -> bytes:
    """曲线坐标 → SEC1 压缩点编码 (0x02/0x03 || x，33 字节)。"""
    return bytes([0x02 | (y & 1)]) + x.to_bytes(32, "big")
