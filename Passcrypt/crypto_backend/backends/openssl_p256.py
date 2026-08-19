# -*- coding: utf-8 -*-
"""
crypto_backend/backends/openssl_p256.py
=======================================
NIST P-256 (secp256r1) 群运算 — 经 ctypes 调用系统 OpenSSL libcrypto。

表示约定（PAEE）：
  - 内存 / 运算结果：SEC1 非压缩 65 字节（EC_POINT_point2oct UNCOMPRESSED）
  - 线格式：to_compressed → 33 字节；读入兼容 33/65

ctypes 注意：
  - 必须设置 restype/argtypes，否则指针被截断为 int 导致崩溃
  - EC_POINT / BIGNUM / BN_CTX 均需成对 free，避免泄漏
  - EC_POINT_mul(group, r, n, q, m, ctx)：
      n≠NULL 且 q=m=NULL → r = n·G（生成元倍点）
      n=NULL 且 q,m≠NULL → r = m·q
"""

from __future__ import annotations

import ctypes
import ctypes.util
import sys
from ctypes import (
    c_char_p,
    c_int,
    c_size_t,
    c_void_p,
    create_string_buffer,
)
from functools import lru_cache

# OpenSSL 曲线名 NID：X9_62_prime256v1 == secp256r1 / NIST P-256
_NID_P256 = 415
# point2oct 转换形式（见 openssl/ec.h）
_POINT_CONVERSION_COMPRESSED = 2  # 0x02/0x03 ‖ x
_POINT_CONVERSION_UNCOMPRESSED = 4  # 0x04 ‖ x ‖ y

POINT_LEN_COMPRESSED = 33
POINT_LEN_UNCOMPRESSED = 65

# 曲线阶 n（与 EC_GROUP_get_order 一致，便于模块级常量断言）
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


class OpenSSLError(RuntimeError):
    """OpenSSL API 返回失败时抛出。"""


def _load_libcrypto() -> ctypes.CDLL:
    """
    按平台尝试加载 libcrypto。
    Windows 常见：libcrypto-3-x64.dll；POSIX：libcrypto.so.3。
    """
    candidates: list[str] = []
    # 系统库搜索路径中的名字
    found = ctypes.util.find_library("crypto") or ctypes.util.find_library("libcrypto")
    if found:
        candidates.append(found)

    if sys.platform == "win32":
        candidates.extend(
            [
                "libcrypto-3-x64",
                "libcrypto-3",
                "libcrypto-1_1-x64",
                "libcrypto-1_1",
                "libcrypto",
                r"C:\Windows\System32\libcrypto.dll",
            ]
        )
    else:
        candidates.extend(["libcrypto.so.3", "libcrypto.so.1.1", "libcrypto.so", "crypto"])

    errors: list[str] = []
    for name in candidates:
        try:
            return ctypes.CDLL(name)  # 成功则返回已加载句柄
        except OSError as e:
            errors.append(f"{name}: {e}")
    raise OpenSSLError(
        "无法加载 OpenSSL libcrypto。请安装 OpenSSL 或确保 libcrypto 在库搜索路径中。\n"
        + "\n".join(errors)
    )


@lru_cache(maxsize=1)
def _lib() -> ctypes.CDLL:
    """
    单例：加载 libcrypto 并为所用符号绑定 C 原型。
    restype=c_void_p 表示返回指针；省略会导致 64 位上高位丢失。
    """
    lib = _load_libcrypto()

    # ---- 曲线群 ----
    # EC_GROUP *EC_GROUP_new_by_curve_name(int nid);
    lib.EC_GROUP_new_by_curve_name.restype = c_void_p
    lib.EC_GROUP_new_by_curve_name.argtypes = [c_int]

    # const EC_POINT *EC_GROUP_get0_generator(const EC_GROUP *group);
    lib.EC_GROUP_get0_generator.restype = c_void_p
    lib.EC_GROUP_get0_generator.argtypes = [c_void_p]

    # int EC_GROUP_get_order(const EC_GROUP *group, BIGNUM *order, BN_CTX *ctx);
    lib.EC_GROUP_get_order.restype = c_int
    lib.EC_GROUP_get_order.argtypes = [c_void_p, c_void_p, c_void_p]

    lib.EC_GROUP_free.restype = None
    lib.EC_GROUP_free.argtypes = [c_void_p]

    # ---- 点对象 ----
    lib.EC_POINT_new.restype = c_void_p
    lib.EC_POINT_new.argtypes = [c_void_p]

    lib.EC_POINT_free.restype = None
    lib.EC_POINT_free.argtypes = [c_void_p]

    # int EC_POINT_mul(const EC_GROUP *, EC_POINT *r, const BIGNUM *n,
    #                  const EC_POINT *q, const BIGNUM *m, BN_CTX *);
    lib.EC_POINT_mul.restype = c_int
    lib.EC_POINT_mul.argtypes = [c_void_p, c_void_p, c_void_p, c_void_p, c_void_p, c_void_p]

    # int EC_POINT_add(const EC_GROUP *, EC_POINT *r, const EC_POINT *a,
    #                  const EC_POINT *b, BN_CTX *);
    lib.EC_POINT_add.restype = c_int
    lib.EC_POINT_add.argtypes = [c_void_p, c_void_p, c_void_p, c_void_p, c_void_p]

    # 字节 ↔ 点（SEC1）
    lib.EC_POINT_oct2point.restype = c_int
    lib.EC_POINT_oct2point.argtypes = [c_void_p, c_void_p, c_char_p, c_size_t, c_void_p]

    lib.EC_POINT_point2oct.restype = c_size_t
    lib.EC_POINT_point2oct.argtypes = [
        c_void_p,  # group
        c_void_p,  # point
        c_int,  # form: COMPRESSED / UNCOMPRESSED
        c_char_p,  # buf
        c_size_t,  # len
        c_void_p,  # BN_CTX
    ]

    lib.EC_POINT_is_on_curve.restype = c_int
    lib.EC_POINT_is_on_curve.argtypes = [c_void_p, c_void_p, c_void_p]

    # int EC_POINT_get_affine_coordinates(group, point, x, y, ctx);
    lib.EC_POINT_get_affine_coordinates.restype = c_int
    lib.EC_POINT_get_affine_coordinates.argtypes = [
        c_void_p,
        c_void_p,
        c_void_p,
        c_void_p,
        c_void_p,
    ]

    # ---- BIGNUM / BN_CTX ----
    lib.BN_new.restype = c_void_p
    lib.BN_new.argtypes = []

    lib.BN_free.restype = None
    lib.BN_free.argtypes = [c_void_p]

    # BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret);
    lib.BN_bin2bn.restype = c_void_p
    lib.BN_bin2bn.argtypes = [c_char_p, c_int, c_void_p]

    # int BN_bn2bin(const BIGNUM *a, unsigned char *to);  // 大端，不含前导零约定
    lib.BN_bn2bin.restype = c_int
    lib.BN_bn2bin.argtypes = [c_void_p, c_char_p]

    lib.BN_num_bits.restype = c_int
    lib.BN_num_bits.argtypes = [c_void_p]

    lib.BN_CTX_new.restype = c_void_p
    lib.BN_CTX_new.argtypes = []

    lib.BN_CTX_free.restype = None
    lib.BN_CTX_free.argtypes = [c_void_p]

    return lib


def _bn_to_int(bn) -> int:
    """OpenSSL BIGNUM* → Python int（大端）。"""
    lib = _lib()
    nbits = lib.BN_num_bits(bn)
    nbytes = (nbits + 7) // 8  # 向上取整到字节
    if nbytes == 0:
        return 0
    buf = create_string_buffer(nbytes)
    written = lib.BN_bn2bin(bn, buf)
    if written <= 0:
        raise OpenSSLError("BN_bn2bin 失败")
    return int.from_bytes(buf.raw[:written], "big")


class _P256Context:
    """
    持有 EC_GROUP* 与 BN_CTX* 的运算上下文。
    进程内通过 get_p256() 单例复用，避免重复建群。
    """

    def __init__(self) -> None:
        lib = _lib()
        # 按 NID 创建 P-256 群参数
        self.group = lib.EC_GROUP_new_by_curve_name(_NID_P256)
        if not self.group:
            raise OpenSSLError("EC_GROUP_new_by_curve_name(P-256) 失败")
        self.bn_ctx = lib.BN_CTX_new()  # 点运算临时大整数栈
        if not self.bn_ctx:
            raise OpenSSLError("BN_CTX_new 失败")

        # 读出曲线阶 → self.order
        order_bn = lib.BN_new()
        if not order_bn:
            raise OpenSSLError("BN_new 失败")
        try:
            if lib.EC_GROUP_get_order(self.group, order_bn, self.bn_ctx) != 1:
                raise OpenSSLError("EC_GROUP_get_order 失败")
            self.order = _bn_to_int(order_bn)
        finally:
            lib.BN_free(order_bn)

        # 标准生成元 → 非压缩字节（内存表示）
        gen = lib.EC_GROUP_get0_generator(self.group)  # 归属 group，勿 free
        if not gen:
            raise OpenSSLError("EC_GROUP_get0_generator 失败")
        self.generator_bytes = self._point_to_bytes(gen)

    def _point_to_bytes(self, point: int) -> bytes:
        """EC_POINT* → SEC1 非压缩 65B（运算结果默认形态）。"""
        lib = _lib()
        out = create_string_buffer(POINT_LEN_UNCOMPRESSED)
        n = lib.EC_POINT_point2oct(
            self.group,
            point,
            _POINT_CONVERSION_UNCOMPRESSED,
            out,
            POINT_LEN_UNCOMPRESSED,
            self.bn_ctx,
        )
        # 无穷远点无法编码为有限 SEC1，n 会失败
        if n != POINT_LEN_UNCOMPRESSED:
            raise OpenSSLError("EC_POINT_point2oct(uncompressed) 失败（可能为无穷远点）")
        return bytes(out.raw)

    def _point_to_compressed_bytes(self, point: int) -> bytes:
        """EC_POINT* → SEC1 压缩 33B（仅线格式出口使用）。"""
        lib = _lib()
        out = create_string_buffer(POINT_LEN_COMPRESSED)
        n = lib.EC_POINT_point2oct(
            self.group,
            point,
            _POINT_CONVERSION_COMPRESSED,
            out,
            POINT_LEN_COMPRESSED,
            self.bn_ctx,
        )
        if n != POINT_LEN_COMPRESSED:
            raise OpenSSLError("EC_POINT_point2oct(compressed) 失败（可能为无穷远点）")
        return bytes(out.raw)

    def _bytes_to_point(self, data: bytes):
        """
        SEC1 字节 → 堆上 EC_POINT*（调用方必须 EC_POINT_free）。
        压缩输入会在库内恢复 y（含模平方根，相对非压缩更慢）。
        """
        lib = _lib()
        if len(data) == POINT_LEN_COMPRESSED and data[0] in (0x02, 0x03):
            pass
        elif len(data) == POINT_LEN_UNCOMPRESSED and data[0] == 0x04:
            pass
        else:
            raise ValueError(
                "expected SEC1 P-256 point: compressed 33B (02/03) or uncompressed 65B (04)"
            )
        point = lib.EC_POINT_new(self.group)
        if not point:
            raise OpenSSLError("EC_POINT_new 失败")
        ok = lib.EC_POINT_oct2point(self.group, point, data, len(data), self.bn_ctx)
        if ok != 1:
            lib.EC_POINT_free(point)
            raise ValueError("invalid P-256 point encoding")
        if lib.EC_POINT_is_on_curve(self.group, point, self.bn_ctx) != 1:
            lib.EC_POINT_free(point)
            raise ValueError("point not on P-256 curve")
        return point

    def affine_coords(self, data: bytes) -> tuple[int, int]:
        """点字节 → 仿射 (x, y)，供 hash-to-curve 内部点加拼坐标。"""
        lib = _lib()
        point = self._bytes_to_point(data)
        x_bn = lib.BN_new()
        y_bn = lib.BN_new()
        try:
            if not x_bn or not y_bn:
                raise OpenSSLError("BN_new 失败")
            if (
                lib.EC_POINT_get_affine_coordinates(
                    self.group, point, x_bn, y_bn, self.bn_ctx
                )
                != 1
            ):
                raise OpenSSLError("EC_POINT_get_affine_coordinates 失败")
            return _bn_to_int(x_bn), _bn_to_int(y_bn)
        finally:
            if x_bn:
                lib.BN_free(x_bn)
            if y_bn:
                lib.BN_free(y_bn)
            lib.EC_POINT_free(point)

    def _int_to_bn(self, value: int):
        """Python int → BIGNUM*（模阶后固定 32 字节大端）；调用方 BN_free。"""
        lib = _lib()
        raw = (value % self.order).to_bytes(32, "big")
        bn = lib.BN_bin2bn(raw, 32, None)  # None → 新建 BIGNUM
        if not bn:
            raise OpenSSLError("BN_bin2bn 失败")
        return bn

    def scalarmult(self, point_bytes: bytes, scalar: int) -> bytes:
        """r = scalar · P；返回非压缩点字节。"""
        lib = _lib()
        point = self._bytes_to_point(point_bytes)
        result = lib.EC_POINT_new(self.group)
        bn = self._int_to_bn(scalar)
        try:
            if not result:
                raise OpenSSLError("EC_POINT_new 失败")
            # n=NULL → 不用生成元项；r = m·q
            if lib.EC_POINT_mul(self.group, result, None, point, bn, self.bn_ctx) != 1:
                raise OpenSSLError("EC_POINT_mul 失败")
            return self._point_to_bytes(result)
        finally:
            lib.BN_free(bn)
            lib.EC_POINT_free(point)
            if result:
                lib.EC_POINT_free(result)

    def generator_scalarmult(self, scalar: int) -> bytes:
        """r = scalar · G（生成元倍点，OpenSSL 可走预计算表）。"""
        lib = _lib()
        result = lib.EC_POINT_new(self.group)
        bn = self._int_to_bn(scalar)
        try:
            if not result:
                raise OpenSSLError("EC_POINT_new 失败")
            # q=m=NULL → 仅 n·G
            if lib.EC_POINT_mul(self.group, result, bn, None, None, self.bn_ctx) != 1:
                raise OpenSSLError("EC_POINT_mul(generator) 失败")
            return self._point_to_bytes(result)
        finally:
            lib.BN_free(bn)
            if result:
                lib.EC_POINT_free(result)

    def point_add(self, a_bytes: bytes, b_bytes: bytes) -> bytes:
        """r = a + b（椭圆曲线点加）。"""
        lib = _lib()
        a = self._bytes_to_point(a_bytes)
        b = self._bytes_to_point(b_bytes)
        result = lib.EC_POINT_new(self.group)
        try:
            if not result:
                raise OpenSSLError("EC_POINT_new 失败")
            if lib.EC_POINT_add(self.group, result, a, b, self.bn_ctx) != 1:
                raise OpenSSLError("EC_POINT_add 失败")
            return self._point_to_bytes(result)
        finally:
            lib.EC_POINT_free(a)
            lib.EC_POINT_free(b)
            if result:
                lib.EC_POINT_free(result)

    def to_uncompressed(self, data: bytes) -> bytes:
        """任意合法 SEC1 → 内存非压缩 65B（已是则校验后原样返回）。"""
        if len(data) == POINT_LEN_UNCOMPRESSED and data[0] == 0x04:
            self.validate_point(data)
            return data
        lib = _lib()
        point = self._bytes_to_point(data)
        try:
            return self._point_to_bytes(point)
        finally:
            lib.EC_POINT_free(point)

    def to_compressed(self, data: bytes) -> bytes:
        """任意合法 SEC1 → 线格式压缩 33B。"""
        if len(data) == POINT_LEN_COMPRESSED and data[0] in (0x02, 0x03):
            self.validate_point(data)
            return data
        lib = _lib()
        point = self._bytes_to_point(data)
        try:
            return self._point_to_compressed_bytes(point)
        finally:
            lib.EC_POINT_free(point)

    def canonicalize_point(self, data: bytes) -> bytes:
        """旧名兼容：等同 to_uncompressed。"""
        return self.to_uncompressed(data)

    def validate_point(self, data: bytes) -> None:
        """校验点编码合法且在曲线上；非法抛 ValueError。"""
        point = self._bytes_to_point(data)
        _lib().EC_POINT_free(point)


@lru_cache(maxsize=1)
def get_p256() -> _P256Context:
    """返回进程内全局 P-256 OpenSSL 上下文。"""
    return _P256Context()
