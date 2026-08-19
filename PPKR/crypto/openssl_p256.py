"""NIST P-256 (secp256r1) 群运算 — OpenSSL libcrypto 后端。

通过 ctypes 调用系统 OpenSSL 的 EC_POINT_mul / EC_POINT_add 等接口，
供 ``crypto.group.GroupContext`` 使用。协议线格式为 SEC1 **压缩点**
（0x02/0x03 || x，33 字节）；读入仍兼容旧非压缩 65 字节。
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

# OpenSSL NID_X9_62_prime256v1 == secp256r1 / NIST P-256
_NID_P256 = 415
_POINT_CONVERSION_COMPRESSED = 2

POINT_LEN_COMPRESSED = 33
POINT_LEN_UNCOMPRESSED = 65

# NIST P-256 曲线阶（与 OpenSSL EC_GROUP_get_order 一致，便于无上下文常量使用）
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


class OpenSSLError(RuntimeError):
    """OpenSSL 群运算失败。"""


def _load_libcrypto() -> ctypes.CDLL:
    """加载 libcrypto；Windows / Linux / macOS 常见名称均尝试。"""
    candidates: list[str] = []
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
            return ctypes.CDLL(name)
        except OSError as e:
            errors.append(f"{name}: {e}")
    raise OpenSSLError(
        "无法加载 OpenSSL libcrypto。请安装 OpenSSL 或确保 libcrypto 在库搜索路径中。\n"
        + "\n".join(errors)
    )


@lru_cache(maxsize=1)
def _lib() -> ctypes.CDLL:
    """缓存已绑定函数原型的 libcrypto 句柄。"""
    lib = _load_libcrypto()

    lib.EC_GROUP_new_by_curve_name.restype = c_void_p
    lib.EC_GROUP_new_by_curve_name.argtypes = [c_int]

    lib.EC_GROUP_get0_generator.restype = c_void_p
    lib.EC_GROUP_get0_generator.argtypes = [c_void_p]

    lib.EC_GROUP_get_order.restype = c_int
    lib.EC_GROUP_get_order.argtypes = [c_void_p, c_void_p, c_void_p]

    lib.EC_GROUP_free.restype = None
    lib.EC_GROUP_free.argtypes = [c_void_p]

    lib.EC_POINT_new.restype = c_void_p
    lib.EC_POINT_new.argtypes = [c_void_p]

    lib.EC_POINT_free.restype = None
    lib.EC_POINT_free.argtypes = [c_void_p]

    lib.EC_POINT_mul.restype = c_int
    lib.EC_POINT_mul.argtypes = [c_void_p, c_void_p, c_void_p, c_void_p, c_void_p, c_void_p]

    lib.EC_POINT_add.restype = c_int
    lib.EC_POINT_add.argtypes = [c_void_p, c_void_p, c_void_p, c_void_p, c_void_p]

    lib.EC_POINT_oct2point.restype = c_int
    lib.EC_POINT_oct2point.argtypes = [c_void_p, c_void_p, c_char_p, c_size_t, c_void_p]

    lib.EC_POINT_point2oct.restype = c_size_t
    lib.EC_POINT_point2oct.argtypes = [
        c_void_p,
        c_void_p,
        c_int,
        c_char_p,
        c_size_t,
        c_void_p,
    ]

    lib.EC_POINT_is_on_curve.restype = c_int
    lib.EC_POINT_is_on_curve.argtypes = [c_void_p, c_void_p, c_void_p]

    lib.EC_POINT_get_affine_coordinates.restype = c_int
    lib.EC_POINT_get_affine_coordinates.argtypes = [
        c_void_p,
        c_void_p,
        c_void_p,
        c_void_p,
        c_void_p,
    ]

    lib.BN_new.restype = c_void_p
    lib.BN_new.argtypes = []

    lib.BN_free.restype = None
    lib.BN_free.argtypes = [c_void_p]

    lib.BN_bin2bn.restype = c_void_p
    lib.BN_bin2bn.argtypes = [c_char_p, c_int, c_void_p]

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
    lib = _lib()
    nbits = lib.BN_num_bits(bn)
    nbytes = (nbits + 7) // 8
    if nbytes == 0:
        return 0
    buf = create_string_buffer(nbytes)
    written = lib.BN_bn2bin(bn, buf)
    if written <= 0:
        raise OpenSSLError("BN_bn2bin 失败")
    return int.from_bytes(buf.raw[:written], "big")


class _P256Context:
    """持有 EC_GROUP / BN_CTX 的 P-256 运算上下文。"""

    def __init__(self) -> None:
        lib = _lib()
        self.group = lib.EC_GROUP_new_by_curve_name(_NID_P256)
        if not self.group:
            raise OpenSSLError("EC_GROUP_new_by_curve_name(P-256) 失败")
        self.bn_ctx = lib.BN_CTX_new()
        if not self.bn_ctx:
            raise OpenSSLError("BN_CTX_new 失败")

        order_bn = lib.BN_new()
        if not order_bn:
            raise OpenSSLError("BN_new 失败")
        try:
            if lib.EC_GROUP_get_order(self.group, order_bn, self.bn_ctx) != 1:
                raise OpenSSLError("EC_GROUP_get_order 失败")
            self.order = _bn_to_int(order_bn)
        finally:
            lib.BN_free(order_bn)

        gen = lib.EC_GROUP_get0_generator(self.group)
        if not gen:
            raise OpenSSLError("EC_GROUP_get0_generator 失败")
        self.generator_bytes = self._point_to_bytes(gen)

    def _point_to_bytes(self, point: int) -> bytes:
        """EC_POINT → SEC1 压缩点（33 字节）。"""
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
        """SEC1 压缩(33)或非压缩(65)点 → OpenSSL EC_POINT。"""
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
        """点字节 → 仿射坐标 (x, y)。"""
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
        lib = _lib()
        raw = (value % self.order).to_bytes(32, "big")
        bn = lib.BN_bin2bn(raw, 32, None)
        if not bn:
            raise OpenSSLError("BN_bin2bn 失败")
        return bn

    def scalarmult(self, point_bytes: bytes, scalar: int) -> bytes:
        """计算 scalar * Point（OpenSSL EC_POINT_mul）。"""
        lib = _lib()
        point = self._bytes_to_point(point_bytes)
        result = lib.EC_POINT_new(self.group)
        bn = self._int_to_bn(scalar)
        try:
            if not result:
                raise OpenSSLError("EC_POINT_new 失败")
            if lib.EC_POINT_mul(self.group, result, None, point, bn, self.bn_ctx) != 1:
                raise OpenSSLError("EC_POINT_mul 失败")
            return self._point_to_bytes(result)
        finally:
            lib.BN_free(bn)
            lib.EC_POINT_free(point)
            if result:
                lib.EC_POINT_free(result)

    def generator_scalarmult(self, scalar: int) -> bytes:
        """计算 scalar * G。"""
        lib = _lib()
        result = lib.EC_POINT_new(self.group)
        bn = self._int_to_bn(scalar)
        try:
            if not result:
                raise OpenSSLError("EC_POINT_new 失败")
            if lib.EC_POINT_mul(self.group, result, bn, None, None, self.bn_ctx) != 1:
                raise OpenSSLError("EC_POINT_mul(generator) 失败")
            return self._point_to_bytes(result)
        finally:
            lib.BN_free(bn)
            if result:
                lib.EC_POINT_free(result)

    def point_add(self, a_bytes: bytes, b_bytes: bytes) -> bytes:
        """点加 a + b。"""
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

    def canonicalize_point(self, data: bytes) -> bytes:
        """任意合法 SEC1 点 → 压缩 33 字节（统一线格式）。"""
        lib = _lib()
        point = self._bytes_to_point(data)
        try:
            return self._point_to_bytes(point)
        finally:
            lib.EC_POINT_free(point)

    def validate_point(self, data: bytes) -> None:
        """校验 SEC1 点在曲线上（压缩或非压缩）。"""
        point = self._bytes_to_point(data)
        _lib().EC_POINT_free(point)


@lru_cache(maxsize=1)
def get_p256() -> _P256Context:
    """返回全局 P-256 OpenSSL 上下文。"""
    return _P256Context()
