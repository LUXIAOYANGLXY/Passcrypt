# -*- coding: utf-8 -*-
"""
crypto_backend/codec.py
=======================
定长群元素线格式校验（Fig.1 群 G = secp256r1）。

Wire / disk（ser_ver = 10）：
  G : 33 字节 —— SEC1 压缩点（0x02/0x03‖x），对齐 PPKR
内存运算仍为非压缩 65 字节；仅 g1_to_bytes / g1_from_bytes 做编解码。

切换曲线或升级 ser_ver 后须清空 data/。
"""

from __future__ import annotations

SER_VER = 10  # v10：ct2 = AES-256-CTR（ct1 仍为 AES-256-GCM）
CURVE_ID = "secp256r1"  # 与后端曲线一致

G_SIZE = 33  # 线格式压缩点长度
G1_SIZE = G_SIZE  # 别名（历史配对后端曾区分 G1）
G2_SIZE = 96  # 配对对照后端用；secp256r1 路径不使用
GT_SIZE = 576  # 配对对照后端用；secp256r1 路径不使用


def assert_g_bytes(data: bytes) -> bytes:
    """校验线格式：必须是 33 字节且前缀为 0x02 或 0x03。"""
    if len(data) != G_SIZE:
        raise ValueError(f"G encoding must be {G_SIZE} bytes, got {len(data)}")
    if data[0] not in (0x02, 0x03):
        raise ValueError("G encoding must be compressed SEC1 (0x02/0x03 prefix)")
    return data


assert_g1_bytes = assert_g_bytes  # 兼容旧调用名


def assert_g2_bytes(data: bytes) -> bytes:
    """配对后端 G2 定长校验（本默认后端不走此路径）。"""
    if len(data) != G2_SIZE:
        raise ValueError(f"G2 encoding must be {G2_SIZE} bytes, got {len(data)}")
    return data


def assert_gt_bytes(data: bytes) -> bytes:
    """配对后端 GT 定长校验（本默认后端不走此路径）。"""
    if len(data) != GT_SIZE:
        raise ValueError(f"GT encoding must be {GT_SIZE} bytes, got {len(data)}")
    return data
