"""协议载荷规范化序列化 / 反序列化。

对应 Faller 等 (CCS 2024) Fig. 3 (encPw+) 与 Fig. 4 (OPRF-PPKR) 中
跨 HSM / 客户端传输的结构化消息体，统一采用「4 字节大端长度前缀 + 内容」格式。

主要载荷类型：
  encPw+ Init   — pw, K, idc, ssid（Fig. 3 客户端→HSM 初始化）
  encPw+ Rec    — ksym, pw, idc, ssid（Fig. 3 恢复阶段）
  OPRF Init     — ssid, pk_C, AES 密文 c（Fig. 4 初始化）
  OPRF AE 明文  — K, sk_C（Fig. 4 恢复阶段 AES 解密后内容）
  Rec Sign Msg  — a', idc, ssid, b', c（Fig. 4 Schnorr 签名消息）
"""

from __future__ import annotations

import struct

from config import IDC, LAMBDA, SSID
from crypto.aes_gcm import AESCiphertext, deserialize_aes
from crypto.dhies import DHIESCiphertext
from crypto.schnorr import SchnorrPublicKey, SchnorrSecretKey, deserialize_schnorr_sig


# ── 基础类型编解码 ────────────────────────────────────────────────────


def pack_string(s: str) -> bytes:
    """UTF-8 字符串 → 4 字节大端长度 || 内容。"""
    b = s.encode()
    return struct.pack(">I", len(b)) + b


def unpack_string(data: bytes, offset: int = 0) -> tuple[str, int]:
    """从 data[offset:] 解析长度前缀字符串；返回 (字符串, 新偏移)。"""
    length = struct.unpack_from(">I", data, offset)[0]
    offset += 4
    s = data[offset : offset + length].decode()
    return s, offset + length


def pack_bytes(b: bytes) -> bytes:
    """字节串 → 4 字节大端长度 || 内容。"""
    return struct.pack(">I", len(b)) + b


def unpack_bytes(data: bytes, offset: int = 0) -> tuple[bytes, int]:
    """从 data[offset:] 解析长度前缀字节串；返回 (字节串, 新偏移)。"""
    length = struct.unpack_from(">I", data, offset)[0]
    offset += 4
    return data[offset : offset + length], offset + length


# ── Fig. 3 encPw+ 载荷 ────────────────────────────────────────────────


def pack_encpw_init_payload(pw: str, K: bytes, idc: IDC, ssid: SSID) -> bytes:
    """Fig. 3 encPw+ 初始化明文：pw || K || idc || ssid（DHIES 加密前）。"""
    return (
        pack_string(pw)
        + pack_bytes(K)
        + pack_string(idc)
        + pack_string(ssid)
    )


def unpack_encpw_init_payload(data: bytes) -> tuple[str, bytes, str, str]:
    """解析 encPw+ 初始化明文。"""
    offset = 0
    pw, offset = unpack_string(data, offset)
    K, offset = unpack_bytes(data, offset)
    idc, offset = unpack_string(data, offset)
    ssid, offset = unpack_string(data, offset)
    return pw, K, idc, ssid


def pack_encpw_rec_payload(ksym: bytes, pw: str, idc: IDC, ssid: SSID) -> bytes:
    """Fig. 3 encPw+ 恢复阶段明文：ksym || pw || idc || ssid。"""
    return (
        pack_bytes(ksym)
        + pack_string(pw)
        + pack_string(idc)
        + pack_string(ssid)
    )


def unpack_encpw_rec_payload(data: bytes) -> tuple[bytes, str, str, str]:
    """解析 encPw+ 恢复阶段明文。"""
    offset = 0
    ksym, offset = unpack_bytes(data, offset)
    pw, offset = unpack_string(data, offset)
    idc, offset = unpack_string(data, offset)
    ssid, offset = unpack_string(data, offset)
    return ksym, pw, idc, ssid


# ── Fig. 4 OPRF-PPKR 载荷 ─────────────────────────────────────────────


def pack_oprf_ae_plaintext(K: bytes, sk: SchnorrSecretKey) -> bytes:
    """Fig. 4 恢复阶段 AES 明文：K || sk_C.x（32 字节大端）。"""
    return pack_bytes(K) + sk.x.value.to_bytes(32, "big")


def unpack_oprf_ae_plaintext(data: bytes) -> tuple[bytes, SchnorrSecretKey]:
    """解析 OPRF 恢复阶段 AES 明文。"""
    from crypto.group import Scalar

    offset = 0
    K, offset = unpack_bytes(data, offset)
    x = Scalar(int.from_bytes(data[offset : offset + 32], "big"))
    return K, SchnorrSecretKey(x=x)


def pack_oprf_init_payload(ssid: SSID, pk_c: SchnorrPublicKey, c: AESCiphertext) -> bytes:
    """Fig. 4 OPRF 初始化载荷：ssid || pk_C || AES 密文 c。"""
    return pack_string(ssid) + pack_bytes(pk_c.serialize()) + pack_bytes(c.serialize())


def unpack_oprf_init_payload(data: bytes) -> tuple[str, bytes, AESCiphertext]:
    """解析 OPRF 初始化载荷；pk_C 以原始压缩点形式返回。"""
    offset = 0
    ssid, offset = unpack_string(data, offset)
    pk_raw, offset = unpack_bytes(data, offset)
    c_raw, offset = unpack_bytes(data, offset)
    return ssid, pk_raw, deserialize_aes(c_raw)


def pack_rec_sign_message(
    a_prime: bytes, idc: IDC, ssid: SSID, b_prime: bytes, c: AESCiphertext
) -> bytes:
    """Fig. 4 恢复阶段 Schnorr 签名消息：a' || idc || ssid || b' || c。"""
    return (
        pack_bytes(a_prime)
        + pack_string(idc)
        + pack_string(ssid)
        + pack_bytes(b_prime)
        + pack_bytes(c.serialize())
    )


# ── 工具 ──────────────────────────────────────────────────────────────


def random_key() -> bytes:
    """生成 AE 密钥长度的均匀随机对称密钥（AES-256 → 32 字节）。"""
    import os

    from config import AE_KEY_BYTES

    return os.urandom(AE_KEY_BYTES)
