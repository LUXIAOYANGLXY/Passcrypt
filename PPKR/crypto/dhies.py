"""DHIES IND-CCA 公钥加密。

对应 Faller 等 (CCS 2024) Table 4 中 CCA Enc (DHIES)：
  KeyGen 1 Exp；Enc 2 Exp + 3 Hash + 1 AE；Dec 1 Exp + 3 Hash + 1 AE。
Fig. 3 encPw+ 协议用 DHIES 保护客户端→HSM 的初始化/恢复载荷。

线格式 (DHIESCiphertext.raw)：
  len(eph) || ephemeral_pk || AES-GCM 密文
  其中 ephemeral_pk 为 33 字节 SEC1 压缩 P-256 点；
  AES-GCM 部分见 aes_gcm 模块。临时公钥作为 GCM AAD 绑定，防篡改/重放。

安全注记：仅使用 AES-256-GCM，无外层 HMAC；IND-CCA 依赖 ECDH + KDF + AEAD 组合。
"""

from __future__ import annotations

from dataclasses import dataclass

from config import AE_KEY_BYTES, CostCounter
from crypto.aes_gcm import AESGCMCipher, AESCiphertext, MIN_AES_SERIALIZED, deserialize_aes
from crypto.elgamal import ElGamal
from crypto.group import GROUP, GroupElement, Scalar
from crypto.kdf import HKDF
from crypto.openssl_p256 import POINT_LEN_COMPRESSED, POINT_LEN_UNCOMPRESSED


# ── 密钥与密文类型 ────────────────────────────────────────────────────


@dataclass(frozen=True)
class DHIESPublicKey:
    """DHIES 公钥 y = g^x。"""

    y: GroupElement

    def serialize(self) -> bytes:
        """返回 33 字节 SEC1 压缩公钥。"""
        return self.y.serialize()


@dataclass(frozen=True)
class DHIESSecretKey:
    """DHIES 私钥 x。"""

    x: Scalar


@dataclass(frozen=True)
class DHIESCiphertext:
    """DHIES 密文容器；raw 字段为完整线格式字节串。"""

    raw: bytes

    def serialize(self) -> bytes:
        """返回完整 DHIES 线格式密文。"""
        return self.raw


# ── DHIES 加解密 ──────────────────────────────────────────────────────


class DHIES:
    """DHIES 封装：密钥生成委托 ElGamal，对称层为 AES-256-GCM + HKDF 派生密钥。"""

    _EPH_POINT_LEN = POINT_LEN_COMPRESSED  # SEC1 压缩 P-256
    _MIN_RAW_LEN = 1 + _EPH_POINT_LEN + MIN_AES_SERIALIZED

    def __init__(self) -> None:
        self._hkdf = HKDF()
        self._aes = AESGCMCipher()
        self._elgamal = ElGamal()

    def keygen(self) -> tuple[DHIESPublicKey, DHIESSecretKey, CostCounter]:
        """生成 (pk, sk)；Table 4 计 1 Exp。"""
        pk, sk, cost = self._elgamal.keygen()
        return DHIESPublicKey(y=pk.y), DHIESSecretKey(x=sk.x), cost

    def _derive_key(self, shared: bytes) -> tuple[bytes, CostCounter]:
        """从 ECDH 共享秘密派生 AES-256 密钥；Table 4 抽象为 3 Hash。"""
        key, _ = self._hkdf.derive(shared, b"dhies", b"enc", AE_KEY_BYTES)
        return key, CostCounter(hash=3)

    def enc(self, pk: DHIESPublicKey, plaintext: bytes) -> tuple[DHIESCiphertext, CostCounter]:
        """加密：临时 ECDH + KDF + AES-GCM；AAD = 临时公钥字节。"""
        # 1. 采样临时标量 r，计算 R = g^r 与共享秘密 y^r
        r = GROUP.random_scalar()
        ephemeral, c_eph = GROUP.exp(GROUP.g, r)  # R = g^r
        shared, c_shared = GROUP.exp(pk.y, r)     # y^r = (g^x)^r
        # 2. HKDF 派生 AES 密钥；GCM 以 R 为 AAD 绑定临时公钥，防替换 R 攻击
        enc_key, kdf_cost = self._derive_key(shared.serialize())
        eph = ephemeral.serialize()
        aes_ct, c_aes = self._aes.enc(enc_key, plaintext, aad=eph)
        # 线格式：1 字节 eph 长度 + eph + AES-GCM 序列化
        raw = bytes([len(eph)]) + eph + aes_ct.serialize()
        return DHIESCiphertext(raw=raw), c_eph + c_shared + kdf_cost + c_aes

    def dec(self, sk: DHIESSecretKey, ct: DHIESCiphertext) -> tuple[bytes | None, CostCounter]:
        """解密：解析线格式、恢复共享秘密、验证 GCM；失败返回 (None, cost)。"""
        raw = ct.raw
        if len(raw) < self._MIN_RAW_LEN:
            return None, CostCounter()

        try:
            # 1. 解析线格式：len || R || AES-GCM 密文
            eph_len = raw[0]
            # 新编码 33B；兼容旧非压缩 65B
            if eph_len not in (POINT_LEN_COMPRESSED, POINT_LEN_UNCOMPRESSED):
                return None, CostCounter()

            eph_end = 1 + eph_len
            eph_bytes = raw[1:eph_end]
            aes_data = raw[eph_end:]
            if len(aes_data) < MIN_AES_SERIALIZED:
                return None, CostCounter()

            ephemeral = GROUP.deserialize_point(eph_bytes)
            aes_ct = deserialize_aes(aes_data)
        except (ValueError, AssertionError, IndexError):
            return None, CostCounter()

        # 2. 恢复共享秘密 R^x，派生密钥并验证 GCM（AAD = R）
        shared, c_shared = GROUP.exp(ephemeral, sk.x)  # R^x = (g^r)^x
        enc_key, kdf_cost = self._derive_key(shared.serialize())
        pt, c_aes = self._aes.dec(enc_key, aes_ct, aad=eph_bytes)
        if pt is None:
            return None, c_shared + kdf_cost + c_aes  # GCM 验证失败，静默拒绝
        return pt, c_shared + kdf_cost + c_aes
