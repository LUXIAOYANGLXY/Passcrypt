# -*- coding: utf-8 -*-
"""secp256r1 曲线辅助：H1 / H2 / H3 实例化。

  H1 : RFC 9380 P256_XMD:SHA-256_SSWU_RO_（口令 → 曲线点）
  H2 : SHA-256 → ℤ_n*（kid = H2(msk, id)）
  H3 : SHA-256 → ℤ_n*（硬化口令 = H3(解盲点, pw)）
"""

import hashlib
import secrets

from ecdsa import curves, ellipticcurve, keys
from ecdsa.ellipticcurve import Point

from hash_to_curve_p256 import PBCS_H1_DST, hash_to_curve_p256

curve_name_map = {
    "SECP256R1": curves.NIST256p,
    "P-256": curves.NIST256p,
    "SECP256K1": curves.SECP256k1,
}


class SimpleEcCurve:
    def __init__(self, curve_name):
        curve_name_upper = curve_name.upper()
        if curve_name_upper in curve_name_map:
            self.curve = curve_name_map[curve_name_upper]
        else:
            raise ValueError(f"Unsupported curve name: {curve_name}")
        self.curve_fp = self.curve.curve
        self.G = self.curve.generator
        self.n = self.curve.order
        self.length4Hash = (self.n.bit_length() + 128) // 8 + 1

    def decode_point(self, encoded_bytes: bytes):
        vk = keys.VerifyingKey.from_string(encoded_bytes, curve=self.curve)
        return vk.pubkey.point

    def encode_point(self, point):
        x = point.x()
        y = point.y()
        prefix = b"\x02" if y % 2 == 0 else b"\x03"
        return prefix + x.to_bytes(32, "big")

    def hash2curve(self, message: bytes, hash_alg: str = "sha256") -> ellipticcurve.Point:
        """
        H1：RFC 9380 hash-to-curve（P256_XMD:SHA-256_SSWU_RO_）。
        ``hash_alg`` 保留兼容参数，实际固定为 SHA-256 XMD 套件。
        """
        if self.curve != curves.NIST256p:
            raise ValueError("H1 RFC9380 suite requires secp256r1 / P-256")
        x, y = hash_to_curve_p256(message, dst=PBCS_H1_DST)
        point = Point(self.curve_fp, x, y)
        if not self.curve_fp.contains_point(point.x(), point.y()):
            raise RuntimeError("RFC9380 H1 produced invalid curve point")
        return point

    def random_big_integer(self) -> int:
        while True:
            rand_int = secrets.randbelow(self.n)
            if 0 < rand_int < self.n:
                return rand_int

    def _sha256_to_zn(self, *parts: bytes) -> int:
        """SHA-256 域分离拼接后映到 ℤ_n*。"""
        h = hashlib.sha256()
        for i, p in enumerate(parts):
            if i:
                h.update(b"|")
            h.update(p)
        digest = h.digest()
        buf = digest
        while len(buf) < self.length4Hash:
            digest = hashlib.sha256(digest).digest()
            buf += digest
        t = int.from_bytes(buf[: self.length4Hash], "big") % self.n
        ctr = 0
        while t == 0:
            ctr += 1
            digest = hashlib.sha256(buf + ctr.to_bytes(4, "big")).digest()
            t = int.from_bytes(digest, "big") % self.n
        return t

    def h2(self, msk: bytes, user_id: bytes) -> int:
        """H2(id, msk) ∈ ℤ_n*，SHA-256。"""
        return self._sha256_to_zn(b"PBCS|H2|", user_id, msk)

    def h3(self, passphrase: bytes, point_bytes: bytes) -> int:
        """H3(pw, σ) ∈ ℤ_n*，SHA-256。"""
        return self._sha256_to_zn(b"PBCS|H3|", passphrase, point_bytes)

    def hash_to_group2(self, input_data: bytes, client_secret: bytes = None) -> int:
        """
        兼容旧调用：
          AuthServer: hash_to_group2(msk, user_id) → H2
          Client:     hash_to_group2(point_bytes, passphrase) → H3
        """
        if client_secret is None:
            return self._sha256_to_zn(b"PBCS|H2|", input_data)
        if len(input_data) == 33 and input_data[0] in (2, 3):
            return self.h3(client_secret, input_data)
        return self.h2(input_data, client_secret)
