import hashlib
import hmac
import math
from ecdsa import curves, ellipticcurve
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from ecdsa.ellipticcurve import Point
from sympy.ntheory.residue_ntheory import sqrt_mod
import secrets
from ecdsa import keys

curve_name_map = {
    "SECP256R1": curves.NIST256p,
    "P-256": curves.NIST256p,
    "SECP256K1": curves.SECP256k1,
    # 可按需添加更多映射
}

class SimpleEcCurve:
    def __init__(self, curve_name):
        curve_name_upper = curve_name.upper()
        if curve_name_upper in curve_name_map:
            self.curve = curve_name_map[curve_name_upper]
        else:
            raise ValueError(f"Unsupported curve name: {curve_name}")
        self.curve_fp = self.curve .curve
        self.G = self.curve.generator
        self.n = self.curve.order
        self.length4Hash = (self.n.bit_length() + 128) // 8 + 1

    def decode_point(self, encoded_bytes: bytes):
        """
        从压缩字节还原椭圆曲线点
        """
        print("decode")
        vk = keys.VerifyingKey.from_string(encoded_bytes, curve=self.curve)
        return vk.pubkey.point

    def encode_point(self, point):
        """
        将椭圆曲线点压缩编码为字节
        """
        print("encode")
        x = point.x()
        y = point.y()
        prefix = b'\x02' if y % 2 == 0 else b'\x03'
        return prefix + x.to_bytes(32, 'big')  # 32字节用于 NIST256p 曲线

    def hash2curve(self, message: bytes, hash_alg='sha256') -> ellipticcurve.Point:
        digest = hashlib.new(hash_alg, message).digest()
        e = int.from_bytes(digest, byteorder='big') % self.n
        a = self.curve_fp.a()
        b = self.curve_fp.b()
        p = self.curve_fp.p()

        while True:
            x = e
            # y² = x³ + ax + b mod p
            rhs = (x ** 3 + a * x + b) % p
            try:
                y = sqrt_mod(rhs, p, all_roots=True)
                y1 = pow(rhs, (p + 1) // 4, p)
                print("y",y)
                print("y1",y1)
            except ValueError:
                y = None

            if y:
                # 取一个解构造点（注意 ECDSA 的 Point 是 affine 点）
                print("1")
                point = Point(self.curve_fp, x, y[0])
                print("2")
                if self.curve_fp.contains_point(point.x(), point.y()):
                    print("3")
                    return point
                    print("4")

            e = (e + 1) % self.n
            print ("5")

    def random_big_integer(self) -> int:
        """
        生成小于曲线阶的随机整数。
        """
        while True:
            rand_int = secrets.randbelow(self.n)
            if 0 < rand_int < self.n:
                return rand_int

    def hash_to_group2(self, input_data: bytes, client_secret: bytes = None) -> int:
        """
        使用 HKDF 将输入数据映射到椭圆曲线群中的整数。
        """
        if client_secret is None:
            hkdf = HKDF(
                algorithm=hashes.SHA512(),
                length=self.length4Hash,
                salt=None,
                info=b'',
                backend=default_backend()
            )
        else:
            hkdf = HKDF(
                algorithm=hashes.SHA512(),
                length=self.length4Hash,
                salt=client_secret,
                info=b'',
                backend=default_backend()
            )
        okm = hkdf.derive(input_data)
        t = int.from_bytes(okm, byteorder='big') >> (len(okm)*8 - self.n.bit_length())
        while t >= self.n or t == 0:
            input_data = hashlib.sha512(input_data).digest()
            okm = hkdf.derive(input_data)
            t = int.from_bytes(okm, byteorder='big') >> (len(okm)*8 - self.n.bit_length())
        return t
