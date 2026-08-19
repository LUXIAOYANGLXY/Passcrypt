import hmac
import hashlib
from hashlib import sha512
from typing import Optional, Union
from io import BytesIO


class HMacKDF:
    def __init__(self, hmac_algorithm: str, ikm: bytes, salt: Optional[bytes] = None):
        self.hmac_algorithm = hmac_algorithm.upper()
        self.hash_func = self.get_hash_func(self.hmac_algorithm)
        self.hash_length = self.hash_func().digest_size

        if salt is None or len(salt) == 0:
            salt = bytes([0] * self.hash_length)

        self.prf_key = hmac.new(salt, ikm, self.hash_func).digest()

        assert len(self.prf_key) == self.hash_length

    def get_hash_func(self, algo: str):
        if algo in ["HMACSHA512", "SHA512", "HMAC-SHA512"]:
            return hashlib.sha512
        elif algo in ["HMACSHA256", "SHA256", "HMAC-SHA256"]:
            return hashlib.sha256
        else:
            raise ValueError("Unsupported HMAC algorithm: {}".format(algo))

    def get_prf_key(self) -> bytes:
        return self.prf_key[:]

    def create_key(self, info: Union[bytes, str] = b"", length: int = 32) -> bytes:
        if isinstance(info, str):
            info = info.encode("utf-8")

        if length > 255 * self.hash_length:
            raise ValueError(f"Requested length {length} exceeds max output length.")

        hmac_key = self.prf_key
        previous = b""
        result = BytesIO()
        iteration = 1

        while result.tell() < length:
            h = hmac.new(hmac_key, digestmod=self.hash_func)
            h.update(previous)
            h.update(info)
            h.update(bytes([iteration]))
            output = h.digest()
            result.write(output)
            previous = output
            iteration += 1

        return result.getvalue()[:length]
