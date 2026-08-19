import hashlib
import hmac
import time
import os
import secrets
from typing import Optional
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


class Constants:
    PASSWORD_SALT = b'some_salt'  # Replace with actual salt if available
    HASHED_PASSWORD_LENGTH = 256  # In bits, will be converted to bytes in code


class Utils:
    HEX_ARRAY = '0123456789ABCDEF'

    @staticmethod
    def bytes_to_hex(byte_array: bytes) -> str:
        return ''.join(Utils.HEX_ARRAY[b >> 4] + Utils.HEX_ARRAY[b & 0x0F] for b in byte_array)

    @staticmethod
    def kdf(passphrase: str, key: bytes, salt: bytes, output_length: int, iterations: int) -> bytes:
        key_and_salt = salt + key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=output_length // 8,  # Convert bits to bytes
            salt=key_and_salt,
            iterations=iterations,
            backend=default_backend()
        )
        return kdf.derive(passphrase.encode('utf-8'))

    @staticmethod
    def h4_hmac(
        key: bytes,
        message: bytes,
        output_length_bits: int,
        *,
        ct2: bytes | None = None,
        ct2_path: str | None = None,
    ) -> bytes:
        """
        H4：HMAC-SHA256。
          默认：τ = H4(k2, ct)           → key=k2, message=ct
          绑定文件密文：τ = H4(ct, k2, ct2) → key=k2, message=ct‖ct2
        ct2 可直接传 bytes，或经 ct2_path 流式读入（大文件）。
        """
        if isinstance(key, str):
            key = key.encode("utf-8")
        h = hmac.new(key, digestmod=hashlib.sha256)
        h.update(message)
        if ct2 is not None:
            h.update(ct2)
        if ct2_path is not None:
            with open(ct2_path, "rb") as f:
                while True:
                    chunk = f.read(1024 * 1024)
                    if not chunk:
                        break
                    h.update(chunk)
        out_len = output_length_bits // 8
        digest = h.digest()
        if out_len > len(digest):
            raise ValueError("H4 output longer than SHA-256 digest")
        return digest[:out_len]

    @staticmethod
    def kdf_benchmark(num_iterations: int, num_bench_repetitions: int) -> int:
        random_bytes = bytearray(10)
        cum_hash = Utils.kdf("start", Constants.PASSWORD_SALT, Constants.PASSWORD_SALT,
                             Constants.HASHED_PASSWORD_LENGTH, num_iterations)
        hash_val = Utils.kdf("start", Constants.PASSWORD_SALT, Constants.PASSWORD_SALT,
                             Constants.HASHED_PASSWORD_LENGTH, num_iterations)

        total_time = 0
        for _ in range(num_bench_repetitions):
            secrets.token_bytes(10)  # Generates random bytes but not used directly here
            rand_str = secrets.token_hex(10)

            start_time = time.time()
            hash_val = Utils.kdf(rand_str, Constants.PASSWORD_SALT, Constants.PASSWORD_SALT,
                                 Constants.HASHED_PASSWORD_LENGTH, num_iterations)
            elapsed_time = time.time()

            total_time += (elapsed_time - start_time) * 1000  # Convert to ms

            for i in range(len(hash_val)):
                cum_hash[i] ^= hash_val[i]

        if cum_hash == hash_val:
            raise RuntimeError("Benchmark Failed")

        return int(total_time / num_bench_repetitions)

    @staticmethod
    def destroy_password(password: Optional[list]):
        if password is not None:
            for i in range(len(password)):
                password[i] = ' '

    @staticmethod
    def destroy_passkey(passkey: Optional[bytearray]):
        if passkey is not None:
            for i in range(len(passkey)):
                passkey[i] = 0
