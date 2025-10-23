import hashlib
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
