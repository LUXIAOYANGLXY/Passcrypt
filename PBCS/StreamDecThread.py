import threading
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from typing import List, BinaryIO
import os

class Constants:
    KEY_ENCRYPTION_CTR_ALGORITHM = 'AES/CTR/NoPadding'  # Informational only
    KEY_ENCRYPTION_BASE_ALGORITHM = 'AES'
    KEY_ENCRYPTION_CTR_IV_LENGTH = 16  # 128-bit IV

class StreamDecThread(threading.Thread):
    def __init__(self, dec_list: List[BinaryIO], source_inter_path: str, des_path: str, key: bytes, part_num: int):
        super().__init__()
        self.list = dec_list
        self.source_inter_path = source_inter_path
        self.des_path = des_path
        self.key = key
        self.part_num = part_num

    def run(self):
        try:
            self.decrypt_stream_ctr_combine(
                self.source_inter_path,
                self.des_path,
                self.key,
                self.part_num
            )
        except Exception as e:
            print(f"Decryption failed: {e}")

    def decrypt_stream_ctr_combine(self, source_inter_path: str, des_path: str,
                                    key: bytes, part_num: int):
        index = 0

        # Clear file contents if exists
        open(des_path, 'wb').close()

        with open(des_path, 'ab') as file_output_stream:
            while index < part_num:
                index += 1

                # Busy-wait until enough streams are ready
                while len(self.list) < index:
                    continue

                input_stream = self.list[index - 1]
                iv = input_stream.read(Constants.KEY_ENCRYPTION_CTR_IV_LENGTH)

                cipher = Cipher(
                    algorithms.AES(key),
                    modes.CTR(iv),
                    backend=default_backend()
                )
                decryptor = cipher.decryptor()

                while True:
                    read_buf = input_stream.read(1024)
                    if not read_buf:
                        break
                    dec = decryptor.update(read_buf)
                    file_output_stream.write(dec)

                final_dec = decryptor.finalize()
                file_output_stream.write(final_dec)

                input_stream.close()
