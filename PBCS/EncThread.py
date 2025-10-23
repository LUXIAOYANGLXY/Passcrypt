import threading
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from queue import Queue

class EncThread(threading.Thread):
    def __init__(self, queue: Queue, part_num: int, part_size: int, source_path: str, dest_path: str, key: bytes):
        super().__init__()
        self.queue = queue
        self.part_num = part_num
        self.part_size = part_size
        self.source_path = source_path
        self.dest_path = dest_path
        self.key = key

    def run(self):
        try:
            self.encrypt_file_parts()
        except Exception as e:
            print("Encryption error:", e)

    def encrypt_file_parts(self):
        os.makedirs(self.dest_path, exist_ok=True)
        with open(self.source_path, 'rb') as f:
            for index in range(1, self.part_num + 1):
                f.seek((index - 1) * self.part_size)
                part_bytes = f.read(self.part_size)

                iv = get_random_bytes(16)
                cipher = AES.new(self.key, AES.MODE_CTR, nonce=iv[:8])
                ct = cipher.encrypt(part_bytes)

                out_file = os.path.join(self.dest_path, f'EncPart{index}')
                with open(out_file, 'wb') as fout:
                    fout.write(iv)
                    fout.write(ct)

                self.queue.put(index)  # 通知上传线程这个 part 准备好了
