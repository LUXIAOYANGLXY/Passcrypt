import threading
import os
from queue import Queue

from se_ctr import CTR_IV_LEN, ctr_encrypt_chunk


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

                iv = os.urandom(CTR_IV_LEN)
                ct = ctr_encrypt_chunk(self.key, iv, part_bytes)

                out_file = os.path.join(self.dest_path, f'EncPart{index}')
                with open(out_file, 'wb') as fout:
                    fout.write(iv)
                    fout.write(ct)

                self.queue.put(index)
