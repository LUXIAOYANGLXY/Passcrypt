import secrets
from Crypto.Cipher import AES  # 用于AES加密
from Crypto.Random import get_random_bytes   # 用于生成随机字节
from Crypto.Hash import SHA256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import boto3
from Crypto.Util import number

class AEKEProtocol:
    def __init__(self, region_name,access_key_id,secret_key_id,p=None, g=None, key_len=24, sec_level=2048,verbose=True): # 初始化方法
        # self.P = p or 0xFFFFFFFEFFFFEE37
        if p is None:
            self.P = number.getPrime(sec_level)
        else:
            self.P = p
        self.G = g or 2
        self.KEY_LEN = key_len
        self.verbose = verbose
        self.user_db = {}   # 模拟数据库,用户注册信息的存储
        self.sk = secrets.randbelow(self.P)
        self.pk = pow(self.G, self.sk, self.P)
        self.uid_list = []  # 用户列表
        self.user_time = {}  # 用户时间戳
        self.user_time_client = {}  # 客户端用户时间戳
        self.user_time_server1 = {}  # 服务端用户时间戳
        self.user_time_server2 = {}  # 服务端用户时间戳
        self.communication_scale = {}  # 通信量统计

        # 初始化 S3 客户端
        self.s3_client = boto3.client(
            's3',
            region_name=region_name,
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_key_id
        )

    # ==== 日志辅助 ====
    def log(self, *args):  #打印log
        if self.verbose:
            print(*args)

    def H_new(*args, lambda_len=16):  # 默认输出λ=128比特=16字节
        data = b''.join(str(arg).encode() for arg in args)
        digest = SHA256.new(data).digest()
        return digest[:lambda_len]

    # ==== 哈希函数模拟 ====
    def H(self, *args):  # H函数，输出48字节
        data = b''.join(str(arg).encode() for arg in args)
        return (SHA256.new(data + b'0').digest()[:self.KEY_LEN] +
                SHA256.new(data + b'1').digest()[:self.KEY_LEN] )

    # # ==== 哈希函数模拟 ====
    # def H(self, *args):  # H函数，输出72字节
    #     data = b''.join(str(arg).encode() for arg in args)
    #     return (SHA256.new(data + b'0').digest()[:self.KEY_LEN] +
    #             SHA256.new(data + b'1').digest()[:self.KEY_LEN] +
    #             SHA256.new(data + b'2').digest()[:self.KEY_LEN])

    def H_prime(self, *args):  # H'函数，输出一个大整数
        data = b''.join(str(arg).encode() for arg in args) #将args中的字符串拼接
        return int.from_bytes(SHA256.new(data).digest(), 'big')  #big大端模式

    def H_double_prime(self, *args):  # H''函数，输出一个字节串
        data = b''.join(str(arg).encode() for arg in args)
        return SHA256.new(data).digest()[:self.KEY_LEN]


    # ==== 理想密码 AES-GCM ====
    def _adjust_key(self, key) -> bytes:
        """确保 key 是 bytes 类型，并且长度为 24 字节，自动填充或截断"""
        if isinstance(key, int):
            # 将 int 转为 bytes，24 字节长度，不足前补 0
            key = key.to_bytes(self.KEY_LEN, byteorder='big', signed=False)
        elif not isinstance(key, bytes):
            raise TypeError("Key must be bytes or int")

        if len(key) < self.KEY_LEN:
            key += b'\x00' * (self.KEY_LEN - len(key))  # 不足补 0
        elif len(key) > self.KEY_LEN:
            key = key[:self.KEY_LEN]  # 超出截断
        return key

    def IC_encrypt(self, key, plaintext):  # AES-GCM加密，理想密码
        try:
            key = self._adjust_key(key)
            # nonce = get_random_bytes(12)  # 生成12字节的随机数
            # cipher = AES.new(key[:self.KEY_LEN], AES.MODE_GCM, nonce=nonce)  # 创建加密器对象，GCM模式支持加密和认证
            # ciphertext, tag = cipher.encrypt_and_digest(plaintext)  # 生成密文和16字节认证标签tag
            nonce = os.urandom(12)
            encryptor = Cipher(
                algorithms.AES(key),
                modes.GCM(nonce),
                backend=default_backend()
            ).encryptor()
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            tag = encryptor.tag

            print("Encrypt Key:", key.hex())
            print("Nonce:", nonce.hex())
            print("Tag:", tag.hex())
            print("Ciphertext len:", len(ciphertext))

            return nonce + tag + ciphertext  # 拼接成一个字符串并返回
        except Exception as e:
            raise ValueError("Encryption failed") from e  # 异常处理，加密过程发生错误，捕获异常并抛出ValueError("Encryption failed")

    def IC_decrypt(self, key, ciphertext_bundle):  # AES-GCM解密 理想密码
        try:
            key = self._adjust_key(key)
            nonce = ciphertext_bundle[:12]  # 提取前12字节作为nonce
            tag = ciphertext_bundle[12:28]  # 提取第12到28字节作为tag
            ciphertext = ciphertext_bundle[28:]  # 提取第28字节到最后的部分作为密文
            # cipher = AES.new(key[:self.KEY_LEN], AES.MODE_GCM, nonce=nonce)  # 创建加密器对象
            # return cipher.decrypt_and_verify(ciphertext, tag)  # 解密并验证
            decryptor = Cipher(
                algorithms.AES(key),
                modes.GCM(nonce, tag),
                backend=default_backend()
            ).decryptor()
            print("Decrypt Key:", key.hex())
            print("Nonce:", nonce.hex())
            print("Tag:", tag.hex())
            print("Ciphertext len:", len(ciphertext))

            return decryptor.update(ciphertext) + decryptor.finalize()
        except Exception:
            raise ValueError("Decryption failed: possibly wrong password")  # 异常处理，解密失败，可能是密码错误

    def AES_encrypt(self, key, plaintext):   #用AES-GCM对密钥进行加密
        key = self._adjust_key(key)
        print(f"【DEBUG】AES_encrypt key: {key.hex()}")
        nonce = os.urandom(12)
        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce),
            backend=default_backend()
        ).encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        tag = encryptor.tag


        print(f"【DEBUG】AES_encrypt nonce: {nonce.hex()}")
        print(f"【DEBUG】AES_encrypt tag: {tag.hex()}")

        return nonce + tag + ciphertext

    def AES_decrypt(self, key, ciphertext_bundle):
        key = self._adjust_key(key)
        print(f"【DEBUG】AES_decrypt key: {key.hex()}")
        nonce = ciphertext_bundle[:12]
        tag = ciphertext_bundle[12:28]
        print(f"【DEBUG】AES_decrypt nonce: {nonce.hex()}")
        print(f"【DEBUG】AES_decrypt tag: {tag.hex()}")
        ciphertext = ciphertext_bundle[28:]
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce, tag),
            backend=default_backend()
        ).decryptor()
        print(f"【DEBUG】AES_decrypt ciphertextccccccccc")
        return decryptor.update(ciphertext) + decryptor.finalize()

    def AES_encrypt_streaming(self, key, plaintext_path, inter_enc_path, k2, chunk_size=1024 * 1024):
        print("key的类型",type(key))
        key = self._adjust_key(key)
        nonce = os.urandom(12)

        print(f"【DEBUG】AES_encrypt key: {key.hex()}")
        print(f"【DEBUG】AES_encrypt nonce: {nonce.hex()}")

        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce),
            backend=default_backend()
        ).encryptor()

        # 创建加密输出目录
        print("inter_enc_path", inter_enc_path)

        enc_file_path = os.path.join(inter_enc_path, f"{k2}")

        os.makedirs(inter_enc_path, exist_ok=True)
        print(f"【DEBUG】加密数据将写入：{enc_file_path}")

        with open(plaintext_path, "rb") as fin, open(enc_file_path, "wb") as fout:
            # 写入 nonce 和 tag 占位
            fout.write(nonce)  # nonce (12 bytes)
            fout.write(b'\x00' * 16)  # tag 占位 (16 bytes)

            print(f"【DEBUG】开始分块加密...")
            while chunk := fin.read(chunk_size):
                encrypted_chunk = encryptor.update(chunk)
                fout.write(encrypted_chunk)

            final_data = encryptor.finalize()
            fout.write(final_data)

            tag = encryptor.tag
            print(f"【DEBUG】AES_encrypt tag: {tag.hex()}")

        # 回写 tag 到 nonce 后的位置
        with open(enc_file_path, "r+b") as fout:
            fout.seek(12)  # 跳过 nonce，定位到 tag 的位置
            fout.write(tag)

        return enc_file_path  # 返回加密文件路径

    def AES_decrypt_streaming(self, key, enc_file_path,dest_path,k1, chunk_size=1024 * 1024):
        key = self._adjust_key(key)
        # print(f"[Client] 准备从文件中读取加密内容：{enc_file_path}")
        with open(enc_file_path, "rb") as fin:
            nonce = fin.read(12)  # 读取 nonce（12 字节）
            tag = fin.read(16)  # 读取 tag（16 字节）

            decryptor = Cipher(
                algorithms.AES(key),
                modes.GCM(nonce, tag),
                backend=default_backend()
            ).decryptor()

            os.makedirs(dest_path, exist_ok=True)  # 确保输出目录存在
            dec_file_path = os.path.join(dest_path, f"_{k1}")
            print(f"[Client] 解密后的数据将保存到：{dec_file_path}")

            with open(dec_file_path, "wb") as fout:
                print("[Client] 开始分块解密...")
                while chunk := fin.read(chunk_size):
                    decrypted_chunk = decryptor.update(chunk)
                    fout.write(decrypted_chunk)

                try:
                    final_data = decryptor.finalize()
                    fout.write(final_data)
                    print("[Client] 解密成功，数据已写入文件")
                except Exception as e:
                    print(f"[ERROR] 解密失败（GCM 验证失败）: {e}")
                    raise

        return dec_file_path



    def AES_encrypt_streaming_to_stream(self, key, plaintext_path, output_stream, k2, chunk_size=1024 * 1024):
        key = self._adjust_key(key)
        nonce = os.urandom(12)

        print(f"[DEBUG] AES_encrypt_streaming_to_stream key: {key.hex()}")
        print(f"[DEBUG] AES_encrypt_streaming_to_stream nonce: {nonce.hex()}")

        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce),
            backend=default_backend()
        ).encryptor()

        output_stream.write(nonce)  # 写入 nonce (12 bytes)
        tag_pos = output_stream.tell()  # 记录 tag 的起始位置
        output_stream.write(b'\x00' * 16)  # tag 占位 (16 bytes)

        with open(plaintext_path, "rb") as fin:
            print("[DEBUG] 开始加密文件流...")
            while chunk := fin.read(chunk_size):
                enc_chunk = encryptor.update(chunk)
                output_stream.write(enc_chunk)

        final_data = encryptor.finalize()
        output_stream.write(final_data)

        tag = encryptor.tag
        print(f"[DEBUG] GCM tag: {tag.hex()}")

        # 回写 tag 到之前的位置
        output_stream.seek(tag_pos)
        output_stream.write(tag)

        output_stream.seek(0)  # 重置游标，准备上传或解密

        print(f"[DEBUG] 加密完成，stream size: {output_stream.getbuffer().nbytes} bytes")

    def AES_decrypt_streaming_from_stream(self, key, input_stream, dest_path, k1, chunk_size=1024 * 1024):
        key = self._adjust_key(key)

        nonce = input_stream.read(12)  # GCM 的 nonce
        tag = input_stream.read(16)  # GCM 的 tag

        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce, tag),
            backend=default_backend()
        ).decryptor()

        os.makedirs(dest_path, exist_ok=True)
        dec_file_path = os.path.join(dest_path, f"_{k1}")
        print(f"[Client] 解密后的数据将保存到：{dec_file_path}")

        with open(dec_file_path, "wb") as fout:
            print("[Client] 开始从内存流分块解密...")
            while True:
                chunk = input_stream.read(chunk_size)
                if not chunk:
                    break
                decrypted_chunk = decryptor.update(chunk)
                fout.write(decrypted_chunk)

            try:
                final_data = decryptor.finalize()
                fout.write(final_data)
                print("[Client] 解密成功，数据已写入文件")
            except Exception as e:
                print(f"[ERROR] 解密失败（GCM 验证失败）: {e}")
                raise

        return dec_file_path

