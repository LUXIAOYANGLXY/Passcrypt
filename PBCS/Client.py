import math
import socket
import ssl
import logging
import sys
import binascii
import random
import time
import threading
from typing import List, Tuple
import boto3
from botocore.exceptions import ClientError,BotoCoreError
import configparser
from queue import Queue
from boto3.s3.transfer import TransferConfig
import secrets
from ecdsa.ellipticcurve import Point
from ecdsa.util import number_to_string
import io
from botocore.exceptions import ClientError, BotoCoreError, IncompleteReadError
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os
import tempfile

from utils import Utils
import comm_model

from SimpleEcCurve import SimpleEcCurve

from Constants import CURVE_NAME, REQ_TYPE_AUTHSERVER_REGISTER, REQ_TYPE_AUTHSERVER_DEPOSIT
from Constants import (
    CURVE_NAME, FILE_PATH,
    KDF_HASH_REPETITIONS, USE_TLS,
    AUTH_SERVER_ADDRESS, AUTH_SERVER_PORT_NUMBER, AUTH_SERVER_NAME,
    TLS_VERSION, TLS_CIPHERSUITE,
    REQ_TYPE_AUTHSERVER_OPRF, RESP_TYPE_OK, RESP_TYPE_ERROR,
    R_LENGTH, KDF1_SALT, KDF2_SALT, KDF3_SALT, KDF4_SALT,
    MAC_KEY_LENGTH, ENC_KEY_LENGTH, AUTH_SERVER_ADDRESS_EC2,
    KEY_ENCRYPTION_ALGORITHM, DATA_ENCRYPTION_BASE_ALGORITHM,
    REQ_TYPE_AUTHSERVER_RETRIEVAL,
    USE_LOCAL_SIM,
)
from EncThread import EncThread
from StreamDecThread import StreamDecThread

# 设置日志
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


class LocalObjectStore:
    """本机模拟 S3：实现 upload_fileobj / get_object，供 Register/Give/Take 使用。"""

    def __init__(self):
        self._obj = {}

    def upload_fileobj(self, f, bucket, key):
        self._obj[f"{bucket}/{key}"] = f.read()

    def get_object(self, Bucket, Key):
        data = self._obj[f"{Bucket}/{Key}"]
        return {"Body": io.BytesIO(data)}


class Client:
    internal_cipher_file_path = os.path.join(FILE_PATH, "internal/")
    plain_file_path = FILE_PATH + "plain"
    secure_ret_file_path = FILE_PATH + "secureRetrieve"
    opt_secure_ret_file_path = FILE_PATH + "optSecureRetrieve"
    encryption_file_path = FILE_PATH + "encryption"
    decryption_file_path = FILE_PATH + "decryption"

    verbose = False

    def _dbg(self, *args):
        if self.verbose:
            print(*args)

    def __init__(self, access_key_id, secret_key_id, region_name, bucket_name,
                 socket_factory=None, logger_instance=None,
                 kdf_hash_repetitions=KDF_HASH_REPETITIONS, use_tls=USE_TLS,
                 use_local_sim=None):
        """
        初始化客户端。
        use_local_sim=True：不访问 AWS，用内存对象存储模拟 S3。
        """
        self.socket_factory = socket_factory if socket_factory else self.default_socket_factory(use_tls)
        self.logger = logger_instance if logger_instance else self.default_logger()
        self.kdf_hash_repetitions = kdf_hash_repetitions
        self.use_tls = use_tls
        self.access_key_id = access_key_id
        self.secret_key_id = secret_key_id
        self.region_name = region_name
        self.bucket_name = bucket_name
        self.use_local_sim = USE_LOCAL_SIM if use_local_sim is None else bool(use_local_sim)
        self.logger = self.default_logger()
        self.curve = SimpleEcCurve(CURVE_NAME)

        if self.use_local_sim:
            self.s3_client = LocalObjectStore()
            self.logger.log(
                f"[local-sim] S3=内存模拟, AuthServer={AUTH_SERVER_ADDRESS}:{AUTH_SERVER_PORT_NUMBER}"
            )
        else:
            self.s3_client = boto3.client(
                's3',
                region_name=region_name,
                aws_access_key_id=access_key_id,
                aws_secret_access_key=secret_key_id
            )

    def default_socket_factory(self, use_tls=False):
        if use_tls:
            return lambda host, port: ssl.wrap_socket(socket.create_connection((host, port)))
        else:
            return lambda host, port: socket.create_connection((host, port))

    @staticmethod
    def default_logger():
        class DefaultLogger:
            @staticmethod
            def log(*messages):
                print(" ".join(str(m) for m in messages))

            @staticmethod
            def info(tag, message):
                logger.info(f"{tag}: {message}")

            @staticmethod
            def warning(tag, message):
                logger.warning(f"{tag}: {message}")
        return DefaultLogger()

    def set_socket_factory(self, socket_factory):
        self.socket_factory = socket_factory
        return self

    def set_kdf_hash_repetitions(self, n):
        self.kdf_hash_repetitions = n
        return self

    def set_use_tls(self, b):
        self.use_tls = b
        return self

    def set_logger(self, logger_instance):
        self.logger = logger_instance
        return self

    def start_rgt(self):
        try:
            rand = random.Random()
            random_bytes = bytes([rand.randint(0, 255) for _ in range(10)])
            user_id = f"username{binascii.hexlify(random_bytes).decode('utf-8')}"
            passphrase = f"passphrase{binascii.hexlify(random_bytes).decode('utf-8')}"
            key5 = f"RGT{user_id}/sid"
            key6 = f"RGT{user_id}/rid"

            self.logger.log("Starting PASSWORD HARDENING PROTOCOL--iboprf0")
            start_time = time.time()
            hardened_pwd = self.ib_oprf(AUTH_SERVER_ADDRESS_EC2, AUTH_SERVER_PORT_NUMBER, AUTH_SERVER_NAME, user_id, passphrase)
            oprf_time = (time.time() - start_time) * 1000  # 转毫秒
            self.logger.log("PASSWORD HARDENING PROTOCOL time--iboprf0:", oprf_time)

            self.register(AUTH_SERVER_ADDRESS_EC2, AUTH_SERVER_PORT_NUMBER, AUTH_SERVER_NAME, user_id, passphrase, self.bucket_name, key5)
            self.logger.log("register success")

            start_time = time.time()
            self.ib_oprf(AUTH_SERVER_ADDRESS_EC2, AUTH_SERVER_PORT_NUMBER, AUTH_SERVER_NAME, user_id, passphrase)
            oprf_time0 = (time.time() - start_time) * 1000
            self.logger.log("PASSWORD HARDENING PROTOCOL time--iboprf1", oprf_time0)

            self.logger.log("KEY DEPOSIT PROTOCOL")
            start_time = time.time()
            msk = self.give(AUTH_SERVER_ADDRESS_EC2, AUTH_SERVER_PORT_NUMBER, AUTH_SERVER_NAME, user_id, passphrase, self.bucket_name, key6, key5)
            give_time = (time.time() - start_time) * 1000
            self.logger.log("KEY DEPOSIT PROTOCOL time", give_time)

            start_time = time.time()
            hardened_pwd1 = self.ib_oprf(AUTH_SERVER_ADDRESS_EC2, AUTH_SERVER_PORT_NUMBER, AUTH_SERVER_NAME, user_id, passphrase)
            oprf_time1 = (time.time() - start_time) * 1000
            self.logger.log("PASSWORD HARDENING PROTOCOL time--iboprf2", oprf_time1)

            self.logger.log("KEY RETRIEVAL PRO+`TOCOL")
            start_time = time.time()
            mskr = self.take(AUTH_SERVER_ADDRESS_EC2, AUTH_SERVER_PORT_NUMBER, AUTH_SERVER_NAME, user_id, passphrase, self.bucket_name, key6, key5)
            take_time = (time.time() - start_time) * 1000
            self.logger.log("Key Retrieval time =", take_time)

            if msk != mskr:
                raise Exception("msk does not match")

            print(f"{oprf_time0},{give_time},{oprf_time1},{take_time}")
            if hardened_pwd1 == hardened_pwd:
                pass
            else:
                self.logger.log(f"The hardened password is {hardened_pwd} and {hardened_pwd1}")

        except Exception as e:
            self.logger.log("Error in start_rgt:", str(e))

    def start(self, source_file_path: str):
        try:
            rand = random.Random()
            random_bytes = bytes([rand.randint(0, 255) for _ in range(10)])
            user_id = f"username{binascii.hexlify(random_bytes).decode('utf-8')}"
            passphrase = f"passphrase{binascii.hexlify(random_bytes).decode('utf-8')}"

            key0 = f"{user_id}/sid"
            key1 = f"{user_id}/rid"
            key2 = f"{user_id}/optimizedEncryptedFile"
            key3 = f"{user_id}/plainFile"
            key4 = f"{user_id}/oneThreadEncryptedFile"
            key5 = f"{user_id}/ctrencrypt"


            total_commucation_scale =0

            self.logger.log("PASSWORD HARDENING PROTOCOL---IBOPRF0")
            start_time = time.time()
            hardened_pwd,send_bytes,recv_bytes = self.ib_oprf(AUTH_SERVER_ADDRESS_EC2, AUTH_SERVER_PORT_NUMBER, AUTH_SERVER_NAME, user_id,
                                        passphrase)
            oprf_time = (time.time() - start_time) * 1000
            self.logger.log(f"PASSWORD HARDENING PROTOCOL time--IBOPRF0: {oprf_time} ms")


            self.logger.log("PASSWORD HARDENING PROTOCOL----REGISTER")
            start_time = time.time()
            self.register(AUTH_SERVER_ADDRESS_EC2, AUTH_SERVER_PORT_NUMBER, AUTH_SERVER_NAME, user_id,
                                        passphrase, self.bucket_name, key0)
            register_time = (time.time() - start_time) * 1000
            self.logger.log(f"PASSWORD HARDENING PROTOCOL time----REGISTER: {oprf_time} ms")

            start_time = time.time()
            hardened_pwd,send_bytes,recv_bytes=self.ib_oprf(AUTH_SERVER_ADDRESS_EC2, AUTH_SERVER_PORT_NUMBER, AUTH_SERVER_NAME, user_id, passphrase)
            oprf_time1 = (time.time() - start_time) * 1000
            self.logger.log("PASSWORD HARDENING PROTOCOL time--iboprf1", oprf_time1)
            total_commucation_scale += send_bytes
            total_commucation_scale += recv_bytes

            self.logger.log("KEY DEPOSIT PROTOCOL")
            start_time = time.time()
            msk,send_bytes,recv_bytes = self.give(AUTH_SERVER_ADDRESS_EC2, AUTH_SERVER_PORT_NUMBER, AUTH_SERVER_NAME, user_id, passphrase,
                            self.bucket_name, key1, key0)
            give_time = (time.time() - start_time) * 1000
            self.logger.log("KEY DEPOSIT PROTOCOL time", give_time)
            total_commucation_scale += send_bytes
            total_commucation_scale += recv_bytes

            # ENCRYPT AND UPLOAD
            t3 = time.time()
            # part_num = self.secure_deposit_optimization(self.bucket_name, key2, msk, source_file_path,self.internal_cipher_file_path)
            part_num = 0
            dep_enc_time_multi = int((time.time() - t3) * 1000)
            self.logger.log(f"Multi-thread enc/upload time: {dep_enc_time_multi} ms")


            start_time = time.time()
            hardened_pwd1,send_bytes,recv_bytes = self.ib_oprf(AUTH_SERVER_ADDRESS_EC2, AUTH_SERVER_PORT_NUMBER, AUTH_SERVER_NAME, user_id,
                                         passphrase)
            oprf_time2 = (time.time() - start_time) * 1000
            self.logger.log("PASSWORD HARDENING PROTOCOL time--iboprf2", oprf_time1)
            total_commucation_scale += send_bytes
            total_commucation_scale += recv_bytes

            self.logger.log("KEY RETRIEVAL PROTOCOL")
            start_time = time.time()
            mskr,send_bytes,recv_bytes = self.take(AUTH_SERVER_ADDRESS_EC2, AUTH_SERVER_PORT_NUMBER, AUTH_SERVER_NAME, user_id, passphrase,
                             self.bucket_name, key1, key0)
            take_time = (time.time() - start_time) * 1000
            self.logger.log("Key Retrieval time =", take_time)
            total_commucation_scale += send_bytes
            total_commucation_scale += recv_bytes

            if msk != mskr:
                raise Exception("msk does not match")

            print(f"{oprf_time1},{give_time},{oprf_time2},{take_time}")
            if hardened_pwd1 == hardened_pwd:
                pass
            else:
                self.logger.log(f"The hardened password is {hardened_pwd} and {hardened_pwd1}")




            # RETRIEVE & DEC
            t6 = time.time()
            # self.secure_retrieve_optimization(part_num, self.bucket_name, key2, mskr, self.opt_secure_ret_file_path,
            #                                   self.internal_cipher_file_path)
            ret_dec_time_multi = int((time.time() - t6) * 1000)
            self.logger.log(f"Retrieve and dec time (multi-thread): {ret_dec_time_multi} ms")

            # # One-thread encryption
            t7 = time.time()
            # print("k4", key4)
            # self.secure_deposit(self.bucket_name, key4, key5, msk, source_file_path, self.internal_cipher_file_path)
            dep_enc_time_one = int((time.time() - t7) * 1000)
            # self.logger.log(f"One-thread enc/upload time: {dep_enc_time_one} ms")
            #
            t8 = time.time()
            # self.secure_retrieve(self.bucket_name, key4, mskr, self.secure_ret_file_path)
            ret_dec_time_one = int((time.time() - t8) * 1000)
            # self.logger.log(f"One-thread retrieve and dec time: {ret_dec_time_one} ms")
            #
            # # Plain upload/retrieve
            t9 = time.time()
            # self.deposit_plain_file(self.bucket_name, key3, source_file_path)
            dep_plain_time = int((time.time() - t9) * 1000)
            # self.logger.log(f"Plain file upload time: {dep_plain_time} ms")
            #
            t10 = time.time()
            # self.retrieve_plain_big_file(self.bucket_name, key3, self.plain_file_path)
            ret_plain_time = int((time.time() - t10) * 1000)
            # self.logger.log(f"Plain file retrieve time: {ret_plain_time} ms")

            # Encrypt plain file (CTR)
            t11 = time.time()
            self.encrypt_ctr_big_file(source_file_path, self.encryption_file_path, msk)
            enc_time = int((time.time() - t11) * 1000)
            self.logger.log(f"Encrypt plain file time: {enc_time} ms")

            # Decrypt CTR file
            t12 = time.time()
            self.decrypt_ctr_big_file(self.encryption_file_path, self.decryption_file_path, mskr)
            dec_time = int((time.time() - t12) * 1000)
            self.logger.log(f"Decrypt CTR file time: {dec_time} ms")

            # 打印所有结果
            print("=====================")

            print(
                "ibOPRF, give, ibOPRF, take, plainDep, plainRet, secureDepOpt, secureRetOpt, secureDep, secureRet, enc, dec, partNum")
            print(
                f"oprf_time={oprf_time},\nregister_time={register_time},\noprf_time1={oprf_time1}\ngive time={give_time},\noprf_time2={oprf_time2},\ntake_time={take_time},\ndep_plain_time={dep_plain_time},\nret_plain_time={ret_plain_time},"
                f"\ndep_enc_time_multi={dep_enc_time_multi},\nret_dec_time_multi={ret_dec_time_multi},\ndep_enc_time_one={dep_enc_time_one},\nret_dec_time_one={ret_dec_time_one},\nenc_time={enc_time},\ndec_time={dec_time},\npart_num={part_num}")

            return (oprf_time, register_time, oprf_time1, give_time, oprf_time2, take_time,
                    dep_plain_time, ret_plain_time,
                    dep_enc_time_multi, ret_dec_time_multi,
                    dep_enc_time_one, ret_dec_time_one,
                    enc_time, dec_time, part_num,total_commucation_scale)


        except Exception as e:
            self.logger.log(f"Error in start(): {e}")
            raise



    def connect_and_get_socket(self, address: str, port: int, name: str) -> socket.socket:
        if self.use_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
            sock.connect((address, port))
            self._dbg("connect")

            return sock
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((address, port))
            return sock

    def encode_point_compressed(self,point: Point, curve) -> bytes:
        x_bytes = point.x().to_bytes(32, 'big')
        prefix = b'\x02' if point.y() % 2 == 0 else b'\x03'
        return prefix + x_bytes

    def ib_oprf(self, auth_server_address: str, auth_server_port: int, auth_server_name: str,
                user_id: str, passphrase: str) -> tuple[str, int, int]:
        try:
            send_bytes = 0
            recv_bytes = 0
            message = passphrase.encode('utf-8')
            hash_point = self.curve.hash2curve(message)
            self._dbg("【IBOPRF】hash_point", hash_point)
            self._dbg(type(hash_point))


            # 将 EC 公钥转换为字节形式

            k= self.curve.random_big_integer()
            self._dbg("【IBOPRF】k", k)
            blind_point = k * hash_point
            self._dbg("【IBOPRF】blind_point", blind_point)

            # 4. 压缩编码
            blind_point_bytes = self.encode_point_compressed(blind_point,self.curve.curve)
            self._dbg("【IBOPRF】blind_point_bytes", blind_point_bytes)

            self._dbg("压缩编码")
            self._dbg("auth_server_address", auth_server_address)
            self._dbg("auth_server_port", auth_server_port)
            self._dbg("auth_server_name", auth_server_name)

            sock = self.connect_and_get_socket(auth_server_address, auth_server_port, auth_server_name)
            out = sock.makefile('wb')
            in_ = sock.makefile('rb')
            self._dbg("auth_server_port", auth_server_port)


            # 发送请求类型
            out.write(bytes([REQ_TYPE_AUTHSERVER_OPRF]))
            send_bytes += 1


            # 发送 userID 长度 + 内容
            user_id_bytes = user_id.encode('utf-8')
            out.write(bytes([len(user_id_bytes)]))
            send_bytes += 1
            out.write(user_id_bytes)
            send_bytes += len(user_id_bytes)

            # 发送 blindPointBytes 长度 + 内容
            out.write(bytes([len(blind_point_bytes)]))
            send_bytes += 1
            out.write(blind_point_bytes)
            send_bytes += len(blind_point_bytes)
            out.flush()

            # 接收响应
            response_type = ord(in_.read(1))
            recv_bytes += 1
            if response_type == RESP_TYPE_OK:
                if self.verbose:
                    self.logger.log("IB-OPRF protocol succeeded.")
            elif response_type == RESP_TYPE_ERROR:
                raise Exception("Auth Server error in IB-OPRF Protocol!")
            else:
                raise Exception("Unknown response from Auth Server!")

            # 接收 blindedecPointBytes
            data_len = ord(in_.read(1))
            recv_bytes += 1
            blindedec_point_bytes = in_.read(data_len)
            recv_bytes += len(blindedec_point_bytes)
            self._dbg("【IBOPRF】--blindedec_point_bytes", blindedec_point_bytes)

            k_inv = pow(k, -1, self.curve.n)
            blindedec_point = self.curve.decode_point(blindedec_point_bytes)
            # 点乘逆元（解盲）
            b_ec_point = (blindedec_point * k_inv).to_affine()  # 变成 Point 类型

            # 编码为压缩点
            b_ec_point_derive_byte = self.encode_point_compressed(b_ec_point, self.curve.curve)

            self._dbg("【IBOPRF】--b_ec_point_derive_byte", b_ec_point_derive_byte)
            self._dbg("passphrase ok")

            hardened_pwd = self.curve.h3(passphrase.encode("utf-8"), b_ec_point_derive_byte)

            sock.close()
            # 论文字段通信量：OPRF = id + u + v（不含帧头）；无 S3
            auth = comm_model.oprf_fields(user_id)
            self.last_comm = {"phase": "oprf", "auth": auth, "s3": {"total": 0}}
            return str(hardened_pwd), int(auth["total"]), 0

        except Exception as e:
            raise Exception(f"Error in ib_oprf(): {e}")

    def create_file_from_bytes(self,data: bytes) -> str:
        with tempfile.NamedTemporaryFile(delete=False) as tmpfile:
            tmpfile.write(data)
            return tmpfile.name



    def register(self, auth_server_address: str, auth_server_port: int, auth_server_name: str,
                 user_id: str, passphrase: str, bucket_name: str, key0: str) -> tuple[int, int]:
        """返回 (auth_comm, s3_comm)：论文字段字节（KS: id,t；S3: id,pwd,sid）。"""
        try:
            send_bytes = 0
            recv_bytes = 0
            sid = get_random_bytes(R_LENGTH)
            self._dbg("sid", sid)

            # 将 sid 写入临时文件
            file_data = self.create_file_from_bytes(sid)  # 返回的是路径字符串
            self._dbg("sid", sid)
            self._dbg("file_data", file_data)

            # 上传 sid 到 S3 / 本地模拟存储
            try:
                with open(file_data, 'rb') as f:
                    self.s3_client.upload_fileobj(f, bucket_name, key0)
                self._dbg("S3 upload ok")
            except ClientError as e:
                print("S3 Error:", e)
                raise e
            self._dbg("s3")

            t = Utils.kdf(passphrase, sid, KDF1_SALT, MAC_KEY_LENGTH, KDF_HASH_REPETITIONS)
            self._dbg("t", t)

            sock = self.connect_and_get_socket(auth_server_address, auth_server_port, auth_server_name)
            out = sock.makefile('wb')

            # 发送请求类型
            out.write(bytes([REQ_TYPE_AUTHSERVER_REGISTER]))
            send_bytes += 1

            # 发送 userID
            user_id_bytes = user_id.encode('utf-8')
            out.write(bytes([len(user_id_bytes)]))
            send_bytes += 1
            out.write(user_id_bytes)
            send_bytes += len(user_id_bytes)

            # 发送 t
            out.write(bytes([len(t)]))
            send_bytes += 1
            out.write(t)
            send_bytes += len(t)
            out.flush()

            in_ = sock.makefile('rb')
            response_type = ord(in_.read(1))
            recv_bytes += 1
            if response_type == RESP_TYPE_OK:
                if self.verbose:
                    print("Register protocol succeeded.")
            elif response_type == RESP_TYPE_ERROR:
                raise Exception("Auth Server error in Register Protocol!")
            else:
                raise Exception("Unknown response from Auth Server!")

            sock.close()
            auth = comm_model.register_ks_fields(user_id)
            s3 = comm_model.s3_register_fields(user_id)
            self.last_comm = {"phase": "register", "auth": auth, "s3": s3}
            return int(auth["total"]), int(s3["total"])

        except Exception as e:
            print(f"Error in register(): {e}")
            raise e

    def give(self, auth_server_address: str, auth_server_port: int, auth_server_name: str,
             user_id: str, passphrase: str, bucket_name: str, key1: str, key0: str,
             plaintext_path: str | None = None, ct2_path: str | None = None,
             file_cipher: str = "ctr",
             ) -> tuple[bytes, int, int]:
        """
        Give / Deposit。
        若提供 plaintext_path：先用 MSK 本地加密得 ct2（file_cipher=ctr|gcm），再
          τ = H4(ct, k2, ct2)；ct2 写入 ct2_path（默认 plaintext_path + ".ct2"）。
        若仅提供 ct2_path：直接用已有密文绑定 τ（不重复加密）。
        否则：τ = H4(ct, k2)（论文默认，不含文件密文）。
        """
        try:
            send_bytes = 0
            recv_bytes = 0
            rid = get_random_bytes(R_LENGTH)
            parameter = rid[:]

            # 存储 rid 到 S3 key1
            file_data = self.create_file_from_bytes(parameter)
            try:
                with open(file_data, 'rb') as f:
                    self.s3_client.upload_fileobj(f, bucket_name, key1)
            except ClientError as e:
                print("S3 Upload Error:", e)
                raise e
            # rid→存储 不计入 AuthServer 通信量

            # 从 S3 获取 sid
            try:
                obj = self.s3_client.get_object(Bucket=bucket_name, Key=key0)
                sid = obj['Body'].read()
            except ClientError as e:
                print("S3 GetObject Error:", e)
                raise e
            # sid←存储 不计入 AuthServer 通信量

            msk = get_random_bytes(32)  # AES-256 密钥长度
            if self.verbose:
                print("Generated msk:", msk.hex())

            t_test = time.perf_counter()
            t = Utils.kdf(passphrase,sid,  KDF1_SALT, MAC_KEY_LENGTH, KDF_HASH_REPETITIONS)
            k1 = Utils.kdf(passphrase,rid,  KDF2_SALT, ENC_KEY_LENGTH, KDF_HASH_REPETITIONS)
            k2 = Utils.kdf(passphrase, rid, KDF3_SALT, ENC_KEY_LENGTH, KDF_HASH_REPETITIONS)
            KDF_time= (time.perf_counter()  - t_test) * 1000
            self.logger.log(f"2026.06__KDF_TIME: {KDF_time} ms")
            self._dbg(f"KDF_TIME: {KDF_time:.3f} ms")


            # AES-CTR 封装 MSK：ivct = IV(16)‖C(msk)；完整性由 τ 保证
            from se_ctr import wrap_key_ctr

            ivct = wrap_key_ctr(k1, msk)

            # 可选：τ 绑定文件密文 ct2
            #   plaintext_path：先加密 m→ct2（ctr|gcm），再 τ=H4(ct,k2,ct2)
            #   仅 ct2_path：已有密文时直接绑定（不重复加密）
            bind_ct2_path = None
            self.last_give_file_ms = 0.0
            if plaintext_path is not None:
                bind_ct2_path = ct2_path or (plaintext_path + ".ct2")
                mode = (file_cipher or "ctr").strip().lower()
                t_fe0 = time.perf_counter()
                if mode == "gcm":
                    from se_gcm import encrypt_file_gcm

                    encrypt_file_gcm(plaintext_path, bind_ct2_path, msk)
                else:
                    from se_ctr import encrypt_file_ctr

                    encrypt_file_ctr(plaintext_path, bind_ct2_path, msk)
                self.last_give_file_ms = (time.perf_counter() - t_fe0) * 1000.0
            elif ct2_path is not None:
                bind_ct2_path = ct2_path

            # 生成 tao（H4 = HMAC-SHA256）
            if bind_ct2_path is not None:
                tao = Utils.h4_hmac(
                    k2, ivct, ENC_KEY_LENGTH, ct2_path=bind_ct2_path
                )
            else:
                tao = Utils.h4_hmac(k2, ivct, ENC_KEY_LENGTH)


            sock = self.connect_and_get_socket(auth_server_address, auth_server_port, auth_server_name)
            out = sock.makefile('wb')

            # 发送请求类型
            out.write(bytes([REQ_TYPE_AUTHSERVER_DEPOSIT]))
            send_bytes += 1

            # 发送 userID
            user_id_bytes = user_id.encode('utf-8')
            out.write(bytes([len(user_id_bytes)]))
            send_bytes += 1
            out.write(user_id_bytes)
            send_bytes += len(user_id_bytes)

            # 发送 t
            out.write(bytes([len(t)]))
            send_bytes += 1
            out.write(t)
            send_bytes += len(t)

            # 发送 tao
            out.write(bytes([len(tao)]))
            send_bytes += 1
            out.write(tao)
            send_bytes += len(tao)

            # 发送 ivct
            out.write(bytes([len(ivct)]))
            send_bytes += 1
            out.write(ivct)
            send_bytes += len(ivct)

            out.flush()

            in_ = sock.makefile('rb')
            response_type = ord(in_.read(1))
            recv_bytes += 1
            if response_type == RESP_TYPE_OK:
                if self.verbose:
                    print("Deposit protocol succeeded.")
            elif response_type == RESP_TYPE_ERROR:
                raise Exception("Auth Server error in Deposit Protocol!")
            else:
                raise Exception("Unknown response from Auth Server!")

            sock.close()

            # 论文字段：KS = id,t,ct,τ,e；S3 = id,pwd,rid,sid
            auth = comm_model.give_ks_fields(user_id)
            s3 = comm_model.s3_give_fields(user_id)
            self.last_comm = {"phase": "give", "auth": auth, "s3": s3}
            return msk, int(auth["total"]), int(s3["total"])

        except Exception as e:
            print(f"Error in give(): {e}")
            raise e

    def take(self, auth_server_address: str, auth_server_port: int, auth_server_name: str,
             user_id: str, passphrase: str, bucket_name: str, key1: str, key0: str,
             ct2_path: str | None = None,
             ) -> tuple[bytes, int, int]:
        """
        Take / Retrieval。
        若 Give 时 τ 绑定了 ct2，则须传同一 ct2_path 验签。
        """
        try:
            send_bytes = 0
            recv_bytes = 0
            # 从 S3 获取 rid / sid（计入 S3 字段通信量）
            obj1 = self.s3_client.get_object(Bucket=bucket_name, Key=key1)
            encrypted_data = obj1['Body'].read()
            rid = encrypted_data[:R_LENGTH]

            obj2 = self.s3_client.get_object(Bucket=bucket_name, Key=key0)
            sid = obj2['Body'].read()

            # 派生密钥
            t = Utils.kdf(passphrase, sid, KDF1_SALT, MAC_KEY_LENGTH, KDF_HASH_REPETITIONS)
            k1 = Utils.kdf(passphrase,rid,  KDF2_SALT, ENC_KEY_LENGTH, KDF_HASH_REPETITIONS)
            k2 = Utils.kdf(passphrase,rid,  KDF3_SALT, ENC_KEY_LENGTH, KDF_HASH_REPETITIONS)

            # 连接认证服务器
            sock = self.connect_and_get_socket(auth_server_address, auth_server_port, auth_server_name)
            out = sock.makefile('wb')

            # 发送请求类型
            out.write(bytes([REQ_TYPE_AUTHSERVER_RETRIEVAL]))
            send_bytes += 1

            # 发送 userID
            user_id_bytes = user_id.encode('utf-8')
            out.write(bytes([len(user_id_bytes)]))
            send_bytes += 1
            out.write(user_id_bytes)
            send_bytes += len(user_id_bytes)

            # 发送 t
            self._dbg("[TAKE] send t")
            self._dbg("[TAKE] t", t)
            out.write(bytes([len(t)]))
            send_bytes += 1
            out.write(t)
            send_bytes += len(t)
            out.flush()

            in_ = sock.makefile('rb')

            response_type = ord(in_.read(1))
            recv_bytes += 1
            if response_type == RESP_TYPE_OK:
                if self.verbose:
                    print("Retrieval protocol succeeded.")
            elif response_type == RESP_TYPE_ERROR:
                raise Exception("Auth Server error in Retrieval Protocol!")
            else:
                raise Exception("Unknown response from Auth Server!")

            self._dbg("1")
            ct_len = ord(in_.read(1))  # 假设长度是单字节
            recv_bytes += 1
            self._dbg("ct_len", ct_len)
            self._dbg("2")
            from se_ctr import CTR_IV_LEN, unwrap_key_ctr

            iv = in_.read(CTR_IV_LEN)
            recv_bytes += CTR_IV_LEN
            self._dbg("iv", iv)
            self._dbg("3")
            len__ct = ct_len - CTR_IV_LEN
            self._dbg("len__ct", len__ct)
            ct = in_.read(len__ct)  # AES-CTR 密文（无 tag）
            recv_bytes += len__ct
            self._dbg("ct ok")
            self._dbg("4")
            tao_len = ord(in_.read(1))
            recv_bytes += 1
            self._dbg("tao_len", tao_len)
            self._dbg("5")
            tao = in_.read(tao_len)
            recv_bytes += tao_len
            self._dbg("tao ok")
            self._dbg("6")

            # 计算 taoCal（H4 = HMAC-SHA256；可选绑定 ct2）
            ivct = iv + ct
            if ct2_path is not None:
                tao_cal = Utils.h4_hmac(
                    k2, ivct, ENC_KEY_LENGTH, ct2_path=ct2_path
                )
            else:
                tao_cal = Utils.h4_hmac(k2, ivct, ENC_KEY_LENGTH)

            if tao != tao_cal:
                raise Exception("User did not provide a valid tao.")

            # AES-CTR 解封装 MSK
            mskr = unwrap_key_ctr(k1, ivct)

            sock.close()
            # 论文字段：KS = id,t,ct,τ；S3 = id,pwd,rid,sid
            auth = comm_model.take_ks_fields(user_id)
            s3 = comm_model.s3_take_fields(user_id)
            self.last_comm = {"phase": "take", "auth": auth, "s3": s3}
            return mskr, int(auth["total"]), int(s3["total"])

        except Exception as e:
            print(f"Error in take(): {e}")
            raise e

    def deposit_plain_file(self, bucket_name: str, key3: str, source_file_path: str):
        try:
            with open(source_file_path, 'rb') as file:
                self.s3_client.upload_fileobj(file, bucket_name, key3)
            if self.verbose:
                print(f"Uploaded {source_file_path} to s3://{bucket_name}/{key3}")
        except FileNotFoundError:
            raise Exception(f"The file {source_file_path} was not found.")
        except ClientError as e:
            print(f"S3 Error during upload: {e}")
            raise e

    def retrieve_plain_big_file(self, bucket_name: str, key3: str, dest_file_path: str):
        try:
            obj = self.s3_client.get_object(Bucket=bucket_name, Key=key3)
            with open(dest_file_path, 'wb') as f:
                for chunk in obj['Body']:
                    f.write(chunk)
            if self.verbose:
                print(f"Downloaded s3://{bucket_name}/{key3} to {dest_file_path}")
        except ClientError as e:
            print(f"S3 Error during download: {e}")
            raise e
        except Exception as e:
            print(f"Error writing file: {e}")
            raise e

    def encrypt_ctr_big_file(self, source_path: str, dest_path: str, key: bytes) -> float:
        """明文 m：AES-256-CTR，格式 IV(16)‖ciphertext。"""
        from se_ctr import encrypt_file_ctr

        return encrypt_file_ctr(source_path, dest_path, key)

    def decrypt_ctr_big_file(self, source_path: str, dest_path: str, key: bytes):
        """明文 m：AES-256-CTR 解密。"""
        from se_ctr import decrypt_file_ctr

        decrypt_file_ctr(source_path, dest_path, key)

    def encrypt_gcm_big_file(self, source_path: str, dest_path: str, key: bytes) -> float:
        """明文 m：AES-256-GCM，格式 nonce(12)‖ciphertext‖tag(16)。"""
        from se_gcm import encrypt_file_gcm

        return encrypt_file_gcm(source_path, dest_path, key)

    def decrypt_gcm_big_file(self, source_path: str, dest_path: str, key: bytes):
        """明文 m：AES-256-GCM 解密。"""
        from se_gcm import decrypt_file_gcm

        decrypt_file_gcm(source_path, dest_path, key)

    def encrypt_file(self, source_path: str, dest_path: str, key: bytes,
                     file_cipher: str = "ctr") -> float:
        """按 file_cipher=ctr|gcm 加密明文文件。"""
        mode = (file_cipher or "ctr").strip().lower()
        if mode == "gcm":
            return self.encrypt_gcm_big_file(source_path, dest_path, key)
        return self.encrypt_ctr_big_file(source_path, dest_path, key)

    def decrypt_file(self, source_path: str, dest_path: str, key: bytes,
                     file_cipher: str = "ctr") -> None:
        """按 file_cipher=ctr|gcm 解密明文文件。"""
        mode = (file_cipher or "ctr").strip().lower()
        if mode == "gcm":
            self.decrypt_gcm_big_file(source_path, dest_path, key)
        else:
            self.decrypt_ctr_big_file(source_path, dest_path, key)

    def secure_deposit(self, bucket_name: str, key4: str,key5:str, skey: bytes,
                       source_file_path: str, internal_cipher_file_path: str) -> None:
        print("【DEBUG】secure_deposit")
        send_bytes = 0
        recv_bytes = 0

        internal_cipher_file_path = os.path.join(internal_cipher_file_path, key5)
        os.makedirs(os.path.dirname(internal_cipher_file_path), exist_ok=True)
        print("internal_cipher_file_path111", internal_cipher_file_path)
        try:
            enc_time = self.encrypt_ctr_big_file(
                source_file_path, internal_cipher_file_path, skey
            )
            print("【DEBUG】enc_time", enc_time)

            self.s3_client.upload_file(internal_cipher_file_path, bucket_name, key4)

        except (ClientError, BotoCoreError) as e:
            print(f"S3 Error during secure deposit: {e}")
            raise
        except Exception as e:
            print(f"Encryption error: {e}")
            raise

    def secure_retrieve(self, bucket_name: str, key2: str, skey: bytes, des_path: str,retry_max=3) -> None:
        if os.path.exists(des_path):
            os.remove(des_path)
        # Use in-memory buffer to prevent partial writes
        buffer = io.BytesIO()
        s3_stream = None

        for attempt in range(retry_max):
            try:

                try:
                    config = TransferConfig(
                        multipart_threshold=8 * 1024 * 1024,
                        multipart_chunksize=8 * 1024 * 1024,
                        max_concurrency=10,
                        use_threads=True
                    )
                    self.s3_client.download_fileobj(Bucket=bucket_name, Key=key2, Fileobj=buffer, Config=config)
                    buffer.seek(0)
                    break  # Success
                except IncompleteReadError as e:
                    print(f"[Retry {attempt + 1}/{retry_max}] IncompleteReadError: {e}, retrying...")
                    time.sleep(2)
            except Exception as e:
                print(f"[Retry {attempt + 1}/{retry_max}] Download failed: {e}, retrying...")
                time.sleep(2)
        else:
            raise RuntimeError(f"Failed to download {key2} after {retry_max} retries.")
        try:
            from se_ctr import CTR_IV_LEN, ctr_decrypt_stream

            iv = buffer.read(CTR_IV_LEN)
            with open(des_path, 'wb') as f_out:
                ctr_decrypt_stream(skey, iv, buffer, f_out)
            print(f"[Secure Retrieve] File saved to: {des_path}")
        except Exception as e:
            print(f"[Decrypt Error] {e}")
            raise

        finally:
            buffer.close()



    def secure_deposit_optimization(self, bucket_name: str, key2: str, skey: bytes, source_path: str,
                                    internal_cipher_file_path: str) -> int:
        file_size = os.path.getsize(source_path)
        part_number = max(1, round(math.sqrt(file_size / (1024 * 1024 * 20))))
        part_size = math.ceil(file_size / part_number)
        os.makedirs(internal_cipher_file_path, exist_ok=True)

        q = Queue(maxsize=5)
        enc_thread = EncThread(q, part_number, part_size, source_path, internal_cipher_file_path, skey)
        enc_thread.start()
        print("enc_thread.start()")
        print("internal_cipher_file_path:", internal_cipher_file_path)

        enc_thread.join()  # 等待加密完成再上传
        print("Encryption completed. Starting upload...")

        self.upload_file_parts_to_s3_11(q, part_number, internal_cipher_file_path, bucket_name, key2)

        return part_number

    def upload_file_parts_to_s3_11(self, q: Queue, part_number: int, cipher_path: str,
                                   bucket_name: str, key2: str):
        print("【DEBUG】enter upload_file_parts_to_s3")
        uploaded = 0
        try:
            while uploaded < part_number:
                index = q.get()  # 获取准备好的 part 索引
                file_path = os.path.join(cipher_path, f'EncPart{index}')
                key_part = f"{key2}/part{index}"

                with open(file_path, 'rb') as f:
                    self.s3_client.upload_fileobj(f, bucket_name, key_part)

                uploaded += 1
                if self.verbose:
                    print(f"Uploaded part {index}")
        except Exception as e:
            print(f"S3 upload error: {e}")
            raise

    def upload_file_parts_to_s3(self, enc_list: List[int], part_number: int, cipher_path: str,
                                bucket_name: str, key2: str):
        print("【DEBUG】enter upload_file_parts_to_s3")
        try:
            # Enable Transfer Acceleration
            try:
                self.s3_client.put_bucket_accelerate_configuration(
                    Bucket=bucket_name,
                    AccelerateConfiguration={'Status': 'Enabled'}
                )
            except Exception as e:
                print(f"Failed to enable accelerate mode: {e}")

            index = 0
            while index < part_number:
                index += 1
                while len(enc_list) < index:
                    time.sleep(0.1)

                file_path = f"{cipher_path}EncPart{index}"
                key_part = f"{key2}/part{index}"

                with open(file_path, 'rb') as f:
                    self.s3_client.upload_fileobj(f, bucket_name, key_part)

                if self.verbose:
                    print(f"Uploaded part {index}")

        except (ClientError, BotoCoreError) as e:
            print(f"S3 Error during upload: {e}")
            raise

    def secure_retrieve_optimization(self, part_number: int, bucket_name: str, key2: str,
                                     skey: bytes, des_path: str, internal_cipher_file_path: str):
        dec_streams = []

        dec_thread = StreamDecThread(dec_streams, internal_cipher_file_path, des_path, skey, part_number)
        dec_thread.start()

        for i in range(part_number):
            part_key = f"{key2}/part{i + 1}"
            response = self.s3_client.get_object(Bucket=bucket_name, Key=part_key)
            stream = response['Body']
            dec_streams.append(stream)

        dec_thread.join()

        for stream in dec_streams:
            stream.close()


# if __name__ == "__main__":
#
#     # source_file_path = sys.argv[2]
#
#     config = configparser.ConfigParser()
#     config.read("config.properties")
#
#     access_key_id = config.get("DEFAULT", "accessKeyId", fallback=None)
#     secret_key_id = config.get("DEFAULT", "secretKeyId", fallback=None)
#     region_name = config.get("DEFAULT", "regionName", fallback=None)
#     bucket_name = config.get("DEFAULT", "bucketName", fallback=None)
#
#     client = Client(access_key_id, secret_key_id, region_name, bucket_name)
#     client.start()








