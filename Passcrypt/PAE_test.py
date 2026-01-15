import configparser
import gzip
import os
import secrets  #用于生成安全的随机数
import shutil
import struct

import boto3

from aEKE import AEKEProtocol
import socket
import pickle
import time
from boto3.s3.transfer import TransferConfig
import paramiko
from io import BytesIO


metrics_total = {
            "PAE_Ext_time":0,
            "PAE_Enc_time": 0,
            "PAE_Dec_time": 0}

PAE_ext_time =0
PAE_enc_time =0
PAE_dec_time =0


def PAE_kgen(protocol, uid, pw):
    sk = secrets.randbelow(protocol.P)
    pk = pow(protocol.G, sk, protocol.P)
    return sk,pk

def PAE_ext(protocol, uid, pw, st):
    a_bytes = protocol.H_new(uid, pw, st)
    return int.from_bytes(a_bytes, 'big')  # 转换为整数返回



def PAE_enc(protocol, uid, pw, pk, st, m_path, inter_path1,k5):
    start_time = time.time()
    a = PAE_ext(protocol, uid, pw, st)
    print("enc_a:", a)
    r = secrets.randbelow(protocol.P)
    u = pow(protocol.G, r, protocol.P)
    val = (a % protocol.P) * pow(pk, r, protocol.P) % protocol.P
    print("val:", val)
    val_bytes = val.to_bytes((val.bit_length() + 7) // 8, 'big')
    print("enc_val:", val_bytes)
    u0 = protocol.H_double_prime(uid, val_bytes)
    print("uid", uid)
    print("val",val_bytes)

    k = secrets.randbelow(protocol.P)
    print("u0:", u0.hex())
    c0 = protocol.AES_encrypt(u0, k.to_bytes(32, 'big'))

    ciphertext_stream = protocol.AES_encrypt_streaming(k, m_path, inter_path1, k5)
    end_time = time.time()
    PAE_enc_time = (end_time - start_time) * 1000

    print("PAE_enc_time: {:.2f} ms".format(PAE_enc_time))
    ciphertext_stream = BytesIO()
    protocol.AES_encrypt_streaming_to_stream(k, m_path, ciphertext_stream, k5)
    ciphertext_stream.seek(0)
    return ciphertext_stream, c0, u ,PAE_enc_time

def PAE_dec(protocol, uid, pw, u_sk,  dest_path,k1, st, ciphertext_stream, c0):
    a = PAE_ext(protocol, uid, pw, st)
    print("dec_a:", a)
    u_prime = ((a % protocol.P) * u_sk) % protocol.P
    print("u_prime:", u_prime)
    print("dec_prime:", u_prime)
    val_bytes = u_prime.to_bytes((u_prime.bit_length() + 7) // 8, 'big')
    print("dec_val_bytes:", val_bytes)
    u1 = protocol.H_double_prime(uid, val_bytes)
    print("uid", uid)
    print("val",val_bytes)
    print("u1",u1.hex())
    k = int.from_bytes(protocol.AES_decrypt(u1, c0), 'big')

    m_path = protocol.AES_decrypt_streaming_from_stream(k, ciphertext_stream, dest_path, k1)

    return m_path

if __name__ == "__main__":
    # Example usage
    # 从 config.properties 加载配置
    config = configparser.ConfigParser()
    with open("config.properties", "r", encoding="utf-8") as f:
        config.read_file(f)
    access_key_id = config.get("DEFAULT", "accessKeyId", fallback=None)
    secret_key_id = config.get("DEFAULT", "secretKeyId", fallback=None)
    region_name = config.get("DEFAULT", "regionName", fallback=None)
    bucket_name = config.get("DEFAULT", "bucketName", fallback=None)

    protocol = AEKEProtocol(region_name, access_key_id, secret_key_id, key_len=24, verbose=True)
    uid = "user123"
    pw = "password123"
    k1 = f"decrypted_data"
    dec_path = "./dec_file/"
    inter_path1 = "./inter_file/"

    sk,pk = PAE_kgen(protocol, uid, pw)
    st = secrets.token_bytes(16)  # Example session token
    m_path = "./500mb"  # Path to the file to be encrypted
    k5 = "c1_path_111"  # Example key for encryption
    for i in range(5):
        print(f"\n======== 第 {i+1} 轮测试 ========")
        start_time = time.time()
        a = PAE_ext(protocol,uid,pw,st)
        end_time = time.time()
        PAE_ext_time = (end_time - start_time) * 1000

        ciphertext_stream, c0, u ,PAE_enc_time= PAE_enc(protocol, uid, pw,  pk, st, m_path,inter_path1, k5)

        # print(f"Ciphertext Stream: {ciphertext_stream.getvalue()[:64]}...")  # Print first 64 bytes for brevity
        u_sk = pow(u, sk, protocol.P)   # Example user secret key derived from u and sk
        start_time = time.time()
        decrypted_stream = PAE_dec(protocol, uid, pw, u_sk, dec_path,k5, st, ciphertext_stream, c0)
        end_time = time.time()
        PAE_dec_time = (end_time - start_time) * 1000

        print("PAE_enc_time: {:.2f} ms".format(PAE_enc_time))
        print("PAE_dec_time: {:.2f} ms".format(PAE_dec_time))

        metrics_total["PAE_Ext_time"] += PAE_ext_time
        metrics_total["PAE_Enc_time"] += PAE_enc_time
        metrics_total["PAE_Dec_time"] += PAE_dec_time

    print("\n======== 📊 平均耗时统计（单位：ms）========")
    for key in metrics_total:
        avg_time = metrics_total[key] / 5
        print(f"{key}: {avg_time:.2f} ms")