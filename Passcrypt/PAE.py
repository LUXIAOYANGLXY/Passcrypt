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

def PAE_kgen(protocol, uid, pw):
    sk = secrets.randbelow(protocol.P)
    pk = pow(protocol.G, sk, protocol.P)
    return sk,pk

def PAE_ext(protocol, uid, pw, st):
    a_bytes = protocol.H_new(uid, pw, st)
    return int.from_bytes(a_bytes, 'big')  # 转换为整数返回



def PAE_enc(protocol, uid, pw, pk, st, m_path, inter_path1,k5):
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

    c_path = protocol.AES_encrypt_streaming(k, m_path, inter_path1, k5)
    return c_path, c0, u

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
    m_path = "./1mb"  # Path to the file to be encrypted
    k5 = "c1_path_111"  # Example key for encryption
    ciphertext_stream, c0, u = PAE_enc(protocol, uid, pw,  pk, st, m_path,inter_path1, k5)
    # print(f"Ciphertext Stream: {ciphertext_stream.getvalue()[:64]}...")  # Print first 64 bytes for brevity
    u_sk = pow(u, sk, protocol.P)   # Example user secret key derived from u and sk

    decrypted_stream = PAE_dec(protocol, uid, pw, u_sk, dec_path,k5, st, ciphertext_stream, c0)
