import time
from aEKE import AEKEProtocol
from boto3.s3.transfer import TransferConfig
from utils import *
import secrets
import socket
import pickle
from Crypto.Random import get_random_bytes
from botocore.exceptions import NoCredentialsError, ClientError
import Constants
import struct
import boto3
import io
import gzip
import os
import shutil


def server_run_register(protocol,conn,run_time,run_scale):
    print("[SERVER] 等待客户端注册！")
    start_time = time.time()
    communication_scale = 0
    pk = protocol.pk
    bytes_sent = send_with_length(conn, pk) ### ▲▲▲▲▲ 发送公钥
    payload,byte_scale = recv_with_length(conn)## ●●●●● 接收uid、gs、e1，e2，A，存储起来
    uid = payload['uid']
    gs = payload['gs']
    e1 = payload['e1']
    e2 = payload['e2']
    A = payload['A']
    protocol.user_db[uid] = {'uid': uid, 'e1': e1, 'e2': e2, 'gs': gs, 'A': A,'pk':protocol.pk,'sk':protocol.sk}
    byte_scale = send_with_length(conn,1)# ▲▲▲▲▲ 发送确认值
    server_run_register_time = (time.time() - start_time) * 1000
    print(f"[SERVER] server_run_register_time: {server_run_register_time:.2f} ms")
    # protocol.user_time_server1[uid]["server_aEKE_time1"] = aEKE_time1
    run_time["server_run_register_time"] = server_run_register_time
    run_scale["server_run_register_time"] = server_run_register_time
    print("[SERVER] 客户端注册成功！")



def server_run_enc(protocol: AEKEProtocol, bucketname:str,k0:str,run_time:dict,conn:socket,c1_path_1,k5,run_scale):  # 服务器端运行函数
    print(f"##########与客户端建立安全信道#########")
    try:
        # ------------------------------------aEKE time↓--------------------------------------------------------##
        start_time = time.time()
        print("[SERVER] start_time", start_time)
        uid,byte_scale = recv_with_length(conn) # ●●●●● 接收用户id
        if uid not in protocol.user_db:
            print(f"[SERVER] User '{uid}' not found!")
            return
        gs = protocol.user_db[uid]['gs']
        st = pow(gs, protocol.sk, protocol.P)
        print("[SERVER] gs", gs)
        print("[SERVER] st",st)
        byte_scale = send_with_length(conn,st) # ▲▲▲▲▲ 发送st

        e1 = protocol.user_db[uid]['e1']
        e2 = protocol.user_db[uid]['e2']
        print("[SERVER] e1",e1.hex())
        print("[SERVER] e2",e2.hex())
        A = protocol.user_db[uid]['A']
        y = secrets.randbelow(protocol.P)  # 服务器临时私钥
        Y = pow(protocol.G, y, protocol.P) # 服务器临时公钥
        f1 = protocol.IC_encrypt(e2, Y.to_bytes(32, 'big'))  # 用理想密码加密 Y,得到f1

        f0, byte_scale = recv_with_length(conn)  # ●●●●● 接收f0
        byte_scale = send_with_length(conn,f1) # ▲▲▲▲▲ 发送f1

        X_prime = int.from_bytes(protocol.IC_decrypt(e1, f0), byteorder='big')
        d1 = protocol.H_prime(uid, st, X_prime)  # 计算 d0
        A_pow_d1 = pow(A, d1, protocol.P)
        l1 = pow((X_prime * A_pow_d1) % protocol.P, y, protocol.P)
        k_server = protocol.H_double_prime(uid, X_prime, l1)

        data = pickle.loads(conn.recv(4096))  # ●●●●● 接收回传 1
        print(f"[SERVER] Shared key: {k_server.hex()}")
        aEKE_time1= (time.time() - start_time) * 1000
        print(f"[SERVER] aEKE耗时: {aEKE_time1:.2f} ms")
        # protocol.user_time_server1[uid]["server_aEKE_time1"] = aEKE_time1
        run_time["server_enc_PAKE_time"] = aEKE_time1
        run_scale["server_enc_PAKE_time"] = aEKE_time1
        print(f"##########成功建立安全信道!#########")
        ###----------------------------------------aEKE time 👆----------------------------------------------##

        # start_time1= time.time()
        pk = protocol.user_db[uid]['pk']
        print(f"[SERVER] protocol.pk,{pk}")
        bytes_sent = send_with_length(conn, pk)# ▲▲▲▲▲ 发送公钥pk

        print("[SERVER] 正在等待接收客户端上传的加密文件...")
        c0 = recv_bytes_with_length(conn) # ●●●●● 接收c0
        u = recv_bytes_with_length(conn) # ●●●●● 接收u
        sent_bytes = send_with_length(conn, 1)  # ▲▲▲▲▲
        ack1,bytes=recv_with_length(conn) # ●●●●● 接收文件上传成功的确认值
        print("[SERVER] 文件上传成功",ack1)

        # start_time3 = time.time()
        k0_filename = f"{uid}_s3s3"
        s3_key = f"{uid}/{k0_filename}"
        #将T,v,c,ctr存储在user_db中
        protocol.user_db[uid]['u'] = u
        protocol.user_db[uid]['c0'] = c0
        protocol.user_db[uid]['c'] = f"s3://{bucketname}/{s3_key}"
        print(protocol.user_db[uid])
        print("######################## Sever存储成功！###############################")
        print()
        print()

        server_run_enc_time = (time.time() - start_time) * 1000
        print(f"[SERVER] 安全存储耗时: {server_run_enc_time:.2f} ms")
        # protocol.user_time_server1[uid]["server_run_enc_time"] = server_run_enc_time
        run_time["server_run_enc_time"] = server_run_enc_time
        run_scale["server_run_enc_time"] = server_run_enc_time

        # print("[SERVER] 运行时间protocol.user_time_server1：", protocol.user_time_server1[uid])
        try:
            ack,bytes = recv_with_length(conn)  # ●●●●● 接收ACK
            print(f"[SERVER] 收到服务器ACK: {ack}")
            print(f"[SERVER] ack==={type(ack)}")
            if ack == 1:
                print("[SERVER] ✅ 上传成功，服务器已确认接收")
            else:
                print("[SERVER] ⚠️ 未收到有效ACK")
        except Exception as e:
            print(f"[SERVER] ❌ 接收ACK失败: {e}")
    except Exception as e:
        print("[SERVER] 错误:", e)



#Server收到解密请求
def server_run_dec(protocol: AEKEProtocol, server_id: str,bucketname:str,k0:str,run_time:dict,conn:socket,server_aeke_path,k6,run_scale):  # 服务器端运行函数
        print("##########Server端收到下载请求#########")
        # ------------------------------------aEKE time↓--------------------------------------------------------##
        start_time = time.time()
        uid, byte_scale = recv_with_length(conn) # ●●●●●接收uid
        if uid not in protocol.user_db:
            print(f"[SERVER] User '{uid}' not found!")
            return
        gs = protocol.user_db[uid]['gs']
        print("[SERVER] gs", gs)
        st = pow(gs, protocol.sk, protocol.P)
        print("[SERVER] st", st)
        byte_scale = send_with_length(conn, st) # ▲▲▲▲▲ 发送随机数st

        e1 = protocol.user_db[uid]['e1']
        e2 = protocol.user_db[uid]['e2']
        print("[SERVER] e1", e1.hex())
        print("[SERVER] e2", e2.hex())
        A = protocol.user_db[uid]['A']
        y = secrets.randbelow(protocol.P)  # 服务器临时私钥
        Y = pow(protocol.G, y, protocol.P)  # 服务器临时公钥
        f1 = protocol.IC_encrypt(e2, Y.to_bytes(32, 'big'))  # 用理想密码加密 Y,得到f1

        f0, byte_scale = recv_with_length(conn) # ●●●●● 接收f0
        byte_scale = send_with_length(conn, f1) # ▲▲▲▲▲ 发送f1

        X_prime = int.from_bytes(protocol.IC_decrypt(e1, f0), byteorder='big')
        d1 = protocol.H_prime(uid, st, X_prime)  # 计算 d0
        A_pow_d1 = pow(A, d1, protocol.P)
        l1 = pow((X_prime * A_pow_d1) % protocol.P, y, protocol.P)
        k_server = protocol.H_double_prime(uid, X_prime, l1)

        data = pickle.loads(conn.recv(4096))  # ●●●●● 接收回传 1
        print(f"[SERVER] Shared key: {k_server.hex()}")
        print()
        server_dec_PAKE_time = (time.time() - start_time) * 1000
        print(f"[SERVER] PAKE耗时: {server_dec_PAKE_time:.2f} ms")
        # protocol.user_time_server1[uid]["server_aEKE_time1"] = aEKE_time1
        run_time["server_dec_PAKE_time"] =server_dec_PAKE_time
        run_scale["server_dec_PAKE_time"] = server_dec_PAKE_time
        print(f"##########成功建立安全信道!#########")
        ###----------------------------------------aEKE time 👆----------------------------------------------##

        start_time1 = time.time()
        pk = protocol.user_db[uid]['pk']
        print(f"[SERVER] protocol.pk,{pk}")
        bytes_sent = send_with_length(conn, pk) # ▲▲▲▲▲ 发送公钥pk

        config = TransferConfig(multipart_threshold=8 * 1024 * 1024, max_concurrency=4)
        k0_filename = f"{uid}_s3s3"
        print("[SERVER]【DEBUG】k0", k0_filename)
        s3_key = f"{uid}/{k0_filename}"

        u = protocol.user_db[uid]['u']
        u_int= int.from_bytes(u, 'big')#将u转为int型
        usk = pow(u_int, protocol.user_db[uid]['sk'], protocol.P)
        bytes_sent = send_with_length(conn, 1) # ▲▲▲▲▲ 发送ack
        byte_scale = send_with_length(conn, usk.to_bytes(32, 'big')) # ▲▲▲▲▲ 发送usk
        c0 = protocol.user_db[uid]['c0']
        byte_scale = send_with_length(conn,c0) # ▲▲▲▲▲ 发送
        ack,byte_scale = recv_with_length(conn) # ●●●●● 接收确认值
        print("[SERVER] 加密密文已直接发送给客户端")
        server_run_dec_time = (time.time() - start_time) * 1000
        print(f"[SERVER] server_run_dec_time 耗时: {server_run_dec_time:.2f} ms")
        # protocol.user_time_server1[uid]["server_aEKE_time1"] = aEKE_time1
        run_time["server_run_dec_time"] = server_run_dec_time
        run_scale["server_run_dec_time"] = server_run_dec_time
        # # 等待客户端确认接收
        # try:
        #     # conn.settimeout(100)
        #     # ack = conn.recv(2)
        #     ack = recv_with_length(conn)
        #     if ack == b'OK':
        #         print("[SERVER] ✅ 客户端确认接收成功")
        #     else:
        #         print("[SERVER] ⚠️ 客户端响应异常")
        # except socket.timeout:
        #     print("[SERVER] ⚠️ 未收到客户端确认（可能断开了）")
        # print("[SERVER] 运行时间protocol.user_time_server2：", protocol.user_time_server2[uid])


def start_file_echo_server(protocol:AEKEProtocol,bucketname,conn):
            # 接收客户端发送的数据
            ack1 = recv_with_length(conn)
            print("[SERVER] 文件上传成功", ack1)
            ack2 = recv_with_length(conn)
            print("[SERVER] 文件上传成功", ack2)
