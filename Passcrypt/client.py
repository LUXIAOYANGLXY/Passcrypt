import os
from aEKE import AEKEProtocol
import time
from boto3.s3.transfer import TransferConfig
from PAE import PAE_kgen,PAE_ext,PAE_enc,PAE_dec,PAE_ext1,PAE_enc1,PAE_dec1
from utils import *
import secrets  #用于生成安全的随机数
import socket
import pickle
from io import BytesIO
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

####——————————————————————————————————————————————————————————————————————————————————————————————————————————————————————###

def gs_generate(protocol,secure_level,gs,uid,eta,k):
    gs_send = gs
    if secure_level == 3 or secure_level == 2:
        gs_send = protocol.serialize_pubkey(gs)
    return gs_send

def client_get_st(protocol: AEKEProtocol,st_rec,eta,uid,k,secure_level):
    st = st_rec
    if secure_level == 2 or secure_level == 3:
        st = st_rec
    return st

def client_run_register(protocol,uid, pw,run_time,secure_level,eta=0, k=0):
    HOST = '54.250.***.**'  # The server's hostname or IP address客户端将连接本地运行的服务器
    PORT = 5202  # The port used by the server客户端与服务器通信的端口
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        print("★★★client开始注册★★★")
        communication_scale = 0
        payload = {'secure_level':secure_level,'type': 'reg'}
        sent_bytes = send_with_length(sock, payload)###与服务器端执行注册过程,选择注册过程
        communication_scale += sent_bytes #11111111111111111111111

        start_time = time.time()
        # 接收客户端传过来的公钥pk
        pk,bytes_scale = recv_with_length(sock)# ●●●●● 接收公钥pk
        communication_scale += bytes_scale  #11111111111111111111111
        # 将字节转为曲线点对象
        peer_pk_obj = protocol.deserialize_pubkey(pk)

        if secure_level == 2 or secure_level == 3:
            s0 = secrets.randbelow(protocol.N)
            s0_priv_obj = ec.derive_private_key(s0, protocol.ec_curve, default_backend())
            st0 = s0_priv_obj.exchange(ec.ECDH(), peer_pk_obj)
            print("[CLIENT] st0:",st0.hex())
            gs0 = s0_priv_obj.public_key()
            print("[CLIENT] gs:",gs0)

            a = protocol.H_new(uid,pw,st0) # H_new函数返回的是byte类型
            a_int = int.from_bytes(a, byteorder='big')% protocol.N
            A_priv_obj = ec.derive_private_key(a_int, protocol.ec_curve, default_backend())
            A_point = A_priv_obj.public_key()
            A = protocol.serialize_pubkey(A_point)
            h_material = protocol.H(uid, pw, a)  ###
            e1 = h_material[:protocol.KEY_LEN]
            e2 = h_material[protocol.KEY_LEN:2 * protocol.KEY_LEN]
            print("[CLIENT] e1:", e1.hex())
            print("[CLIENT] e2:", e2.hex())

            gs_send0 = gs_generate(protocol,secure_level,gs0,uid,eta,k)
            print("[Client]gs_send0:",gs_send0.hex())

            payload = {'uid': uid, 'e1': e1, 'e2': e2, 'gs0': gs_send0, 'A': A}
            sent_bytes = send_with_length(sock, payload)# ▲▲▲▲▲ 将uid，e1，e2，A，gs发送到服务器进行保存
            communication_scale += sent_bytes  #11111111111111111111111

            ack,bytes_received = recv_with_length(sock) ## ●●●●● 接收确认值
            communication_scale += bytes_received  #11111111111111111111111
        elif secure_level ==1:
            st_scalar = secrets.randbelow(protocol.N)
            st = st_scalar.to_bytes(32, 'big')

            a = protocol.H_new(uid, pw, st)  # H_new函数返回的是byte类型
            a_int = int.from_bytes(a, byteorder='big') % protocol.N
            A_point = ec.derive_private_key(a_int, protocol.ec_curve, default_backend()).public_key()
            A = protocol.serialize_pubkey(A_point)

            h_material = protocol.H(uid, pw,a)
            e1 = h_material[:protocol.KEY_LEN]
            e2 = h_material[protocol.KEY_LEN:2 * protocol.KEY_LEN]

            payload = {'uid': uid, 'e1': e1, 'st':st,'e2': e2, 'A': A}
            sent_bytes = send_with_length(sock, payload)  # ▲▲▲▲▲ 将uid，e1，e2，A，gs发送到服务器进行保存
            communication_scale += sent_bytes  # 11111111111111111111111

            ack, bytes_received = recv_with_length(sock)  ## ●●●●● 接收确认值
            communication_scale += bytes_received  # 11111111111111111111111
        register_time = (time.time() - start_time) * 1000
        print(f"[CLIENT]register_time 耗时: {register_time:.2f} ms")
        protocol.user_time_client[uid]["register_time"] = register_time
        run_time["register_time"] = register_time
        protocol.user_time_client[uid]["client_register_bytes"] = communication_scale
        run_time["client_register_bytes"] = communication_scale
        print("[CLIENT] 注册的ack：",ack)
        print("★★★注册成功★★★")




#####————————————————————————————————————————————————————————————————————————————————————————————————————————————————####

def client_run_enc1(protocol: AEKEProtocol, source_file_path,run_time,uid, pw_input,inter_path1,k44,bucket_name,secure_level):    #TODO
    print("###############客户端请求与server建立socket连接###############")
    HOST = '54.250.***.**'  # The server's hostname or IP address客户端将连接本地运行的服务器
    PORT = 5202  # The port used by the server客户端与服务器通信的端口
    total_bytes = 0
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s: #创建一个TCP套接字对象s，用于与服务器进行通信，AF_INET 表示 IPv4 地址族，SOCK_STREAM 表示 TCP 协议
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8 * 1024 * 1024)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
        s.connect((HOST, PORT))
        print(f"[CLIENT] enter socket.connect!")
        payload = {'secure_level':secure_level,'type': 'enc'}
        sent_bytes=send_with_length(s,payload) # 选择加密流程
        # total_bytes += sent_bytes   #11111111111111111111111
        ##----------------------------------------PAE_Enc time ↓----------------------------------------------##
        start_time = time.time()
        sent_bytes = send_with_length(s, uid) # ▲▲▲▲▲ 发送uid
        total_bytes += sent_bytes  # 11111111111111111111111

        print("★★★客户端加密数据★★★")
        print("[CLIENT] 运行PAE")
        pk_bytes,byte_scale = recv_with_length(s) # ▲▲▲▲▲ 接收公钥pk
        pk = protocol.deserialize_pubkey(pk_bytes)  # 变回 ECPublicKey 对象
        total_bytes += byte_scale ##11111111111111111111111111
        st, byte_scale = recv_with_length(s)  # ▲▲▲▲▲ 接收st
        total_bytes += byte_scale  ##11111111111111111111111111

        print("[CLIENT] pk:", pk)
        start_time1 = time.time()
        a_int = PAE_ext(protocol,uid,pw_input,st)
        print("[CLIENT] a_int:",a_int)
        PAE_Ext_time1 = (time.time() - start_time1) * 1000
        print(f"[CLIENT] PAE_Ext 耗时: {PAE_Ext_time1:.2f} ms")
        protocol.user_time_client[uid]["PAE_Ext_time1"] = PAE_Ext_time1
        run_time["PAE_Ext_time1"] = PAE_Ext_time1
        
        MSG_TYPE_KEY = 0x01
        header = (
                uid.encode() +
                secure_level.to_bytes(1, "big") +
                MSG_TYPE_KEY.to_bytes(1, "big")
        )

        start_time2 = time.time()
        c_path, c0, u = PAE_enc(protocol,uid,pw_input,pk,st,source_file_path,inter_path1, k44,header) #PAE_Enc过程
        PAE_Enc_time= (time.time() - start_time2) * 1000
        print(f"[CLIENT] PAE Enc 耗时: {PAE_Enc_time:.2f} ms")
        protocol.user_time_client[uid]["PAE_Enc_time"] = PAE_Enc_time
        run_time["PAE_Enc_time"] = PAE_Enc_time
        print("[CLIENT] 加密成功！")
        print("[CLIENT] u", u)
        print("[CLIENT] c0", c0.hex())
        send_bytes_with_length(s, c0)  # ▲▲▲▲▲ 发送c0
        total_bytes += 4 + len(c0)  ##11111111111111111111111111
        u_bytes = protocol.serialize_pubkey(u)
        send_bytes_with_length(s, u_bytes)  # ▲▲▲▲▲ 发送u
        total_bytes += 4 + len(u_bytes)  ##11111111111111111111111111
        # print("[CLIENT] 333333333")
        ack1, bytes = recv_with_length(s)  # ●●●●● 密钥文件上传成功的确认值
        print("[CLIENT] 文件上传成功", ack1)
        PAE_Enc_commucation_time = (time.time() - start_time2) * 1000
        print(f"[CLIENT] PAE Enc commucation 耗时: {PAE_Enc_commucation_time:.2f} ms")
        protocol.user_time_client[uid]["PAE_Enc_commucation_time"] = PAE_Enc_commucation_time
        run_time["PAE_Enc_commucation_time"] = PAE_Enc_commucation_time
        #-------------------------------------------------------------------------------------------------------#
        ###-------------------------------------upload time---------------------------------------------------###
        #将文件传到s3上
        start_time3 = time.time()   ####222222
        # try:
        #     BUFFER_SIZE = 4*1024 * 1024
        #     protocol.s3_client.put_bucket_accelerate_configuration(
        #         Bucket=bucket_name,
        #         AccelerateConfiguration={'Status': 'Enabled'}
        #     )
        #     protocol.s3_client.upload_file(c_path, bucket_name, f"{uid}/{uid}_s3s3")
        #     sent_bytes = send_with_length(s, 1) # ▲▲▲▲▲ 发送密文文件上传成功的确认消息
        #     total_bytes += sent_bytes ##11111111111111111111111111
        # except Exception as e:
        #     print(f"[CLIENT] 密文发送失败: {e}")
        #     return   #####2222
        sent_bytes = send_with_length(s, 1)  # ▲▲▲▲▲ 发送确认消息
        total_bytes += sent_bytes  ##11111111111111111111111111
        client_upload_file_time= (time.time() - start_time3) * 1000
        print(f"[CLIENT] client上传密文文件耗时: {client_upload_file_time:.2f} ms")
        protocol.user_time_client[uid]["client_upload_file_time"] = client_upload_file_time
        run_time["client_upload_file_time"] = client_upload_file_time

        client_secure_deposit_time = (time.time() - start_time) * 1000
        print(f"[CLIENT]client_secure_deposit_time 耗时: {client_secure_deposit_time:.2f} ms")
        protocol.user_time_client[uid]["client_secure_deposit_time"] = client_secure_deposit_time
        run_time["client_secure_deposit_time"] = client_secure_deposit_time
        protocol.user_time_client[uid]["client_enc_bytes"] = total_bytes
        run_time["client_enc_bytes"] = total_bytes
        s.close()
        return c_path  # 2222


#客户端请求解密
def client_run_dec1(protocol: AEKEProtocol, dest_path:str,k1:str,run_time:dict,uid: str, pw_input: str,bucketname:str,secure_level,c_path):
    HOST = '54.250.***.**'  # The server's hostname or IP address客户端将连接本地运行的服务器
    PORT = 5202  # The port used by the server客户端与服务器通信的端口
    total_bytes =0
    with (socket.socket(socket.AF_INET,
                       socket.SOCK_STREAM) as s):  # 创建一个TCP套接字对象s，用于与服务器进行通信，AF_INET 表示 IPv4 地址族，SOCK_STREAM 表示 TCP 协议
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8 * 1024 * 1024)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
        # s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 256 * 1024)
        s.connect((HOST, PORT))
        print()
        print()
        print("[CLIENT] 客户端请求解密")
        payload = {'secure_level':secure_level,'type': 'dec'}
        sent_bytes=send_with_length(s, payload)##选择解密模式
        print(f"[CLIENT] 字节数 sent: {sent_bytes}")
        total_bytes += sent_bytes #11111111111111111111111111
        #------------------------------------aEKE time ↓---------------------------------------------------------#
        start_time = time.time()
        flag = 1
        while flag:
            sent_bytes = send_with_length(s, uid)  # ▲▲▲▲▲ 发送uid
            total_bytes += sent_bytes  # 11111111111111111111111111
            st, byte_scale = recv_with_length(s)  # ▲▲▲▲▲ 接收st
            total_bytes += byte_scale  ##11111111111111111111111111

            a = protocol.H_new(uid, pw_input,st)
            a_int = int.from_bytes(a, byteorder='big') % protocol.N
            A_point = ec.derive_private_key(a_int, protocol.ec_curve, default_backend()).public_key()
            A = protocol.serialize_pubkey(A_point)

            h_material = protocol.H(uid, pw_input,a)
            e1 = h_material[:protocol.KEY_LEN]
            e2 = h_material[protocol.KEY_LEN:2 * protocol.KEY_LEN]
            print("[CLIENT] e1:", e1.hex())
            print("[CLIENT] e2:", e2.hex())

            payload = {'A':A}
            # bytes_sent = send_with_length(s, f0)  # ▲▲▲▲▲ 发送A/e1
            bytes_sent = send_with_length(s, payload)  # ▲▲▲▲▲ 发送A/e1
            total_bytes += bytes_sent  # 11111111111111111111111111

            flag, received_bytes = recv_with_length(s) #  ●●●●● 接收 flag
            print(f"字节数 received: {received_bytes}")
            total_bytes += received_bytes  # 11111111111111111111111111

            if flag == -1:
                print("[Client] 用户未注册或非法用户！")
                exit()
            if flag == 1:
                print("[Client] 口令错误！请重新输入")
                pw_input = input("请输入密码: ").strip()
            if flag == -2:
                print("[Client] 口令输入错误，账户已锁定！")
                exit()

        #--------------------------------------------接收密文时间---------------------------------------------------###
        print("[CLIENT] 客户端请求检索数据")
        start_time1 = time.time()
        # ===== Step1: 接收文件 =====
        # buf = BytesIO()
        # config = TransferConfig(
        #     multipart_threshold=8 * 1024 * 1024,
        #     multipart_chunksize=8 * 1024 * 1024,
        #     max_concurrency=10,
        #     use_threads=True
        # )
        # protocol.s3_client.download_fileobj(bucketname, f"{uid}/{uid}_s3s3", buf, Config=config)
        # buf.seek(0)
        with open(c_path, "rb") as f_in:
            encrypted_data = f_in.read()  # 把整个文件读入内存
        # 将字节内容封装成 BytesIO 流对象
        buf = BytesIO(encrypted_data)
        client_download_file_time = (time.time() - start_time1) * 1000
        print(f"[CLIENT] client从s3下载密文文件耗时: {client_download_file_time:.2f} ms")
        protocol.user_time_client[uid]["client_download_file_time"] = client_download_file_time
        run_time["client_download_file_time"] = client_download_file_time
        #--------------------------------------------------------------------------------------------------------###
        ##----------------------------------------PAE Dec time ↓----------------------------------------------##
        start_time2 = time.time()
        a_int = PAE_ext(protocol, uid, pw_input,st)
        PAE_Ext_time2 = (time.time() - start_time2) * 1000
        print(f"[CLIENT] PAE_Ext_time2 耗时: {PAE_Ext_time2:.2f} ms")
        protocol.user_time_client[uid]["PAE_Ext_time2"] =PAE_Ext_time2
        run_time["PAE_Ext_time2"] = PAE_Ext_time2

        start_time3 = time.time()
        ack ,bytes_received = recv_with_length(s)# ●●●●● 接收确认值
        print("[CLIENT] ack:", ack)
        pk, byte_scale = recv_with_length(s) # ●●●●● 接收公钥pk
        total_bytes += byte_scale # 11111111111111111111111111
        usk_byte,received_bytes = recv_with_length(s) # ●●●●● 接收 usk
        total_bytes += received_bytes  # 11111111111111111111111111
        c0,received_bytes = recv_with_length(s) # ●●●●● 接收c0
        total_bytes += received_bytes  # 11111111111111111111111111
        print("[CLIENT] pk:", pk)
        print("[CLIENT] usk_byte:", usk_byte.hex())
        print("[CLIENT] received_c0",c0.hex())

        sent_bytes=send_with_length(s,1) # ▲▲▲▲▲ 发送确认值
        total_bytes += sent_bytes #11111111111111111111111111111111111111111
        usk = int.from_bytes(usk_byte, byteorder='big') % protocol.N #将usk_byte转为int
        #--------------------------------------------PAE_Dec解密时间---------------------------------------------------###
        MSG_TYPE_KEY = 0x01
        header = (
                uid.encode() +
                secure_level.to_bytes(1, "big") +
                MSG_TYPE_KEY.to_bytes(1, "big")
        )

        start_time4 = time.time()
        m_path = PAE_dec(protocol, uid, pw_input, usk, dest_path, k1,st, buf, c0,header)
        PAE_Dec_time= (time.time() - start_time4) * 1000
        print(f"[CLIENT] PAE_Dec 耗时: {PAE_Dec_time:.2f} ms")
        protocol.user_time_client[uid]["PAE_Dec_time"] = PAE_Dec_time
        run_time["PAE_Dec_time"] = PAE_Dec_time
        PAE_Dec_commucation_time = (time.time() - start_time3) * 1000
        print(f"[CLIENT] PAE_Dec_commucation_time 耗时: {PAE_Dec_commucation_time:.2f} ms")
        protocol.user_time_client[uid]["PAE_Dec_commucation_time"] = PAE_Dec_commucation_time
        run_time["PAE_Dec_commucation_time"] = PAE_Dec_commucation_time
        print("✅ 解密完成")
        #---------------------------------------------------------------------------------------------------------###
        client_secure_retrieve_time= (time.time() - start_time) * 1000
        print(f"[CLIENT] client_secure_retrieve_time耗时：: {client_secure_retrieve_time:.2f} ms ")
        protocol.user_time_client[uid]["client_secure_retrieve_time"] = client_secure_retrieve_time
        run_time["client_secure_retrieve_time"] = client_secure_retrieve_time
        protocol.user_time_client[uid]["client_dec_bytes"] = total_bytes
        run_time["client_dec_bytes"] = total_bytes


###————————————————————————————————————————————————————————————————————————————————————————————————————————————————————###


def client_run_enc2(protocol: AEKEProtocol, source_file_path,run_time,uid, pw_input,inter_path1,k44,bucket_name,secure_level):    #TODO
    print("###############客户端请求与server建立socket连接###############")
    HOST = '54.250.***.**'  # The server's hostname or IP address客户端将连接本地运行的服务器
    PORT = 5202  # The port used by the server客户端与服务器通信的端口
    total_bytes = 0
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s: #创建一个TCP套接字对象s，用于与服务器进行通信，AF_INET 表示 IPv4 地址族，SOCK_STREAM 表示 TCP 协议
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8 * 1024 * 1024)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
        s.connect((HOST, PORT))
        print(f"[CLIENT] enter socket.connect!")
        payload = {'secure_level':secure_level,'type': 'enc'}
        sent_bytes=send_with_length(s,payload) # 选择加密流程
        # total_bytes += sent_bytes   #11111111111111111111111
        ##----------------------------------------PAE_Enc time ↓----------------------------------------------##
        start_time = time.time()
        sent_bytes = send_with_length(s, uid) # ▲▲▲▲▲ 发送uid
        total_bytes += sent_bytes  # 11111111111111111111111
        gs0,bytes_received = recv_with_length(s) # ●●●●● 接收gs
        total_bytes += bytes_received  # 11111111111111111111111
        st0 =protocol.H_pw_gs(gs0,pw_input)
        print("[debug] st0:",st0.hex())

        print("★★★客户端加密数据★★★")
        print("[CLIENT] 运行PAE")
        pk_bytes,byte_scale = recv_with_length(s) # ▲▲▲▲▲ 接收公钥pk
        total_bytes += byte_scale ##11111111111111111111111111
        pk = protocol.deserialize_pubkey(pk_bytes)  # 转回对象
        print("[CLIENT] pk:", pk)
        start_time1 = time.time()
        a_int = PAE_ext(protocol,uid,pw_input,st0)
        print("[CLIENT] a_int:",a_int)
        PAE_Ext_time1 = (time.time() - start_time1) * 1000
        print(f"[CLIENT] PAE_Ext 耗时: {PAE_Ext_time1:.2f} ms")
        protocol.user_time_client[uid]["PAE_Ext_time1"] = PAE_Ext_time1
        run_time["PAE_Ext_time1"] = PAE_Ext_time1
        MSG_TYPE_KEY = 0x01
        header = (
                uid.encode() +
                secure_level.to_bytes(1, "big") +
                MSG_TYPE_KEY.to_bytes(1, "big")
        )

        start_time2 = time.time()
        c_path, c0, u = PAE_enc(protocol,uid,pw_input,pk,st0,source_file_path,inter_path1, k44,header) #PAE_Enc过程
        PAE_Enc_time= (time.time() - start_time2) * 1000
        print(f"[CLIENT] PAE Enc 耗时: {PAE_Enc_time:.2f} ms")
        protocol.user_time_client[uid]["PAE_Enc_time"] = PAE_Enc_time
        run_time["PAE_Enc_time"] = PAE_Enc_time
        print("[CLIENT] 加密成功！")
        print("[CLIENT] u", u)
        print("[CLIENT] c0", c0.hex())
        send_bytes_with_length(s, c0)  # ▲▲▲▲▲ 发送c0
        total_bytes += 4 + len(c0)  ##11111111111111111111111111
        # 序列化临时点 u 并发送
        u_bytes = protocol.serialize_pubkey(u)  #ECC 点序列化
        send_bytes_with_length(s, u_bytes)  # ▲▲▲▲▲ 发送u
        total_bytes += 4 + len(u_bytes)  ##11111111111111111111111111
        # print("[CLIENT] 333333333")
        ack1, bytes = recv_with_length(s)  # ●●●●● 密钥文件上传成功的确认值
        print("[CLIENT] 文件上传成功", ack1)
        PAE_Enc_commucation_time = (time.time() - start_time2) * 1000
        print(f"[CLIENT] PAE Enc commucation 耗时: {PAE_Enc_commucation_time:.2f} ms")
        protocol.user_time_client[uid]["PAE_Enc_commucation_time"] = PAE_Enc_commucation_time
        run_time["PAE_Enc_commucation_time"] = PAE_Enc_commucation_time
        #-------------------------------------------------------------------------------------------------------#
        ###-------------------------------------upload time---------------------------------------------------###
        #将文件传到s3上
        start_time3 = time.time()   ####222222
        # try:
        #     BUFFER_SIZE = 4*1024 * 1024
        #     protocol.s3_client.put_bucket_accelerate_configuration(
        #         Bucket=bucket_name,
        #         AccelerateConfiguration={'Status': 'Enabled'}
        #     )
        #     protocol.s3_client.upload_file(c_path, bucket_name, f"{uid}/{uid}_s3s3")
        #     sent_bytes = send_with_length(s, 1) # ▲▲▲▲▲ 发送密文文件上传成功的确认消息
        #     total_bytes += sent_bytes ##11111111111111111111111111
        # except Exception as e:
        #     print(f"[CLIENT] 密文发送失败: {e}")
        #     return   #####2222
        sent_bytes = send_with_length(s, 1)  # ▲▲▲▲▲ 发送确认消息
        total_bytes += sent_bytes  ##11111111111111111111111111
        client_upload_file_time= (time.time() - start_time3) * 1000
        print(f"[CLIENT] client上传密文文件耗时: {client_upload_file_time:.2f} ms")
        protocol.user_time_client[uid]["client_upload_file_time"] = client_upload_file_time
        run_time["client_upload_file_time"] = client_upload_file_time

        client_secure_deposit_time = (time.time() - start_time) * 1000
        print(f"[CLIENT]client_secure_deposit_time 耗时: {client_secure_deposit_time:.2f} ms")
        protocol.user_time_client[uid]["client_secure_deposit_time"] = client_secure_deposit_time
        run_time["client_secure_deposit_time"] = client_secure_deposit_time
        protocol.user_time_client[uid]["client_enc_bytes"] = total_bytes
        run_time["client_enc_bytes"] = total_bytes
        s.close()
        return c_path  


#客户端请求解密
def client_run_dec2(protocol: AEKEProtocol, dest_path:str,k1:str,run_time:dict,uid: str, pw_input: str,bucketname:str,secure_level,c_path):
    HOST = '54.250.***.**'  # The server's hostname or IP address客户端将连接本地运行的服务器
    PORT = 5202  # The port used by the server客户端与服务器通信的端口
    total_bytes =0
    with (socket.socket(socket.AF_INET,
                       socket.SOCK_STREAM) as s):  # 创建一个TCP套接字对象s，用于与服务器进行通信，AF_INET 表示 IPv4 地址族，SOCK_STREAM 表示 TCP 协议
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8 * 1024 * 1024)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
        s.connect((HOST, PORT))
        print()
        print()
        print("[CLIENT] 客户端请求解密")
        payload = {'secure_level':secure_level,'type': 'dec'}
        sent_bytes=send_with_length(s, payload)##选择解密模式
        print(f"[CLIENT] 字节数 sent: {sent_bytes}")
        total_bytes += sent_bytes #11111111111111111111111111
        #------------------------------------aEKE time ↓---------------------------------------------------------#
        start_time = time.time()
        flag = 1
        while flag:
            sent_bytes = send_with_length(s, uid)  # ▲▲▲▲▲ 发送uid
            total_bytes += sent_bytes  # 11111111111111111111111111
            gs0, bytes_received = recv_with_length(s)  # ●●●●● 接收随机数gs
            total_bytes += bytes_received  # 11111111111111111111111111
            st0 = protocol.H_pw_gs(gs0, pw_input)
            print("[debug] st0:",st0.hex())

            a_bytes = protocol.H_new(uid, pw_input, st0)
            print("[Client]a_bytes:",a_bytes.hex())
            a_int = int.from_bytes(a_bytes, byteorder='big') % protocol.N
            A_obj = ec.derive_private_key(a_int, protocol.ec_curve, default_backend()).public_key()
            A_bytes = protocol.serialize_pubkey(A_obj)  # 序列化 A
            print("[Client]A_bytes",A_bytes.hex())
            h_material = protocol.H(uid, pw_input, a_bytes)
            e1 = h_material[:protocol.KEY_LEN]
            e2 = h_material[protocol.KEY_LEN:2 * protocol.KEY_LEN]
            print("[CLIENT] e1:", e1.hex())
            print("[CLIENT] e2:", e2.hex())

            payload = {'A':A_bytes}
            # bytes_sent = send_with_length(s, f0)  # ▲▲▲▲▲ 发送A/e1
            bytes_sent = send_with_length(s, payload)  # ▲▲▲▲▲ 发送A/e1
            total_bytes += bytes_sent  # 11111111111111111111111111

            flag, received_bytes = recv_with_length(s) #  ●●●●● 接收 flag
            print(f"字节数 received: {received_bytes}")
            total_bytes += received_bytes  # 11111111111111111111111111

            if flag == -1:
                print("[Client] 用户未注册或非法用户！")
                exit()
            if flag == 1:
                print("[Client] 口令错误！请重新输入")
                pw_input = input("请输入密码: ").strip()
            if flag == -2:
                print("[Client] 口令输入错误，账户已锁定！")
                exit()

        #--------------------------------------------接收密文时间---------------------------------------------------###
        print("[CLIENT] 客户端请求检索数据")
        start_time1 = time.time()
        # ===== Step1: 接收文件 =====
        # buf = BytesIO()
        # config = TransferConfig(
        #     multipart_threshold=8 * 1024 * 1024,
        #     multipart_chunksize=8 * 1024 * 1024,
        #     max_concurrency=10,
        #     use_threads=True
        # )
        # protocol.s3_client.download_fileobj(bucketname, f"{uid}/{uid}_s3s3", buf, Config=config)
        # buf.seek(0)
        with open(c_path, "rb") as f_in:
            encrypted_data = f_in.read()  # 把整个文件读入内存
        # 将字节内容封装成 BytesIO 流对象
        buf = BytesIO(encrypted_data)

        client_download_file_time = (time.time() - start_time1) * 1000
        print(f"[CLIENT] client从s3下载密文文件耗时: {client_download_file_time:.2f} ms")
        protocol.user_time_client[uid]["client_download_file_time"] = client_download_file_time
        run_time["client_download_file_time"] = client_download_file_time
        #--------------------------------------------------------------------------------------------------------###
        ##----------------------------------------PAE Dec time ↓----------------------------------------------##
        start_time2 = time.time()
        a_int = PAE_ext(protocol, uid, pw_input, st0)
        PAE_Ext_time2 = (time.time() - start_time2) * 1000
        print(f"[CLIENT] PAE_Ext_time2 耗时: {PAE_Ext_time2:.2f} ms")
        protocol.user_time_client[uid]["PAE_Ext_time2"] =PAE_Ext_time2
        run_time["PAE_Ext_time2"] = PAE_Ext_time2

        start_time3 = time.time()
        ack ,bytes_received = recv_with_length(s)# ●●●●● 接收确认值
        print("[CLIENT] ack:", ack)
        pk, byte_scale = recv_with_length(s) # ●●●●● 接收公钥pk
        total_bytes += byte_scale # 11111111111111111111111111
        usk_byte,received_bytes = recv_with_length(s) # ●●●●● 接收 usk
        total_bytes += received_bytes  # 11111111111111111111111111
        c0,received_bytes = recv_with_length(s) # ●●●●● 接收c0
        total_bytes += received_bytes  # 11111111111111111111111111
        print("[CLIENT] pk:", pk)
        print("[CLIENT] usk_byte:", usk_byte.hex())
        print("[CLIENT] received_c0",c0.hex())

        sent_bytes=send_with_length(s,1) # ▲▲▲▲▲ 发送确认值
        total_bytes += sent_bytes #11111111111111111111111111111111111111111
        usk = int.from_bytes(usk_byte, byteorder='big') % protocol.N #将usk_byte转为int
        #--------------------------------------------PAE_Dec解密时间---------------------------------------------------###
        MSG_TYPE_KEY = 0x01
        header = (
                uid.encode() +
                secure_level.to_bytes(1, "big") +
                MSG_TYPE_KEY.to_bytes(1, "big")
        )

        start_time4 = time.time()
        m_path = PAE_dec(protocol, uid, pw_input, usk, dest_path, k1, st0, buf, c0,header)
        PAE_Dec_time= (time.time() - start_time4) * 1000
        print(f"[CLIENT] PAE_Dec 耗时: {PAE_Dec_time:.2f} ms")
        protocol.user_time_client[uid]["PAE_Dec_time"] = PAE_Dec_time
        run_time["PAE_Dec_time"] = PAE_Dec_time
        PAE_Dec_commucation_time = (time.time() - start_time3) * 1000
        print(f"[CLIENT] PAE_Dec_commucation_time 耗时: {PAE_Dec_commucation_time:.2f} ms")
        protocol.user_time_client[uid]["PAE_Dec_commucation_time"] = PAE_Dec_commucation_time
        run_time["PAE_Dec_commucation_time"] = PAE_Dec_commucation_time
        print("✅ 解密完成")
        #---------------------------------------------------------------------------------------------------------###
        client_secure_retrieve_time= (time.time() - start_time) * 1000
        print(f"[CLIENT] client_secure_retrieve_time耗时：: {client_secure_retrieve_time:.2f} ms ")
        protocol.user_time_client[uid]["client_secure_retrieve_time"] = client_secure_retrieve_time
        run_time["client_secure_retrieve_time"] = client_secure_retrieve_time
        protocol.user_time_client[uid]["client_dec_bytes"] = total_bytes
        run_time["client_dec_bytes"] = total_bytes

###————————————————————————————————————————————————————————————————————————————————————————————————————————————————————###


def client_run_enc3_PAKE(protocol: AEKEProtocol, run_time,uid, pw_input,secure_level,eta=0,k=0):    #TODO
    print("###############客户端请求与server建立安全信道###############")
    HOST = '54.250.***.**'  # The server's hostname or IP address客户端将连接本地运行的服务器
    PORT = 5202  # The port used by the server客户端与服务器通信的端口
    total_bytes = 0
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8 * 1024 * 1024)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
    s.connect((HOST, PORT))
    print(f"[CLIENT] enter socket.connect!")
    payload = {'secure_level':secure_level,'type': 'enc'}
    sent_bytes=send_with_length(s,payload) # 选择加密流程
    total_bytes += sent_bytes   #11111111111111111111111
    #------------------------------------aEKE time↓---------------------------------------------------------#
    start_time = time.time()
    sent_bytes = send_with_length(s, uid) # ▲▲▲▲▲ 发送uid
    total_bytes += sent_bytes  # 11111111111111111111111
    gs0,bytes_received = recv_with_length(s) # ●●●●● 接收st
    total_bytes += bytes_received  # 11111111111111111111111
    st0 = protocol.H_pw_gs(gs0, pw_input)
    print("[debug] st0:", st0)

    a_bytes = protocol.H_new(uid, pw_input, st0)
    # h_material = protocol.H(uid, pw_input, a)
    a_int = int.from_bytes(a_bytes, byteorder='big') % protocol.N
    x = secrets.randbelow(protocol.N)  # 客户端临时私钥
    X_obj = ec.derive_private_key(x, protocol.ec_curve, default_backend()).public_key()
    X_bytes = protocol.serialize_pubkey(X_obj)  # 序列化点 X
    print("[CLIENT] X_bytes", X_bytes.hex())
    h_material = protocol.H(uid, pw_input, a_bytes)
    e1 = h_material[:protocol.KEY_LEN]
    e2 = h_material[protocol.KEY_LEN:2 * protocol.KEY_LEN]
    print("[CLIENT] e1:", e1.hex())
    print("[CLIENT] e2:", e2.hex())
    f0 = protocol.IC_encrypt(e1, X_bytes)  # 用理想密码加密X
    bytes_sent = send_with_length(s, f0) # ●●●●● 发送f0
    total_bytes += bytes_sent  # 11111111111111111111111
    f1,bytes_received = recv_with_length(s) # ●●●●● 接收f1
    total_bytes += bytes_received  # 11111111111111111111111
    print("[CLIENT] f1:", f1.hex())
    print("[CLIENT] f0:", f0.hex())

    Y_prime_bytes =protocol.IC_decrypt(e2, f1)
    print("[CLIENT] Y_prime_bytes", Y_prime_bytes.hex())
    Y_prime_obj = protocol.deserialize_pubkey(Y_prime_bytes)  # 还原服务端发来的点 Y'
    d0_bytes = protocol.H_prime(uid, X_bytes)
    d0 = int.from_bytes(d0_bytes, 'big') % protocol.N
    scalar = (d0 * a_int + x) % protocol.N
    # 1. 计算第一个分量: term_a = (x * Y')
    term_a_bytes = ec.derive_private_key(x, protocol.ec_curve).exchange(ec.ECDH(), Y_prime_obj)
    # 2. 计算第二个分量: term_b = (d0 * a * Y')
    scalar_b = (d0 * a_int) % protocol.N
    term_b_bytes = ec.derive_private_key(scalar_b, protocol.ec_curve).exchange(ec.ECDH(), Y_prime_obj)
    # 3. 按照 Server 的顺序拼接 (X_prime * y  +  A * y*d1)
    # 对应 Client  (x * Y' + d0 * a * Y')
    l0_material = term_a_bytes + term_b_bytes
    k_client = protocol.H_double_prime(uid, X_bytes, l0_material)

    print(f"[CLIENT] Shared key: {k_client.hex()}")
    s.sendall(pickle.dumps(1))  # ▲▲▲▲▲ 回传 1（仅为同步）
    # total_bytes += len(pickle.dumps(1)) ##11111111111111111111111111
    print(f"[CLIENT] 字节数 sent: {len(pickle.dumps(1))}")

    enc_PAKE_time = (time.time() - start_time) * 1000
    print(f"[CLIENT] aEKE 耗时: {enc_PAKE_time:.2f} ms")
    protocol.user_time_client[uid]["enc_PAKE_time"] = enc_PAKE_time
    run_time["enc_PAKE_time"] = enc_PAKE_time

    protocol.user_time_client[uid]["client_enc_PAKE_bytes"] = total_bytes
    run_time["client_enc_PAKE_bytes"] = total_bytes
    print("##########成功建立安全信道#########")
    print()
    print()
    return k_client,st0,s,total_bytes


def client_run_enc3(protocol: AEKEProtocol, s,source_file_path,run_time,uid, pw_input,inter_path1,k44,bucket_name,k_client,st0,total_bytes,secure_level):    #TODO
    # total_bytes = 0
    print("[CLIENT] total_bytes: ", total_bytes)
    start_time = time.time()
    ##----------------------------------------PAE_Enc time ↓----------------------------------------------##
    print("★★★客户端加密数据★★★")
    print("[CLIENT] 运行PAE")
    pk_rec,byte_scale = recv_with_length(s) # ▲▲▲▲▲ 接收公钥pk
    total_bytes += byte_scale ##11111111111111111111111111
    pk_bytes = protocol.AES_decrypt(k_client,pk_rec)####PAKE
    pk = protocol.deserialize_pubkey(pk_bytes)
    print("[CLIENT] pk reconstructed successfully")
    print("[CLIENT] pk:", pk)
    start_time1 = time.time()
    a_int = PAE_ext(protocol,uid,pw_input,st0)
    print("[CLIENT] a_int:",a_int)
    PAE_Ext_time1 = (time.time() - start_time1) * 1000
    print(f"[CLIENT] PAE_Ext 耗时: {PAE_Ext_time1:.2f} ms")
    protocol.user_time_client[uid]["PAE_Ext_time1"] = PAE_Ext_time1
    run_time["PAE_Ext_time1"] = PAE_Ext_time1
    MSG_TYPE_KEY = 0x01
    header = (
            uid.encode() +
            secure_level.to_bytes(1, "big") +
            MSG_TYPE_KEY.to_bytes(1, "big")
    )

    start_time2 = time.time()
    c_path, c0, u = PAE_enc(protocol,uid,pw_input,pk,st0,source_file_path,inter_path1, k44,header) #PAE_Enc过程
    PAE_Enc_time= (time.time() - start_time2) * 1000
    print(f"[CLIENT] PAE_Enc 耗时: {PAE_Enc_time:.2f} ms")
    protocol.user_time_client[uid]["PAE_Enc_time"] = PAE_Enc_time
    run_time["PAE_Enc_time"] = PAE_Enc_time
    print("[CLIENT] 加密成功！")
    print("[CLIENT] u", u)
    print("[CLIENT] c0", c0.hex())
    print("[Client] c0 type", type(c0))
    c0_send = protocol.AES_encrypt(k_client,c0) ###PAKE
    print("[CLIENT] c0_send type",type(c0_send))
    send_bytes_with_length(s, c0_send)  # ▲▲▲▲▲ 发送c0
    total_bytes += 4 + len(c0_send)  ##11111111111111111111111111
    u_bytes = protocol.serialize_pubkey(u)
    u_send= protocol.AES_encrypt(k_client,u_bytes) ###PAKE
    send_bytes_with_length(s, u_send)  # ▲▲▲▲▲ 发送u
    total_bytes += 4 + len(u_send)  ##11111111111111111111111111
    PAE_Enc_commucation_time = (time.time() - start_time2) * 1000
    ack1, bytes = recv_with_length(s)  # ●●●●● 接收文件上传成功的确认值
    print("[CLIENT] 文件上传成功", ack1)

    print(f"[CLIENT] PAE Enc commucation 耗时: {PAE_Enc_commucation_time:.2f} ms")
    protocol.user_time_client[uid]["PAE_Enc_commucation_time"] = PAE_Enc_commucation_time
    run_time["PAE_Enc_commucation_time"] = PAE_Enc_commucation_time
    #-------------------------------------------------------------------------------------------------------#
    ###-------------------------------------upload time---------------------------------------------------###
    #将文件传到s3上
    start_time3 = time.time()
    # try:
    #     BUFFER_SIZE = 4*1024 * 1024
    #     protocol.s3_client.put_bucket_accelerate_configuration(
    #         Bucket=bucket_name,
    #         AccelerateConfiguration={'Status': 'Enabled'}
    #     )
    #     protocol.s3_client.upload_file(c_path, bucket_name, f"{uid}/{uid}_s3s3")
    #     sent_bytes = send_with_length(s, 1) # ▲▲▲▲▲ 发送文件上传成功的确认消息
    #     total_bytes += sent_bytes ##11111111111111111111111111
    # except Exception as e:
    #     print(f"[CLIENT] 密文发送失败: {e}")
    #     return
    sent_bytes = send_with_length(s, 1)  # ▲▲▲▲▲ 发送确认消息
    total_bytes += sent_bytes  ##11111111111111111111111111
    client_upload_file_time= (time.time() - start_time3) * 1000
    print(f"[CLIENT] client上传密文文件耗时: {client_upload_file_time:.2f} ms")
    protocol.user_time_client[uid]["client_upload_file_time"] = client_upload_file_time
    run_time["client_upload_file_time"] = client_upload_file_time

    client_secure_deposit_time = (time.time() - start_time) * 1000
    print(f"[CLIENT]client_secure_deposit_time 耗时: {client_secure_deposit_time:.2f} ms")
    protocol.user_time_client[uid]["client_secure_deposit_time"] = client_secure_deposit_time
    run_time["client_secure_deposit_time"] = client_secure_deposit_time
    protocol.user_time_client[uid]["client_enc_bytes"] = total_bytes
    run_time["client_enc_bytes"] = total_bytes

    s.close()
    return c_path

#客户端请求解密
def client_run_dec3_PAKE(protocol: AEKEProtocol, run_time:dict,uid: str, pw_input: str,secure_level,eta=0,k=0):
    HOST = '54.250.***.**'  # The server's hostname or IP address客户端将连接本地运行的服务器
    PORT = 5202  # The port used by the server客户端与服务器通信的端口
    total_bytes =0
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8 * 1024 * 1024)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
    # s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 256 * 1024)
    s.connect((HOST, PORT))
    print()
    print()
    payload = {'secure_level':secure_level,'type': 'dec'}
    sent_bytes=send_with_length(s, payload)##选择解密模式
    print(f"[CLIENT] 字节数 sent: {sent_bytes}")
    total_bytes += sent_bytes #11111111111111111111111111
    #------------------------------------aEKE time ↓---------------------------------------------------------#
    start_time = time.time()
    flag = 1
    while flag:
        print("############客户端请求解密--建立安全信道#############")
        sent_bytes = send_with_length(s, uid)  # ▲▲▲▲▲ 发送uid
        total_bytes += sent_bytes  # 11111111111111111111111111
        gs0, bytes_received = recv_with_length(s)  # ●●●●● 接收随机数st
        total_bytes += bytes_received  # 11111111111111111111111111
        # gs0 = gs['gs0']
        # gs1 = gs['gs1']
        st0 = protocol.H_pw_gs(gs0, pw_input)
        # st1 = protocol.H_pw_gs(gs1, pw_input)
        print("[debug] st0:", st0)
        # print("[debug] st1:", st1)


        a_bytes = protocol.H_new(uid, pw_input, st0)
        a_int = int.from_bytes(a_bytes, byteorder='big') % protocol.N
        A_obj = ec.derive_private_key(a_int, protocol.ec_curve, default_backend()).public_key()
        A_bytes = protocol.serialize_pubkey(A_obj)
        x = secrets.randbelow(protocol.N)
        X_obj = ec.derive_private_key(x, protocol.ec_curve, default_backend()).public_key()
        X_bytes = protocol.serialize_pubkey(X_obj)
        h_material = protocol.H(uid, pw_input, a_bytes)
        e1 = h_material[:protocol.KEY_LEN]
        e2 = h_material[protocol.KEY_LEN:2 * protocol.KEY_LEN]
        print("[CLIENT] e1:", e1.hex())
        print("[CLIENT] e2:", e2.hex())
        f0 = protocol.IC_encrypt(e1, X_bytes)  # 用理想密码加密X

        payload = {'f0':f0,
                   'A':A_bytes
                   }
        bytes_sent = send_with_length(s, payload)  # ▲▲▲▲▲ 发送f0，A/e1
        total_bytes += bytes_sent  # 11111111111111111111111111

        flag, received_bytes = recv_with_length(s) #  ●●●●● 接收 flag
        print(f"[CLIENT] 字节数 received: {received_bytes}")
        total_bytes += received_bytes  # 11111111111111111111111111

        if flag == -1:
            print("[CLIENT] 用户未注册或非法用户！")
            exit()
        if flag == 1:
            print("[CLIENT] 口令错误！请重新输入")
            pw_input = input("请输入密码: ").strip()
        if flag == -2:
            print("[CLIENT] 口令输入错误，账户已锁定！")
            exit()

    f1, bytes_received = recv_with_length(s) # ●●●●● 接收f1
    total_bytes += bytes_received # 11111111111111111111111111

    Y_prime_bytes = protocol.IC_decrypt(e2, f1)
    print("[CLIENT] Y_prime_bytes", Y_prime_bytes.hex())
    Y_prime_obj = protocol.deserialize_pubkey(Y_prime_bytes)  # 还原服务端发来的点 Y'
    d0_bytes = protocol.H_prime(uid, X_bytes)
    d0 = int.from_bytes(d0_bytes, 'big') % protocol.N
    scalar = (d0 * a_int + x) % protocol.N
    # 1. 计算第一个分量: term_a = (x * Y')
    term_a_bytes = ec.derive_private_key(x, protocol.ec_curve).exchange(ec.ECDH(), Y_prime_obj)
    # 2. 计算第二个分量: term_b = (d0 * a * Y')
    scalar_b = (d0 * a_int) % protocol.N
    term_b_bytes = ec.derive_private_key(scalar_b, protocol.ec_curve).exchange(ec.ECDH(), Y_prime_obj)
    # 3. 按照 Server 的顺序拼接 (X_prime * y  +  A * y*d1)
    # 对应 Client 这边是 (x * Y' + d0 * a * Y')
    l0_material = term_a_bytes + term_b_bytes
    k_client = protocol.H_double_prime(uid, X_bytes, l0_material)

    print(f"[CLIENT] Shared key: {k_client.hex()}")
    s.sendall(pickle.dumps(1))  # ▲▲▲▲▲ 回传 1（仅为同步）
    print(f"[CLIENT] 字节数 sent: {len(pickle.dumps(1))}")
    # total_bytes_sent += len(pickle.dumps(1)) ##11111111111111111111111111

    dec_PAKE_time = (time.time() - start_time) * 1000
    print(f"[CLIENT] dec_PAKE 耗时: {dec_PAKE_time:.2f} ms")
    protocol.user_time_client[uid]["dec_PAKE_time"] = dec_PAKE_time
    run_time["dec_PAKE_time"] = dec_PAKE_time
    protocol.user_time_client[uid]["client_dec_PAKE_bytes"] = total_bytes
    run_time["client_dec_PAKE_bytes"] = total_bytes
    print("##########成功建立安全信道#########")
    print()
    print()
    return k_client,st0,s,total_bytes


#客户端请求解密
def client_run_dec3(protocol: AEKEProtocol, s,dest_path:str,k1:str,run_time:dict,uid: str, pw_input: str,bucketname:str,k_client,st0,total_bytes,c_path,secure_level):
    # total_bytes =0
    print("[CLIENT] total_bytes: ", total_bytes)
    print("[CLIENT] 客户端请求解密")
    #------------------------------------aEKE time ↓---------------------------------------------------------#
    start_time = time.time()
    #--------------------------------------------接收密文时间---------------------------------------------------###
    print("[CLIENT] 客户端请求检索数据")
    start_time1 = time.time()
    # ===== Step1: 接收文件 =====
    # buf = BytesIO()
    # config = TransferConfig(
    #     multipart_threshold=8 * 1024 * 1024,
    #     multipart_chunksize=8 * 1024 * 1024,
    #     max_concurrency=10,
    #     use_threads=True
    # )
    # protocol.s3_client.download_fileobj(bucketname, f"{uid}/{uid}_s3s3", buf, Config=config)
    # buf.seek(0)
    with open(c_path, "rb") as f_in:
        encrypted_data = f_in.read()
    buf=BytesIO(encrypted_data)

    client_download_file_time = (time.time() - start_time1) * 1000
    print(f"[CLIENT] client下载密文文件耗时: {client_download_file_time:.2f} ms")
    protocol.user_time_client[uid]["client_download_file_time"] = client_download_file_time
    run_time["client_download_file_time"] = client_download_file_time
    #--------------------------------------------------------------------------------------------------------###
    ##----------------------------------------检索数据 time ↓----------------------------------------------##
    start_time2 = time.time()
    a_int = PAE_ext(protocol, uid, pw_input, st0)
    PAE_Ext_time2 = (time.time() - start_time2) * 1000
    print(f"[CLIENT] PAE_Ext_time2 耗时: {PAE_Ext_time2:.2f} ms")
    protocol.user_time_client[uid]["PAE_Ext_time2"] =PAE_Ext_time2
    run_time["PAE_Ext_time2"] = PAE_Ext_time2

    ack ,bytes_received = recv_with_length(s)
    print("[CLIENT] ack:", ack)
    pk_rec, byte_scale = recv_with_length(s) # ●●●●● 接收公钥pk
    total_bytes += byte_scale # 11111111111111111111111111
    start_time3 = time.time()
    pk_bytes = protocol.AES_decrypt(k_client, pk_rec)  ####PAKE
    pk = int.from_bytes(pk_bytes, 'big')  ###PAKE
    usk_byte_rec,received_bytes = recv_with_length(s) # ●●●●● 接收 usk
    total_bytes += received_bytes  # 11111111111111111111111111
    usk_byte = protocol.AES_decrypt(k_client, usk_byte_rec)
    c0_rec,received_bytes = recv_with_length(s) # ●●●●● 接收c0
    c0 = protocol.AES_decrypt(k_client, c0_rec)
    total_bytes += received_bytes  # 11111111111111111111111111
    sent_bytes=send_with_length(s,1) # ▲▲▲▲▲ 发送确认值
    total_bytes += sent_bytes #11111111111111111111111111111111111111111
    usk = int.from_bytes(usk_byte, byteorder='big') % protocol.N #将usk_byte转为int
    #--------------------------------------------PAE_Dec解密时间---------------------------------------------------###
    MSG_TYPE_KEY = 0x01
    header = (
            uid.encode() +
            secure_level.to_bytes(1, "big") +
            MSG_TYPE_KEY.to_bytes(1, "big")
    )

    start_time4 = time.time()
    m_path = PAE_dec(protocol, uid, pw_input, usk, dest_path, k1, st0, buf, c0,header)
    PAE_Dec_time= (time.time() - start_time4) * 1000
    print(f"[CLIENT] PAE_Dec 耗时: {PAE_Dec_time:.2f} ms")
    protocol.user_time_client[uid]["PAE_Dec_time"] = PAE_Dec_time
    run_time["PAE_Dec_time"] = PAE_Dec_time
    PAE_Dec_commucation_time = (time.time() - start_time3) * 1000
    print(f"[CLIENT] PAE_Dec_commucation_time 耗时: {PAE_Dec_commucation_time:.2f} ms")
    protocol.user_time_client[uid]["PAE_Dec_commucation_time"] = PAE_Dec_commucation_time
    run_time["PAE_Dec_commucation_time"] = PAE_Dec_commucation_time
    print("✅ 解密完成")
    #---------------------------------------------------------------------------------------------------------###
    client_secure_retrieve_time= (time.time() - start_time) * 1000
    print(f"[CLIENT] client_secure_retrieve_time耗时：: {client_secure_retrieve_time:.2f} ms ")
    protocol.user_time_client[uid]["client_secure_retrieve_time"] = client_secure_retrieve_time
    run_time["client_secure_retrieve_time"] = client_secure_retrieve_time
    #
    protocol.user_time_client[uid]["client_dec_bytes"] = total_bytes
    run_time["client_dec_bytes"] = total_bytes




