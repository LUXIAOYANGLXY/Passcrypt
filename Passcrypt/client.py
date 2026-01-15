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


####——————————————————————————————————————————————————————————————————————————————————————————————————————————————————————###


def gs_generate(protocol,secure_level,gs,uid,eta,k):
    gs_send = gs
    if secure_level == 3 or secure_level == 2:
        gs_send = gs
    elif secure_level == 4:
        i_bytes = protocol.H_new(eta, uid)  # 混合哈希
        i = int.from_bytes(i_bytes, 'big') % (k + 1)
        print(f"[CLIENT] 真正的 gs 存在第 {i} 位")
        gs_list = []
        for j in range(k + 1):
            if j == i:
                gs_list.append(gs)
            else:
                fake_s = secrets.randbelow(protocol.P)
                gs_list.append(pow(protocol.G, fake_s, protocol.P))
        gs_send = gs_list
    return gs_send

def client_get_st(protocol: AEKEProtocol,st_rec,eta,uid,k,secure_level):
    st = st_rec
    if secure_level == 2 or secure_level == 3:
        st = st_rec
    elif secure_level == 4:
        i_bytes = protocol.H_new(eta, uid)  # 混合哈希
        i = int.from_bytes(i_bytes, 'big') % (k + 1)
        print(f"[CLIENT] 真正的 st 存在第 {i} 位")
        st = st_rec[i]
    return st


def client_run_register(protocol,uid, pw,run_time,secure_level,eta=0, k=0):
    HOST = '54.250.191.84'  # The server's hostname or IP address客户端将连接本地运行的服务器
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
        if secure_level == 2 or secure_level == 3:
            s0 = secrets.randbelow(protocol.P)
            st0 = pow(pk, s0, protocol.P)  # 协商随机数st0
            # s1 = secrets.randbelow(protocol.P)
            # st1 = pow(pk, s1, protocol.P)  # 协商随机数st0
            print("[CLIENT] st0:",st0)
            # print("[CLIENT] st1:",st1)
            gs0 = pow(protocol.G, s0, protocol.P)
            print("[CLIENT] gs:",gs0)
            # gs1 = pow(protocol.G, s1, protocol.P)
            # print("[CLIENT] gs:",gs1)


            a = protocol.H_new(uid,pw,st0) # H_new函数返回的是byte类型
            a_int = int.from_bytes(a, byteorder='big')% protocol.P
            A = pow(protocol.G, a_int, protocol.P) # pow运算需要int类型
            h_material = protocol.H(uid, pw, a)  ###
            e1 = h_material[:protocol.KEY_LEN]
            e2 = h_material[protocol.KEY_LEN:2 * protocol.KEY_LEN]
            print("[CLIENT] e1:", e1.hex())
            print("[CLIENT] e2:", e2.hex())

            gs_send0 = gs_generate(protocol,secure_level,gs0,uid,eta,k)
            # gs_send1 = gs_generate(protocol,secure_level,gs1,uid,eta,k)

            payload = {'uid': uid, 'e1': e1, 'e2': e2, 'gs0': gs_send0, 'A': A}
            sent_bytes = send_with_length(sock, payload)# ▲▲▲▲▲ 将uid，e1，e2，A，gs发送到服务器进行保存
            communication_scale += sent_bytes  #11111111111111111111111

            ack,bytes_received = recv_with_length(sock) ## ●●●●● 接收确认值
            communication_scale += bytes_received  #11111111111111111111111
        elif secure_level ==1:
            st = secrets.randbelow(protocol.P)


            a = protocol.H_new(uid, pw, st)  # H_new函数返回的是byte类型
            a_int = int.from_bytes(a, byteorder='big') % protocol.P
            A = pow(protocol.G, a_int, protocol.P)  # pow运算需要int类型

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
    HOST = '54.250.191.84'  # The server's hostname or IP address客户端将连接本地运行的服务器
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
        pk,byte_scale = recv_with_length(s) # ▲▲▲▲▲ 接收公钥pk
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
        # payload = {'u':u,'c0':c0}
        # print("[CLIENT] 1111111111")
        print("[CLIENT] u", u)
        print("[CLIENT] c0", c0.hex())
        send_bytes_with_length(s, c0)  # ▲▲▲▲▲ 发送c0
        total_bytes += 4 + len(c0)  ##11111111111111111111111111
        # print("[CLIENT] 222222222")
        u_bytes = u.to_bytes((u.bit_length() + 7) // 8, 'big')
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
        # protocol.communication_scale[uid]["send_bytes"] += sent_bytes
        protocol.user_time_client[uid]["client_enc_bytes"] = total_bytes
        run_time["client_enc_bytes"] = total_bytes

        s.close()

        return c_path  # 2222


#客户端请求解密
def client_run_dec1(protocol: AEKEProtocol, dest_path:str,k1:str,run_time:dict,uid: str, pw_input: str,bucketname:str,secure_level,c_path):
    HOST = '54.250.191.84'  # The server's hostname or IP address客户端将连接本地运行的服务器
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
            a_int = int.from_bytes(a, byteorder='big') % protocol.P
            A = pow(protocol.G, a_int, protocol.P)  # pow运算需要int类型

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
        usk = int.from_bytes(usk_byte, byteorder='big') % protocol.P #将usk_byte转为int
        #--------------------------------------------PAE_Dec解密时间---------------------------------------------------###

        MSG_TYPE_KEY = 0x01

        header = (
                uid.encode() +
                secure_level.to_bytes(1, "big") +
                MSG_TYPE_KEY.to_bytes(1, "big")
        )


        start_time4 = time.time()
        m_path = PAE_dec(protocol, uid, pw_input, usk, dest_path, k1,st, buf, c0,header)

        # print("[CLIENT]【DEBUG】UDecwancheng !!!")
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


###————————————————————————————————————————————————————————————————————————————————————————————————————————————————————###



def client_run_enc2(protocol: AEKEProtocol, source_file_path,run_time,uid, pw_input,inter_path1,k44,bucket_name,secure_level):    #TODO
    print("###############客户端请求与server建立socket连接###############")
    HOST = '54.250.191.84'  # The server's hostname or IP address客户端将连接本地运行的服务器
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
        # gs0 = gs['gs0']
        # gs1 = gs['gs1']
        st0 =protocol.H_pw_gs(gs0,pw_input)
        # st1 = protocol.H_pw_gs(gs1,pw_input)
        print("[debug] st0:",st0)
        # print("[debug] st1:",st1)



        print("★★★客户端加密数据★★★")
        print("[CLIENT] 运行PAE")
        pk,byte_scale = recv_with_length(s) # ▲▲▲▲▲ 接收公钥pk
        total_bytes += byte_scale ##11111111111111111111111111
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
        # payload = {'u':u,'c0':c0}
        # print("[CLIENT] 1111111111")
        print("[CLIENT] u", u)
        print("[CLIENT] c0", c0.hex())
        send_bytes_with_length(s, c0)  # ▲▲▲▲▲ 发送c0
        total_bytes += 4 + len(c0)  ##11111111111111111111111111
        # print("[CLIENT] 222222222")
        u_bytes = u.to_bytes((u.bit_length() + 7) // 8, 'big')
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
        # protocol.communication_scale[uid]["send_bytes"] += sent_bytes
        protocol.user_time_client[uid]["client_enc_bytes"] = total_bytes
        run_time["client_enc_bytes"] = total_bytes

        s.close()

        return c_path  # 2222


#客户端请求解密
def client_run_dec2(protocol: AEKEProtocol, dest_path:str,k1:str,run_time:dict,uid: str, pw_input: str,bucketname:str,secure_level,c_path):
    HOST = '54.250.191.84'  # The server's hostname or IP address客户端将连接本地运行的服务器
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
            gs0, bytes_received = recv_with_length(s)  # ●●●●● 接收随机数gs
            total_bytes += bytes_received  # 11111111111111111111111111
            # gs0 = gs['gs0']
            # gs1 = gs['gs1']
            # Hpw_int = int.from_bytes(protocol.H(pw_input), byteorder='big') % protocol.P
            # val0 = pow(Hpw_int, -1, protocol.P)
            # val1 = pow(Hpw_int, -1, protocol.P)
            # st0 = pow(gs0, val0, protocol.P)
            # st1 = pow(gs1, val1, protocol.P)
            st0 = protocol.H_pw_gs(gs0, pw_input)
            # st1 = protocol.H_pw_gs(gs1, pw_input)
            print("[debug] st0:",st0)
            # print("[debug] st1:",st1)



            a = protocol.H_new(uid, pw_input, st0)
            a_int = int.from_bytes(a, byteorder='big') % protocol.P
            A = pow(protocol.G, a_int, protocol.P)  # pow运算需要int类型
            h_material = protocol.H(uid, pw_input, a)
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
        usk = int.from_bytes(usk_byte, byteorder='big') % protocol.P #将usk_byte转为int
        #--------------------------------------------PAE_Dec解密时间---------------------------------------------------###

        MSG_TYPE_KEY = 0x01

        header = (
                uid.encode() +
                secure_level.to_bytes(1, "big") +
                MSG_TYPE_KEY.to_bytes(1, "big")
        )


        start_time4 = time.time()
        m_path = PAE_dec(protocol, uid, pw_input, usk, dest_path, k1, st0, buf, c0,header)

        # print("[CLIENT]【DEBUG】UDecwancheng !!!")
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


###————————————————————————————————————————————————————————————————————————————————————————————————————————————————————###


def client_run_enc3_PAKE(protocol: AEKEProtocol, run_time,uid, pw_input,secure_level,eta=0,k=0):    #TODO
    print("###############客户端请求与server建立安全信道###############")
    HOST = '54.250.191.84'  # The server's hostname or IP address客户端将连接本地运行的服务器
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
    # gs0 = gs['gs0']
    # gs1 = gs['gs1']
    # Hpw_int = int.from_bytes(protocol.H(pw_input), byteorder='big') % protocol.P
    # val0 = pow(Hpw_int, -1, protocol.P)
    # val1 = pow(Hpw_int, -1, protocol.P)
    # st0 = pow(gs0, val0, protocol.P)
    # st1 = pow(gs1, val1, protocol.P)
    st0 = protocol.H_pw_gs(gs0, pw_input)
    # st1 = protocol.H_pw_gs(gs1, pw_input)
    print("[debug] st0:", st0)
    # print("[debug] st1:", st1)


    a = protocol.H_new(uid, pw_input, st0)
    # h_material = protocol.H(uid, pw_input, a)
    a_int = int.from_bytes(a, byteorder='big') % protocol.P
    x = secrets.randbelow(protocol.P)  # 客户端临时私钥
    X = pow(protocol.G, x, protocol.P)  # 客户端临时公钥
    h_material = protocol.H(uid, pw_input, a)
    e1 = h_material[:protocol.KEY_LEN]
    e2 = h_material[protocol.KEY_LEN:2 * protocol.KEY_LEN]
    print("[CLIENT] e1:", e1.hex())
    print("[CLIENT] e2:", e2.hex())
    f0 = protocol.IC_encrypt(e1, X.to_bytes(32, 'big'))  # 用理想密码加密X

    bytes_sent = send_with_length(s, f0) # ●●●●● 发送f0
    total_bytes += bytes_sent  # 11111111111111111111111
    f1,bytes_received = recv_with_length(s) # ●●●●● 接收f1
    total_bytes += bytes_received  # 11111111111111111111111

    Y_prime = int.from_bytes(protocol.IC_decrypt(e2, f1), byteorder='big')
    d0 = protocol.H_prime(uid, X)  # 计算 d0
    l0 = pow(Y_prime, d0 * a_int + x, protocol.P)
    k_client = protocol.H_double_prime(uid, X, l0)

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
    pk = int.from_bytes(pk_bytes, 'big')  ###PAKE
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
    # payload = {'u':u,'c0':c0}
    # print("[CLIENT] 1111111111")
    print("[CLIENT] u", u)
    print("[CLIENT] c0", c0.hex())
    print("[Client] c0 type", type(c0))
    c0_send = protocol.AES_encrypt(k_client,c0) ###PAKE
    print("[CLIENT] c0_send type",type(c0_send))
    send_bytes_with_length(s, c0_send)  # ▲▲▲▲▲ 发送c0
    total_bytes += 4 + len(c0_send)  ##11111111111111111111111111
    # print("[CLIENT] 222222222")
    u_bytes = u.to_bytes((u.bit_length() + 7) // 8, 'big')
    u_send= protocol.AES_encrypt(k_client,u_bytes) ###PAKE
    send_bytes_with_length(s, u_send)  # ▲▲▲▲▲ 发送u
    total_bytes += 4 + len(u_send)  ##11111111111111111111111111
    # print("[CLIENT] 333333333")
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
    # protocol.communication_scale[uid]["send_bytes"] += sent_bytes
    protocol.user_time_client[uid]["client_enc_bytes"] = total_bytes
    run_time["client_enc_bytes"] = total_bytes

    s.close()

    return c_path





#客户端请求解密
def client_run_dec3_PAKE(protocol: AEKEProtocol, run_time:dict,uid: str, pw_input: str,secure_level,eta=0,k=0):
    HOST = '54.250.191.84'  # The server's hostname or IP address客户端将连接本地运行的服务器
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


        a = protocol.H_new(uid, pw_input, st0)
        a_int = int.from_bytes(a, byteorder='big') % protocol.P
        A = pow(protocol.G, a_int, protocol.P)  # pow运算需要int类型
        x = secrets.randbelow(protocol.P)  # 客户端临时私钥
        X = pow(protocol.G, x, protocol.P)  # 客户端临时公钥
        h_material = protocol.H(uid, pw_input, a)
        e1 = h_material[:protocol.KEY_LEN]
        e2 = h_material[protocol.KEY_LEN:2 * protocol.KEY_LEN]
        print("[CLIENT] e1:", e1.hex())
        print("[CLIENT] e2:", e2.hex())
        f0 = protocol.IC_encrypt(e1, X.to_bytes(32, 'big'))  # 用理想密码加密X

        payload = {'f0':f0,
                   'A':A
                   }
        # bytes_sent = send_with_length(s, f0)  # ▲▲▲▲▲ 发送f0，A/e1
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

    Y_prime = int.from_bytes(protocol.IC_decrypt(e2, f1), byteorder='big')
    d0 = protocol.H_prime(uid, X)  # 计算 d0
    l0 = pow(Y_prime, d0 * a_int + x, protocol.P)
    k_client = protocol.H_double_prime(uid, X, l0)

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


    # print("[CLIENT] pk:", pk)
    # print("[CLIENT] usk_byte:", usk_byte.hex())
    # print("[CLIENT] received_c0",c0.hex())


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
    usk = int.from_bytes(usk_byte, byteorder='big') % protocol.P #将usk_byte转为int
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



# def client_run_enc22(protocol: AEKEProtocol, s,source_file_path,run_time,uid, pw_input,inter_path1,k44,bucket_name,k_client,st):    #TODO
#     total_bytes = 0
#     start_time = time.time()
#     ##----------------------------------------PAE_Enc time ↓----------------------------------------------##
#
#     print("★★★客户端加密数据★★★")
#     print("[CLIENT] 【DEBUG】运行UEnc")
#     pk,byte_scale = recv_with_length(s) # ▲▲▲▲▲ 接收公钥pk
#     total_bytes += byte_scale ##11111111111111111111111111
#     print("pk:", pk)
#     start_time1 = time.time()
#     a_int = PAE_ext(protocol,uid,pw_input,st)
#     print("[CLIENT] aINT:",a_int)
#     PAE_Ext_time1 = (time.time() - start_time1) * 1000
#     print(f"[CLIENT] PAE_UEnc 耗时: {PAE_Ext_time1:.2f} ms")
#     protocol.user_time_client[uid]["PAE_Ext_time1"] = PAE_Ext_time1
#     run_time["PAE_Ext_time1"] = PAE_Ext_time1
#
#     start_time2 = time.time()
#     c_path, c0, u = PAE_enc(protocol,uid,pw_input,pk,st,source_file_path,inter_path1, k44) #PAE_Enc过程
#     PAE_Enc_time= (time.time() - start_time2) * 1000
#     print(f"[CLIENT] PAE Enc 耗时: {PAE_Enc_time:.2f} ms")
#     protocol.user_time_client[uid]["PAE_Enc_time"] = PAE_Enc_time
#     run_time["PAE_Enc_time"] = PAE_Enc_time
#     print("[CLIENT] 加密成功！")
#     # payload = {'u':u,'c0':c0}
#     print("[CLIENT] 1111111111")
#     print("[CLIENT] u", u)
#     print("[CLIENT] c0", c0)
#     send_bytes_with_length(s, c0)  # ▲▲▲▲▲ 发送c0
#     total_bytes += 4 + len(c0)  ##11111111111111111111111111
#     print("[CLIENT] 222222222")
#     u_bytes = u.to_bytes((u.bit_length() + 7) // 8, 'big')
#     send_bytes_with_length(s, u_bytes)  # ▲▲▲▲▲ 发送u
#     total_bytes += 4 + len(u_bytes)  ##11111111111111111111111111
#     print("[CLIENT] 333333333")
#     ack1, bytes = recv_with_length(s)  # ●●●●● 接收文件上传成功的确认值
#     print("[SERVER] 文件上传成功", ack1)
#     PAE_Enc_commucation_time = (time.time() - start_time2) * 1000
#     print(f"[CLIENT] PAE Enc commucation 耗时: {PAE_Enc_commucation_time:.2f} ms")
#     protocol.user_time_client[uid]["PAE_Enc_commucation_time"] = PAE_Enc_commucation_time
#     run_time["PAE_Enc_commucation_time"] = PAE_Enc_commucation_time
#     #-------------------------------------------------------------------------------------------------------#
#     ###-------------------------------------upload time---------------------------------------------------###
#     #将文件传到s3上
#     start_time3 = time.time()
#     try:
#         BUFFER_SIZE = 4*1024 * 1024
#         protocol.s3_client.put_bucket_accelerate_configuration(
#             Bucket=bucket_name,
#             AccelerateConfiguration={'Status': 'Enabled'}
#         )
#         protocol.s3_client.upload_file(c_path, bucket_name, f"{uid}/{uid}_s3s3")
#         sent_bytes = send_with_length(s, 1) # ▲▲▲▲▲ 发送文件上传成功的确认消息
#         total_bytes += sent_bytes ##11111111111111111111111111
#     except Exception as e:
#         print(f"[CLIENT] 密文发送失败: {e}")
#         return
#     sent_bytes = send_with_length(s, 1)  # ▲▲▲▲▲ 发送确认消息
#     total_bytes += sent_bytes  ##11111111111111111111111111
#     client_upload_file_time= (time.time() - start_time3) * 1000
#     print(f"[CLIENT] client上传密文文件耗时: {client_upload_file_time:.2f} ms")
#     protocol.user_time_client[uid]["client_upload_file_time"] = client_upload_file_time
#     run_time["client_upload_file_time"] = client_upload_file_time
#
#     client_secure_deposit_time = (time.time() - start_time) * 1000
#     print(f"[CLIENT]client_secure_deposit_time 耗时: {client_secure_deposit_time:.2f} ms")
#     protocol.user_time_client[uid]["client_secure_deposit_time"] = client_secure_deposit_time
#     run_time["client_secure_deposit_time"] = client_secure_deposit_time
#     # protocol.communication_scale[uid]["send_bytes"] += sent_bytes
#     protocol.user_time_client[uid]["client_enc_bytes"] = total_bytes
#     run_time["client_enc_bytes"] = total_bytes
#
#     s.close()
#
#
# #客户端请求解密
# def client_run_dec22(protocol: AEKEProtocol, s,dest_path:str,k1:str,run_time:dict,uid: str, pw_input: str,bucketname:str,k_client,st):
#     total_bytes =0
#     print("[CLIENT] 客户端请求解密")
#     #------------------------------------aEKE time ↓---------------------------------------------------------#
#     start_time = time.time()
#     #--------------------------------------------接收密文时间---------------------------------------------------###
#     print("[CLIENT] 客户端请求检索数据")
#     start_time1 = time.time()
#     # ===== Step1: 接收文件 =====
#     buf = BytesIO()
#     config = TransferConfig(
#         multipart_threshold=8 * 1024 * 1024,
#         multipart_chunksize=8 * 1024 * 1024,
#         max_concurrency=10,
#         use_threads=True
#     )
#     protocol.s3_client.download_fileobj(bucketname, f"{uid}/{uid}_s3s3", buf, Config=config)
#     buf.seek(0)
#     client_download_file_time = (time.time() - start_time1) * 1000
#     print(f"[CLIENT] client从s3下载密文文件耗时: {client_download_file_time:.2f} ms")
#     protocol.user_time_client[uid]["client_download_file_time"] = client_download_file_time
#     run_time["client_download_file_time"] = client_download_file_time
#     #--------------------------------------------------------------------------------------------------------###
#     ##----------------------------------------检索数据 time ↓----------------------------------------------##
#     start_time2 = time.time()
#     a_int = PAE_ext(protocol, uid, pw_input, st)
#     PAE_Ext_time2 = (time.time() - start_time2) * 1000
#     print(f"[CLIENT] PAE_Ext_time2 耗时: {PAE_Ext_time2:.2f} ms")
#     protocol.user_time_client[uid]["PAE_Ext_time2"] =PAE_Ext_time2
#     run_time["PAE_Ext_time2"] = PAE_Ext_time2
#
#     start_time3 = time.time()
#     ack ,bytes_received = recv_with_length(s)
#     print("ack:", ack)
#     pk, byte_scale = recv_with_length(s) # ●●●●● 接收公钥pk
#     total_bytes += byte_scale # 11111111111111111111111111
#     usk_byte,received_bytes = recv_with_length(s) # ●●●●● 接收 usk
#     total_bytes += received_bytes  # 11111111111111111111111111
#     c0,received_bytes = recv_with_length(s) # ●●●●● 接收c0
#     total_bytes += received_bytes  # 11111111111111111111111111
#     print("[CLIENT] pk:", pk)
#     print("[CLIENT] usk_byte:", usk_byte)
#     print("[CLIENT] received_c0",c0)
#
#     sent_bytes=send_with_length(s,1) # ▲▲▲▲▲ 发送确认值
#     total_bytes += sent_bytes #11111111111111111111111111111111111111111
#     usk = int.from_bytes(usk_byte, byteorder='big') % protocol.P #将usk_byte转为int
#     #--------------------------------------------PAE_Dec解密时间---------------------------------------------------###
#     start_time4 = time.time()
#     m_path = PAE_dec(protocol, uid, pw_input, usk, dest_path, k1, st, buf, c0)
#     print("[CLIENT]【DEBUG】UDecwancheng !!!")
#     PAE_Dec_time= (time.time() - start_time4) * 1000
#     print(f"[CLIENT] PAE_Dec 耗时: {PAE_Dec_time:.2f} ms")
#     protocol.user_time_client[uid]["PAE_Dec_time"] = PAE_Dec_time
#     run_time["PAE_Dec_time"] = PAE_Dec_time
#     PAE_Dec_commucation_time = (time.time() - start_time3) * 1000
#     print(f"[CLIENT] PAE_Dec_commucation_time 耗时: {PAE_Dec_commucation_time:.2f} ms")
#     protocol.user_time_client[uid]["PAE_Dec_commucation_time"] = PAE_Dec_commucation_time
#     run_time["PAE_Dec_commucation_time"] = PAE_Dec_commucation_time
#     print("✅ 解密完成")
#     #---------------------------------------------------------------------------------------------------------###
#     client_secure_retrieve_time= (time.time() - start_time1) * 1000
#     print(f"[CLIENT] client_secure_retrieve_time耗时：: {client_secure_retrieve_time:.2f} ms ")
#     protocol.user_time_client[uid]["client_secure_retrieve_time"] = client_secure_retrieve_time
#     run_time["client_secure_retrieve_time"] = client_secure_retrieve_time
#     #
#     protocol.user_time_client[uid]["client_dec_bytes"] = total_bytes
#     run_time["client_dec_bytes"] = total_bytes
#

#####————————————————————————————————————————————————————————————————————————————————————————————————————————————————####

# def client_run_register3(protocol,uid, pw,run_time,eta,k,secure_level):
#     HOST = '54.250.191.84'  # The server's hostname or IP address客户端将连接本地运行的服务器
#     PORT = 5202  # The port used by the server客户端与服务器通信的端口
#     # HOST = '10.102.104.8'
#     # PORT = 25555
#     # HOST = '127.0.0.1'
#     # PORT = 20202
#
#     with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
#         sock.connect((HOST, PORT))
#         print("★★★client开始注册★★★")
#         #接收客户端传过来的公钥pk
#         communication_scale = 0
#         payload = {'secure_level':secure_level,'type': 'reg'}
#         sent_bytes = send_with_length(sock, payload)###与服务器端执行注册过程,选择注册过程
#         communication_scale += sent_bytes #11111111111111111111111
#
#         start_time = time.time()
#         pk,bytes_scale = recv_with_length(sock)# ●●●●● 接收公钥
#         communication_scale += bytes_scale  #11111111111111111111111
#         s = secrets.randbelow(protocol.P)
#         st = pow(pk, s, protocol.P)  # 协商随机数st
#         print("[CLIENT] st:",st)
#         gs = pow(protocol.G, s, protocol.P)
#
#         print("[CLIENT] gs:",gs)
#         h_material = protocol.H(uid,pw,st)
#         e1 = h_material[:protocol.KEY_LEN]
#         e2 = h_material[protocol.KEY_LEN:2 * protocol.KEY_LEN]
#
#         a = protocol.H_new(uid,pw,st) # H_new函数返回的是byte类型
#         a_int = int.from_bytes(a, byteorder='big')% protocol.P
#         A = pow(protocol.G, a_int, protocol.P) # pow运算需要int类型
#
#         # i_bytes = protocol.H_new(eta, uid)  # 混合哈希
#         # i = int.from_bytes(i_bytes, 'big') % (k + 1)
#         # print(f"[CLIENT] 真正的 gs 存在第 {i} 位")
#         #
#         # gs_list = []
#         # for j in range(k + 1):
#         #     if j == i:
#         #         gs_list.append(gs)
#         #     else:
#         #         fake_s = secrets.randbelow(protocol.P)
#         #         gs_list.append(pow(protocol.G, fake_s, protocol.P))
#
#         gs_send = gs_generate(protocol, secure_level, gs, uid, eta, k)
#         payload = {'uid': uid, 'e1': e1, 'e2': e2, 'gs': gs_send,'A':A}
#         sent_bytes = send_with_length(sock, payload)# ▲▲▲▲▲ 将uid，e1，e2，A，gs发送到服务器进行保存
#         communication_scale += sent_bytes  #11111111111111111111111
#
#         ack,bytes_received = recv_with_length(sock) ## ●●●●● 接收确认值
#         communication_scale += bytes_received  #11111111111111111111111
#         register_time = (time.time() - start_time) * 1000
#         print(f"[CLIENT]register_time 耗时: {register_time:.2f} ms")
#         protocol.user_time_client[uid]["register_time"] = register_time
#         run_time["register_time"] = register_time
#         protocol.user_time_client[uid]["client_register_bytes"] = communication_scale
#         run_time["client_register_bytes"] = communication_scale
#         print("[CLIENT] 注册的ack：",ack)
#         print("★★★注册成功★★★")
#
#


# def client_run_enc3_PAKE(protocol: AEKEProtocol, run_time, uid, pw_input, secure_level, eta, k):
#     print("###############客户端请求与server建立安全信道###############")
#     HOST = '54.250.191.84'  # The server's hostname or IP address客户端将连接本地运行的服务器
#     PORT = 5202  # The port used by the server客户端与服务器通信的端口
#     total_bytes = 0
#     s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8 * 1024 * 1024)
#     s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
#     s.connect((HOST, PORT))
#     print(f"[CLIENT] enter socket.connect!")
#     payload = {'secure_level': secure_level, 'type': 'enc'}
#     sent_bytes = send_with_length(s, payload)  # 选择加密流程
#     total_bytes += sent_bytes  # 11111111111111111111111
#     # ------------------------------------aEKE time↓---------------------------------------------------------#
#     start_time = time.time()
#     sent_bytes = send_with_length(s, uid)  # ▲▲▲▲▲ 发送uid
#     total_bytes += sent_bytes  # 11111111111111111111111
#     st_rec, bytes_received = recv_with_length(s)  # ●●●●● 接收st
#     total_bytes += bytes_received  # 11111111111111111111111
#
#     st = client_get_st(protocol, st_rec, eta, uid, k, secure_level)
#     h_material = protocol.H(uid, pw_input, st)
#     print("[CLIENT] st:", st)
#     e1 = h_material[:protocol.KEY_LEN]
#     e2 = h_material[protocol.KEY_LEN:2 * protocol.KEY_LEN]
#     print("[CLIENT] e1:", e1.hex())
#     print("[CLIENT] e2:", e2.hex())
#
#     a = protocol.H_new(uid, pw_input, st)
#     a_int = int.from_bytes(a, byteorder='big') % protocol.P
#     x = secrets.randbelow(protocol.P)  # 客户端临时私钥
#     X = pow(protocol.G, x, protocol.P)  # 客户端临时公钥
#     f0 = protocol.IC_encrypt(e1, X.to_bytes(32, 'big'))  # 用理想密码加密X
#
#     bytes_sent = send_with_length(s, f0)  # ●●●●● 发送f0
#     total_bytes += bytes_sent  # 11111111111111111111111
#     f1, bytes_received = recv_with_length(s)  # ●●●●● 接收f1
#     total_bytes += bytes_received  # 11111111111111111111111
#
#     Y_prime = int.from_bytes(protocol.IC_decrypt(e2, f1), byteorder='big')
#     d0 = protocol.H_prime(uid, X)  # 计算 d0
#     l0 = pow(Y_prime, d0 * a_int + x, protocol.P)
#     k_client = protocol.H_double_prime(uid, X, l0)
#
#     print(f"[CLIENT] Shared key: {k_client.hex()}")
#     s.sendall(pickle.dumps(1))  # ▲▲▲▲▲ 回传 1（仅为同步）
#     # total_bytes += len(pickle.dumps(1)) ##11111111111111111111111111
#     print(f"[CLIENT] 字节数 sent: {len(pickle.dumps(1))}")
#
#     enc_PAKE_time = (time.time() - start_time) * 1000
#     print(f"[CLIENT] aEKE 耗时: {enc_PAKE_time:.2f} ms")
#     protocol.user_time_client[uid]["enc_PAKE_time"] = enc_PAKE_time
#     run_time["enc_PAKE_time"] = enc_PAKE_time
#     print("##########成功建立安全信道#########")
#     print()
#     print()
#     return k_client, st, s


# def client_run_enc3(protocol: AEKEProtocol, s,source_file_path,run_time,uid, pw_input,inter_path1,k44,bucket_name,k_client,st):    #TODO
#     total_bytes = 0
#     start_time = time.time()
#     ##----------------------------------------PAE_Enc time ↓----------------------------------------------##
#     print("★★★客户端加密数据★★★")
#     print("[CLIENT] 【DEBUG】运行UEnc")
#     pk,byte_scale = recv_with_length(s) # ▲▲▲▲▲ 接收公钥pk
#     total_bytes += byte_scale ##11111111111111111111111111
#     print("pk:", pk)
#     start_time1 = time.time()
#     a_int = PAE_ext(protocol,uid,pw_input,st)
#     print("[CLIENT] aINT:",a_int)
#     PAE_Ext_time1 = (time.time() - start_time1) * 1000
#     print(f"[CLIENT] PAE_UEnc 耗时: {PAE_Ext_time1:.2f} ms")
#     protocol.user_time_client[uid]["PAE_Ext_time1"] = PAE_Ext_time1
#     run_time["PAE_Ext_time1"] = PAE_Ext_time1
#
#     start_time2 = time.time()
#     c_path, c0, u = PAE_enc(protocol,uid,pw_input,pk,st,source_file_path,inter_path1, k44) #PAE_Enc过程
#     PAE_Enc_time= (time.time() - start_time2) * 1000
#     print(f"[CLIENT] PAE Enc 耗时: {PAE_Enc_time:.2f} ms")
#     protocol.user_time_client[uid]["PAE_Enc_time"] = PAE_Enc_time
#     run_time["PAE_Enc_time"] = PAE_Enc_time
#     print("[CLIENT] 加密成功！")
#     # payload = {'u':u,'c0':c0}
#     print("[CLIENT] 1111111111")
#     print("[CLIENT] u", u)
#     print("[CLIENT] c0", c0)
#     send_bytes_with_length(s, c0)  # ▲▲▲▲▲ 发送c0
#     total_bytes += 4 + len(c0)  ##11111111111111111111111111
#     print("[CLIENT] 222222222")
#     u_bytes = u.to_bytes((u.bit_length() + 7) // 8, 'big')
#     send_bytes_with_length(s, u_bytes)  # ▲▲▲▲▲ 发送u
#     total_bytes += 4 + len(u_bytes)  ##11111111111111111111111111
#     print("[CLIENT] 333333333")
#     ack1, bytes = recv_with_length(s)  # ●●●●● 接收文件上传成功的确认值
#     print("[SERVER] 文件上传成功", ack1)
#     PAE_Enc_commucation_time = (time.time() - start_time2) * 1000
#     print(f"[CLIENT] PAE Enc commucation 耗时: {PAE_Enc_commucation_time:.2f} ms")
#     protocol.user_time_client[uid]["PAE_Enc_commucation_time"] = PAE_Enc_commucation_time
#     run_time["PAE_Enc_commucation_time"] = PAE_Enc_commucation_time
#     #-------------------------------------------------------------------------------------------------------#
#     ###-------------------------------------upload time---------------------------------------------------###
#     #将文件传到s3上
#     start_time3 = time.time()
#     try:
#         BUFFER_SIZE = 4*1024 * 1024
#         protocol.s3_client.put_bucket_accelerate_configuration(
#             Bucket=bucket_name,
#             AccelerateConfiguration={'Status': 'Enabled'}
#         )
#         protocol.s3_client.upload_file(c_path, bucket_name, f"{uid}/{uid}_s3s3")
#         sent_bytes = send_with_length(s, 1) # ▲▲▲▲▲ 发送文件上传成功的确认消息
#         total_bytes += sent_bytes ##11111111111111111111111111
#     except Exception as e:
#         print(f"[CLIENT] 密文发送失败: {e}")
#         return
#     sent_bytes = send_with_length(s, 1)  # ▲▲▲▲▲ 发送确认消息
#     total_bytes += sent_bytes  ##11111111111111111111111111
#     client_upload_file_time= (time.time() - start_time3) * 1000
#     print(f"[CLIENT] client上传密文文件耗时: {client_upload_file_time:.2f} ms")
#     protocol.user_time_client[uid]["client_upload_file_time"] = client_upload_file_time
#     run_time["client_upload_file_time"] = client_upload_file_time
#
#     client_secure_deposit_time = (time.time() - start_time) * 1000
#     print(f"[CLIENT]client_secure_deposit_time 耗时: {client_secure_deposit_time:.2f} ms")
#     protocol.user_time_client[uid]["client_secure_deposit_time"] = client_secure_deposit_time
#     run_time["client_secure_deposit_time"] = client_secure_deposit_time
#     # protocol.communication_scale[uid]["send_bytes"] += sent_bytes
#     protocol.user_time_client[uid]["client_enc_bytes"] = total_bytes
#     run_time["client_enc_bytes"] = total_bytes
#
#     s.close()
#
#
# #客户端请求解密
# def client_run_dec3_PAKE(protocol: AEKEProtocol, run_time:dict,uid: str, pw_input: str,secure_level,eta,k):
#     HOST = '54.250.191.84'  # The server's hostname or IP address客户端将连接本地运行的服务器
#     PORT = 5202  # The port used by the server客户端与服务器通信的端口
#     # HOST = '10.102.104.8'
#     # PORT = 25555
#     # HOST = '127.0.0.1'
#     # PORT = 20202
#     total_bytes =0
#     s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8 * 1024 * 1024)
#     s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
#     # s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 256 * 1024)
#     s.connect((HOST, PORT))
#     print()
#     print()
#     print("[CLIENT] 客户端请求解密")
#     payload = {'secure_level':secure_level,'type': 'dec'}
#     sent_bytes=send_with_length(s, payload)##选择解密模式
#     print(f"[CLIENT] 字节数 sent: {sent_bytes}")
#     total_bytes += sent_bytes #11111111111111111111111111
#     #------------------------------------aEKE time ↓---------------------------------------------------------#
#     start_time = time.time()
#     flag = 1
#     while flag:
#         print("############客户端请求解密--建立安全信道#############")
#         sent_bytes = send_with_length(s, uid)  # ▲▲▲▲▲ 发送uid
#         total_bytes += sent_bytes  # 11111111111111111111111111
#         st_list, bytes_received = recv_with_length(s)  # ●●●●● 接收st
#         total_bytes += bytes_received  # 11111111111111111111111
#         st = client_get_st(protocol,st_list,eta,uid,k,secure_level)
#         h_material = protocol.H(uid, pw_input, st)
#         print("[CLIENT] st:", st)
#         e1 = h_material[:protocol.KEY_LEN]
#         e2 = h_material[protocol.KEY_LEN:2 * protocol.KEY_LEN]
#         print("[CLIENT] e1:", e1.hex())
#         print("[CLIENT] e2:", e2.hex())
#
#         a = protocol.H_new(uid, pw_input, st)
#         a_int = int.from_bytes(a, byteorder='big') % protocol.P
#         A = pow(protocol.G, a_int, protocol.P)  # pow运算需要int类型
#         x = secrets.randbelow(protocol.P)  # 客户端临时私钥
#         X = pow(protocol.G, x, protocol.P)  # 客户端临时公钥
#         f0 = protocol.IC_encrypt(e1, X.to_bytes(32, 'big'))  # 用理想密码加密X
#
#         payload = {'f0':f0,
#                    'A':A
#                    }
#         # bytes_sent = send_with_length(s, f0)  # ▲▲▲▲▲ 发送f0，A/e1
#         bytes_sent = send_with_length(s, payload)  # ▲▲▲▲▲ 发送f0，A/e1
#         total_bytes += bytes_sent  # 11111111111111111111111111
#
#         flag, received_bytes = recv_with_length(s) #  ●●●●● 接收 flag
#         print(f"字节数 received: {received_bytes}")
#         total_bytes += received_bytes  # 11111111111111111111111111
#
#         if flag == -1:
#             print("[Client] 用户未注册或非法用户！")
#             exit()
#         if flag == 1:
#             print("[Client] 口令错误！请重新输入")
#             pw_input = input("请输入密码: ").strip()
#         if flag == -2:
#             print("[Client] 口令输入错误，账户已锁定！")
#             exit()
#
#
#     f1, bytes_received = recv_with_length(s) # ●●●●● 接收f1
#     total_bytes += bytes_received # 11111111111111111111111111
#
#     Y_prime = int.from_bytes(protocol.IC_decrypt(e2, f1), byteorder='big')
#     d0 = protocol.H_prime(uid, X)  # 计算 d0
#     l0 = pow(Y_prime, d0 * a_int + x, protocol.P)
#     k_client = protocol.H_double_prime(uid, X, l0)
#
#     print(f"[CLIENT] Shared key: {k_client.hex()}")
#     s.sendall(pickle.dumps(1))  # ▲▲▲▲▲ 回传 1（仅为同步）
#     print(f"[CLIENT] 字节数 sent: {len(pickle.dumps(1))}")
#     # total_bytes_sent += len(pickle.dumps(1)) ##11111111111111111111111111
#
#     dec_PAKE_time = (time.time() - start_time) * 1000
#     print(f"[CLIENT] dec_PAKE 耗时: {dec_PAKE_time:.2f} ms")
#     protocol.user_time_client[uid]["dec_PAKE_time"] = dec_PAKE_time
#     run_time["dec_PAKE_time"] = dec_PAKE_time
#     print("##########成功建立安全信道#########")
#     print()
#     print()
#     return k_client, st, s


# #客户端请求解密
# def client_run_dec3(protocol: AEKEProtocol,s, dest_path:str,k1:str,run_time:dict,uid: str, pw_input: str,bucketname:str,k_client,st):
#     total_bytes =0
#
#     #--------------------------------------------接收密文时间---------------------------------------------------###
#     print("[CLIENT] 客户端请求检索数据")
#     start_time1 = time.time()
#     # ===== Step1: 接收文件 =====
#     buf = BytesIO()
#     config = TransferConfig(
#         multipart_threshold=8 * 1024 * 1024,
#         multipart_chunksize=8 * 1024 * 1024,
#         max_concurrency=10,
#         use_threads=True
#     )
#     protocol.s3_client.download_fileobj(bucketname, f"{uid}/{uid}_s3s3", buf, Config=config)
#     buf.seek(0)
#     client_download_file_time = (time.time() - start_time1) * 1000
#     print(f"[CLIENT] client从s3下载密文文件耗时: {client_download_file_time:.2f} ms")
#     protocol.user_time_client[uid]["client_download_file_time"] = client_download_file_time
#     run_time["client_download_file_time"] = client_download_file_time
#     #--------------------------------------------------------------------------------------------------------###
#     ##----------------------------------------检索数据 time ↓----------------------------------------------##
#     start_time2 = time.time()
#     a_int = PAE_ext(protocol, uid, pw_input, st)
#     PAE_Ext_time2 = (time.time() - start_time2) * 1000
#     print(f"[CLIENT] PAE_Ext_time2 耗时: {PAE_Ext_time2:.2f} ms")
#     protocol.user_time_client[uid]["PAE_Ext_time2"] =PAE_Ext_time2
#     run_time["PAE_Ext_time2"] = PAE_Ext_time2
#
#     start_time3 = time.time()
#     ack ,bytes_received = recv_with_length(s)
#     print("ack:", ack)
#     pk, byte_scale = recv_with_length(s) # ●●●●● 接收公钥pk
#     total_bytes += byte_scale # 11111111111111111111111111
#     usk_byte,received_bytes = recv_with_length(s) # ●●●●● 接收 usk
#     total_bytes += received_bytes  # 11111111111111111111111111
#     c0,received_bytes = recv_with_length(s) # ●●●●● 接收c0
#     total_bytes += received_bytes  # 11111111111111111111111111
#     print("[CLIENT] pk:", pk)
#     print("[CLIENT] usk_byte:", usk_byte)
#     print("[CLIENT] received_c0",c0)
#
#     sent_bytes=send_with_length(s,1) # ▲▲▲▲▲ 发送确认值
#     total_bytes += sent_bytes #11111111111111111111111111111111111111111
#     usk = int.from_bytes(usk_byte, byteorder='big') % protocol.P #将usk_byte转为int
#     #--------------------------------------------PAE_Dec解密时间---------------------------------------------------###
#     start_time4 = time.time()
#     m_path = PAE_dec(protocol, uid, pw_input, usk, dest_path, k1, st, buf, c0)
#     print("[CLIENT]【DEBUG】UDecwancheng !!!")
#     PAE_Dec_time= (time.time() - start_time4) * 1000
#     print(f"[CLIENT] PAE_Dec 耗时: {PAE_Dec_time:.2f} ms")
#     protocol.user_time_client[uid]["PAE_Dec_time"] = PAE_Dec_time
#     run_time["PAE_Dec_time"] = PAE_Dec_time
#     PAE_Dec_commucation_time = (time.time() - start_time3) * 1000
#     print(f"[CLIENT] PAE_Dec_commucation_time 耗时: {PAE_Dec_commucation_time:.2f} ms")
#     protocol.user_time_client[uid]["PAE_Dec_commucation_time"] = PAE_Dec_commucation_time
#     run_time["PAE_Dec_commucation_time"] = PAE_Dec_commucation_time
#     print("✅ 解密完成")
#     #---------------------------------------------------------------------------------------------------------###
#     client_secure_retrieve_time= (time.time() - start_time1) * 1000
#     print(f"[CLIENT] client_secure_retrieve_time耗时：: {client_secure_retrieve_time:.2f} ms ")
#     protocol.user_time_client[uid]["client_secure_retrieve_time"] = client_secure_retrieve_time
#     run_time["client_secure_retrieve_time"] = client_secure_retrieve_time
#     #
#     protocol.user_time_client[uid]["client_dec_bytes"] = total_bytes
#     run_time["client_dec_bytes"] = total_bytes
#
#     s.close()

def measure_file_upload_download(protocol:AEKEProtocol, file_path: str, uid:str,run_time:dict,bucket_name,host='54.250.191.84', port=20202):
    """上传文件并测量上传+下载明文用时"""
    total_bytes_sent2=0
    if not os.path.isfile(file_path):
        print(f"[CLIENT] 文件不存在: {file_path}")
        return

    filename = os.path.basename(file_path)
    with open(file_path, 'rb') as f:
        file_content = f.read()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))

        payload = {'type': 3, 'uid': uid}
        print(f"[CLIENT] 发送 uid: {uid}")
        # s.sendall(pickle.dumps(payload) )
        sent_bytes=send_with_length(s, payload)
        # protocol.communication_scale[uid]["send_bytes"] += sent_bytes
        # total_bytes_sent2 += sent_bytes



        # 发送数据
        start_time = time.time()
        try:
            BUFFER_SIZE = 4 * 1024 * 1024

            protocol.s3_client.put_bucket_accelerate_configuration(
                Bucket=bucket_name,
                AccelerateConfiguration={'Status': 'Enabled'}
            )
            protocol.s3_client.upload_file(file_path, bucket_name, f"{uid}/{uid}_s3s3")
            sent_bytes=send_with_length(s, b'OK')
            # protocol.communication_scale[uid]["send_bytes"] += sent_bytes
            # total_bytes_sent2 += sent_bytes
        except Exception as e:
            print(f"[CLIENT] 密文发送失败: {e}")
            return
        client_deposit_plain_time = (time.time() - start_time) * 1000
        print(f"[CLIENT] client_deposit_plain_time 耗时: {client_deposit_plain_time:.2f} ms")
        protocol.user_time_client[uid]["client_deposit_plain_time"] = client_deposit_plain_time
        run_time["client_deposit_plain_time"] = client_deposit_plain_time

        start_time = time.time()

        # 接收返回数据
        buf = BytesIO()
        start_time1 = time.time()
        config = TransferConfig(
            multipart_threshold=8 * 1024 * 1024,
            multipart_chunksize=8 * 1024 * 1024,
            max_concurrency=10,
            use_threads=True
        )
        # recv_with_length(s)
        # cc_file_path = os.path.join(inter_path, "received_cc_from_s3")
        # with open(cc_file_path, 'wb') as f:
        #     protocol.s3_client.download_fileobj(bucketname, f"{uid}/{uid}_s3s3", f,Config=config)

        protocol.s3_client.download_fileobj(bucket_name, f"{uid}/{uid}_s3s3", buf, Config=config)
        buf.seek(0)
        sent_bytes=send_with_length(s, b'OK')
        # protocol.communication_scale[uid]["send_bytes"] += sent_bytes
        # total_bytes_sent2 += sent_bytes

        client_retrieve_plain_time = (time.time() - start_time) * 1000
        print(f"[CLIENT] client_retrieve_plain_time 耗时: {client_retrieve_plain_time:.2f} ms")
        protocol.user_time_client[uid]["client_retrieve_plain_time"] = client_retrieve_plain_time
        run_time["client_retrieve_plain_time"] = client_retrieve_plain_time





