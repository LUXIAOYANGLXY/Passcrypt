import time
from aEKE import AEKEProtocol
from boto3.s3.transfer import TransferConfig
from utils import *
import secrets
import socket
import pickle

###——————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————###
def server_get_st_list(protocol: AEKEProtocol,uid,conn,secure_level):
    if secure_level == 2 or secure_level == 3:
        gs0 = protocol.user_db[uid]['gs_store0']
        # gs1 = protocol.user_db[uid]['gs_store1']
    elif secure_level == 4:
        gs_list = protocol.user_db[uid]['gs_store']
        st_list = []
        for idx, gs in enumerate(gs_list):
            try:
                st = pow(gs, protocol.sk, protocol.P)
            except Exception as exc:
                # 如果出现类型或值错误，记录并返回错误（健壮性处理）
                print(f"[SERVER] 计算 st 时出错 idx={idx}, gs={gs}: {exc}")
                send_with_length(conn, {'error': 'st_calc_failed', 'idx': idx})
                return
            st_list.append(st)
        st_send = st_list
    return gs0


def rate_limiting(protocol: AEKEProtocol,uid,conn,A,A_rec):
    if uid in protocol.user_db:
        # retrieved = protocol.user_db[uid]
        print("[SERVER] received")
    else:
        print("[SERVER] 非法用户！")
        conn.sendall(pickle.dumps(-1))
        exit()
    print("ctr:", protocol.user_db[uid]['ctr'])

    if protocol.user_db[uid]['ctr'] == 0:
        print('[SERVER] 拒绝访问')
        conn.sendall(pickle.dumps(-1))
    else:
        protocol.user_db[uid]['ctr'] -= 1
        # 判断pw1是否正确,
        if A_rec != A:
            print('[SERVER] 口令错误')
            # conn.sendall(pickle.dumps(1))
            send_with_length(conn, '1')
            # 再次输入，知道ctr为0
            while protocol.user_db[uid]['ctr'] > 0:
                payload1, byte_scale = recv_with_length(conn)  # ●●●●● 接收A///f0,A
                # uid = payload1['uid']
                # f0 = payload1['f0']
                A_rec = payload1['A']

                if A_rec == A:
                    print('[SERVER] 口令正确')
                    # conn.sendall(pickle.dumps(0))
                    send_with_length(conn, '0')
                    protocol.user_db[uid]['ctr'] = 3
                    break
                else:
                    protocol.user_db[uid]['ctr'] -= 1
                    print('[SERVER] 口令错误')
                    if protocol.user_db[uid]['ctr'] > 0:
                        conn.sendall(pickle.dumps(1))

            if protocol.user_db[uid]['ctr'] == 0:
                # print("0000000000")
                conn.sendall(pickle.dumps(-2))
                # exit()

        else:
            # print('口令正确')
            # conn.sendall(pickle.dumps(0))
            byte_scale = send_with_length(conn, 0)
            # communication_scale += byte_scale
            protocol.user_db[uid]['ctr'] = 3
            print("[SERVER] 口令正确，ctr重置为3")
            # print("口令正确，ctr重置为3")

    return protocol.user_db[uid]['ctr']


###————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————###


def server_run_register(protocol,conn,run_time,run_scale,secure_level):
    print("[SERVER] 等待客户端注册！")
    start_time = time.time()
    communication_scale = 0
    pk = protocol.pk
    bytes_sent = send_with_length(conn, pk) ### ▲▲▲▲▲ 发送公钥
    if secure_level == 2 or secure_level == 3:
        payload,byte_scale = recv_with_length(conn)## ●●●●● 接收uid、gs、e1，e2，A，存储起来
        uid = payload['uid']
        gs_rec0 = payload['gs0']
        # gs_rec1 = payload['gs1']
        e1 = payload['e1']
        e2 = payload['e2']
        A = payload['A']
        print("gs_rec0", gs_rec0)
        gs_store0 =pow(gs_rec0, protocol.sk, protocol.P)
        # gs_store1 = pow(gs_rec1, protocol.sk, protocol.P)
        protocol.user_db[uid] = {'uid': uid, 'e1': e1, 'e2': e2, 'gs_store0': gs_store0, 'A': A,'pk':protocol.pk,'sk':protocol.sk}
        byte_scale = send_with_length(conn,1)# ▲▲▲▲▲ 发送确认值
    elif secure_level == 1:
        payload, byte_scale = recv_with_length(conn)  ## ●●●●● 接收uid、gs、e1，e2，A，存储起来
        uid = payload['uid']
        e1 = payload['e1']
        e2 = payload['e2']
        A = payload['A']
        st = payload['st']
        protocol.user_db[uid] = {'uid': uid, 'e1': e1, 'e2': e2, 'A': A,'st':st, 'pk': protocol.pk,'sk': protocol.sk}
        byte_scale = send_with_length(conn, 1)  # ▲▲▲▲▲ 发送确认值
    server_run_register_time = (time.time() - start_time) * 1000
    print(f"[SERVER] server_run_register_time: {server_run_register_time:.2f} ms")
    # protocol.user_time_server1[uid]["server_aEKE_time1"] = aEKE_time1
    run_time["server_run_register_time"] = server_run_register_time
    run_scale["server_run_register_time"] = server_run_register_time
    print("[SERVER] 客户端注册成功！")


def server_run_enc1(protocol: AEKEProtocol, bucketname:str,run_time:dict,conn:socket,run_scale):  # 服务器端运行函数
    print(f"##########与客户端建立socket通道#########")
    try:
        start_time = time.time()
        print("[SERVER] start_time", start_time)
        uid,byte_scale = recv_with_length(conn) # ●●●●● 接收用户uid
        if uid not in protocol.user_db:
            print(f"[SERVER] User '{uid}' not found!")
            return
        # start_time1= time.time()
        pk = protocol.user_db[uid]['pk']
        print(f"[SERVER] protocol.pk,{pk}")
        bytes_sent = send_with_length(conn, pk)# ▲▲▲▲▲ 发送公钥pk
        st = protocol.user_db[uid]['st']
        bytes_sent = send_with_length(conn, st)  # ▲▲▲▲▲ 发送公钥pk

        print("[SERVER] 正在等待接收客户端上传的密钥文件...")
        c0 = recv_bytes_with_length(conn) # ●●●●● 接收c0
        u = recv_bytes_with_length(conn) # ●●●●● 接收u
        sent_bytes = send_with_length(conn, 1)  # ▲▲▲▲▲
        ack1,bytes=recv_with_length(conn) # ●●●●● 接收密钥文件上传成功的确认值
        print("[SERVER] 文件上传成功",ack1)

        # start_time3 = time.time()
        k0_filename = f"{uid}_s3s3"
        s3_key = f"{uid}/{k0_filename}"

        # 计数器ctr设为3
        ctr = 3
        #将T,v,c,ctr存储在user_db中
        protocol.user_db[uid]['u'] = u
        protocol.user_db[uid]['c0'] = c0
        protocol.user_db[uid]['c'] = f"s3://{bucketname}/{s3_key}"
        protocol.user_db[uid]['ctr'] = ctr
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
            # print(f"[SERVER] ack==={type(ack)}")
            if ack == 1:
                print("[SERVER] ✅ 上传成功，服务器已确认接收")
            else:
                print("[SERVER] ⚠️ 未收到有效ACK")
        except Exception as e:
            print(f"[SERVER] 接收ACK: {e}")
    except Exception as e:
        print("[SERVER] 错误:", e)

#Server收到解密请求
def server_run_dec1(protocol: AEKEProtocol, run_time:dict,conn:socket,run_scale):  # 服务器端运行函数
        print("##########Server端收到下载请求#########")
        # ------------------------------------aEKE time↓--------------------------------------------------------##
        start_time = time.time()
        uid, byte_scale = recv_with_length(conn) # ●●●●●接收uid
        st = protocol.user_db[uid]['st']
        bytes_sent = send_with_length(conn, st)  # ▲▲▲▲▲ 发送公钥pk

        A = protocol.user_db[uid]['A']
        payload, byte_scale = recv_with_length(conn)  # ●●●●● 接收A
        A_rec=payload['A']

        ctr = rate_limiting(protocol,uid,conn,A,A_rec)

        if ctr == 3:
            start_time1 = time.time()
            bytes_sent = send_with_length(conn, 1)  # ▲▲▲▲▲ 发送ack
            pk = protocol.user_db[uid]['pk']
            print(f"[SERVER] protocol.pk,{pk}")
            bytes_sent = send_with_length(conn, pk) # ▲▲▲▲▲ 发送公钥pk

            config = TransferConfig(multipart_threshold=8 * 1024 * 1024, max_concurrency=4)
            k0_filename = f"{uid}_s3s3"
            # print("[SERVER]【DEBUG】k0", k0_filename)
            s3_key = f"{uid}/{k0_filename}"


            u = protocol.user_db[uid]['u']
            u_int= int.from_bytes(u, 'big')#将u转为int型
            usk = pow(u_int, protocol.user_db[uid]['sk'], protocol.P)
            byte_scale = send_with_length(conn, usk.to_bytes(32, 'big')) # ▲▲▲▲▲ 发送usk
            c0 = protocol.user_db[uid]['c0']
            byte_scale = send_with_length(conn,c0) # ▲▲▲▲▲ 发送c0
            ack,byte_scale = recv_with_length(conn) # ●●●●● 接收确认值
            print("[SERVER] 加密密文已直接发送给客户端")
            server_run_dec_time = (time.time() - start_time) * 1000
            print(f"[SERVER] server_run_dec_time 耗时: {server_run_dec_time:.2f} ms")
            # protocol.user_time_server1[uid]["server_aEKE_time1"] = aEKE_time1
            run_time["server_run_dec_time"] = server_run_dec_time
            run_scale["server_run_dec_time"] = server_run_dec_time




def server_run_enc2(protocol: AEKEProtocol, bucketname:str,run_time:dict,conn:socket,run_scale):  # 服务器端运行函数
    print(f"##########与客户端建立socket通道#########")
    try:
        start_time = time.time()
        print("[SERVER] start_time", start_time)
        uid,byte_scale = recv_with_length(conn) # ●●●●● 接收用户uid
        if uid not in protocol.user_db:
            print(f"[SERVER] User '{uid}' not found!")
            return


        gs0 = protocol.user_db[uid]['gs_store0']
        # gs1 = protocol.user_db[uid]['gs_store1']
        # payload = {'gs0':gs0,'gs1': gs1}

        byte_scale = send_with_length(conn,gs0) # ▲▲▲▲▲ 发送gs0

        # start_time1= time.time()
        pk = protocol.user_db[uid]['pk']
        print(f"[SERVER] protocol.pk,{pk}")
        bytes_sent = send_with_length(conn, pk)# ▲▲▲▲▲ 发送公钥pk

        print("[SERVER] 正在等待接收客户端上传的密钥文件...")
        c0 = recv_bytes_with_length(conn) # ●●●●● 接收c0
        u = recv_bytes_with_length(conn) # ●●●●● 接收u
        sent_bytes = send_with_length(conn, 1)  # ▲▲▲▲▲
        ack1,bytes=recv_with_length(conn) # ●●●●● 接收密钥文件上传成功的确认值
        print("[SERVER] 文件上传成功",ack1)

        # start_time3 = time.time()
        k0_filename = f"{uid}_s3s3"
        s3_key = f"{uid}/{k0_filename}"

        # 计数器ctr设为3
        ctr = 3
        #将T,v,c,ctr存储在user_db中
        protocol.user_db[uid]['u'] = u
        protocol.user_db[uid]['c0'] = c0
        protocol.user_db[uid]['c'] = f"s3://{bucketname}/{s3_key}"
        protocol.user_db[uid]['ctr'] = ctr
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
            # print(f"[SERVER] ack==={type(ack)}")
            if ack == 1:
                print("[SERVER] ✅ 上传成功，服务器已确认接收")
            else:
                print("[SERVER] ⚠️ 未收到有效ACK")
        except Exception as e:
            print(f"[SERVER] 接收ACK: {e}")
    except Exception as e:
        print("[SERVER] 错误:", e)

#Server收到解密请求
def server_run_dec2(protocol: AEKEProtocol, run_time:dict,conn:socket,run_scale):  # 服务器端运行函数
        print("##########Server端收到下载请求#########")
        # ------------------------------------aEKE time↓--------------------------------------------------------##
        start_time = time.time()
        uid, byte_scale = recv_with_length(conn) # ●●●●●接收uid
        # if uid not in protocol.user_db:
        #     print(f"[SERVER] User '{uid}' not found!")
        #     return
        gs0 = protocol.user_db[uid]['gs_store0']
        # gs1 = protocol.user_db[uid]['gs_store1']
        # payload = {'gs0': gs0, 'gs1': gs1}
        byte_scale = send_with_length(conn, gs0) # ▲▲▲▲▲ 发送随机数gs
        print("gs已发送11111111111111111111")


        A = protocol.user_db[uid]['A']
        payload, byte_scale = recv_with_length(conn)  # ●●●●● 接收A
        A_rec=payload['A']

        ctr = rate_limiting(protocol,uid,conn,A,A_rec)

        if ctr == 3:
            start_time1 = time.time()
            bytes_sent = send_with_length(conn, 1)  # ▲▲▲▲▲ 发送ack
            pk = protocol.user_db[uid]['pk']
            print(f"[SERVER] protocol.pk,{pk}")
            bytes_sent = send_with_length(conn, pk) # ▲▲▲▲▲ 发送公钥pk

            config = TransferConfig(multipart_threshold=8 * 1024 * 1024, max_concurrency=4)
            k0_filename = f"{uid}_s3s3"
            # print("[SERVER]【DEBUG】k0", k0_filename)
            s3_key = f"{uid}/{k0_filename}"


            u = protocol.user_db[uid]['u']
            u_int= int.from_bytes(u, 'big')#将u转为int型
            usk = pow(u_int, protocol.user_db[uid]['sk'], protocol.P)
            byte_scale = send_with_length(conn, usk.to_bytes(32, 'big')) # ▲▲▲▲▲ 发送usk
            c0 = protocol.user_db[uid]['c0']
            byte_scale = send_with_length(conn,c0) # ▲▲▲▲▲ 发送c0
            ack,byte_scale = recv_with_length(conn) # ●●●●● 接收确认值
            print("[SERVER] 加密密文已直接发送给客户端")
            server_run_dec_time = (time.time() - start_time) * 1000
            print(f"[SERVER] server_run_dec_time 耗时: {server_run_dec_time:.2f} ms")
            # protocol.user_time_server1[uid]["server_aEKE_time1"] = aEKE_time1
            run_time["server_run_dec_time"] = server_run_dec_time
            run_scale["server_run_dec_time"] = server_run_dec_time



######————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————#####


def server_run_enc3_PAKE(protocol: AEKEProtocol,run_time:dict,conn:socket,run_scale,secure_level):  # 服务器端运行函数
    print(f"##########与客户端建立安全信道#########")
    try:
        # ------------------------------------aEKE time↓--------------------------------------------------------##
        start_time = time.time()
        print("[SERVER] start_time", start_time)
        uid,byte_scale = recv_with_length(conn) # ●●●●● 接收用户id
        if uid not in protocol.user_db:
            print(f"[SERVER] User '{uid}' not found!")
            return
        gs0 = server_get_st_list(protocol,uid,conn,secure_level)
        # payload = {'gs0': gs0, 'gs1': gs1}
        byte_scale = send_with_length(conn,gs0) # ▲▲▲▲▲ 发送st
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
        d1 = protocol.H_prime(uid, X_prime)  # 计算 d0
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
        return k_server, uid
        ###----------------------------------------aEKE time 👆----------------------------------------------##
    except Exception as e:
        print("[SERVER] 错误:", e)


def server_run_enc3(protocol: AEKEProtocol, bucketname:str,run_time:dict,conn:socket,run_scale,k_server, uid):  # 服务器端运行函数
    print(f"##########与客户端建立安全信道#########")
    try:
        # ------------------------------------aEKE time↓--------------------------------------------------------##
        start_time = time.time()
        # start_time1= time.time()
        pk = protocol.user_db[uid]['pk']
        print(f"[SERVER] protocol.pk,{pk}")
        pk_send = protocol.AES_encrypt(k_server,pk.to_bytes(32, 'big')) ###PAKE
        bytes_sent = send_with_length(conn, pk_send)# ▲▲▲▲▲ 发送公钥pk  PAKE

        print("[SERVER] 正在等待接收客户端上传的加密文件...")
        c0_rec = recv_bytes_with_length(conn) # ●●●●● 接收c0
        # print("[SERVER] c0_rec type ", type(c0_rec))
        c0 = protocol.AES_decrypt(k_server,c0_rec)  ##PAKE
        # print("[SERVER] c0 type ", type(c0))
        u_rec = recv_bytes_with_length(conn) # ●●●●● 接收u
        u = protocol.AES_decrypt(k_server,u_rec)  ###PAKE
        sent_bytes = send_with_length(conn, 1)  # ▲▲▲▲▲
        ack1,bytes=recv_with_length(conn) # ●●●●● 接收文件上传成功的确认值
        print("[SERVER] 文件上传成功",ack1)

        # start_time3 = time.time()
        k0_filename = f"{uid}_s3s3"
        s3_key = f"{uid}/{k0_filename}"

        # 计数器ctr设为3
        ctr = 3
        #将T,v,c,ctr存储在user_db中
        protocol.user_db[uid]['u'] = u
        protocol.user_db[uid]['c0'] = c0
        protocol.user_db[uid]['c'] = f"s3://{bucketname}/{s3_key}"
        protocol.user_db[uid]['ctr'] = ctr
        print(protocol.user_db[uid])
        print("######################## Sever存储成功！###############################")
        print()
        print()

        server_run_enc_time = (time.time() - start_time) * 1000
        print(f"[SERVER] 安全存储耗时: {server_run_enc_time:.2f} ms")
        # protocol.user_time_server1[uid]["server_run_enc_time"] = server_run_enc_time
        run_time["server_run_enc_time"] = server_run_enc_time
        run_scale["server_run_enc_time"] = server_run_enc_time

        try:
            ack,bytes = recv_with_length(conn)  # ●●●●● 接收ACK
            print(f"[SERVER] 收到服务器ACK: {ack}")
            print(f"[SERVER] ack==={type(ack)}")
            if ack == 1:
                print("[SERVER] ✅ 上传成功，服务器已确认接收")
            else:
                print("[SERVER] ⚠️ 未收到有效ACK")
        except Exception as e:
            print(f"[SERVER] 接收ACK: {e}")
    except Exception as e:
        print("[SERVER] 错误:", e)







#Server收到解密请求
def server_run_dec3_PAKE(protocol: AEKEProtocol, run_time:dict,conn:socket,run_scale,secure_level):  # 服务器端运行函数
    print("##########Server端收到下载请求#########")
    # ------------------------------------aEKE time↓--------------------------------------------------------##
    start_time = time.time()
    uid, byte_scale = recv_with_length(conn) # ●●●●●接收uid

    # st_send = server_get_st_list(protocol, uid, conn, secure_level)
    # # print("[SERVER] st", st_send)
    # byte_scale = send_with_length(conn, st_send) # ▲▲▲▲▲ 发送随机数st
    gs0 = server_get_st_list(protocol, uid, conn, secure_level)
    # payload = {'gs0': gs0, 'gs1': gs1}
    byte_scale = send_with_length(conn, gs0)  # ▲▲▲▲▲ 发送st

    e1 = protocol.user_db[uid]['e1']
    e2 = protocol.user_db[uid]['e2']
    print("[SERVER] e1", e1.hex())
    print("[SERVER] e2", e2.hex())
    A = protocol.user_db[uid]['A']
    y = secrets.randbelow(protocol.P)  # 服务器临时私钥
    Y = pow(protocol.G, y, protocol.P)  # 服务器临时公钥
    f1 = protocol.IC_encrypt(e2, Y.to_bytes(32, 'big'))  # 用理想密码加密 Y,得到f1

    payload, byte_scale = recv_with_length(conn)  # ●●●●● 接收f0,A
    f0 = payload['f0']
    A_rec=payload['A']

    ctr = rate_limiting(protocol,uid,conn,A,A_rec)
    if ctr == 3:
        byte_scale = send_with_length(conn, f1) # ▲▲▲▲▲ 发送f1
        X_prime = int.from_bytes(protocol.IC_decrypt(e1, f0), byteorder='big')
        d1 = protocol.H_prime(uid, X_prime)  # 计算 d0
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
        return k_server, uid

#Server收到解密请求
def server_run_dec3(protocol: AEKEProtocol, run_time:dict,conn:socket,run_scale,k_server, uid):  # 服务器端运行函数
    print("##########Server端收到下载请求#########")
    # ------------------------------------aEKE time↓--------------------------------------------------------#
    start_time1 = time.time()
    bytes_sent = send_with_length(conn, 1)  # ▲▲▲▲▲ 发送ack
    pk = protocol.user_db[uid]['pk']
    print(f"[SERVER] protocol.pk,{pk}")
    pk_send = protocol.AES_encrypt(k_server, pk.to_bytes(32, 'big'))  ###PAKE
    bytes_sent = send_with_length(conn, pk_send) # ▲▲▲▲▲ 发送公钥pk PAKE

    config = TransferConfig(multipart_threshold=8 * 1024 * 1024, max_concurrency=4)
    k0_filename = f"{uid}_s3s3"
    # print("[SERVER]【DEBUG】k0", k0_filename)
    s3_key = f"{uid}/{k0_filename}"


    ####
    u = protocol.user_db[uid]['u']
    u_int= int.from_bytes(u, 'big')#将u转为int型
    usk = pow(u_int, protocol.user_db[uid]['sk'], protocol.P)
    print(f"[SERVER] usk,{usk.to_bytes(32, 'big').hex()}")
    usk_send = protocol.AES_encrypt(k_server,usk.to_bytes(32, 'big'))##PAKE
    byte_scale = send_with_length(conn, usk_send)  # ▲▲▲▲▲ 发送usk
    # byte_scale = send_with_length(conn, usk.to_bytes(32, 'big')) # ▲▲▲▲▲ 发送usk
    c0 = protocol.user_db[uid]['c0']
    print("[SERVER] c0", c0.hex())
    c0_send = protocol.AES_encrypt(k_server, c0)  ###PAKE
    byte_scale = send_with_length(conn,c0_send) # ▲▲▲▲▲ 发送c0
    ack,byte_scale = recv_with_length(conn) # ●●●●● 接收确认值
    print("[SERVER] 加密密文已直接发送给客户端")
    server_run_dec_time = (time.time() - start_time1) * 1000
    print(f"[SERVER] server_run_dec_time 耗时: {server_run_dec_time:.2f} ms")
    # protocol.user_time_server1[uid]["server_aEKE_time1"] = aEKE_time1
    run_time["server_run_dec_time"] = server_run_dec_time
    run_scale["server_run_dec_time"] = server_run_dec_time


#####————————————————————————————————————————————————————————————————————————————————————————————————————————————————————####
# def server_run_enc22(protocol: AEKEProtocol, bucketname:str,run_time:dict,conn:socket,run_scale,k_server, uid):  # 服务器端运行函数
#     print(f"##########与客户端建立安全信道#########")
#     try:
#         # ------------------------------------aEKE time↓--------------------------------------------------------##
#         start_time = time.time()
#         # start_time1= time.time()
#         pk = protocol.user_db[uid]['pk']
#         print(f"[SERVER] protocol.pk,{pk}")
#         bytes_sent = send_with_length(conn, pk)# ▲▲▲▲▲ 发送公钥pk
#
#         print("[SERVER] 正在等待接收客户端上传的加密文件...")
#         c0 = recv_bytes_with_length(conn) # ●●●●● 接收c0
#         u = recv_bytes_with_length(conn) # ●●●●● 接收u
#         sent_bytes = send_with_length(conn, 1)  # ▲▲▲▲▲
#         ack1,bytes=recv_with_length(conn) # ●●●●● 接收文件上传成功的确认值
#         print("[SERVER] 文件上传成功",ack1)
#
#         # start_time3 = time.time()
#         k0_filename = f"{uid}_s3s3"
#         s3_key = f"{uid}/{k0_filename}"
#
#         # 计数器ctr设为3
#         ctr = 3
#         #将T,v,c,ctr存储在user_db中
#         protocol.user_db[uid]['u'] = u
#         protocol.user_db[uid]['c0'] = c0
#         protocol.user_db[uid]['c'] = f"s3://{bucketname}/{s3_key}"
#         protocol.user_db[uid]['ctr'] = ctr
#         print(protocol.user_db[uid])
#         print("######################## Sever存储成功！###############################")
#         print()
#         print()
#
#         server_run_enc_time = (time.time() - start_time) * 1000
#         print(f"[SERVER] 安全存储耗时: {server_run_enc_time:.2f} ms")
#         # protocol.user_time_server1[uid]["server_run_enc_time"] = server_run_enc_time
#         run_time["server_run_enc_time"] = server_run_enc_time
#         run_scale["server_run_enc_time"] = server_run_enc_time
#
#         try:
#             ack,bytes = recv_with_length(conn)  # ●●●●● 接收ACK
#             print(f"[SERVER] 收到服务器ACK: {ack}")
#             print(f"[SERVER] ack==={type(ack)}")
#             if ack == 1:
#                 print("[SERVER] ✅ 上传成功，服务器已确认接收")
#             else:
#                 print("[SERVER] ⚠️ 未收到有效ACK")
#         except Exception as e:
#             print(f"[SERVER] ❌ 接收ACK失败: {e}")
#     except Exception as e:
#         print("[SERVER] 错误:", e)
#
# #Server收到解密请求
# def server_run_dec22(protocol: AEKEProtocol, run_time:dict,conn:socket,run_scale,k_server, uid):  # 服务器端运行函数
#     print("##########Server端收到下载请求#########")
#     # ------------------------------------aEKE time↓--------------------------------------------------------#
#     start_time1 = time.time()
#     pk = protocol.user_db[uid]['pk']
#     print(f"[SERVER] protocol.pk,{pk}")
#     bytes_sent = send_with_length(conn, pk) # ▲▲▲▲▲ 发送公钥pk
#
#     config = TransferConfig(multipart_threshold=8 * 1024 * 1024, max_concurrency=4)
#     k0_filename = f"{uid}_s3s3"
#     print("[SERVER]【DEBUG】k0", k0_filename)
#     s3_key = f"{uid}/{k0_filename}"
#
#     u = protocol.user_db[uid]['u']
#     u_int= int.from_bytes(u, 'big')#将u转为int型
#     usk = pow(u_int, protocol.user_db[uid]['sk'], protocol.P)
#     bytes_sent = send_with_length(conn, 1) # ▲▲▲▲▲ 发送ack
#     byte_scale = send_with_length(conn, usk.to_bytes(32, 'big')) # ▲▲▲▲▲ 发送usk
#     c0 = protocol.user_db[uid]['c0']
#     byte_scale = send_with_length(conn,c0) # ▲▲▲▲▲ 发送
#     ack,byte_scale = recv_with_length(conn) # ●●●●● 接收确认值
#     print("[SERVER] 加密密文已直接发送给客户端")
#     server_run_dec_time = (time.time() - start_time1) * 1000
#     print(f"[SERVER] server_run_dec_time 耗时: {server_run_dec_time:.2f} ms")
#     # protocol.user_time_server1[uid]["server_aEKE_time1"] = aEKE_time1
#     run_time["server_run_dec_time"] = server_run_dec_time
#     run_scale["server_run_dec_time"] = server_run_dec_time
#

# def server_run_register3(protocol,conn,run_time,run_scale,secure_level):
#     print("[SERVER] 等待客户端注册！")
#     start_time = time.time()
#     communication_scale = 0
#     pk = protocol.pk
#     bytes_sent = send_with_length(conn, pk) ### ▲▲▲▲▲ 发送公钥
#     payload,byte_scale = recv_with_length(conn)## ●●●●● 接收uid、gs、e1，e2，A，存储起来
#     uid = payload['uid']
#     gs_rec= payload['gs']
#     e1 = payload['e1']
#     e2 = payload['e2']
#     A = payload['A']
#     protocol.user_db[uid] = {'uid': uid, 'e1': e1, 'e2': e2, 'gs_store': gs_rec, 'A': A,'pk':protocol.pk,'sk':protocol.sk}
#     byte_scale = send_with_length(conn,1)# ▲▲▲▲▲ 发送确认值
#     server_run_register_time = (time.time() - start_time) * 1000
#     print(f"[SERVER] server_run_register_time: {server_run_register_time:.2f} ms")
#     # protocol.user_time_server1[uid]["server_aEKE_time1"] = aEKE_time1
#     run_time["server_run_register_time"] = server_run_register_time
#     run_scale["server_run_register_time"] = server_run_register_time
#     print("[SERVER] 客户端注册成功！")


# def server_get_st_list(protocol: AEKEProtocol,uid,conn):
#     gs_list = protocol.user_db[uid]['gs_store']
#     st_list = []
#     for idx, gs in enumerate(gs_list):
#         try:
#             st = pow(gs, protocol.sk, protocol.P)
#         except Exception as exc:
#             # 如果出现类型或值错误，记录并返回错误（健壮性处理）
#             print(f"[SERVER] 计算 st 时出错 idx={idx}, gs={gs}: {exc}")
#             send_with_length(conn, {'error': 'st_calc_failed', 'idx': idx})
#             return
#         st_list.append(st)
#     return st_list

# def server_run_enc3_PAKE(protocol: AEKEProtocol, run_time:dict,conn:socket,run_scale,secure_level):  # 服务器端运行函数
#     print(f"##########与客户端建立安全信道#########")
#     try:
#         # ------------------------------------aEKE time↓--------------------------------------------------------##
#         start_time = time.time()
#         print("[SERVER] start_time", start_time)
#         uid,byte_scale = recv_with_length(conn) # ●●●●● 接收用户id
#         if uid not in protocol.user_db:
#             print(f"[SERVER] User '{uid}' not found!")
#             return
#         st_send = server_get_st_list(protocol,uid,conn,secure_level)
#         byte_scale = send_with_length(conn,st_send) # ▲▲▲▲▲ 发送st
#
#         e1 = protocol.user_db[uid]['e1']
#         e2 = protocol.user_db[uid]['e2']
#         print("[SERVER] e1",e1.hex())
#         print("[SERVER] e2",e2.hex())
#         A = protocol.user_db[uid]['A']
#         y = secrets.randbelow(protocol.P)  # 服务器临时私钥
#         Y = pow(protocol.G, y, protocol.P) # 服务器临时公钥
#         f1 = protocol.IC_encrypt(e2, Y.to_bytes(32, 'big'))  # 用理想密码加密 Y,得到f1
#
#         f0, byte_scale = recv_with_length(conn)  # ●●●●● 接收f0
#         byte_scale = send_with_length(conn,f1) # ▲▲▲▲▲ 发送f1
#
#         X_prime = int.from_bytes(protocol.IC_decrypt(e1, f0), byteorder='big')
#         d1 = protocol.H_prime(uid, X_prime)  # 计算 d0
#         A_pow_d1 = pow(A, d1, protocol.P)
#         l1 = pow((X_prime * A_pow_d1) % protocol.P, y, protocol.P)
#         k_server = protocol.H_double_prime(uid, X_prime, l1)
#
#         data = pickle.loads(conn.recv(4096))  # ●●●●● 接收回传 1
#         print(f"[SERVER] Shared key: {k_server.hex()}")
#         aEKE_time1= (time.time() - start_time) * 1000
#         print(f"[SERVER] aEKE耗时: {aEKE_time1:.2f} ms")
#         # protocol.user_time_server1[uid]["server_aEKE_time1"] = aEKE_time1
#         run_time["server_enc_PAKE_time"] = aEKE_time1
#         run_scale["server_enc_PAKE_time"] = aEKE_time1
#         print(f"##########成功建立安全信道!#########")
#         return k_server,uid
#         ###----------------------------------------aEKE time 👆----------------------------------------------##
#     except Exception as e:
#         print("[SERVER] 错误:", e)

# def server_run_enc3(protocol: AEKEProtocol, bucketname:str,run_time:dict,conn:socket,run_scale,k_server,uid):  # 服务器端运行函数
#     print(f"##########与客户端建立安全信道#########")
#     try:
#
#         start_time = time.time()
#
#         # start_time1= time.time()
#         pk = protocol.user_db[uid]['pk']
#         print(f"[SERVER] protocol.pk,{pk}")
#         bytes_sent = send_with_length(conn, pk)# ▲▲▲▲▲ 发送公钥pk
#
#         print("[SERVER] 正在等待接收客户端上传的加密文件...")
#         c0 = recv_bytes_with_length(conn) # ●●●●● 接收c0
#         u = recv_bytes_with_length(conn) # ●●●●● 接收u
#         sent_bytes = send_with_length(conn, 1)  # ▲▲▲▲▲
#         ack1,bytes=recv_with_length(conn) # ●●●●● 接收文件上传成功的确认值
#         print("[SERVER] 文件上传成功",ack1)
#
#         # start_time3 = time.time()
#         k0_filename = f"{uid}_s3s3"
#         s3_key = f"{uid}/{k0_filename}"
#
#         # 计数器ctr设为3
#         ctr = 3
#         #将T,v,c,ctr存储在user_db中
#         protocol.user_db[uid]['u'] = u
#         protocol.user_db[uid]['c0'] = c0
#         protocol.user_db[uid]['c'] = f"s3://{bucketname}/{s3_key}"
#         protocol.user_db[uid]['ctr'] = ctr
#         print(protocol.user_db[uid])
#         print("######################## Sever存储成功！###############################")
#         print()
#         print()
#
#         server_run_enc_time = (time.time() - start_time) * 1000
#         print(f"[SERVER] 安全存储耗时: {server_run_enc_time:.2f} ms")
#         # protocol.user_time_server1[uid]["server_run_enc_time"] = server_run_enc_time
#         run_time["server_run_enc_time"] = server_run_enc_time
#         run_scale["server_run_enc_time"] = server_run_enc_time
#
#         try:
#             ack,bytes = recv_with_length(conn)  # ●●●●● 接收ACK
#             print(f"[SERVER] 收到服务器ACK: {ack}")
#             print(f"[SERVER] ack==={type(ack)}")
#             if ack == 1:
#                 print("[SERVER] ✅ 上传成功，服务器已确认接收")
#             else:
#                 print("[SERVER] ⚠️ 未收到有效ACK")
#         except Exception as e:
#             print(f"[SERVER] ❌ 接收ACK失败: {e}")
#     except Exception as e:
#         print("[SERVER] 错误:", e)
#


#
# #Server收到解密请求
# def server_run_dec3_PAKE(protocol: AEKEProtocol, run_time:dict,conn:socket,run_scale):  # 服务器端运行函数
#         print("##########Server端收到下载请求#########")
#         # ------------------------------------aEKE time↓--------------------------------------------------------##
#         start_time = time.time()
#         uid, byte_scale = recv_with_length(conn) # ●●●●●接收uid
#         gs_list = protocol.user_db[uid]['gs_store']
#         st_list = []
#         for idx, gs in enumerate(gs_list):
#             try:
#                 st = pow(gs, protocol.sk, protocol.P)
#             except Exception as exc:
#                 print(f"[SERVER] 计算 st 时出错 idx={idx}, gs={gs}: {exc}")
#                 send_with_length(conn, {'error': 'st_calc_failed', 'idx': idx})
#                 return
#             st_list.append(st)
#         byte_scale = send_with_length(conn, st_list) # ▲▲▲▲▲ 发送随机数st
#
#         e1 = protocol.user_db[uid]['e1']
#         e2 = protocol.user_db[uid]['e2']
#         print("[SERVER] e1", e1.hex())
#         print("[SERVER] e2", e2.hex())
#         A = protocol.user_db[uid]['A']
#         y = secrets.randbelow(protocol.P)  # 服务器临时私钥
#         Y = pow(protocol.G, y, protocol.P)  # 服务器临时公钥
#         f1 = protocol.IC_encrypt(e2, Y.to_bytes(32, 'big'))  # 用理想密码加密 Y,得到f1
#
#         payload, byte_scale = recv_with_length(conn)  # ●●●●● 接收f0,A
#         f0 = payload['f0']
#         A_rec=payload['A']
#
#         ctr = rate_limiting(protocol,uid,conn,A,A_rec)
#         if ctr == 3:
#             byte_scale = send_with_length(conn, f1) # ▲▲▲▲▲ 发送f1
#             X_prime = int.from_bytes(protocol.IC_decrypt(e1, f0), byteorder='big')
#             d1 = protocol.H_prime(uid, X_prime)  # 计算 d0
#             # d1 = protocol.H_prime(uid, st, X_prime)  # 计算 d0
#             A_pow_d1 = pow(A, d1, protocol.P)
#             l1 = pow((X_prime * A_pow_d1) % protocol.P, y, protocol.P)
#             k_server = protocol.H_double_prime(uid, X_prime, l1)
#
#             data = pickle.loads(conn.recv(4096))  # ●●●●● 接收回传 1
#             print(f"[SERVER] Shared key: {k_server.hex()}")
#             print()
#             server_dec_PAKE_time = (time.time() - start_time) * 1000
#             print(f"[SERVER] PAKE耗时: {server_dec_PAKE_time:.2f} ms")
#             run_time["server_dec_PAKE_time"] =server_dec_PAKE_time
#             run_scale["server_dec_PAKE_time"] = server_dec_PAKE_time
#             print(f"##########成功建立安全信道!#########")
#             return k_server, uid
#
# #Server收到解密请求
# def server_run_dec3_PAKE(protocol: AEKEProtocol, run_time:dict,conn:socket,run_scale,secure_level):  # 服务器端运行函数
#         print("##########Server端收到下载请求#########")
#         # ------------------------------------aEKE time↓--------------------------------------------------------##
#         start_time = time.time()
#         uid, byte_scale = recv_with_length(conn) # ●●●●●接收uid
#         st_send = server_get_st_list(protocol, uid, conn, secure_level)
#         byte_scale = send_with_length(conn, st_send) # ▲▲▲▲▲ 发送随机数st
#
#         e1 = protocol.user_db[uid]['e1']
#         e2 = protocol.user_db[uid]['e2']
#         print("[SERVER] e1", e1.hex())
#         print("[SERVER] e2", e2.hex())
#         A = protocol.user_db[uid]['A']
#         y = secrets.randbelow(protocol.P)  # 服务器临时私钥
#         Y = pow(protocol.G, y, protocol.P)  # 服务器临时公钥
#         f1 = protocol.IC_encrypt(e2, Y.to_bytes(32, 'big'))  # 用理想密码加密 Y,得到f1
#
#         payload, byte_scale = recv_with_length(conn)  # ●●●●● 接收f0,A
#         f0 = payload['f0']
#         A_rec=payload['A']
#
#         ctr = rate_limiting(protocol,uid,conn,A,A_rec)
#         if ctr == 3:
#             byte_scale = send_with_length(conn, f1) # ▲▲▲▲▲ 发送f1
#             X_prime = int.from_bytes(protocol.IC_decrypt(e1, f0), byteorder='big')
#             d1 = protocol.H_prime(uid, X_prime)  # 计算 d0
#             # d1 = protocol.H_prime(uid, st, X_prime)  # 计算 d0
#             A_pow_d1 = pow(A, d1, protocol.P)
#             l1 = pow((X_prime * A_pow_d1) % protocol.P, y, protocol.P)
#             k_server = protocol.H_double_prime(uid, X_prime, l1)
#
#             data = pickle.loads(conn.recv(4096))  # ●●●●● 接收回传 1
#             print(f"[SERVER] Shared key: {k_server.hex()}")
#             print()
#             server_dec_PAKE_time = (time.time() - start_time) * 1000
#             print(f"[SERVER] PAKE耗时: {server_dec_PAKE_time:.2f} ms")
#             run_time["server_dec_PAKE_time"] =server_dec_PAKE_time
#             run_scale["server_dec_PAKE_time"] = server_dec_PAKE_time
#             print(f"##########成功建立安全信道!#########")
#             return k_server, uid


# #Server收到解密请求
# def server_run_dec3(protocol: AEKEProtocol, run_time:dict,conn:socket,run_scale,k_server, uid):  # 服务器端运行函数
#         start_time1 = time.time()
#         pk = protocol.user_db[uid]['pk']
#         print(f"[SERVER] protocol.pk,{pk}")
#         bytes_sent = send_with_length(conn, pk) # ▲▲▲▲▲ 发送公钥pk
#
#         config = TransferConfig(multipart_threshold=8 * 1024 * 1024, max_concurrency=4)
#         k0_filename = f"{uid}_s3s3"
#         print("[SERVER]【DEBUG】k0", k0_filename)
#         s3_key = f"{uid}/{k0_filename}"
#
#         u = protocol.user_db[uid]['u']
#         u_int= int.from_bytes(u, 'big')#将u转为int型
#         usk = pow(u_int, protocol.user_db[uid]['sk'], protocol.P)
#         bytes_sent = send_with_length(conn, 1) # ▲▲▲▲▲ 发送ack
#         byte_scale = send_with_length(conn, usk.to_bytes(32, 'big')) # ▲▲▲▲▲ 发送usk
#         c0 = protocol.user_db[uid]['c0']
#         byte_scale = send_with_length(conn,c0) # ▲▲▲▲▲ 发送
#         ack,byte_scale = recv_with_length(conn) # ●●●●● 接收确认值
#         print("[SERVER] 加密密文已直接发送给客户端")
#         server_run_dec_time = (time.time() - start_time1) * 1000
#         print(f"[SERVER] server_run_dec_time 耗时: {server_run_dec_time:.2f} ms")
#         # protocol.user_time_server1[uid]["server_aEKE_time1"] = aEKE_time1
#         run_time["server_run_dec_time"] = server_run_dec_time
#         run_scale["server_run_dec_time"] = server_run_dec_time
#




def start_file_echo_server(protocol:AEKEProtocol,bucketname,conn):
            # 接收客户端发送的数据
            ack1 = recv_with_length(conn)
            print("[SERVER] 文件上传成功", ack1)
            ack2 = recv_with_length(conn)
            print("[SERVER] 文件上传成功", ack2)
