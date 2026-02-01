import time
from aEKE import AEKEProtocol
from boto3.s3.transfer import TransferConfig
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from utils import *
import secrets
import socket
import pickle


###——————————————————————————————————————————————————————————————————————————————————————————————————————————————————————————###
def server_get_st_list(protocol: AEKEProtocol,uid,conn,secure_level):
    if secure_level == 2 or secure_level == 3:
        gs0 = protocol.user_db[uid]['gs_store0']
    elif secure_level == 4:
        gs_list = protocol.user_db[uid]['gs_store']
        st_list = []
        sk_obj = ec.derive_private_key(protocol.sk, protocol.ec_curve, default_backend())
        for idx, gs in enumerate(gs_list):
            try:
                # 将字节转回点对象并执行点乘 (ECDH exchange)
                gs_point = protocol.deserialize_pubkey(gs)
                st_bytes = sk_obj.exchange(ec.ECDH(), gs_point)
                st_list.append(st_bytes)
            except Exception as exc:
                print(f"[SERVER] 计算 st 时出错 idx={idx}, gs={gs}: {exc}")
                send_with_length(conn, {'error': 'st_calc_failed', 'idx': idx})
                return
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
            print('[SERVER] 口令错误1')
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
                    print('[SERVER] 口令错误2')
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
    pk_bytes = protocol.serialize_pubkey(protocol.ec_public_key)
    bytes_sent = send_with_length(conn, pk_bytes) ### ▲▲▲▲▲ 发送公钥
    if secure_level == 2 or secure_level == 3:
        payload,byte_scale = recv_with_length(conn)## ●●●●● 接收uid、gs、e1，e2，A，存储起来
        uid = payload['uid']
        gs_rec0_bytes = payload['gs0']
        e1 = payload['e1']
        e2 = payload['e2']
        A = payload['A']
        print("gs_rec0", gs_rec0_bytes.hex())
        gs_rec0_point = protocol.deserialize_pubkey(gs_rec0_bytes)
        # 直接使用 protocol.ec_private_key
        gs_store0_bytes = protocol.ec_private_key.exchange(ec.ECDH(), gs_rec0_point)
        # 直接使用 protocol.ec_private_key
        protocol.user_db[uid] = {'uid': uid, 'e1': e1, 'e2': e2, 'gs_store0': gs_store0_bytes, 'A': A,'pk':protocol.pk,'sk':protocol.sk}
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
        pk_obj = protocol.user_db[uid]['pk']
        pk_bytes = protocol.serialize_pubkey(pk_obj)
        print(f"[SERVER] protocol.pk,{pk_bytes}")
        bytes_sent = send_with_length(conn, pk_bytes)# ▲▲▲▲▲ 发送公钥pk
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
            pk_obj = protocol.user_db[uid]['pk']
            pk_bytes = protocol.serialize_pubkey(pk_obj)
            print(f"[SERVER] protocol.pk,{pk_bytes}")
            bytes_sent = send_with_length(conn, pk_bytes) # ▲▲▲▲▲ 发送公钥pk

            config = TransferConfig(multipart_threshold=8 * 1024 * 1024, max_concurrency=4)
            k0_filename = f"{uid}_s3s3"
            # print("[SERVER]【DEBUG】k0", k0_filename)
            s3_key = f"{uid}/{k0_filename}"

            u = protocol.user_db[uid]['u']
            u_point = protocol.deserialize_pubkey(u)
            # 2. 计算共享秘密 usk = sk_server * u_client
            usk_bytes = protocol.ec_private_key.exchange(ec.ECDH(), u_point)
            byte_scale = send_with_length(conn, usk_bytes) # ▲▲▲▲▲ 发送usk
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
        byte_scale = send_with_length(conn,gs0) # ▲▲▲▲▲ 发送gs0

        # start_time1= time.time()
        pk_obj = protocol.user_db[uid]['pk']
        pk_bytes = protocol.serialize_pubkey(pk_obj)
        print(f"[SERVER] protocol.pk,{pk_bytes}")
        bytes_sent = send_with_length(conn, pk_bytes)# ▲▲▲▲▲ 发送公钥pk

        print("[SERVER] 正在等待接收客户端上传的密钥文件...")
        c0 = recv_bytes_with_length(conn) # ●●●●● 接收c0
        u_bytes = recv_bytes_with_length(conn) # ●●●●● 接收u
        sent_bytes = send_with_length(conn, 1)  # ▲▲▲▲▲
        ack1,bytes=recv_with_length(conn) # ●●●●● 接收密钥文件上传成功的确认值
        print("[SERVER] 文件上传成功",ack1)

        # start_time3 = time.time()
        k0_filename = f"{uid}_s3s3"
        s3_key = f"{uid}/{k0_filename}"

        # 计数器ctr设为3
        ctr = 3
        #将T,v,c,ctr存储在user_db中
        protocol.user_db[uid]['u'] = u_bytes
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
        gs0 = protocol.user_db[uid]['gs_store0']
        byte_scale = send_with_length(conn, gs0) # ▲▲▲▲▲ 发送随机数gs
        print("gs已发送11111111111111111111")

        A = protocol.user_db[uid]['A']
        payload, byte_scale = recv_with_length(conn)  # ●●●●● 接收A
        A_rec=payload['A']
        print("[SERVER] A_rec",A_rec.hex())
        print("[SERVER] A",A.hex())

        ctr = rate_limiting(protocol,uid,conn,A,A_rec)

        if ctr == 3:
            start_time1 = time.time()
            bytes_sent = send_with_length(conn, 1)  # ▲▲▲▲▲ 发送ack
            pk_obj = protocol.user_db[uid]['pk']
            pk_bytes = protocol.serialize_pubkey(pk_obj)
            print(f"[SERVER] protocol.pk,{pk_bytes}")
            bytes_sent = send_with_length(conn, pk_bytes) # ▲▲▲▲▲ 发送公钥pk

            config = TransferConfig(multipart_threshold=8 * 1024 * 1024, max_concurrency=4)
            k0_filename = f"{uid}_s3s3"
            s3_key = f"{uid}/{k0_filename}"


            u_bytes = protocol.user_db[uid]['u']
            u_point = protocol.deserialize_pubkey(u_bytes)
            usk_bytes = protocol.ec_private_key.exchange(ec.ECDH(), u_point)
            byte_scale = send_with_length(conn, usk_bytes) # ▲▲▲▲▲ 发送usk
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
        uid,byte_scale = recv_with_length(conn) # ●●●●● 接收用户id
        if uid not in protocol.user_db:
            print(f"[SERVER] User '{uid}' not found!")
            return
        gs0 = server_get_st_list(protocol,uid,conn,secure_level)
        byte_scale = send_with_length(conn,gs0) # ▲▲▲▲▲ 发送st
        e1 = protocol.user_db[uid]['e1']
        e2 = protocol.user_db[uid]['e2']
        print("[SERVER] e1",e1.hex())
        print("[SERVER] e2",e2.hex())
        A_bytes = protocol.user_db[uid]['A']
        A_obj = protocol.deserialize_pubkey(A_bytes)
        y = secrets.randbelow(protocol.N)  # 服务器临时私钥
        Y_obj = ec.derive_private_key(y, protocol.ec_curve, default_backend()).public_key()
        Y_bytes = protocol.serialize_pubkey(Y_obj)
        print("[SERVER] Y_prime_bytes", Y_bytes.hex())
        f1 = protocol.IC_encrypt(e2, Y_bytes)  # 用理想密码加密 Y,得到f1

        start_time = time.time()
        f0, byte_scale = recv_with_length(conn)  # ●●●●● 接收f0
        byte_scale = send_with_length(conn,f1) # ▲▲▲▲▲ 发送f1
        print("[SERVER] f0",f0.hex())
        print("[SERVER] f1",f1.hex())

        X_prime_bytes = protocol.IC_decrypt(e1, f0)
        print("[SERVER] X_prime_bytes",X_prime_bytes.hex())
        X_prime_obj = protocol.deserialize_pubkey(X_prime_bytes)
        print(f"[DEBUG] X_prime_obj type: {type(X_prime_obj)}")

        d1_hash_bytes = protocol.H_prime(uid, X_prime_bytes)
        d1 = int.from_bytes(d1_hash_bytes, 'big') % protocol.N

        # 计算共享点部分
        term1_bytes = ec.derive_private_key(y, protocol.ec_curve).exchange(ec.ECDH(), X_prime_obj)
        scalar2 = (y * d1) % protocol.N
        term2_bytes = ec.derive_private_key(scalar2, protocol.ec_curve).exchange(ec.ECDH(), A_obj)

        l1_material = term1_bytes + term2_bytes
        k_server = protocol.H_double_prime(uid, X_prime_bytes, l1_material)

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
        pk_obj = protocol.user_db[uid]['pk']
        pk_bytes = protocol.serialize_pubkey(pk_obj)
        print(f"[SERVER] protocol.pk,{pk_bytes}")
        pk_send = protocol.AES_encrypt(k_server,pk_bytes) ###PAKE
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
    uid, byte_scale = recv_with_length(conn) # ●●●●●接收uid
    gs0 = server_get_st_list(protocol, uid, conn, secure_level)
    byte_scale = send_with_length(conn, gs0)  # ▲▲▲▲▲ 发送st

    e1 = protocol.user_db[uid]['e1']
    e2 = protocol.user_db[uid]['e2']
    print("[SERVER] e1", e1.hex())
    print("[SERVER] e2", e2.hex())
    A_bytes = protocol.user_db[uid]['A']
    A_obj = protocol.deserialize_pubkey(A_bytes)
    y = secrets.randbelow(protocol.N)  # 服务器临时私钥
    Y_obj = ec.derive_private_key(y, protocol.ec_curve, default_backend()).public_key()
    Y_bytes = protocol.serialize_pubkey(Y_obj)
    f1 = protocol.IC_encrypt(e2, Y_bytes)  # 用理想密码加密 Y,得到f1

    start_time = time.time()
    payload, byte_scale = recv_with_length(conn)  # ●●●●● 接收f0,A
    f0 = payload['f0']
    A_rec=payload['A']


    ctr = rate_limiting(protocol,uid,conn,A_bytes,A_rec)
    if ctr == 3:
        byte_scale = send_with_length(conn, f1) # ▲▲▲▲▲ 发送f1
        X_prime_bytes = protocol.IC_decrypt(e1, f0)
        print("[SERVER] X_prime_bytes", X_prime_bytes.hex())
        X_prime_obj = protocol.deserialize_pubkey(X_prime_bytes)
        print(f"[DEBUG] X_prime_obj type: {type(X_prime_obj)}")

        d1_hash_bytes = protocol.H_prime(uid, X_prime_bytes)
        d1 = int.from_bytes(d1_hash_bytes, 'big') % protocol.N

        term1_bytes = ec.derive_private_key(y, protocol.ec_curve).exchange(ec.ECDH(), X_prime_obj)
        scalar2 = (y * d1) % protocol.N
        term2_bytes = ec.derive_private_key(scalar2, protocol.ec_curve).exchange(ec.ECDH(), A_obj)

        l1_material = term1_bytes + term2_bytes
        k_server = protocol.H_double_prime(uid, X_prime_bytes, l1_material)

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
    pk_obj = protocol.user_db[uid]['pk']
    pk_bytes = protocol.serialize_pubkey(pk_obj)
    print(f"[SERVER] protocol.pk,{pk_bytes}")
    pk_send = protocol.AES_encrypt(k_server, pk_bytes)  ###PAKE
    bytes_sent = send_with_length(conn, pk_send) # ▲▲▲▲▲ 发送公钥pk PAKE

    config = TransferConfig(multipart_threshold=8 * 1024 * 1024, max_concurrency=4)
    k0_filename = f"{uid}_s3s3"
    # print("[SERVER]【DEBUG】k0", k0_filename)
    s3_key = f"{uid}/{k0_filename}"

    u_bytes = protocol.user_db[uid]['u']
    u_point = protocol.deserialize_pubkey(u_bytes)

    usk_bytes = protocol.ec_private_key.exchange(ec.ECDH(), u_point)
    print(f"[SERVER] usk 计算完成: {usk_bytes.hex()}")
    usk_send = protocol.AES_encrypt(k_server,usk_bytes)##PAKE
    byte_scale = send_with_length(conn, usk_send)  # ▲▲▲▲▲ 发送usk
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




def start_file_echo_server(protocol:AEKEProtocol,bucketname,conn):
            # 接收客户端发送的数据
            ack1 = recv_with_length(conn)
            print("[SERVER] 文件上传成功", ack1)
            ack2 = recv_with_length(conn)
            print("[SERVER] 文件上传成功", ack2)


