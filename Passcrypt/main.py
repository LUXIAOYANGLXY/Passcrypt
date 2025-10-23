import binascii
import string
import sys
import configparser
import Constants
from aEKE import AEKEProtocol
from client import client_run_enc
from client import client_run_dec,client_run_register
from client import measure_file_upload_download
from server import server_run_enc
from server import server_run_dec,server_run_register
from server import start_file_echo_server
from Constants import SERVER_ID,INTER_FILE, INTER_ENC_FILE,C1_PATH,INTER_FILE1,SERVER_AEKE_PATH
import random
from utils import *
import pickle
import socket
import struct
import time


def main(run_time):
    if len(sys.argv) == 1:
        print("第一个参数：client/erver")
        print("如果第一个参数是 client，第二个参数是源文件路径")
        return

    role = sys.argv[1]
    print(role)
    dec_dest_path =Constants.DEC_DEST_FILE

    k0 = f"encrypted_data"
    k1 = f"decrypted_data"
    k2 = f"enc_client_data"
    k3 = f"inter_data"
    k4 = f"enc_client_data"
    k44 = f"inter_enc_data"
    k5 = f"c1_path_111"
    k6 = f"server_aeke_data"
    print("【DEBUG】main k2:", k2)
    inter_path1 = INTER_FILE1
    inter_path = INTER_FILE
    inter_enc_path = INTER_ENC_FILE
    c1_path_1 = C1_PATH
    server_aeke_path = SERVER_AEKE_PATH


    if role == Constants.CLIENT:
        if len(sys.argv) < 3:
            print("[CLIENT] 请在 args[1] 中指定源文件路径")
            return

        source_file_path = sys.argv[2]
        print("[CLIENT] 客户端测试整个流程")
        print(f"[CLIENT] 源文件路径为：{source_file_path}")
        print("[CLIENT] 耗时统计 (ms)")

        # 从 config.properties 加载配置
        config = configparser.ConfigParser()
        with open("config.properties", "r", encoding="utf-8") as f:
            config.read_file(f)
        access_key_id = config.get("DEFAULT", "accessKeyId", fallback=None)
        secret_key_id = config.get("DEFAULT", "secretKeyId", fallback=None)
        region_name = config.get("DEFAULT", "regionName", fallback=None)
        bucket_name = config.get("DEFAULT", "bucketName", fallback=None)

        # 创建指标累计字典
        metrics_total = {
            "register_time":0,
            "enc_PAKE_time": 0,
            "PAE_Ext_time1": 0,
            "PAE_Enc_time": 0,
            'PAE_Enc_commucation_time': 0,
            # "client_PAKE_PAE_time1": 0,
            "client_upload_file_time": 0,
            "client_secure_deposit_time": 0,
            "dec_PAKE_time": 0,
            "client_download_file_time": 0,
            "PAE_Ext_time2": 0,
            "PAE_Dec_time": 0,
            'PAE_Dec_commucation_time': 0,
            # "client_PAKE_PAE_time2": 0,
            "client_secure_retrieve_time": 0,
            "client_deposit_plain_time": 0,
            "client_retrieve_plain_time": 0,
            "client_register_bytes": 0,
            "client_enc_bytes": 0,
            "client_dec_bytes": 0
        }
        # total_communication_scale ={
        #     "send_bytes": 0,
        #     "recv_bytes": 0
        # }
        for i in range(10):
            print(f"\n=========== 第 {i + 1} 次测试 ===========")
            protocol = AEKEProtocol(region_name,access_key_id,secret_key_id,key_len=24,sec_level=2048, verbose=True)

            # 用户名和密码1
            rand = random.Random()
            random_bytes = bytes([rand.randint(0, 255) for _ in range(10)])
            user_id = f"username{binascii.hexlify(random_bytes).decode('utf-8')}"
            passphrase = f"passphrase{binascii.hexlify(random_bytes).decode('utf-8')}"
            # desired_length = 40
            # chars = string.ascii_letters + string.digits + "!@#$%^&*"
            # passphrase = ''.join(random.choice(chars) for _ in range(desired_length))
            print(f"1用户名：{user_id}，密码：{passphrase}")
            protocol.user_time_client.setdefault(user_id, {})  # 初始化时间字典
            protocol.communication_scale.setdefault(user_id, {})  # 初始化通信量字典
            print("\n[CLIENT] Connecting to server...\n")
            print(f"2用户名：{user_id}，密码：{passphrase}")

            client_run_register(protocol,user_id,passphrase,run_time)

            client_run_enc(protocol, source_file_path,run_time,user_id, passphrase,inter_path1,k44,inter_enc_path,k4,bucket_name)##aEKE+加密+上传

            client_run_dec(protocol, dec_dest_path,k1,inter_path,k3,run_time,user_id, passphrase,bucket_name)#aEKE+解密+下载

            # measure_file_upload_download(protocol,source_file_path,user_id,run_time,bucket_name)

            print("[CLIENT] 运行时间：",protocol.user_time_client[user_id])
            print("[CLIENT] 通信量：", protocol.communication_scale[user_id])
            for key in metrics_total:
                if key in protocol.user_time_client[user_id]:
                    metrics_total[key] += protocol.user_time_client[user_id][key]
                else:
                    print(f"[CLIENT] ⚠️ Warning: 第{i + 1}次测试未记录指标 {key}")
            # for key in total_communication_scale:
            #     if key in protocol.communication_scale[user_id]:
            #         total_communication_scale[key] += protocol.communication_scale[user_id][key]
            #     else:
            #         print(f"⚠️ Warning: 第{i + 1}次测试未记录通信量 {key}")

        print("\n======== 📊 平均耗时统计（单位：ms）========")
        for key in metrics_total:
            avg_time = metrics_total[key] / 10
            print(f"{key}: {avg_time:.2f} ms")
        # for key in total_communication_scale:
        #     avg_scale = total_communication_scale[key] / 10
        #     print(f"{key}: {avg_scale:.2f} bytes")

    elif role == Constants.SERVER:
        print("[SERVER] 运行 Server")

        metrics_total = {
            'server_run_register_time': 0,
            'server_enc_PAKE_time': 0,
            'server_run_enc_time': 0,
            'server_dec_PAKE_time': 0,
            'server_run_dec_time': 0
        }
        run_scale = {}

        # 从 config.properties 加载配置
        config = configparser.ConfigParser()
        with open("config.properties", "r", encoding="utf-8") as f:
            config.read_file(f)
        access_key_id = config.get("DEFAULT", "accessKeyId", fallback=None)
        secret_key_id = config.get("DEFAULT", "secretKeyId", fallback=None)
        region_name = config.get("DEFAULT", "regionName", fallback=None)
        bucket_name = config.get("DEFAULT", "bucketName", fallback=None)

        PORT = 5202  # The port used by the server
        with (socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s): # 创建一个TCP套接字对象s，用于与客户端进行通信，AF_INET 表示 IPv4 地址族，SOCK_STREAM 表示 TCP 协议
             # s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 256 * 1024)
             s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8 * 1024 * 1024)
             s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
             s.bind(('', PORT))  # 绑定主机地址和端口号
             s.listen()  # 监听传入的连接请求
             print("[SERVER] Waiting for connection...")
             protocol = AEKEProtocol(region_name, access_key_id, secret_key_id, key_len=24, sec_level=2048, verbose=True)

             try:
                 while True:
                    i=0
                    print(f"\n=========== 第 {i + 1} 次测试 ===========")
                    newsocket, _ = s.accept()
                    conn = newsocket
                    print("\n[SERVER] Listening for client connection...\n")
                    try:
                        print("[SERVER]:receive")
                        request,bytes_rec=recv_with_length(conn)
                        if request['type'] == 0:
                            print("\n[SERVER] 等待客户端连接...\n")
                            server_run_register(protocol,conn,run_time,run_scale)
                        elif request['type'] == 1:
                            print("\n[SERVER] 与客户端运行加密操作...\n")
                            server_run_enc(protocol,  bucket_name, k0, run_time,conn,c1_path_1,k5,run_scale)
                        elif request['type'] ==2:
                            print("\n[SERVER] 与客户端运行解密操作...\n")
                            server_run_dec(protocol, SERVER_ID, bucket_name, k0, run_time,conn,server_aeke_path,k6,run_scale)
                        # elif request['type'] ==3:
                        #     start_file_echo_server(protocol,bucket_name,conn)
                        for key in metrics_total:
                            if key in run_scale:
                                metrics_total[key] += run_scale[key]
                            else:
                                print(f"[SERVER] ⚠️ Warning: 第{i + 1}次测试未记录指标 {key}")
                        for key in metrics_total:
                            avg_time = metrics_total[key] / 10
                            print(f"{key}: {avg_time:.2f} ")
                    except KeyboardInterrupt:
                        print("[SERVER] 收到退出信号，关闭服务器")
                        break
                    except Exception as e:
                        print(f"[SERVER] 运行出错: {e}")
                        continue
             finally:
                 s.close()

    else:
        print("参数错误，应为 client + 文件路径 或 server")
    # print("运行时间run_time：",run_time)

if __name__ == "__main__":
    run_time = {}
    main(run_time)
