import pickle
import secrets
import socket
import struct
from io import BytesIO
import boto3
import paramiko


def recv_with_length(sock):
    # 先接收前4个字节，表示后续数据长度
    raw_msglen = sock.recv(4)
    if not raw_msglen:
        return None
    msglen = struct.unpack('>I', raw_msglen)[0]
    data = b''
    while len(data) < msglen:
        packet = sock.recv(msglen - len(data))
        if not packet:
            return None
        data += packet
    return pickle.loads(data),4+msglen

def send_with_length(sock, obj):
    data = pickle.dumps(obj)
    length = len(data).to_bytes(4, 'big')
    sock.sendall(length)  # 先发送数据长度
    sock.sendall(data)  # 再发送数据本体
    return 4 + len(data)

# 发送原始字节数据
def send_bytes_with_length(sock, byte_data: bytes):
    sock.sendall(len(byte_data).to_bytes(4, 'big'))
    sock.sendall(byte_data)

# 接收原始字节数据（不反序列化）
def recv_bytes_with_length(sock):
    raw_msglen = sock.recv(4)
    if not raw_msglen:
        return None
    msglen = struct.unpack('>I', raw_msglen)[0]
    data = b''
    while len(data) < msglen:
        packet = sock.recv(msglen - len(data))
        if not packet:
            return None
        data += packet
    return data


def UEnc_to_stream(protocol, m_path, pw, B, a, k5):
    # 生成随机对称密钥 k（整数），用于加密明文
    k = secrets.randbelow(protocol.P)

    # --- Step 1: 将明文加密为 ciphertext_stream ---
    ciphertext_stream = BytesIO()
    protocol.AES_encrypt_streaming_to_stream(k, m_path, ciphertext_stream, k5)
    ciphertext_stream.seek(0)  # 重置指针以供后续读取

    # --- Step 2: 使用 H(pw) 和 a, B 生成共享密钥 B_pw ---
    pw_hash = protocol.H(pw)
    a_pw = (a * int.from_bytes(pw_hash, 'big')) % protocol.P
    B_pw = pow(B, a_pw, protocol.P)

    # --- Step 3: 计算共享对称密钥 u1（H''） ---
    hash_input = str(B_pw) + pw + str(B)
    u = protocol.H_double_prime(hash_input.encode())  # bytes

    # --- Step 4: 用 u 加密对称密钥 k（32字节）生成密文 v ---
    v = protocol.AES_encrypt(u, k.to_bytes(32, 'big'))

    return ciphertext_stream, v


def UEnc(protocol, m_path, pw, B, a,inter_path1,k5, iv_unused=None):

    # 生成随机对称密钥 k（整数），用于加密明文
    k = secrets.randbelow(protocol.P)

    c_path = protocol.AES_encrypt_streaming(k, m_path,inter_path1,k5)

    # 口令哈希并混合私钥生成共享密码
    pw_hash = protocol.H(pw)
    a_pw = (a * int.from_bytes(pw_hash, 'big')) % protocol.P
    B_pw = pow(B, a_pw, protocol.P)

    # 计算 H''，生成对称密钥 u
    hash_input = str(B_pw) + pw + str(B)
    u = protocol.H_double_prime(hash_input.encode())  # 输出为 bytes

    # 用 u 加密 k（转为 32 字节），返回 AES-GCM 格式密文
    v = protocol.AES_encrypt(u, k.to_bytes(32, 'big'))

    return c_path, v


# def UDec(protocol, pw, c_path, v, B, a, iv,dest_path,k1):
#     pw_hash = protocol.H(pw)
#     a_pw = (a * int.from_bytes(pw_hash, 'big')) % protocol.P
#     B_pw = pow(B, a_pw, protocol.P)
#     hash_input = str(B_pw) + pw + str(B)
#
#     u1 = protocol.H_double_prime(hash_input.encode())  # 直接用返回值（bytes）
#     print("【DEBUG】u1", u1.hex())
#
#     k = protocol.AES_decrypt(u1, v)
#     m_path = protocol.AES_decrypt_streaming(int.from_bytes(k, 'big'), c_path,dest_path,k1)
#     print("mmmmmmmm")
#     return m_path

def UDec_from_stream(protocol, pw, ciphertext_stream, v, B, a, dest_path, k1):
    pw_hash = protocol.H(pw)
    a_pw = (a * int.from_bytes(pw_hash, 'big')) % protocol.P
    B_pw = pow(B, a_pw, protocol.P)
    hash_input = str(B_pw) + pw + str(B)

    u1 = protocol.H_double_prime(hash_input.encode())
    print("【DEBUG】u1", u1.hex())

    k = protocol.AES_decrypt(u1, v)

    # 修改为从内存流解密：
    m_path = protocol.AES_decrypt_streaming_from_stream(int.from_bytes(k, 'big'), ciphertext_stream, dest_path, k1)
    return m_path


def connect_and_get_socket(address: str, port: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((address, port))
    return sock


def upload_encrypted_file_to_s3(file_path, bucket_name, object_key, uid):
    s3 = boto3.client('s3', region_name='ap-southeast-2')  # 更改为你使用的区域
    s3.upload_file(file_path, bucket_name, object_key)
    print(f"[Client] 加密文件已上传到 S3：s3://{bucket_name}/{uid}_{object_key}")


def upload_file_to_ec2(local_path, remote_path, hostname, username, pem_path):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname=hostname, username=username, key_filename=pem_path)

    sftp = ssh.open_sftp()
    sftp.put(local_path, remote_path)
    sftp.close()
    ssh.close()


def download_file_from_ec2(remote_path, local_path, hostname, username, pem_path):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname=hostname, username=username, key_filename=pem_path)

    sftp = ssh.open_sftp()
    sftp.get(remote_path, local_path)  # 从 EC2 下载文件
    sftp.close()
    ssh.close()