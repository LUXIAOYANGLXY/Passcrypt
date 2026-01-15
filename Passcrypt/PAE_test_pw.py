import configparser
import secrets
import time
import random
import string
from io import BytesIO
from aEKE import AEKEProtocol


def PAE_kgen(protocol, uid, pw):
    sk = secrets.randbelow(protocol.P)
    pk = pow(protocol.G, sk, protocol.P)
    return sk, pk


def PAE_ext(protocol, uid, pw, st):
    a_bytes = protocol.H_new(uid, pw, st)
    return int.from_bytes(a_bytes, 'big')


def PAE_enc(protocol, uid, pw, pk, st, m_path, inter_path1, k5):
    a = PAE_ext(protocol, uid, pw, st)
    r = secrets.randbelow(protocol.P)
    u = pow(protocol.G, r, protocol.P)
    val = (a % protocol.P) * pow(pk, r, protocol.P) % protocol.P
    val_bytes = val.to_bytes((val.bit_length() + 7) // 8, 'big')
    u0 = protocol.H_double_prime(uid, val_bytes)
    k = secrets.randbelow(protocol.P)
    c0 = protocol.AES_encrypt(u0, k.to_bytes(32, 'big'))

    ciphertext_stream = BytesIO()
    protocol.AES_encrypt_streaming_to_stream(k, m_path, ciphertext_stream, k5)
    ciphertext_stream.seek(0)
    return ciphertext_stream, c0, u


def PAE_dec(protocol, uid, pw, u_sk, dest_path, k1, st, ciphertext_stream, c0):
    a = PAE_ext(protocol, uid, pw, st)
    u_prime = ((a % protocol.P) * u_sk) % protocol.P
    val_bytes = u_prime.to_bytes((u_prime.bit_length() + 7) // 8, 'big')
    u1 = protocol.H_double_prime(uid, val_bytes)
    k = int.from_bytes(protocol.AES_decrypt(u1, c0), 'big')
    m_path = protocol.AES_decrypt_streaming_from_stream(k, ciphertext_stream, dest_path, k1)
    return m_path


def random_password(length: int) -> str:
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(random.choice(chars) for _ in range(length))


if __name__ == "__main__":
    # ========= 手动设置口令长度 =========
    pw_length = 24  # 可以改为 4, 8, 12, 16, 20, 24 等
    num_tests = 10  # 测试次数
    print(f"\n=== 测试口令长度: {pw_length}, 每个模块运行 {num_tests} 次取平均 (单位: ms) ===")

    # ========= 加载配置 =========
    config = configparser.ConfigParser()
    with open("config.properties", "r", encoding="utf-8") as f:
        config.read_file(f)
    access_key_id = config.get("DEFAULT", "accessKeyId", fallback=None)
    secret_key_id = config.get("DEFAULT", "secretKeyId", fallback=None)
    region_name = config.get("DEFAULT", "regionName", fallback=None)
    bucket_name = config.get("DEFAULT", "bucketName", fallback=None)

    # 初始化协议
    protocol = AEKEProtocol(region_name, access_key_id, secret_key_id, key_len=24, verbose=False)

    # ========= 公共参数 =========
    uid = f"user_{pw_length}"
    k1 = "decrypted_data"
    dec_path = "./dec_file/"
    inter_path1 = "./inter_file/"
    m_path = "./1mb"
    k5 = "c1_path_111"

    # ========= 测试模块 =========
    ext_times, enc_times, dec_times = [], [], []

    for i in range(num_tests):
        print(f"第 {i + 1}/{num_tests} 次测试...")

        # 随机生成新密码
        pw = random_password(pw_length)
        st = secrets.token_bytes(16)

        # 密钥生成
        sk, pk = PAE_kgen(protocol, uid, pw)

        # --- EXT ---
        start = time.time()
        _ = PAE_ext(protocol, uid, pw, st)
        ext_times.append((time.time() - start) * 1000)  # 转换为毫秒

        # --- ENC ---
        start = time.time()
        ciphertext_stream, c0, u = PAE_enc(protocol, uid, pw, pk, st, m_path, inter_path1, k5)
        enc_times.append((time.time() - start) * 1000)

        # --- DEC ---
        u_sk = pow(u, sk, protocol.P)
        start = time.time()
        _ = PAE_dec(protocol, uid, pw, u_sk, dec_path, k5, st, ciphertext_stream, c0)
        dec_times.append((time.time() - start) * 1000)

    # ========= 输出平均时间 =========
    avg_ext = sum(ext_times) / num_tests
    avg_enc = sum(enc_times) / num_tests
    avg_dec = sum(dec_times) / num_tests

    print("\n=== 平均执行时间（10次） ===")
    print(f"口令长度: {pw_length}")
    print(f"PAE_ext 平均时间: {avg_ext:.10f} ms")
    print(f"PAE_enc 平均时间: {avg_enc:.10f} ms")
    print(f"PAE_dec 平均时间: {avg_dec:.10f} ms")
