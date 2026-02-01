import configparser
import secrets
import time
import random
import string
from io import BytesIO
from aEKE import AEKEProtocol
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend


def PAE_kgen(protocol, uid, pw):
    """生成 ECC 密钥对"""
    # 随机生成私钥 sk (标量)
    sk = secrets.randbelow(protocol.N)
    # 计算公钥 pk = sk * G (点)
    pk = ec.derive_private_key(sk, protocol.ec_curve, default_backend()).public_key()
    return sk,pk

def PAE_ext(protocol, uid, pw, st):
    """导出 a (标量)"""
    # st 如果是 bytes 则直接哈希，如果是点则先序列化
    st_bytes = st if isinstance(st, bytes) else protocol.serialize_pubkey(st)
    a_bytes = protocol.H_new(uid, pw, st_bytes)
    # 对曲线阶 N 取模
    return int.from_bytes(a_bytes, 'big') % protocol.N



def PAE_enc(protocol, uid, pw, pk, st, m_path, inter_path1,k5,header):
    a = PAE_ext(protocol, uid, pw, st)
    print("enc_a:", a)
    # 随机标量 r
    r = secrets.randbelow(protocol.N)
    # u = r * G (点)
    r_priv = ec.derive_private_key(r, protocol.ec_curve, default_backend())
    u = r_priv.public_key()

    # 计算 val = a * (r * pk)
    r_pk_bytes  = r_priv.exchange(ec.ECDH(), pk)

    val_material = a.to_bytes(32, 'big') + r_pk_bytes
    u0 = protocol.H_double_prime(uid, val_material)
    # 对称加密密钥 k
    k_scalar = secrets.randbelow(protocol.N)
    k_raw_bytes = k_scalar.to_bytes(32, 'big')
    print("enc_k_raw:", k_raw_bytes)
    print("u0:", u0.hex())
    c0 = protocol.AES_CTR_encrypt(u0, k_raw_bytes)

    c_path = protocol.AES_encrypt_streaming_h(k_raw_bytes, m_path, inter_path1, k5,header)

    # ciphertext_stream = BytesIO()
    # protocol.AES_encrypt_streaming_to_stream(k, m_path, ciphertext_stream, k5)
    # ciphertext_stream.seek(0)
    return c_path, c0, u

def PAE_dec(protocol, uid, pw, u_sk,  dest_path,k1, st, ciphertext_stream, c0,header):
    a = PAE_ext(protocol, uid, pw, st)
    print("dec_a:", a)
    u_sk_bytes = u_sk if isinstance(u_sk, bytes) else u_sk.to_bytes(32, 'big')
    val_material = a.to_bytes(32, 'big') + u_sk_bytes
    u1 = protocol.H_double_prime(uid, val_material)

    k_derived = protocol.AES_CTR_decrypt(u1, c0)
    print(f"【DEBUG】Decrypted Derived Key: {k_derived.hex()}")
    m_path = protocol.AES_decrypt_streaming_from_stream_h(k_derived, ciphertext_stream, dest_path, k1, header)

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
    header = b"test_header"

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
        ciphertext_stream, c0, u_obj = PAE_enc(protocol, uid, pw, pk, st, m_path, inter_path1, k5,header)
        enc_times.append((time.time() - start) * 1000)

        # --- DEC ---
        sk_priv_obj = ec.derive_private_key(sk, protocol.ec_curve, default_backend())
        # sk * u_obj
        u_sk_bytes = sk_priv_obj.exchange(ec.ECDH(), u_obj)
        start = time.time()
        with open(ciphertext_stream, "rb") as f:
            _ = PAE_dec(protocol, uid, pw, u_sk_bytes, dec_path, k5, st, f, c0,header)
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
