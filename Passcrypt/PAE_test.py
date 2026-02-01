import configparser
import secrets  
from aEKE import AEKEProtocol
import time
from io import BytesIO
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

metrics_total = {
            "PAE_Ext_time":0,
            "PAE_Enc_time": 0,
            "PAE_Dec_time": 0}

PAE_ext_time =0
PAE_enc_time =0
PAE_dec_time =0


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
    start_time = time.time()
    a = PAE_ext(protocol, uid, pw, st)
    print("enc_a:", a)
    # 随机标量 r
    r = secrets.randbelow(protocol.N)
    # u = r * G (点)
    r_priv = ec.derive_private_key(r, protocol.ec_curve, default_backend())
    u = r_priv.public_key()

    # 计算 val = a * (r * pk)
    r_pk_bytes = r_priv.exchange(ec.ECDH(), pk)
    val_material = a.to_bytes(32, 'big') + r_pk_bytes
    u0 = protocol.H_double_prime(uid, val_material)
    # 对称加密密钥 k
    k_scalar = secrets.randbelow(protocol.N)
    k_raw_bytes = k_scalar.to_bytes(32, 'big')
    print("enc_k_raw:", k_raw_bytes)
    print("u0:", u0.hex())
    c0 = protocol.AES_CTR_encrypt(u0, k_raw_bytes)

    c_path = protocol.AES_encrypt_streaming_h(k_raw_bytes, m_path, inter_path1, k5, header)
    end_time = time.time()
    PAE_enc_time = (end_time - start_time) * 1000

    print("PAE_enc_time: {:.2f} ms".format(PAE_enc_time))
    ciphertext_stream = BytesIO()
    protocol.AES_encrypt_streaming_to_stream_h(k_raw_bytes, m_path, ciphertext_stream, k5, header)
    ciphertext_stream.seek(0)
    return ciphertext_stream, c0, u ,PAE_enc_time

def PAE_dec(protocol, uid, pw, u_sk,  dest_path,k1, st, ciphertext_stream, c0,header):
    a = PAE_ext(protocol, uid, pw, st)
    print("dec_a:", a)
    # val_material = a * (sk * u)
    u_sk_bytes = u_sk if isinstance(u_sk, bytes) else u_sk.to_bytes(32, 'big')
    val_material = a.to_bytes(32, 'big') + u_sk_bytes
    u1 = protocol.H_double_prime(uid, val_material)

    k_derived = protocol.AES_CTR_decrypt(u1, c0)
    print(f"【DEBUG】Decrypted Derived Key: {k_derived.hex()}")

    m_path = protocol.AES_decrypt_streaming_from_stream_h(k_derived, ciphertext_stream, dest_path, k1, header)
    return m_path

if __name__ == "__main__":
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
    header = b"test_header"

    sk,pk = PAE_kgen(protocol, uid, pw)
    st = secrets.token_bytes(16)  # Example session token
    m_path = "./500mb"  # Path to the file to be encrypted
    k5 = "c1_path_111"  # Example key for encryption
    for i in range(5):
        start_time = time.time()
        a = PAE_ext(protocol,uid,pw,st)
        end_time = time.time()
        PAE_ext_time = (end_time - start_time) * 1000

        ciphertext_stream, c0, u ,PAE_enc_time= PAE_enc(protocol, uid, pw,  pk, st, m_path,inter_path1, k5,header)

        sk_priv_obj = ec.derive_private_key(sk, protocol.ec_curve, default_backend())
        # sk * u_obj
        u_sk_bytes = sk_priv_obj.exchange(ec.ECDH(), u)
        start_time = time.time()
        decrypted_stream = PAE_dec(protocol, uid, pw, u_sk_bytes, dec_path,k5, st, ciphertext_stream, c0,header)
        end_time = time.time()
        PAE_dec_time = (end_time - start_time) * 1000
        print("PAE_dec_time: {:.2f} ms".format(PAE_dec_time))

        metrics_total["PAE_Ext_time"] += PAE_ext_time
        metrics_total["PAE_Enc_time"] += PAE_enc_time
        metrics_total["PAE_Dec_time"] += PAE_dec_time

    print("\n======== 📊 平均耗时统计（单位：ms）========")
    for key in metrics_total:
        avg_time = metrics_total[key] / 5
        print(f"{key}: {avg_time:.2f} ms")
