import configparser
import secrets  #用于生成安全的随机数
from aEKE import AEKEProtocol
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend



def PAE_kgen(protocol, uid, pw):
    #生成 ECC 密钥对
    sk = secrets.randbelow(protocol.N)
    pk = ec.derive_private_key(sk, protocol.ec_curve, default_backend()).public_key()
    return sk,pk

def PAE_ext(protocol, uid, pw, st):
    st_bytes = st if isinstance(st, bytes) else protocol.serialize_pubkey(st)
    a_bytes = protocol.H_new(uid, pw, st_bytes)
    return int.from_bytes(a_bytes, 'big') % protocol.N

def PAE_enc(protocol, uid, pw, pk, st, m_path, inter_path1,k5,header):
    a = PAE_ext(protocol, uid, pw, st)
    print("enc_a:", a)
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
    print("enc_k_raw:", k_raw_bytes.hex())
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

    m_path = protocol.AES_decrypt_streaming_from_stream_h(k_derived, ciphertext_stream, dest_path, k1,header)
    return m_path




def PAE_ext1(protocol, uid, pw):
    a_bytes = protocol.H_new(uid, pw)
    # 对曲线阶 N 取模
    return int.from_bytes(a_bytes, 'big') % protocol.N



def PAE_enc1(protocol, uid, pw, pk,  m_path, inter_path1,k5,header):
    a = PAE_ext1(protocol, uid, pw)
    print("enc_a:", a)
    r = secrets.randbelow(protocol.N)
    r_priv = ec.derive_private_key(r, protocol.ec_curve, default_backend())
    u = r_priv.public_key()
    r_pk_bytes = r_priv.exchange(ec.ECDH(), pk)
    val_material = a.to_bytes(32, 'big') + r_pk_bytes
    u0 = protocol.H_double_prime(uid, val_material)

    k = secrets.randbelow(protocol.N)
    k_raw_bytes = k.to_bytes(32, 'big')
    print("u0:", u0.hex())
    c0 = protocol.AES_encrypt_h(u0, k_raw_bytes, header)

    c_path = protocol.AES_encrypt_streaming(k_raw_bytes, m_path, inter_path1, k5)

    # ciphertext_stream = BytesIO()
    # protocol.AES_encrypt_streaming_to_stream(k, m_path, ciphertext_stream, k5)
    # ciphertext_stream.seek(0)
    return c_path, c0, u

def PAE_dec1(protocol, uid, pw, u_sk,  dest_path,k1,  ciphertext_stream, c0,header):
    a = PAE_ext1(protocol, uid, pw)
    print("dec_a:", a)
    # val_material = a * (sk * u)
    u_sk_bytes = u_sk if isinstance(u_sk, bytes) else u_sk.to_bytes(32, 'big')
    val_material = a.to_bytes(32, 'big') + u_sk_bytes

    u1 = protocol.H_double_prime(uid, val_material)
    k_derived = protocol.AES_decrypt_h(u1, c0, header)

    m_path = protocol.AES_decrypt_streaming_from_stream(k_derived, ciphertext_stream, dest_path, k1)

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
    secure_level = 1
    MSG_TYPE_KEY = 22
    header = (
            uid.encode() +
            secure_level.to_bytes(1, "big") +
            MSG_TYPE_KEY.to_bytes(1, "big")
    )

    sk,pk = PAE_kgen(protocol, uid, pw)
    st = secrets.token_bytes(16)  # Example session token
    m_path = "./1mb"  # Path to the file to be encrypted
    k5 = "c1_path_111"  # Example key for encryption
    ciphertext_stream, c0, u = PAE_enc(protocol, uid, pw,  pk, st, m_path,inter_path1, k5,header)
    sk_priv_obj = ec.derive_private_key(sk, protocol.ec_curve, default_backend())
    u_sk = sk_priv_obj.exchange(ec.ECDH(), u)  # 结果是 bytes
    with open(ciphertext_stream, "rb") as f:
        decrypted_path = PAE_dec(protocol, uid, pw, u_sk, dec_path, k1, st, f, c0, header)

