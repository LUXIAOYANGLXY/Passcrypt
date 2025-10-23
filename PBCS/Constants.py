import os
import configparser

# TLS Settings
USE_TLS = False
# USE_TLS = True
PWD_HASH_REPETITIONS = 1
KDF_HASH_REPETITIONS = 1

TLS_VERSION = "TLSv1.2"
TLS_CIPHERSUITE = "ECDHE-RSA-AES128-GCM-SHA256"

ANDROID_LOCALHOST = "10.0.2.2"

# Request and Response Types (byte values)
REQ_TYPE_AUTHSERVER_DEPOSIT = 0x02
REQ_TYPE_AUTHSERVER_RETRIEVAL = 0x03
REQ_TYPE_AUTHSERVER_OPRF = 0x08
REQ_TYPE_AUTHSERVER_REGISTER = 0x09

RESP_TYPE_OK = 0x06
RESP_TYPE_ERROR = 0x07

# Cryptographic Constants
MAC_LENGTH = 32                # bytes
MAC_KEY_LENGTH = 128           # bits
R_LENGTH = 128 // 8            # bytes
HASHED_PASSWORD_LENGTH = 128   # bits
ENC_KEY_LENGTH = 128           # bits
CHALLENGE_LENGTH = 128 // 8    # bytes

# Salt values
PASSWORD_SALT = b"edu.sydney.e2se.PASSWORD_SALT"
KDF1_SALT = b"edu.sydney.e2se.KDF1_SALT"
KDF2_SALT = b"edu.sydney.e2se.KDF2_SALT"
KDF3_SALT = b"edu.sydney.e2se.KDF3_SALT"
KDF4_SALT = b"edu.sydney.e2se.KDF4_SALT"

# Authentication Limits
MAX_FAILED_ATTEMPTS_DATASERVER = 3
MAX_FAILED_ATTEMPTS_AUTHSERVER = 3

# Algorithms
MAC_ALGORITHM = "HMACSHA256"
DATA_ENCRYPTION_BASE_ALGORITHM = "AES"
KEY_ENCRYPTION_BASE_ALGORITHM = "AES"
KEY_ENCRYPTION_ALGORITHM = "AES/GCM/NoPadding"
KEY_ENCRYPTION_IV_LENGTH = 96 // 8     # bytes
GCM_TAG_LENGTH = 16 * 8                # bits

KEY_ENCRYPTION_CTR_ALGORITHM = "AES/CTR/NoPadding"
KEY_ENCRYPTION_CTR_IV_LENGTH = 128 // 8  # bytes

CLIENT = "client"
AUTH_SERVER = "authserver"

# File Paths
# FILE_PATH = "D:/Pycharm/Project/E2SE-python-s3/DataFile/"
FILE_PATH = "./DataFile/"
# AUTH_SERVER_KEYSTORE_PATH = "./certificatesNew/AuthServerKeyStore.jks"
# AUTH_SERVER_KEYSTORE_PASSWORD = "changeit"
AUTH_SERVER_CERT_PATH = "./certificatesNew/authserver_cert.pem"
AUTH_SERVER_KEY_PATH = "./certificatesNew/authserver_key.pem"

CURVE_NAME = "secp256r1"

# ————————————————————————
# 动态加载配置项（IP、Port、Name）
# ————————————————————————

CONFIG_FILE = "config.properties"

def load_config():
    config = configparser.ConfigParser()
    try:
        with open(CONFIG_FILE, 'r') as f:
            config.read_file(f)

        return {
            "authServerIp": config.get("DEFAULT", "authServerIp"),
            "authServerPort": int(config.get("DEFAULT", "authServerPort")),
            "authServerName": config.get("DEFAULT", "authServerName")
        }
    except Exception as e:
        raise RuntimeError(f"Failed to load configuration from {CONFIG_FILE}: {e}")

# 加载配置
try:
    config_data = load_config()
    AUTH_SERVER_ADDRESS = config_data["authServerIp"]
    AUTH_SERVER_ADDRESS_EC2 = '54.250.*******'
    AUTH_SERVER_PORT_NUMBER = config_data["authServerPort"]
    AUTH_SERVER_NAME = config_data["authServerName"]
except Exception as e:
    print(f"[ERROR] Configuration loading failed: {e}")
    # 可选：设置默认值或退出程序
    AUTH_SERVER_ADDRESS = "localhost"
    AUTH_SERVER_PORT_NUMBER = 20202

    AUTH_SERVER_NAME = "CN=usyd.authserver,OU=authserver,O=server,L=sydney,ST=NSW,C=AU"

