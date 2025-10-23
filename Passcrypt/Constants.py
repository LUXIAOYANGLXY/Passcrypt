import configparser

CLIENT = "client"
SERVER = "server"
USE_TLS = True
AUTH_SERVER_CERT_PATH= "./certificatesNew/authserver_cert.pem"
AUTH_SERVER_KEY_PATH = "./certificatesNew/authserver_key.pem"
TLS_CIPHERSUITE ="ECDHE-RSA-AES128-GCM-SHA256"

SERVER_ID = "S"

FILE_PATH = "./DataFile/"
DEC_DEST_FILE ="./dec_file/"
# ENC_FILE="./enc_file/"D:\Pycharm\Project\SecureChannelPassCrypt\SecureChannelPassCrypt\PassCrypt-SecureChannel-s3-ec2
ENC_FILE="D:/Pycharm/Project/SecureChannelPassCrypt/SecureChannelPassCrypt/PassCrypt-SecureChannel-s3-ec2/local_storage/enc_file/"
INTER_FILE="D:/Pycharm/Project/SecureChannelPassCrypt/SecureChannelPassCrypt/PassCrypt-SecureChannel-s3-ec2/inter_file/"
INTER_FILE1="D:/Pycharm/Project/SecureChannelPassCrypt/SecureChannelPassCrypt/PassCrypt-SecureChannel-s3-ec2/inter_file1/"
INTER_ENC_FILE="D:/Pycharm/Project/SecureChannelPassCrypt/SecureChannelPassCrypt/PassCrypt-SecureChannel-s3-ec2/inter_enc_file/"
C1_PATH="D:/Pycharm/Project/SecureChannelPassCrypt/SecureChannelPassCrypt/PassCrypt-SecureChannel-s3-ec2/c1_path/"
SERVER_AEKE_PATH = "D:/Pycharm/Project/SecureChannelPassCrypt/SecureChannelPassCrypt/PassCrypt-SecureChannel-s3-ec2/server_aeke_path/"



# ————————————————————————
# 动态加载配置项（IP、Port、Name）
# ————————————————————————

CONFIG_FILE = "config.properties"


def load_config():
    config = configparser.ConfigParser()
    try:
        with open(CONFIG_FILE, 'r',encoding='utf-8') as f:
            config.read_file(f)

        return {
            "ServerIp": config.get("DEFAULT", "ServerIp"),
            "ServerPort": int(config.get("DEFAULT", "ServerPort")),
            # "ServerName": config.get("DEFAULT", "ServerName")
        }
    except Exception as e:
        raise RuntimeError(f"Failed to load configuration from {CONFIG_FILE}: {e}")

# 加载配置
try:
    config_data = load_config()
    AUTH_SERVER_ADDRESS = config_data["ServerIp"]
    AUTH_SERVER_PORT_NUMBER = config_data["ServerPort"]
    #AUTH_SERVER_NAME = config_data["ServerName"]
except Exception as e:
    print(f"[ERROR] Configuration loading failed: {e}")
    # 可选：设置默认值或退出程序
    AUTH_SERVER_ADDRESS = "localhost"
    AUTH_SERVER_PORT_NUMBER = 20202

