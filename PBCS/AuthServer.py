import socket
import ssl
import time
import Constants
from SimpleEcCurve import SimpleEcCurve

class UserRecord:
    def __init__(self, tao, ct):
        self.tao = tao
        self.ct = ct
        self.c = 0


class UserRegister:
    def __init__(self, t):
        self.t = t
        self.c = 0


class AuthServer:
    verbose = False
    simple_ec_curve = SimpleEcCurve(Constants.CURVE_NAME)
    m_secret_key = b"addd"

    def __init__(self):
        self.users_rec = {}
        self.users_reg = {}

    def start(self):
        print(f"TLS enabled: {Constants.USE_TLS}, PBKDF KDF iterations: {Constants.KDF_HASH_REPETITIONS}, "
              f"PBKDF pwd hash iterations: {Constants.PWD_HASH_REPETITIONS}")
        print(f"AuthServer starting on port {Constants.AUTH_SERVER_PORT_NUMBER}...")

        if Constants.USE_TLS:
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(certfile=Constants.AUTH_SERVER_CERT_PATH,
                                    keyfile=Constants.AUTH_SERVER_KEY_PATH)
            context.set_ciphers(Constants.TLS_CIPHERSUITE)
            bindsocket = socket.socket()
            bindsocket.bind(('', Constants.AUTH_SERVER_PORT_NUMBER))
            bindsocket.listen(5)
            print ("server：wait connect...")
        else:
            print("Is building an insecure http connection.")
            bindsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            bindsocket.bind(('', Constants.AUTH_SERVER_PORT_NUMBER))
            bindsocket.listen(5)

        try:
            while True:
                newsocket, _ = bindsocket.accept()
                conn = newsocket
                if Constants.USE_TLS:
                    conn = context.wrap_socket(newsocket, server_side=True)

                try:
                    print("server:receive")
                    request_type = conn.recv(1)[0]
                    print("request_type:", request_type)
                    user_id_len = conn.recv(1)[0]
                    user_id_bytes = conn.recv(user_id_len)
                    user_id = user_id_bytes.decode()

                    if request_type == Constants.REQ_TYPE_AUTHSERVER_OPRF:
                        ec_len = conn.recv(1)[0]
                        ec_p_bytes = conn.recv(ec_len)
                        print("EC point first byte:", ec_p_bytes[0])
                        print("EC point length:", len(ec_p_bytes))

                        start = time.time()
                        ec_point = self.simple_ec_curve.decode_point(ec_p_bytes)
                        key_id = self.simple_ec_curve.hash_to_group2(self.m_secret_key, user_id_bytes)
                        b_ec_point = ec_point * key_id
                        byte_b_ec_point = self.simple_ec_curve.encode_point(b_ec_point)
                        end = time.time()
                        print(int((end - start) * 1000))
                        conn.send(bytes([Constants.RESP_TYPE_OK, len(byte_b_ec_point)]))
                        conn.send(byte_b_ec_point)

                    elif request_type == Constants.REQ_TYPE_AUTHSERVER_REGISTER:
                        t_len = conn.recv(1)[0]
                        t = conn.recv(t_len)
                        if user_id in self.users_reg:
                            print(f"User {user_id} already registered.")
                            conn.send(bytes([Constants.RESP_TYPE_ERROR]))
                        else:
                            self.users_reg[user_id] = UserRegister(t)
                            conn.send(bytes([Constants.RESP_TYPE_OK]))

                    elif request_type == Constants.REQ_TYPE_AUTHSERVER_DEPOSIT:
                        if user_id not in self.users_reg:
                            print(f"User {user_id} not registered.")
                            conn.send(bytes([Constants.RESP_TYPE_ERROR]))
                            continue
                        if user_id in self.users_rec:
                            print(f"User {user_id} already deposited.")
                            conn.send(bytes([Constants.RESP_TYPE_ERROR]))
                            continue
                        t_len = conn.recv(1)[0]
                        t_receive = conn.recv(t_len)
                        if self.users_reg[user_id].t != t_receive:
                            print(f"Invalid password for user {user_id}.")
                            conn.send(bytes([Constants.RESP_TYPE_ERROR]))
                            continue
                        tao_len = conn.recv(1)[0]
                        tao = conn.recv(tao_len)
                        ct_len = conn.recv(1)[0]
                        ct = conn.recv(ct_len)
                        self.users_rec[user_id] = UserRecord(tao, ct)
                        conn.send(bytes([Constants.RESP_TYPE_OK]))

                    elif request_type == Constants.REQ_TYPE_AUTHSERVER_RETRIEVAL:
                        t_len = conn.recv(1)[0]  # 接收长度字节，转换成整数
                        t_receive = conn.recv(t_len)  # 再根据长度读出 t 的真实数据
                        print("t_len", t_len)
                        print("users_reg[user_id].t", self.users_reg[user_id].t)
                        print("t_receive", t_receive)
                        if user_id not in self.users_reg or user_id not in self.users_rec:
                            print(f"User {user_id} not registered or did not deposit.")
                            conn.send(bytes([Constants.RESP_TYPE_ERROR]))
                            continue
                        if self.users_reg[user_id].t != t_receive:
                            print(f"Incorrect password for user {user_id}.")
                            conn.send(bytes([Constants.RESP_TYPE_ERROR]))
                            continue
                        user_c = self.users_rec[user_id]
                        conn.send(bytes([Constants.RESP_TYPE_OK, len(user_c.ct)]))
                        conn.send(user_c.ct)
                        conn.send(bytes([len(user_c.tao)]))
                        conn.send(user_c.tao)
                        conn.send(bytes([Constants.RESP_TYPE_OK]))

                    else:
                        print("Unknown request received.")

                finally:
                    conn.close()

        finally:
            bindsocket.close()


# if __name__ == "__main__":
#     AuthServer().start()
