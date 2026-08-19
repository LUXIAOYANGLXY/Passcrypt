"""WBP 基准实验脚本包。

入口：
  - tcp_benchmark            基线（对齐 PAEE）：分阶段延迟 + 通信量
  - password_length_bench    实验1（对齐 PAEE）：口令长度扫描
  - file_size_proto_bench    实验3（对齐 PAEE）：文件大小 Enc/Dec（口令长=16）
  - file_encrypt_bench       大文件加解密（取钥后反复 AE）
  - e2e_key_file_bench       Init→加密→Rec→解密
"""
