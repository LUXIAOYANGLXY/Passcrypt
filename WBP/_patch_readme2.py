from pathlib import Path

p = Path(r"d:\pythonfile\project\WBPv1\README.md")
text = p.read_text(encoding="utf-8")

# directory structure
old_dir = """    tcp_benchmark.py            # 基线（对齐 PAEE）：分阶段延迟 + 通信量
    password_length_bench.py    # 实验1（对齐 PAEE）：口令长度扫描
    file_encrypt_bench.py       # TCP 取 K 后大文件加解密
    e2e_key_file_bench.py       # Init→加密→Rec→解密"""
new_dir = """    tcp_benchmark.py            # 基线（对齐 PAEE）：分阶段延迟 + 通信量
    password_length_bench.py    # 实验1（对齐 PAEE）：口令长度扫描
    file_size_proto_bench.py    # 实验3（对齐 PAEE）：文件大小 vs Enc/Dec（pw=16）
    file_encrypt_bench.py       # TCP 取 K 后大文件加解密
    e2e_key_file_bench.py       # Init→加密→Rec→解密"""
if old_dir in text:
    text = text.replace(old_dir, new_dir)

# experiment table row insert after password_length
needle = "| `python -m experiment.password_length_bench --trials 20` | **实验1（对齐 PAEE）**：口令长度 8…512 下 Init/Rec 延迟 | `password_length_benchmark.xlsx` |"
insert = (
    needle
    + "\n"
    + "| `python -m experiment.file_size_proto_bench --trials 3` | **实验3（对齐 PAEE）**：口令长=16，不同文件大小 Enc/Dec | `file_size_proto_benchmark.xlsx` |"
)
if needle in text and "file_size_proto_bench" not in text.split("实验命令")[1][:800]:
    text = text.replace(needle, insert, 1)

# bash block
old_bash = """# 实验1：口令长度扫描（连 EC2 时改 --host）
python -m experiment.password_length_bench --port 8876 --trials 20 -q
python -m experiment.file_encrypt_bench"""
new_bash = """# 实验1：口令长度扫描（连 EC2 时改 --host）
python -m experiment.password_length_bench --port 8876 --trials 20 -q
# 实验3：文件大小 vs Enc/Dec（口令长度=16）
python -m experiment.file_size_proto_bench --port 8876 --trials 3 -q
python -m experiment.file_encrypt_bench"""
if old_bash in text:
    text = text.replace(old_bash, new_bash)

# insert experiment 3 section after experiment 1 section
marker = "### 实验1 说明（对齐 PAEE `password_length_bench`）"
exp3 = """### 实验3 说明（对齐 PAEE `file_size_proto_bench`）

- **口令长度**：固定 **16**（`--password-len`，默认 `"a"*16`）
- **自变量**：文件大小 `1,10,100,200,300,400,500` MB（`--sizes`）
- **Enc**：`Init`（TCP 取/存 K）+ 本地 AES-GCM 加密文件；**大文件密文不上传**
- **Dec**：`Rec`（TCP 恢复 K'）+ 本地 AES-GCM 解密
- **表格式**：行=阶段，列=`{N}MB`（主表 + 分解表）
- **对标**：WBP Init↔PAEE Enc_proto；WBP 无 Ext；Enc_total / Dec_total 含义与 PAEE 一致（协议取钥 + 本地文件 AE）

"""
if marker in text and "### 实验3 说明" not in text:
    # insert after experiment 1 block (before 文件大小默认 or 指标含义)
    idx = text.find(marker)
    # find next ### or 文件大小默认
    next_h = text.find("\n文件大小默认", idx)
    if next_h < 0:
        next_h = text.find("\n### 指标含义", idx)
    if next_h > 0:
        text = text[:next_h] + "\n" + exp3 + text[next_h:]

# AWS section commands
old_aws = """python -m experiment.password_length_bench --host <EC2_IP> --port 8765 --trials 20 -q
python -m experiment.file_encrypt_bench --host <EC2_IP> --port 8765 --trials 5 --sizes 1 10 100 -q"""
new_aws = """python -m experiment.password_length_bench --host <EC2_IP> --port 8765 --trials 20 -q
python -m experiment.file_size_proto_bench --host <EC2_IP> --port 8765 --trials 3 -q
python -m experiment.file_encrypt_bench --host <EC2_IP> --port 8765 --trials 5 --sizes 1 10 100 -q"""
if old_aws in text:
    text = text.replace(old_aws, new_aws)

p.write_text(text, encoding="utf-8")
print("README patched")
