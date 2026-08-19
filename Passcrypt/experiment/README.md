# PAEE 四个实验说明

## 共用工程口径

相对 Fig.1 可验证 POPRF，本仓库实验统一采用：

| 项 | 约定 |
|----|------|
| π | **不传**（服务端不 Prove，客户端不 Vf） |
| 线协议 | PBCS/E2SE 二进制：`opcode ‖ len ‖ field`；无 JSON/Base64 |
| 真实往返 | = 论文箭头：Reg=2，Ext=1，Enc_proto=2，Dec_proto=2 |
| pk | Reg 随 `REG_EVAL` **线上**下发；**报告通信量剔除**（约 68B） |
| ctx | Client 采样；Reg 随 `REG_BLIND` 提交；**报告通信量剔除**（约 33B）；Ext 不上线 |
| τ / ct2 | `τ = H5(kMAC,(ct0,ct1,ct2))`；`ENC_COMMIT` / `DEC_RESP` **不上传 ct2 体** |
| 计时 | 长连接；**建连不计时**（实验一～三） |

阶段含义（实验一～三 TCP 路径）：

| 报告名 | 含义 | 轮数 |
|--------|------|------|
| Reg | BLIND↔EVAL + COMMIT↔ACK（一次性参考） | 2 |
| Ext | BLIND↔EVAL(ã) | 1 |
| Enc_proto≈Init | Ext + Wrap + ENC_COMMIT（不含 SE.Enc 大文件时另有 Enc_full） | 2 |
| Dec_proto≈Rec | Ext + DEC_REQ/RESP（至 dek；大文件时 Dec_full 另含 SE.Dec） | 2 |

远程实验前请同步代码并重启：`python main.py server`。

---

## 总览

| # | 名称 | 脚本 | 自变量 | 网络 | 默认固定量 |
|---|------|------|--------|------|------------|
| 一 | 协议阶段延迟与通信量 | `tcp_benchmark` | 无（重复 trials） | TCP | 口令 16；**不对明文加密**；ct1=GCM |
| 二 | 口令长度扫描 | `password_length_bench` | 口令长度 | TCP | 明文 10MB |
| 三 | 文件大小 × 含网络 | `file_size_proto_bench` | 文件 MB | TCP | 口令 16；τ 含 ct2 |
| 三′ | 同上，τ 不含 ct2 | `file_size_proto_bench_tau_no_ct2` | 文件 MB | TCP | **仅** τ=H5(kMAC,(ct0,ct1)) |
| 四 | 文件大小 × 纯密码学 | `file_size_crypto_bench` | 文件 MB | **无** | 口令 16；τ 含 ct2 |
| 四′ | 同上，τ 不含 ct2 | `file_size_crypto_bench_tau_no_ct2` | 文件 MB | **无** | **仅** τ=H5(kMAC,(ct0,ct1)) |

---

## 实验一：协议阶段延迟与通信量

**回答的问题：** 口令长度固定、**不对明文加密** 时，各协议阶段的 **延迟** 与 **通信量** 是多少？（对齐 PBCS「只测密钥协议、不测文件 AE」）

| 项 | 内容 |
|----|------|
| 脚本 | `python -m experiment.tcp_benchmark` |
| 流程 | 每 trial：长连接 → Reg → Enc_proto → Dec_proto（m=∅） |
| 自变量 | 无；`--trials` 次取 mean±std |
| 默认 | 口令长度 **16**；明文 **0**（不加密 m）；密钥封装 **AES-256-GCM** |
| 主表 | Reg / Ext / Enc_proto / Dec_proto 的 latency (ms) + comm (B) |
| 输出 | `experiment/output/tcp_network_benchmark.{xlsx,md,csv}` |

```text
python -m experiment.tcp_benchmark --trials 20 --host <IP> --port 5202
python -m experiment.tcp_benchmark --trials 20 --auto-server
# 若需旧口径（含 10MB 文件 AE）：加 --plaintext-mb 10
```

---

## 实验二：口令长度扫描

**回答的问题：** 固定文件大小时，**口令变长** 会如何影响 Ext / Enc_proto / Dec_proto 延迟？

| 项 | 内容 |
|----|------|
| 脚本 | `python -m experiment.password_length_bench` |
| 流程 | 复用实验一的 `run_trials`（每长度独立 Reg→Enc→Dec） |
| 自变量 | 口令字节长度，默认 `8,16,32,64,128,256,512` |
| 默认 | 每长度 `trials` 次；明文 **10MB**（`--plaintext-mb 0` 可做空明文对照） |
| 主表 | 行=Ext / Enc_proto / Dec_proto；列=口令长度；mean±std (ms) |
| 输出 | `password_length_benchmark.{xlsx,md,csv}` |

```text
python -m experiment.password_length_bench --trials 20 --host <IP> --port 5202
```

---

## 实验三：文件大小 × 含网络协议

**回答的问题：** 固定口令时，**明文/密文变大** 时含 TCP 的 Enc / Dec 延迟如何变化？（含 H5 扫完整 ct2，但 ct2 不上云）

| 项 | 内容 |
|----|------|
| 脚本 | `python -m experiment.file_size_proto_bench` |
| 流程 | 每 trial：Reg → Enc(含网络) → Dec(含网络)；ct2 本地 |
| 自变量 | 文件大小 MB，默认 `1,10,100,200,300,400,500` |
| 默认 | 口令长度 **16** |
| 主表 | Ext / Enc_total / Dec_total；分解 Enc_key（Wrap+H5+COMMIT）、Enc_file（SE.Enc）、Dec_proto、Dec_file 等 |
| 输出 | `file_size_proto_benchmark.{xlsx,md,csv}` |

```text
python -m experiment.file_size_proto_bench --trials 3 --host <IP> --port 5202
```

说明：大文件下 Enc_key 往往被 **H5(完整 ct2)** 主导，而非 RTT。

---

## 实验三′：文件大小 × 含网络（τ 不含 ct2）

**与实验三唯一差别：** `τ := H5(kMAC, (ct0, ct1))`（H5 **不扫** ct2）。Enc/Dec 验 τ 对称；ct2 仍本地生成/解密、不上云。

| 项 | 内容 |
|----|------|
| 脚本 | `python -m experiment.file_size_proto_bench_tau_no_ct2` |
| 其余 | 同实验三（尺寸、口令、网络、输出列） |
| 输出 | `file_size_proto_tau_no_ct2_benchmark.{xlsx,md,csv}` |

```text
python -m experiment.file_size_proto_bench_tau_no_ct2 --trials 3 --host <IP> --port 5202
```

用途：与实验三对照，量化 **H5 扫完整 ct2** 对 Enc_key / Dec_proto 的贡献。

---

## 实验四：文件大小 × 纯密码学（无网络）

**回答的问题：** 去掉 TCP/RTT 后，同一套 Ext / Enc / Dec 的 **本地密码学时间** 随文件大小如何变化？（与实验三对照，拆开网络因素）

| 项 | 内容 |
|----|------|
| 脚本 | `python -m experiment.file_size_crypto_bench` |
| 流程 | 进程内 `PAEEServerState`；无 socket |
| 自变量 | 同实验三：`1…500` MB |
| 默认 | 口令长度 **16**；**不需要** `--host/--port` |
| 主表 | Ext / Enc / Dec mean±std (ms)，列=文件大小 |
| 输出 | `file_size_crypto_benchmark.{xlsx,md,csv}` |

```text
python -m experiment.file_size_crypto_bench --trials 5
```

---

## 实验四′：文件大小 × 纯密码学（τ 不含 ct2）

**与实验四唯一差别：** `τ := H5(kMAC, (ct0, ct1))`（H5 **不扫** ct2）。

| 项 | 内容 |
|----|------|
| 脚本 | `python -m experiment.file_size_crypto_bench_tau_no_ct2` |
| 其余 | 同实验四 |
| 输出 | `file_size_crypto_tau_no_ct2_benchmark.{xlsx,md,csv}` |

```text
python -m experiment.file_size_crypto_bench_tau_no_ct2 --trials 5
```

用途：与实验四对照，量化本地路径上 **H5 扫完整 ct2** 的开销；并可与实验三 / 三′ 一起拆开「网络 vs 密码学」。

---

## 与对照方案对齐时注意

- **通信量**：Reg/Ext eval 比可验证 Fig.1 少一整份 π；报告值再剔除 pk/ctx。
- **延迟**：少 Prove / Vf；大文件路径仍可能由 H5(ct2) 主导。
- 实验三 vs 四：同尺寸差分可近似隔离「网络 + 序列化」开销。
