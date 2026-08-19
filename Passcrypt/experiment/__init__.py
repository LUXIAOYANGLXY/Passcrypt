# -*- coding: utf-8 -*-
"""
experiment/__init__.py
======================
PAEE 四个基准实验：

  1. tcp_benchmark            口令16、不对明文加密：阶段延迟 + 通信量（TCP；ct1=GCM）
  2. password_length_bench    口令长度扫描：Ext / Enc_proto / Dec_proto（TCP）
  3. file_size_proto_bench            文件大小扫描：含网络 Enc / Dec（τ 含 ct2）
  3′. file_size_proto_bench_tau_no_ct2 同上，仅 τ=H5(kMAC,(ct0,ct1))
  4. file_size_crypto_bench              文件大小扫描：纯密码学（τ 含 ct2）
  4′. file_size_crypto_bench_tau_no_ct2  同上，仅 τ=H5(kMAC,(ct0,ct1))

共用：tcp_benchmark_lib
详见 experiment/README.md
"""
