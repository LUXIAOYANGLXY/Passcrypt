"""PPKR 密码学原语包。

对应 Faller 等 (CCS 2024) Sec. 5 / Table 4 中的 Exp、Mult、Hash、AE、
KDF、MAC、Signature、CPA/CCA Enc 等原语实现，供 encPw+ (Fig. 3) 与
OPRF-PPKR (Fig. 4) 协议栈调用。

子模块概览：
  group          — P-256 群运算 (Exp / Mult / hash-to-curve；OpenSSL 后端)
  openssl_p256   — OpenSSL libcrypto 点乘/点加封装
  elgamal        — ElGamal CPA 加密
  dhies          — DHIES IND-CCA 加密
  aes_gcm        — AES-256-GCM 认证加密
  schnorr        — Schnorr 数字签名
  oprf_2hashdh   — 2HashDH 不经意伪随机函数
  random_oracle  — H / H1 / H2 随机预言机
  hash_to_curve  — RFC 9380 P-256 hash-to-curve (H1 底层)
  kdf            — HKDF 密钥派生 / HMAC 消息认证
  serialize      — 协议载荷规范化序列化
"""
