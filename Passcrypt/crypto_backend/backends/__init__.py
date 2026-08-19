# -*- coding: utf-8 -*-
"""
群后端包：具体曲线实现由 pairing.py 按配置动态 import。

可用模块：
  - secp256r1：NIST P-256（OpenSSL，默认）
  - pymcl_bls12_381：BLS12-381 + pymcl
  - py_ecc_bls12_381：BLS12-381 + py_ecc（对照）
  - mcl_bn254：BN254 + mclbn256（遗留）
  - py_ecc_bn254：BN254 + py_ecc（遗留对照）
"""
