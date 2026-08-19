# -*- coding: utf-8 -*-
"""
crypto_backend/pairing.py
=========================
曲线/群后端选择器（历史名称含 pairing；现默认无配对的 secp256r1）。

加载顺序：
  1) 环境变量 PAEE_PAIRING_BACKEND
  2) 否则 config.yaml → crypto.backend
  3) 默认 secp256r1

导出的 g1/g1_mul/… 被 group.py 再包装为 Fig.1 的 (p,G,g) API。
切换后端后必须清空 data/（ser_ver / 点编码不同）。
"""

from __future__ import annotations

import os
from pathlib import Path

# 环境变量优先（便于脚本临时切换，无需改 yaml）
_ENV = os.environ.get("PAEE_PAIRING_BACKEND", "").strip().lower()


def _read_backend_from_config() -> str:
    """从仓库根 config.yaml 读 crypto.backend；失败则 secp256r1。"""
    cfg_path = Path(__file__).resolve().parent.parent / "config.yaml"
    if not cfg_path.exists():
        return "secp256r1"
    try:
        import yaml

        with open(cfg_path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
        return str(cfg.get("crypto", {}).get("backend", "secp256r1")).strip().lower()
    except Exception:
        return "secp256r1"


_backend_name = _ENV or _read_backend_from_config()

# ---- 按名字导入具体实现模块 ----
if _backend_name in ("secp256r1", "p256", "prime256v1", "nistp256", "secp256r1_ecdsa"):
    # Fig.1 v2 默认：素数阶群 + OpenSSL
    from crypto_backend.backends import secp256r1 as _impl
elif _backend_name in ("bls12_381", "bls12-381", "bls12381", "pymcl", "pymcl_bls12_381"):
    # 对照/旧版：BLS12-381 + pymcl（原生快）
    from crypto_backend.backends import pymcl_bls12_381 as _impl
elif _backend_name in ("py_ecc_bls12_381", "bls12-381-pyecc", "bls12_381_pyecc"):
    # 纯 Python BLS12-381（慢，便于无原生库时调试）
    from crypto_backend.backends import py_ecc_bls12_381 as _impl
elif _backend_name in ("mcl", "mclbn256"):
    # 遗留 BN254 / mclbn256
    from crypto_backend.backends import mcl_bn254 as _impl
elif _backend_name in ("py_ecc", "pyecc", "bn254"):
    # 遗留 BN254 / py_ecc
    from crypto_backend.backends import py_ecc_bn254 as _impl
else:
    raise ImportError(
        f"Unknown group backend {_backend_name!r}; "
        f"use 'secp256r1' (default), 'bls12_381', 'py_ecc_bls12_381', 'mcl', or 'py_ecc'"
    )

# ---- 统一再导出：group.py / 旧配对代码依赖这些名字 ----
g1 = _impl.g1
g2 = getattr(_impl, "g2", None)  # secp256r1 无 G2
r = getattr(_impl, "r", _impl.p)  # 群阶
p = r
e = _impl.e  # 配对；素数阶后端会 NotImplemented
g1_mul = _impl.g1_mul
g2_mul = _impl.g2_mul
g1_add = _impl.g1_add
g1_eq = _impl.g1_eq
gt_mul = _impl.gt_mul
gt_eq = _impl.gt_eq
gt_pow = _impl.gt_pow
gt_inv_pow = _impl.gt_inv_pow
is_in_g1 = _impl.is_in_g1
is_in_g2 = _impl.is_in_g2
hash_to_g1 = _impl.hash_to_g1
hash_to_g2 = _impl.hash_to_g2
g1_to_bytes = _impl.g1_to_bytes
g1_from_bytes = _impl.g1_from_bytes
g2_to_bytes = _impl.g2_to_bytes
g2_from_bytes = _impl.g2_from_bytes
gt_to_bytes = _impl.gt_to_bytes
gt_from_bytes = _impl.gt_from_bytes

CURVE_NAME = getattr(_impl, "CURVE_NAME", _backend_name)
BACKEND_NAME = getattr(_impl, "BACKEND_NAME", _backend_name)
ACTIVE_BACKEND = _backend_name  # 配置里写的名字

try:
    from crypto_backend import codec as _codec

    SER_VER = getattr(_impl, "SER_VER", _codec.SER_VER)
    CURVE_ID = CURVE_NAME if CURVE_NAME else _codec.CURVE_ID
except Exception:
    SER_VER = getattr(_impl, "SER_VER", 0)
    CURVE_ID = CURVE_NAME
