# -*- coding: utf-8 -*-
"""
PBCS 协议字段通信量（论文口径，载荷字节；不含 TCP/TLS 帧头、opcode、长度前缀）。

AuthServer / Key Server::
  OPRF: id, u, v
  Give: id, t, ct, τ, e
  Take: id, t, ct, τ

Data Server (S3)::
  id, pwd, rid, sid
  （pwd 为数据服务器登录用硬化口令长度；本实现按 HASHED_PASSWORD_LENGTH 计）

字段 ↔ 实现::
  u, v     = secp256r1 压缩点 33 B
  t, τ     = KDF 输出 16 B（128-bit）
  e        = AES-CTR IV 16 B
  ct(Give) = AES-CTR(C(msk)) 32 B；Give 中 e‖ct = 原 ivct（无 GCM tag）
  ct(Take) = e‖C = 48 B（取回整段包装密文）
  sid,rid  = R_LENGTH 16 B
  pwd      = HASHED_PASSWORD_LENGTH/8 = 16 B
"""

from __future__ import annotations

from typing import Dict

from Constants import (
    ENC_KEY_LENGTH,
    HASHED_PASSWORD_LENGTH,
    MAC_KEY_LENGTH,
    R_LENGTH,
)

POINT_LEN = 33  # compressed secp256r1
T_LEN = MAC_KEY_LENGTH // 8  # 16
TAU_LEN = ENC_KEY_LENGTH // 8  # 16
E_LEN = 16  # CTR IV used in Client.give
CT_BODY_LEN = 32  # C(msk) — Give 的 ct（AES-CTR，无 tag）
CT_FULL_LEN = E_LEN + CT_BODY_LEN  # Take 收到的 ct = ivct
SID_LEN = R_LENGTH
RID_LEN = R_LENGTH
PWD_LEN = HASHED_PASSWORD_LENGTH // 8


def id_len(user_id: str) -> int:
    return len(user_id.encode("utf-8"))


def oprf_fields(user_id: str) -> Dict[str, int]:
    n = id_len(user_id)
    return {"id": n, "u": POINT_LEN, "v": POINT_LEN, "total": n + POINT_LEN + POINT_LEN}


def give_ks_fields(user_id: str) -> Dict[str, int]:
    """Give → Key Server: id, t, ct, τ, e"""
    n = id_len(user_id)
    total = n + T_LEN + CT_BODY_LEN + TAU_LEN + E_LEN
    return {
        "id": n,
        "t": T_LEN,
        "ct": CT_BODY_LEN,
        "tau": TAU_LEN,
        "e": E_LEN,
        "total": total,
    }


def take_ks_fields(user_id: str) -> Dict[str, int]:
    """Take ↔ Key Server: id, t, ct, τ"""
    n = id_len(user_id)
    total = n + T_LEN + CT_FULL_LEN + TAU_LEN
    return {
        "id": n,
        "t": T_LEN,
        "ct": CT_FULL_LEN,
        "tau": TAU_LEN,
        "total": total,
    }


def register_ks_fields(user_id: str) -> Dict[str, int]:
    """Register → Key Server: id, t"""
    n = id_len(user_id)
    return {"id": n, "t": T_LEN, "total": n + T_LEN}


def s3_register_fields(user_id: str) -> Dict[str, int]:
    """S3 Register: id, pwd, sid"""
    n = id_len(user_id)
    return {"id": n, "pwd": PWD_LEN, "sid": SID_LEN, "rid": 0, "total": n + PWD_LEN + SID_LEN}


def s3_give_fields(user_id: str) -> Dict[str, int]:
    """S3 Give: login(id,pwd) + put rid + get sid"""
    n = id_len(user_id)
    return {
        "id": n,
        "pwd": PWD_LEN,
        "rid": RID_LEN,
        "sid": SID_LEN,
        "total": n + PWD_LEN + RID_LEN + SID_LEN,
    }


def s3_take_fields(user_id: str) -> Dict[str, int]:
    """S3 Take: login(id,pwd) + get rid + get sid"""
    n = id_len(user_id)
    return {
        "id": n,
        "pwd": PWD_LEN,
        "rid": RID_LEN,
        "sid": SID_LEN,
        "total": n + PWD_LEN + RID_LEN + SID_LEN,
    }


def phase_totals(user_id: str) -> Dict[str, int]:
    """各实验阶段合计（AuthServer 字段 + S3 字段）。"""
    reg = register_ks_fields(user_id)["total"] + s3_register_fields(user_id)["total"]
    oprf = oprf_fields(user_id)["total"]
    give = give_ks_fields(user_id)["total"] + s3_give_fields(user_id)["total"]
    take = take_ks_fields(user_id)["total"] + s3_take_fields(user_id)["total"]
    return {
        "reg": reg,
        "oprf": oprf,
        "give": give,
        "take": take,
        "enc_proto": oprf + give,  # OPRF + Give(+S3)
        "dec_proto": oprf + take,  # OPRF + Take(+S3)
    }
