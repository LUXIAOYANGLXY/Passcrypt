# -*- coding: utf-8 -*-
"""
paee/serde.py
=============
Fig.1 对象 ↔ JSON/Base64 线格式。
群元素经 g_to_bytes / g_from_bytes：线格式为 33B SEC1 压缩（ser_ver=10）。
"""

from __future__ import annotations

import base64
from typing import Any, Dict

from crypto_backend import group as bg
from paee.types import Ciphertext, DLEQProof, PasswordRecord, ServerKey


def b64(data: bytes) -> str:
    """bytes → ASCII Base64 字符串（JSON 友好）。"""
    return base64.b64encode(data).decode("ascii")


def u64(s: str) -> bytes:
    """Base64 字符串 → bytes。"""
    return base64.b64decode(s.encode("ascii"))


def _meta() -> Dict[str, Any]:
    """写入磁盘/消息的元数据：防止不同曲线或编码版本混用。"""
    return {
        "ser_ver": int(getattr(bg, "SER_VER", 4)),
        "curve": str(getattr(bg, "CURVE_ID", getattr(bg, "CURVE_NAME", "BLS12-381"))),
    }


def _check_ser_meta(obj: Dict[str, Any], *, require: bool = False) -> None:
    """校验 ser_ver / curve；不匹配则要求清空 data/ 后重跑。"""
    if "ser_ver" not in obj:
        if require:
            raise ValueError("missing ser_ver; clear data/ and re-register")
        return
    want = int(getattr(bg, "SER_VER", 4))
    got = int(obj["ser_ver"])
    if got != want:
        raise ValueError(
            f"ser_ver mismatch: file={got}, runtime={want}. Clear data/ and re-run."
        )
    if "curve" in obj:
        want_c = str(getattr(bg, "CURVE_ID", getattr(bg, "CURVE_NAME", "")))
        got_c = str(obj["curve"])
        if got_c and want_c and got_c != want_c:
            raise ValueError(
                f"curve mismatch: file={got_c}, runtime={want_c}. Clear data/."
            )


def export_pk(sk: ServerKey) -> Dict[str, Any]:
    """导出公钥 pk=(K,X)；不含私钥 k,x。"""
    out = _meta()
    out.update({"K": b64(bg.g_to_bytes(sk.K)), "X": b64(bg.g_to_bytes(sk.X))})
    return out


def import_pk(obj: Dict[str, Any]) -> ServerKey:
    """导入公钥；k,x 置 0（客户端不需要私钥）。"""
    _check_ser_meta(obj)
    return ServerKey(
        k=0,
        x=0,
        K=bg.g_from_bytes(u64(obj["K"])),
        X=bg.g_from_bytes(u64(obj["X"])),
    )


def export_a(a) -> str:
    """盲化点 a ∈ G → Base64。"""
    return b64(bg.g_to_bytes(a))


def import_a(s: str):
    """Base64 → 盲化点 a。"""
    return bg.g_from_bytes(u64(s))


def export_g(el) -> str:
    """任意群元素 → Base64（ã、d、ct0 等共用）。"""
    return b64(bg.g_to_bytes(el))


def import_g(s: str):
    """Base64 → 群元素。"""
    return bg.g_from_bytes(u64(s))


# Fig.1 返回 ã；兼容旧字段名时仍可用 export_g / import_g
export_a_tilde = export_g
import_a_tilde = import_g


def export_pi(pi: DLEQProof) -> Dict[str, Any]:
    """DLEQ 证明 π=(A1,A2,z)；z 以十六进制字符串传输。"""
    return {
        "A1": b64(bg.g_to_bytes(pi.A1)),
        "A2": b64(bg.g_to_bytes(pi.A2)),
        "z": format(pi.z, "x"),
    }


def import_pi(obj: Dict[str, Any]) -> DLEQProof:
    """JSON → DLEQProof。"""
    return DLEQProof(
        A1=bg.g_from_bytes(u64(obj["A1"])),
        A2=bg.g_from_bytes(u64(obj["A2"])),
        z=int(obj["z"], 16),
    )


def export_ct(ct: Ciphertext) -> Dict[str, Any]:
    """信封密文 ct=(ct0,ct1,ct2,τ)（含完整 ct2，用于本地落盘）。"""
    out = _meta()
    out.update(
        {
            "ct0": b64(bg.g_to_bytes(ct.ct0)),
            "ct1": b64(ct.ct1),
            "ct2": b64(ct.ct2),
            "tau": b64(ct.tau),
            "ct2_len": len(ct.ct2),
        }
    )
    return out


def export_ct_server(ct: Ciphertext) -> Dict[str, Any]:
    """
    上传/下发用的信封：**不含 ct2 本体**（ct2 留在 Client 本地）。
    τ 仍按完整 (ct0,ct1,ct2) 计算；仅 wire 省略 ct2 字节。
    """
    out = _meta()
    out.update(
        {
            "ct0": b64(bg.g_to_bytes(ct.ct0)),
            "ct1": b64(ct.ct1),
            "ct2": b64(b""),  # 不上云
            "tau": b64(ct.tau),
            "ct2_len": len(ct.ct2),
            "omit_ct2": True,
        }
    )
    return out


def import_ct(obj: Dict[str, Any]) -> Ciphertext:
    """JSON → Ciphertext；允许 omit_ct2（ct2 为空，由 Client 本地补齐）。"""
    _check_ser_meta(obj)
    return Ciphertext(
        ct0=bg.g_from_bytes(u64(obj["ct0"])),
        ct1=u64(obj["ct1"]),
        ct2=u64(obj["ct2"]) if obj.get("ct2") else b"",
        tau=u64(obj["tau"]),
    )


def merge_local_ct2(ct: Ciphertext, local_ct2: bytes) -> Ciphertext:
    """将 Server 返回的 (ct0,ct1,τ) 与本地 ct2 拼成完整信封。"""
    return Ciphertext(ct0=ct.ct0, ct1=ct.ct1, ct2=local_ct2, tau=ct.tau)


def export_rec(rec: PasswordRecord) -> Dict[str, Any]:
    """口令记录 rec=(id,ctx,c) 落盘格式。"""
    out = _meta()
    out.update({"id": rec.id, "ctx": b64(rec.ctx), "c": b64(rec.c)})
    return out


def import_rec(obj: Dict[str, Any]) -> PasswordRecord:
    """JSON → PasswordRecord。"""
    _check_ser_meta(obj)
    return PasswordRecord(id=obj["id"], ctx=u64(obj["ctx"]), c=u64(obj["c"]))


def export_sk(sk: ServerKey) -> Dict[str, Any]:
    """服务器私钥落盘（仅服务端 data/；含 k,x）。"""
    out = _meta()
    out.update(
        {
            "k": format(sk.k, "x"),
            "x": format(sk.x, "x"),
            "K": b64(bg.g_to_bytes(sk.K)),
            "X": b64(bg.g_to_bytes(sk.X)),
        }
    )
    return out


def import_sk(obj: Dict[str, Any]) -> ServerKey:
    """从磁盘恢复完整 ServerKey；强制要求 ser_ver。"""
    _check_ser_meta(obj, require=True)
    return ServerKey(
        k=int(obj["k"], 16),
        x=int(obj["x"], 16),
        K=bg.g_from_bytes(u64(obj["K"])),
        X=bg.g_from_bytes(u64(obj["X"])),
    )
