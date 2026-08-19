"""随机预言机 H、H1、H2。

对应 Faller 等 (CCS 2024) Fig. 3–4 中的哈希原语：
  Fig. 3 encPw+：H(sid, s1, pw) → h；H(sid, s2, pw) → 掩码 XOR K。
  Fig. 4 OPRF-PPKR：H1(pw||IDC) 映射到群；H2(pw||IDC, ·) 输出 ρ。

安全注记：H 隐式以 sid（服务器标识，非 ssid）为首个输入；
H1 使用 RFC 9380 hash_to_curve；输出截断至 λ 位或 AE 密钥长度。
"""

from __future__ import annotations

import hashlib

from config import AE_KEY_BYTES, CostCounter, IDC, LAMBDA, SID, SSID
from crypto.group import GROUP, GroupElement


def _truncate(data: bytes, nbytes: int = LAMBDA // 8) -> bytes:
    """截断哈希输出至指定字节数。"""
    return data[:nbytes]


# ── Fig. 3 encPw+ 随机预言机 H ────────────────────────────────────────


class RandomOracleH:
    """Fig. 3 随机预言机 H：H(s1, pw) 在实现中为 H(sid, s1, pw)。"""

    def eval(self, sid: SID, salt: bytes, pw: str) -> tuple[bytes, CostCounter]:
        """计算 H(sid, salt, pw) 并截断至 AE 密钥长度（与 K 同宽，供 XOR 掩码）；计 1 Hash。"""
        data = sid.encode() + salt + pw.encode()
        digest = hashlib.sha256(data).digest()
        return _truncate(digest, AE_KEY_BYTES), CostCounter(hash=1)


# ── Fig. 4 OPRF 盲化基 H1 (hash-to-group) ─────────────────────────────


class RandomOracleH1:
    """Fig. 4 OPRF 盲化基：a = H1(pw || IDC)^r（hash-to-group）。"""

    def hash_to_group(self, pw: str, idc: IDC) -> tuple[GroupElement, CostCounter]:
        """将 pw||IDC 映射到 P-256 曲线点。"""
        label = pw.encode() + b"||" + idc.encode()
        return GROUP.hash_to_group(label)


# ── Fig. 4 OPRF 终结 H2 ───────────────────────────────────────────────


class RandomOracleH2:
    """Fig. 4 OPRF 终结：ρ = H2(pw || IDC, b^(1/r))。"""

    def eval(self, pw: str, idc: IDC, element: GroupElement) -> tuple[bytes, CostCounter]:
        """对 pw||IDC 与群元素序列化后哈希，输出 AE 密钥长度。"""
        label = pw.encode() + b"||" + idc.encode()
        data = label + element.serialize()
        digest = hashlib.sha256(data).digest()
        return _truncate(digest, AE_KEY_BYTES), CostCounter(hash=1)
