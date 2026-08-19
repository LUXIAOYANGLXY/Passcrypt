"""HSM 用户文件持久化存储模块。

本模块模拟 HSM 内部的安全存储区，保存两种协议的用户记录：

- **Fig. 3 encPw+**：``EncPwPlusFile`` = ⟨File, IDC, c, h, s₁, s₂, ctr⟩
- **Fig. 4 OPRF-PPKR**：``OPRFPPKRFile`` = ⟨File, IDC, pk_C, c, k_OPRF, ctr⟩

HSM 角色
--------
HSM 是用户密钥的唯一保管者：Init 阶段写入记录，Rec 阶段读取并验证。
``ctr`` 计数器实现论文中的猜测次数限制——每次 Rec 尝试递减，
耗尽后删除记录并返回 DelRec。

会话生命周期
------------
存储操作与 SSID 会话无直接绑定：Init/Rec 的会话状态在 ``HSMCore._sessions``
中管理，而用户文件以 ``IDC`` 为键长期驻留，跨多次 Rec 尝试共享同一记录。
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Union

from config import CTR_MAX, IDC, SALT_BYTES
from crypto.aes_gcm import AESCiphertext
from crypto.oprf_2hashdh import OPRFKey
from crypto.schnorr import SchnorrPublicKey


# ─────────────────────────────────────────────────────────────────────────────
# 用户文件记录结构（Fig. 3 / Fig. 4）
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class EncPwPlusFile:
    """Fig. 3 π_encPw+ 用户文件记录。

    对应论文符号 ⟨File, IDC, c, h, s₁, s₂, ctr⟩：
        c:   经 H(s₂, pw) 掩码后的密钥 K（XOR 掩码，非 AE 加密）。
        h:   密码验证哈希 H(s₁, pw)，Rec 时用于校验恢复密码。
        s₁/s₂: 随机盐值，分别用于密码验证与密钥掩码。
        ctr: 剩余恢复尝试次数，初始为 CTR_MAX。
    """

    idc: IDC
    c: bytes
    h: bytes
    s1: bytes
    s2: bytes
    ctr: int = CTR_MAX


@dataclass
class OPRFPPKRFile:
    """Fig. 4 π_OPRF-PPKR 用户文件记录。

    对应论文符号 ⟨File, IDC, pk_C, c, k_OPRF, ctr⟩：
        pk_c:   Client 注册时生成的 Schnorr 公钥，Rec 时用于验证签名。
        c:      经 OPRF 输出 ρ 加密的 AE 密文，封装 (K, sk_C)。
        k_oprf: Init 阶段生成的 OPRF 服务器密钥，Rec 时对 a' 求值。
        ctr:    剩余恢复尝试次数，初始为 CTR_MAX。
    """

    idc: IDC
    pk_c: SchnorrPublicKey
    c: AESCiphertext
    k_oprf: OPRFKey
    ctr: int = CTR_MAX


UserFile = Union[EncPwPlusFile, OPRFPPKRFile]


# ─────────────────────────────────────────────────────────────────────────────
# HSM 内存存储后端
# ─────────────────────────────────────────────────────────────────────────────


class HSMStorage:
    """HSM 内部用户文件存储，按 IDC 索引。

    维护两个独立字典分别存放 encPw+ 与 OPRF-PPKR 记录，
    并提供泄露快照接口供安全实验使用。
    """

    def __init__(self) -> None:
        self._encpw: dict[str, EncPwPlusFile] = {}   # Fig. 3 用户文件，按 IDC 索引
        self._oprf: dict[str, OPRFPPKRFile] = {}     # Fig. 4 用户文件，按 IDC 索引
        self._leaked_snapshots: list[list[UserFile]] = []

    # ── encPw+ 文件操作（Fig. 3）──

    def store_encpw_plus(self, record: EncPwPlusFile) -> None:
        """存储或覆盖指定 IDC 的 encPw+ 用户记录（Init 成功后调用）。"""
        self._encpw[record.idc] = record  # 以 IDC 为键，跨 SSID 会话持久驻留

    def retrieve_encpw_plus(self, idc: IDC) -> EncPwPlusFile | None:
        """按 IDC 检索 encPw+ 记录；不存在时返回 None。"""
        return self._encpw.get(idc)

    def delete_encpw(self, idc: IDC) -> None:
        """删除指定 IDC 的 encPw+ 记录（ctr 耗尽或 DelRec 时调用）。"""
        self._encpw.pop(idc, None)  # 永久删除，后续 Rec 将返回 Fail

    # ── OPRF-PPKR 文件操作（Fig. 4）──

    def store_oprf_ppkr(self, record: OPRFPPKRFile) -> None:
        """存储或覆盖指定 IDC 的 OPRF-PPKR 用户记录（InitFinish 成功后调用）。"""
        self._oprf[record.idc] = record  # 含 pk_C、c、k_OPRF，供 Rec 阶段使用

    def retrieve_oprf_ppkr(self, idc: IDC) -> OPRFPPKRFile | None:
        """按 IDC 检索 OPRF-PPKR 记录；不存在时返回 None。"""
        return self._oprf.get(idc)

    def delete_oprf(self, idc: IDC) -> None:
        """删除指定 IDC 的 OPRF-PPKR 记录（ctr 耗尽或 DelRec 时调用）。"""
        self._oprf.pop(idc, None)

    # ── 安全实验与工具方法 ──

    def leak_all(self) -> list[UserFile]:
        """返回当前所有用户文件的深拷贝快照。

        输出: encPw+ 与 OPRF-PPKR 记录的合并列表。
        副作用: 将快照追加到 ``leaked_snapshots`` 历史，供泄露分析使用。
        后续对活跃存储的修改不影响已泄露视图。
        """
        snapshot: list[UserFile] = []
        snapshot.extend(copy.deepcopy(list(self._encpw.values())))
        snapshot.extend(copy.deepcopy(list(self._oprf.values())))
        # 深拷贝快照：后续修改活跃存储不影响已泄露视图（安全实验用）
        self._leaked_snapshots.append(copy.deepcopy(snapshot))
        return snapshot

    @property
    def leaked_snapshots(self) -> list[list[UserFile]]:
        """历次 ``leak_all`` 调用的快照历史列表（只读）。"""
        return self._leaked_snapshots

    @staticmethod
    def random_salt() -> bytes:
        """生成密码学安全的随机盐值（长度 SALT_BYTES）。"""
        import os

        return os.urandom(SALT_BYTES)
