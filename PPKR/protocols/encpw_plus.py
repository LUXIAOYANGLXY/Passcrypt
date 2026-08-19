"""π_encPw+ 客户端协议实现（论文 Fig. 3 灰色方框）。

对应 Faller et al. (CCS 2024) 的 Lev-2 方案：基于 DHIES 公钥加密通道，
HSM 持有 ElGamal 加密私钥，Client 通过密码派生密钥 K 完成 Init/Rec。

Fig. 3 灰色方框（HSM 侧，本类为 Client 侧对应逻辑）
---------------------------------------------------
    InitS  → HSM 生成 pkEnc，Client 验证签名后加密 (pw, K)
    Init   → HSM 存储掩码密钥，返回 InitRes
    RecS   → HSM 生成恢复用 pkEnc，Client 加密 (ksym, pw)
    Rec    → HSM 验证密码并返回 AES 加密的 K

协议流程（各 3 轮 Client → Server → HSM）：
    Init:
        1. Client 发送 InitS  → HSM 返回认证公钥 pkEnc
        2. Client 用 DHIES 加密 (pw, K) → HSM 验证并存储
        3. HSM 返回 InitRes（Succ / Fail）
    Rec:
        1. Client 发送 RecS   → HSM 返回恢复用公钥
        2. Client 用 DHIES 加密 (ksym, pw) → HSM 解密验证密码
        3. HSM 返回 AES 加密的 K（或 Fail / DelRec）

会话生命周期
------------
每次 Init 或 Rec 调用 ``new_ssid()`` 生成独立 SSID，贯穿该次三轮回合。
HSM 在 InitS/RecS 时创建临时会话，Init/Rec 处理完毕后销毁；
Client 侧无显式会话表，通过 SSID 参数在各轮方法间传递绑定。

架构：本类仅实现 Client 侧逻辑；Server 转发、HSM 运算分别由
``server.ppkr_server.PPKRServer`` 与 ``hsm.hsm_core.HSMCore`` 承担。
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from config import CostCounter, IDC, SID, SSID
from common.payload_codec import decode_payload
from crypto.aes_gcm import AESGCMCipher, deserialize_aes
from crypto.dhies import DHIES, DHIESPublicKey
from crypto.group import GROUP
from crypto.serialize import (
    pack_encpw_init_payload,
    pack_encpw_rec_payload,
    random_key,
)
from hsm.attest import AttestedMessage, HSMAttestation
from protocols.messages import ProtocolMessage


# ─────────────────────────────────────────────────────────────────────────────
# π_encPw+ Client 端
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class EncPwPlusClient:
    """π_encPw+ 协议的 Client 端（IDC 角色）。

    持有 HSM 认证公钥，所有来自 HSM 的响应均经 Schnorr 签名验证后方可信任。
    """

    sid: SID
    idc: IDC
    hsm_pk: object  # SchnorrPublicKey
    dhies: DHIES = field(default_factory=DHIES)
    aes: AESGCMCipher = field(default_factory=AESGCMCipher)
    attest: HSMAttestation = field(default_factory=HSMAttestation)
    cost: CostCounter = field(default_factory=CostCounter)

    def new_ssid(self) -> SSID:
        """生成新的会话标识 SSID。

        阶段: 每次 Init 或 Rec 开始前调用，确保会话隔离。

        输出: 全局唯一的 UUID 字符串，作为 SSID。
        """
        return SSID(str(uuid.uuid4()))

    def _verify_attested(self, data: bytes, ssid: SSID, idc: IDC) -> tuple[dict, CostCounter]:
        """验证 HSM 认证消息并解析二进制载荷。"""
        msg = AttestedMessage.deserialize(data)
        ok, cost = self.attest.verify(msg, self.hsm_pk, ssid, idc)
        if not ok:
            raise ValueError("HSM attestation verification failed")
        return decode_payload(msg.payload), cost

    # ── Init 阶段（Fig. 3 注册流程）──

    def init_start(self, ssid: SSID) -> ProtocolMessage:
        """Init 第 1 轮：请求 Server 触发 HSM 的 InitS，获取 pkEnc。

        阶段: InitS

        输入:
            ssid: 本次 Init 会话标识。

        输出:
            ProtocolMessage: phase="InitS"，body 为空，携带 sid/idc/ssid。
        """
        return ProtocolMessage(
            phase="InitS",
            sid=self.sid,
            ssid=ssid,
            idc=self.idc,
            body={},  # InitS 无需密码学载荷，仅触发 HSM 生成 pkEnc
        )

    def init_on_pk(self, attested_data: bytes, ssid: SSID, pw: str) -> tuple[ProtocolMessage, bytes, CostCounter]:
        """Init 第 2 轮：接收 HSM 认证的 pkEnc，构造 DHIES 密文 C 并发送 Init 消息。

        阶段: Init

        输入:
            attested_data: Server 转发的 HSM 认证响应（含 pkEnc）。
            ssid:          与第 1 轮一致的会话标识。
            pw:            用户注册密码。

        输出:
            ProtocolMessage: phase="Init"，body 含 DHIES 密文 C 的十六进制。
            bytes:           随机生成的对称密钥 K（Init 成功时保留）。
            CostCounter:     签名验证 + DHIES 加密开销。
        """
        payload, c_vfy = self._verify_attested(attested_data, ssid, self.idc)
        # Fig. 3 InitS → Client：从认证载荷中提取 HSM 临时公钥 pkEnc
        pk = DHIESPublicKey(y=GROUP.deserialize_point(payload["pk"]))
        K = random_key()  # 生成本次注册的对称密钥 K（Init 成功后由 Client 保留）
        # 明文绑定 (pw, K, IDC, SSID)，供 HSM 验证身份并掩码存储 K
        plaintext = pack_encpw_init_payload(pw, K, self.idc, ssid)
        C, c_enc = self.dhies.enc(pk, plaintext)  # DHIES 加密 → 密文 C
        self._last_K = K
        msg = ProtocolMessage(
            phase="Init",
            sid=self.sid,
            ssid=ssid,
            idc=self.idc,
            body={"C": C.serialize()},
        )
        return msg, K, c_vfy + c_enc

    def init_finish(self, attested_data: bytes, ssid: SSID, K: bytes) -> tuple[bytes | str, CostCounter]:
        """Init 第 3 轮：解析 HSM 返回的 InitRes，Succ 时保留密钥 K。

        阶段: InitRes

        输入:
            attested_data: Server 转发的 HSM InitRes 认证响应。
            ssid:          会话标识。
            K:             第 2 轮生成的对称密钥。

        输出:
            bytes | str: Succ 时返回 K；Fail 时返回字符串 "Fail"。
            CostCounter: 签名验证开销。
        """
        payload, c_vfy = self._verify_attested(attested_data, ssid, self.idc)
        # Fig. 3 InitRes：HSM 已完成掩码存储，Succ 表示注册成功
        if payload.get("result") == "Succ":
            return K, c_vfy  # 返回第 2 轮生成的 K，供上层持久化
        return "Fail", c_vfy  # 密码验证或存储失败

    # ── Rec 阶段（Fig. 3 恢复流程）──

    def rec_start(self, ssid: SSID) -> ProtocolMessage:
        """Rec 第 1 轮：请求 Server 触发 HSM 的 RecS，获取恢复用公钥。

        阶段: RecS

        输入:
            ssid: 本次 Rec 会话标识。

        输出:
            ProtocolMessage: phase="RecS"，body 为空，携带 sid/idc/ssid。
        """
        return ProtocolMessage(
            phase="RecS",
            sid=self.sid,
            ssid=ssid,
            idc=self.idc,
            body={},  # RecS 无需载荷，触发 HSM 生成恢复用 pkEnc
        )

    def rec_on_pk(self, attested_data: bytes, ssid: SSID, pw: str) -> tuple[ProtocolMessage, bytes, CostCounter]:
        """Rec 第 2 轮：接收公钥，用 DHIES 加密 (ksym, pw) 并发送 Rec 消息。

        阶段: Rec

        输入:
            attested_data: Server 转发的 HSM 认证响应（含 pkEnc）。
            ssid:          与第 1 轮一致的会话标识。
            pw:            用户恢复密码。

        输出:
            ProtocolMessage: phase="Rec"，body 含 DHIES 密文 C 的十六进制。
            bytes:           随机生成的会话密钥 ksym（第 3 轮解密用）。
            CostCounter:     签名验证 + DHIES 加密开销。
        """
        payload, c_vfy = self._verify_attested(attested_data, ssid, self.idc)
        # Fig. 3 RecS → Client：提取恢复阶段临时公钥 pkEnc（与 Init 独立生成）
        pk = DHIESPublicKey(y=GROUP.deserialize_point(payload["pk"]))
        ksym = random_key()  # 会话密钥，用于第 3 轮解密 HSM 返回的 C'
        # 明文绑定 (ksym, pw, IDC, SSID)；HSM 用 pw 验证后以 ksym 加密 K 返回
        plaintext = pack_encpw_rec_payload(ksym, pw, self.idc, ssid)
        C, c_enc = self.dhies.enc(pk, plaintext)
        self._last_ksym = ksym  # 暂存 ksym，供 rec_finish 解密 C' 使用
        msg = ProtocolMessage(
            phase="Rec",
            sid=self.sid,
            ssid=ssid,
            idc=self.idc,
            body={"C": C.serialize()},
        )
        return msg, ksym, c_vfy + c_enc

    def rec_finish(
        self, attested_data: bytes, ssid: SSID, ksym: bytes
    ) -> tuple[bytes | str, CostCounter]:
        """Rec 第 3 轮：用 ksym 解密 HSM 返回的 C'，恢复密钥 K 或返回 Fail/DelRec。

        阶段: RecRes

        输入:
            attested_data: Server 转发的 HSM RecRes 认证响应。
            ssid:          会话标识。
            ksym:          第 2 轮生成的会话密钥。

        输出:
            bytes | str: Succ 时返回恢复的 K；Fail / DelRec 时返回对应字符串。
            CostCounter: 签名验证 + AES 解密开销。
        """
        payload, c_vfy = self._verify_attested(attested_data, ssid, self.idc)
        result = payload.get("result")
        # Fig. 3 RecRes 分支：ctr 耗尽时 HSM 删除记录并返回 DelRec
        if result == "DelRec":
            return "DelRec", c_vfy
        # 密码验证失败（H(s₁,pw) 不匹配）→ Fail
        if result == "Fail":
            return "Fail", c_vfy
        # Succ 路径：HSM 以 ksym 加密的 AES-GCM 密文 C'，Client 本地解密得 K
        aes_ct = deserialize_aes(payload["C_prime"])
        K_masked, c_dec = self.aes.dec(ksym, aes_ct)
        if K_masked is None:
            # AES-GCM 认证标签校验失败（密文被篡改或 ksym 不匹配）
            return "Fail", c_vfy + c_dec
        return K_masked, c_vfy + c_dec  # 恢复成功，返回对称密钥 K
