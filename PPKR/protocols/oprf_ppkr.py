"""π_OPRF-PPKR 客户端协议实现（论文 Fig. 4 灰色方框）。

对应 Faller et al. (CCS 2024) 的 Lev-3 方案：基于 2HashDH OPRF，
Client 盲化密码后由 HSM 求值，结合 DHIES 通道与 Schnorr 签名完成
Init/Rec 密钥注册与恢复。

Fig. 4 灰色方框（HSM 侧，本类为 Client 侧对应逻辑）
---------------------------------------------------
    Init (OPRF)  → HSM 对盲化 a 求值，返回 (b, pkEnc)
    InitFinish   → HSM 解密 C，存储 OPRFPPKRFile
    Rec (OPRF)   → HSM 对盲化 a' 求值，返回 (b', c)
    RecSign      → HSM 验证 Schnorr 签名 σ，返回 RecRes

协议流程（各 3 轮）：
    Init:
        1. Client 盲化密码 → HSM OPRF 求值并返回 pkEnc
        2. Client 用 OPRF 输出 ρ 加密 (K, sk_c)，经 DHIES 发送 InitFinish
        3. HSM 验证并存储 → 返回 InitRes
    Rec:
        1. Client 盲化密码 → HSM OPRF 求值并返回 c（AE 密文）
        2. Client 解密得 (K, sk_c)，对 Rec 消息签名 RecSign
        3. HSM 验证签名 → 返回 RecRes（Succ / Fail / DelRec）

会话生命周期
------------
每次 Init 或 Rec 调用 ``new_ssid()`` 生成独立 SSID。
OPRF Init 阶段 HSM 保存 k_OPRF 与 pkEnc 至 InitFinish 完成；
Rec 阶段 HSM 无会话状态，直接读写持久化 OPRFPPKRFile。

架构：本类实现 Client 侧；OPRF 求值与 Schnorr 验证在 HSM 内完成。
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from config import CostCounter, IDC, SID, SSID
from common.payload_codec import decode_payload
from crypto.aes_gcm import AESGCMCipher, deserialize_aes
from crypto.dhies import DHIES, DHIESCiphertext, DHIESPublicKey
from crypto.group import GROUP
from crypto.oprf_2hashdh import OPRF2HashDH, OPRFBlindedInput, OPRFClientState, OPRFEvaluated
from crypto.serialize import (
    pack_oprf_ae_plaintext,
    pack_oprf_init_payload,
    pack_rec_sign_message,
    random_key,
    unpack_oprf_ae_plaintext,
)
from crypto.schnorr import Schnorr, SchnorrSecretKey
from hsm.attest import AttestedMessage, HSMAttestation
from protocols.messages import ProtocolMessage


# ─────────────────────────────────────────────────────────────────────────────
# π_OPRF-PPKR Client 端
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class OPRFPPKRClient:
    """π_OPRF-PPKR 协议的 Client 端（IDC 角色）。

    集成 OPRF 盲化/去盲化、DHIES 加密、AES-GCM 封装及 Schnorr 签名，
    所有 HSM 响应经认证验证。
    """

    sid: SID
    idc: IDC
    hsm_pk: object
    oprf: OPRF2HashDH = field(default_factory=OPRF2HashDH)
    dhies: DHIES = field(default_factory=DHIES)
    aes: AESGCMCipher = field(default_factory=AESGCMCipher)
    schnorr: Schnorr = field(default_factory=Schnorr)
    attest: HSMAttestation = field(default_factory=HSMAttestation)
    cost: CostCounter = field(default_factory=CostCounter)

    def new_ssid(self) -> SSID:
        """生成新的会话标识 SSID。

        阶段: 每次 Init 或 Rec 开始前调用。

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

    # ── Init 阶段（Fig. 4 注册流程）──

    def init_blind(self, ssid: SSID, pw: str) -> tuple[ProtocolMessage, OPRFClientState, bytes, CostCounter]:
        """Init 第 1 轮：盲化密码 pw，发送 OPRF 盲化值 a，同时生成随机密钥 K。

        阶段: Init（OPRF 盲化段）

        输入:
            ssid: 本次 Init 会话标识。
            pw:   用户注册密码。

        输出:
            ProtocolMessage:  phase="Init"，body 含盲化值 a 的十六进制。
            OPRFClientState:  客户端 OPRF 状态（含去盲因子，第 2 轮使用）。
            bytes:            随机生成的对称密钥 K。
            CostCounter:      OPRF 盲化开销。
        """
        K = random_key()  # Fig. 4 Init：Client 生成待注册的对称密钥 K
        # 2HashDH OPRF 盲化：pw → 盲化值 a，state 含去盲因子 r
        blinded, state, cost = self.oprf.client_blind(pw, self.idc)
        msg = ProtocolMessage(
            phase="Init",
            sid=self.sid,
            ssid=ssid,
            idc=self.idc,
            body={"a": blinded.serialize()},
        )
        return msg, state, K, cost

    def init_on_oprf_response(
        self,
        attested_data: bytes,
        ssid: SSID,
        state: OPRFClientState,
        K: bytes,
        pk_c_sk: tuple | None = None,
    ) -> tuple[ProtocolMessage, bytes, CostCounter]:
        """Init 第 2 轮：去盲化 OPRF 输出 ρ，加密 (K, sk_c) 并经 DHIES 发送 InitFinish。

        阶段: InitFinish

        输入:
            attested_data: Server 转发的 HSM 响应（含 b, pkEnc）。
            ssid:          会话标识。
            state:         第 1 轮返回的 OPRF 客户端状态。
            K:             第 1 轮生成的对称密钥。
            pk_c_sk:       可选的 (pk_C, sk_C) 元组；为 None 时自动生成。

        输出:
            ProtocolMessage: phase="InitFinish"，body 含 DHIES 密文 C。
            bytes:           密钥 K（Init 成功时保留）。
            CostCounter:     验证 + 去盲化 + 签名密钥生成 + AES + DHIES 开销。
        """
        payload, c_vfy = self._verify_attested(attested_data, ssid, self.idc)
        # Fig. 4 Init(OPRF) → Client：HSM 返回 OPRF 求值 b 与临时 pkEnc
        evaluated = OPRFEvaluated(b=GROUP.deserialize_point(payload["b"]))
        rho, c_fin = self.oprf.client_finalize(evaluated, state)  # 去盲化得 OPRF 输出 ρ
        if pk_c_sk is None:
            # 生成 Schnorr 密钥对 (pk_C, sk_C)，Rec 阶段用于 RecSign 签名
            pk_c, sk_c, c_sig = self.schnorr.keygen()
        else:
            pk_c, sk_c = pk_c_sk
            c_sig = CostCounter()
        # 用 ρ 作为 AES 密钥加密 (K, sk_C) → AE 密文 c
        ae_pt = pack_oprf_ae_plaintext(K, sk_c)
        c_ae, c_aes = self.aes.enc(rho, ae_pt)
        pk_enc = DHIESPublicKey(y=GROUP.deserialize_point(payload["pkEnc"]))
        # DHIES 绑定明文：(SSID, pk_C, c)，供 HSM InitFinish 验证并持久化
        bind_pt = pack_oprf_init_payload(ssid, pk_c, c_ae)
        C, c_pke = self.dhies.enc(pk_enc, bind_pt)
        self._init_sk_c = sk_c
        self._init_a = None  # Init 阶段结束，清除临时盲化状态
        msg = ProtocolMessage(
            phase="InitFinish",
            sid=self.sid,
            ssid=ssid,
            idc=self.idc,
            body={"C": C.serialize()},
        )
        return msg, K, c_vfy + c_fin + c_sig + c_aes + c_pke

    def init_finish(self, attested_data: bytes, ssid: SSID, K: bytes) -> tuple[bytes | str, CostCounter]:
        """Init 第 3 轮：解析 HSM 返回的 InitRes。

        阶段: InitRes

        输入:
            attested_data: Server 转发的 HSM InitRes 认证响应。
            ssid:          会话标识。
            K:             第 1 轮生成的对称密钥。

        输出:
            bytes | str: Succ 时返回 K；Fail 时返回 "Fail"。
            CostCounter: 签名验证开销。
        """
        payload, c_vfy = self._verify_attested(attested_data, ssid, self.idc)
        if payload.get("result") == "Succ":
            return K, c_vfy  # Fig. 4 InitRes：HSM 已写入 OPRFPPKRFile
        return "Fail", c_vfy

    # ── Rec 阶段（Fig. 4 恢复流程）──

    def rec_blind(self, ssid: SSID, pw: str) -> tuple[ProtocolMessage, OPRFClientState, CostCounter]:
        """Rec 第 1 轮：盲化密码，发送 OPRF 盲化值 a'。

        阶段: Rec（OPRF 盲化段）

        输入:
            ssid: 本次 Rec 会话标识。
            pw:   用户恢复密码。

        输出:
            ProtocolMessage:  phase="Rec"，body 含盲化值 a' 的十六进制。
            OPRFClientState:  客户端 OPRF 状态（第 2 轮去盲化用）。
            CostCounter:      OPRF 盲化开销。
        """
        blinded, state, cost = self.oprf.client_blind(pw, self.idc)
        self._rec_a = blinded.serialize()  # 暂存 a'，供 rec_sign 构造签名消息
        msg = ProtocolMessage(
            phase="Rec",
            sid=self.sid,
            ssid=ssid,
            idc=self.idc,
            body={"a_prime": blinded.serialize()},
        )
        return msg, state, cost

    def rec_on_oprf_response(
        self,
        attested_data: bytes,
        ssid: SSID,
        state: OPRFClientState,
    ) -> tuple[bytes | None, SchnorrSecretKey | None, bytes, bytes, CostCounter]:
        """Rec 第 2 轮：去盲化 OPRF 输出，解密 AE 密文 c 恢复 (K, sk_c)。

        阶段: Rec（OPRF 去盲化 + 解密段）

        输入:
            attested_data: Server 转发的 HSM 响应（含 b', c 或 Fail/DelRec）。
            ssid:          会话标识。
            state:         第 1 轮返回的 OPRF 客户端状态。

        输出:
            bytes | None:            Succ 时返回 K；失败时为 None。
            SchnorrSecretKey | None: Succ 时返回 sk_C；失败时为 None。
            bytes:                   盲化输入 a' 的序列化（供 rec_sign 使用）。
            bytes:                   OPRF 求值 b' 的序列化（供 rec_sign 使用）。
            CostCounter:             验证 + 去盲化 + AES 解密开销。
        """
        payload, c_vfy = self._verify_attested(attested_data, ssid, self.idc)
        # HSM 提前返回 RecRes（记录不存在或 ctr=0）→ 跳过后续 RecSign
        if payload.get("type") == "RecRes":
            return None, None, b"", b"", c_vfy
        # Fig. 4 Rec(OPRF) → Client：HSM 返回 b' 与存储的 AE 密文 c
        evaluated = OPRFEvaluated(b=GROUP.deserialize_point(payload["b_prime"]))
        c_ae = deserialize_aes(payload["c"])
        rho, c_fin = self.oprf.client_finalize(evaluated, state)  # 去盲化得 ρ
        pt, c_dec = self.aes.dec(rho, c_ae)  # 用 ρ 解密 c → (K, sk_C)
        if pt is None:
            # AES-GCM 解密失败（密码错误导致 ρ 不匹配）
            return None, None, self._rec_a, evaluated.serialize(), c_vfy + c_fin + c_dec
        K, sk_c = unpack_oprf_ae_plaintext(pt)
        return K, sk_c, self._rec_a, evaluated.serialize(), c_vfy + c_fin + c_dec

    def rec_sign(
        self,
        ssid: SSID,
        a_prime: bytes,
        b_prime: bytes,
        c_ser: bytes,
        sk_c: SchnorrSecretKey,
    ) -> tuple[ProtocolMessage, CostCounter]:
        """Rec 第 2 轮续：对 (a', b', c) 签名，发送 RecSign 消息供 HSM 验证。

        阶段: RecSign

        输入:
            ssid:    会话标识。
            a_prime: 盲化 OPRF 输入 a' 的序列化字节。
            b_prime: HSM OPRF 求值 b' 的序列化字节。
            c_ser:   AE 密文 c 的序列化字节（str 或 bytes）。
            sk_c:    从 AE 密文解密得到的 Schnorr 私钥。

        输出:
            ProtocolMessage: phase="RecSign"，body 含签名 σ 与密文 c。
            CostCounter:     Schnorr 签名开销。
        """
        from crypto.aes_gcm import deserialize_aes

        c_bytes = c_ser if isinstance(c_ser, bytes) else bytes(c_ser)
        c_ae = deserialize_aes(c_bytes)
        # Fig. 4 RecSign：构造待签名消息 m = (a', IDC, SSID, b', c)
        message = pack_rec_sign_message(a_prime, self.idc, ssid, b_prime, c_ae)
        pk_y, _ = GROUP.exp(GROUP.g, sk_c.x)
        from crypto.schnorr import SchnorrPublicKey
        pk_c = SchnorrPublicKey(y=pk_y)
        sig, cost = self.schnorr.sign(sk_c, pk_c, message)  # Client 用 sk_C 签名 σ
        msg = ProtocolMessage(
            phase="RecSign",
            sid=self.sid,
            ssid=ssid,
            idc=self.idc,
            body={
                "sigma": sig.serialize(),
                "c": c_bytes,
                "a_prime": a_prime,
                "b_prime": b_prime,
            },
        )
        return msg, cost

    def rec_finish(self, attested_data: bytes, ssid: SSID, K: bytes) -> tuple[bytes | str, CostCounter]:
        """Rec 第 3 轮：解析 HSM 返回的 RecRes（Succ / Fail / DelRec）。

        阶段: RecRes

        输入:
            attested_data: Server 转发的 HSM RecRes 认证响应。
            ssid:          会话标识。
            K:             第 2 轮解密得到的对称密钥。

        输出:
            bytes | str: Succ 时返回 K；Fail / DelRec 时返回对应字符串。
            CostCounter: 签名验证开销。
        """
        payload, c_vfy = self._verify_attested(attested_data, ssid, self.idc)
        # Fig. 4 RecRes：HSM 验证 RecSign 签名后的最终结果
        if payload.get("result") == "Succ":
            return K, c_vfy  # 签名验证通过，ctr 已重置
        if payload.get("result") == "DelRec":
            return "DelRec", c_vfy  # ctr 耗尽，记录已删除
        return "Fail", c_vfy  # Schnorr 签名验证失败
