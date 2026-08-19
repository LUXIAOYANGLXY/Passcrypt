"""HSM 核心运算模块 — 实现论文 Fig. 3 / Fig. 4 中的灰色方框逻辑。

本模块封装硬件安全模块（HSM）的全部密码学操作，对应 Faller et al. (CCS 2024)
PPKR 论文中 Server 不可直接访问的受信执行环境。Server 仅作为透明转发层，
所有密钥生成、加密/解密、OPRF 求值、用户文件读写均在此完成。

架构角色
--------
- **Client (IDC)**：发起 Init/Rec 请求，持有密码与临时对称密钥。
- **Server (S)**：路由消息，调用本模块的公开接口，将认证响应回传 Client。
- **HSM（本模块）**：执行灰色方框内的密码学步骤，对输出做 Schnorr 签名认证（↪ x）。

Fig. 3 — π_encPw+（Lev-2）
--------------------------
灰色方框对应以下 HSM 操作：
    InitS  → 生成临时 DHIES 密钥对 (pkEnc, skEnc)，返回认证公钥
    Init   → 解密 C，验证 (IDC, SSID)，用 H(pw) 掩码存储 K，写入 EncPwPlusFile
    RecS   → 生成新的临时 DHIES 密钥对，返回认证公钥
    Rec    → 解密 C，验证密码哈希，用掩码恢复 K 并以 ksym 加密返回

Fig. 4 — π_OPRF-PPKR（Lev-3）
------------------------------
灰色方框对应以下 HSM 操作：
    Init (OPRF)  → 对盲化输入 a 做 OPRF 求值，生成 pkEnc，返回 (b, pkEnc)
    InitFinish   → 解密 C，存储 OPRFPPKRFile（含 pk_C, c, k_OPRF）
    Rec (OPRF)   → 用存储的 k_OPRF 对 a' 求值，返回 (b', c)
    RecSign      → 验证 Client 的 Schnorr 签名 σ，返回 RecRes

会话生命周期
------------
每次 Init 或 Rec 由唯一 SSID 标识。HSM 在 ``_sessions`` 中维护临时状态：

1. **创建**：``encpw_get_pk`` / ``encpw_rec_get_pk`` / ``oprf_init_oprf`` 写入会话，
   保存临时 DHIES 密钥（及 OPRF 密钥 k_OPRF）。
2. **消费**：``encpw_init`` / ``encpw_rec`` / ``oprf_init_finish`` 读取会话、
   完成运算后于 ``finally`` 块中清除。
3. **无状态阶段**：``oprf_rec_evaluate`` / ``oprf_rec_verify`` 直接读写持久化文件，
   不依赖会话字典。

所有对外返回值均为 ``(AttestedMessage, CostCounter)`` 元组，供 Server 转发并计费统计。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from config import CTR_MAX, CostCounter, IDC, SID, SSID
from common.payload_codec import (
    encode_init_res,
    encode_oprf_eval,
    encode_oprf_rec_eval,
    encode_pk_enc,
    encode_rec_res,
)
from crypto.aes_gcm import AESGCMCipher
from crypto.dhies import DHIES, DHIESCiphertext, DHIESPublicKey, DHIESSecretKey
from crypto.oprf_2hashdh import OPRF2HashDH, OPRFBlindedInput, OPRFKey, OPRFEvaluated
from crypto.random_oracle import RandomOracleH
from crypto.serialize import (
    unpack_encpw_init_payload,
    unpack_encpw_rec_payload,
    unpack_oprf_init_payload,
)
from crypto.schnorr import Schnorr, SchnorrPublicKey, deserialize_schnorr_sig
from hsm.attest import AttestedMessage, HSMAttestation
from hsm.storage import EncPwPlusFile, HSMStorage, OPRFPPKRFile


# ─────────────────────────────────────────────────────────────────────────────
# 数据结构：临时密钥与会话状态
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class EphemeralPKE:
    """单次会话使用的临时 DHIES 公钥/私钥对。"""

    pk: DHIESPublicKey
    sk: DHIESSecretKey


@dataclass
class HSMSession:
    """HSM 内部会话记录，以 SSID 为键索引。

    Attributes:
        ssid:      当前会话标识。
        idc:       客户端身份标识。
        phase:     会话所处阶段（"init" / "rec" / "oprf_init"）。
        ephemeral: 临时 DHIES 密钥对；OPRF Init 阶段同时承载 pkEnc。
        k_oprf:    OPRF Init 阶段生成的服务器密钥，待 InitFinish 持久化。
    """

    ssid: SSID
    idc: IDC
    phase: str
    ephemeral: EphemeralPKE | None = None
    k_oprf: OPRFKey | None = None


# ─────────────────────────────────────────────────────────────────────────────
# HSM 核心类
# ─────────────────────────────────────────────────────────────────────────────


class HSMCore:
    """HSM 核心入口；仅供 Server 内部调用，Client 不可直接访问。

    聚合密码学原语（DHIES、AES-GCM、OPRF、随机预言机、Schnorr）、
    消息认证（``HSMAttestation``）、持久化存储（``HSMStorage``）及
    按 SSID 索引的临时会话表。
    """

    def __init__(self) -> None:
        self.dhies = DHIES()
        self.aes = AESGCMCipher()
        self.ro_h = RandomOracleH()
        self.oprf = OPRF2HashDH()
        self.schnorr = Schnorr()
        self.attest = HSMAttestation(self.schnorr)
        self.storage = HSMStorage()
        self._sessions: dict[str, HSMSession] = {}  # 按 SSID 索引的临时会话表
        self.cost = CostCounter()

    @property
    def attestation_public_key(self) -> SchnorrPublicKey:
        """HSM 长期 Schnorr 认证公钥，供 Client 验证所有 HSM 响应签名。"""
        return self.attest.public_key

    def _session_key(self, ssid: SSID) -> str:
        """将会话 ID 规范化为字典键。"""
        return ssid

    def _clear_session(self, ssid: SSID) -> None:
        """主动清除指定 SSID 的临时会话状态。"""
        # 销毁临时 DHIES 密钥与 OPRF 状态，防止 SSID 重用导致密钥泄露
        self._sessions.pop(self._session_key(ssid), None)

    # ─────────────────────────────────────────────────────────────────────────
    # π_encPw+ 协议 — Fig. 3 灰色方框
    # ─────────────────────────────────────────────────────────────────────────

    def encpw_get_pk(self, ssid: SSID, idc: IDC) -> tuple[AttestedMessage, CostCounter]:
        """Fig. 3 InitS：生成临时 DHIES 公钥并建立 Init 会话。

        阶段: Init 第 1 轮（HSM 侧，对应 Client 的 ``init_start``）

        输入:
            ssid: 本次 Init 会话标识。
            idc:  客户端身份标识。

        输出:
            AttestedMessage: 载荷 ``{"type":"pkEnc","pk":...}``，含 Schnorr 签名。
            CostCounter:     DHIES 密钥生成 + 签名开销。

        副作用: 在 ``_sessions`` 中创建 phase="init" 的临时会话。
        """
        pk, sk, cost = self.dhies.keygen()
        # 创建 Init 会话：保存临时 skEnc，供下一轮 encpw_init 解密 C
        self._sessions[self._session_key(ssid)] = HSMSession(
            ssid=ssid, idc=idc, phase="init", ephemeral=EphemeralPKE(pk=pk, sk=sk)
        )
        payload = encode_pk_enc(pk.serialize())
        msg, c_att = self.attest.attest(payload, ssid, idc)  # ↪ x：签名后返回 pkEnc
        return msg, cost + c_att

    def encpw_init(
        self, sid: SID, ssid: SSID, idc: IDC, C: DHIESCiphertext
    ) -> tuple[AttestedMessage, CostCounter]:
        """Fig. 3 Init：解密 Client 密文，验证身份并存储掩码密钥。

        阶段: Init 第 2–3 轮（HSM 侧，对应 Client 的 ``init_on_pk`` → ``init_finish``）

        输入:
            sid:  服务器标识（用于随机预言机 H 的域分离）。
            ssid: 必须与 InitS 阶段一致的会话标识。
            idc:  客户端身份标识。
            C:    Client 用 pkEnc 加密的 DHIES 密文，明文为 (pw, K, IDC, SSID)。

        输出:
            AttestedMessage: 载荷 ``{"type":"InitRes","result":"Succ"|"Fail"}``。
            CostCounter:     解密 + 两次 H 求值 + 签名开销。

        副作用: 成功时写入 ``EncPwPlusFile``；无论成败均在 finally 中清除会话。
        """
        key = self._session_key(ssid)
        try:
            session = self._sessions.get(key)
            # 会话不存在或缺少临时密钥 → InitS 未完成或 SSID 不匹配
            if not session or not session.ephemeral:
                return self._fail_init(ssid, idc)

            # 用 InitS 阶段生成的 skEnc 解密 Client 发来的 DHIES 密文 C
            pt, c_dec = self.dhies.dec(session.ephemeral.sk, C)
            if pt is None:
                return self._fail_init(ssid, idc)  # DHIES 解密失败

            pw, K, id_prime, ssid_prime = unpack_encpw_init_payload(pt)
            # 验证明文绑定的 IDC/SSID 与当前请求一致
            if idc != id_prime or ssid != ssid_prime:
                return self._fail_init(ssid, idc)

            s1 = self.storage.random_salt()
            s2 = self.storage.random_salt()
            h, c_h1 = self.ro_h.eval(sid, s1, pw)       # h = H(s₁, pw)，Rec 时验证密码
            mask, c_h2 = self.ro_h.eval(sid, s2, pw)   # mask = H(s₂, pw)，掩码 K
            c_store = self.aes.xor_mask(mask, K)        # c = K ⊕ mask（非 AE 加密）

            # 写入 Fig. 3 用户文件 ⟨File, IDC, c, h, s₁, s₂, ctr⟩
            self.storage.store_encpw_plus(
                EncPwPlusFile(idc=idc, c=c_store, h=h, s1=s1, s2=s2, ctr=CTR_MAX)
            )
            payload = encode_init_res("Succ")
            msg, c_att = self.attest.attest(payload, ssid, idc)
            total = c_dec + c_h1 + c_h2 + c_att
            self.cost += total
            return msg, total
        finally:
            # Init 完成（无论成败）→ 销毁临时 skEnc，会话不可复用
            self._sessions.pop(key, None)

    def encpw_rec_get_pk(self, ssid: SSID, idc: IDC) -> tuple[AttestedMessage, CostCounter]:
        """Fig. 3 RecS：生成临时 DHIES 公钥并建立 Rec 会话。

        阶段: Rec 第 1 轮（HSM 侧，对应 Client 的 ``rec_start``）

        输入:
            ssid: 本次 Rec 会话标识。
            idc:  客户端身份标识。

        输出:
            AttestedMessage: 载荷 ``{"type":"pkEnc","pk":...}``，含 Schnorr 签名。
            CostCounter:     DHIES 密钥生成 + 签名开销。

        副作用: 在 ``_sessions`` 中创建 phase="rec" 的临时会话。
        """
        pk, sk, cost = self.dhies.keygen()
        # 创建 Rec 会话：Rec 使用与 Init 独立的临时 DHIES 密钥对
        self._sessions[self._session_key(ssid)] = HSMSession(
            ssid=ssid, idc=idc, phase="rec", ephemeral=EphemeralPKE(pk=pk, sk=sk)
        )
        payload = encode_pk_enc(pk.serialize())
        msg, c_att = self.attest.attest(payload, ssid, idc)
        return msg, cost + c_att

    def encpw_rec(
        self, sid: SID, ssid: SSID, idc: IDC, C: DHIESCiphertext
    ) -> tuple[AttestedMessage, CostCounter]:
        """Fig. 3 Rec：验证恢复密码，解密掩码密钥并以 ksym 加密返回。

        阶段: Rec 第 2–3 轮（HSM 侧，对应 Client 的 ``rec_on_pk`` → ``rec_finish``）

        输入:
            sid:  服务器标识。
            ssid: 必须与 RecS 阶段一致的会话标识。
            idc:  客户端身份标识。
            C:    Client 用 pkEnc 加密的 DHIES 密文，明文为 (ksym, pw, IDC, SSID)。

        输出:
            AttestedMessage: 载荷 ``{"type":"RecRes","result":...}``；
                Succ 时附加 ``C_prime``（AES-GCM 加密的 K）；
                Fail / DelRec 时仅含 result 字段。
            CostCounter: 解密 + H 求值 + AES 加密 + 签名开销。

        副作用: 递减 ctr 计数器；ctr=0 时删除记录并返回 DelRec；成功后重置 ctr。
        """
        key = self._session_key(ssid)
        try:
            session = self._sessions.get(key)
            if not session or not session.ephemeral:
                return self._fail_rec(ssid, idc, "Fail")

            pt, c_dec = self.dhies.dec(session.ephemeral.sk, C)
            if pt is None:
                return self._fail_rec(ssid, idc, "Fail")

            ksym, pw_prime, id_prime, ssid_prime = unpack_encpw_rec_payload(pt)
            if idc != id_prime or ssid != ssid_prime:
                return self._fail_rec(ssid, idc, "Fail")

            record = self.storage.retrieve_encpw_plus(idc)
            if record is None:
                return self._fail_rec(ssid, idc, "Fail")  # 用户未注册

            # ctr 耗尽 → 删除记录，返回 DelRec（论文猜测次数限制）
            if record.ctr == 0:
                self.storage.delete_encpw(idc)
                return self._fail_rec(ssid, idc, "DelRec")

            record.ctr -= 1  # 每次 Rec 尝试递减计数器
            h_check, c_h = self.ro_h.eval(sid, record.s1, pw_prime)
            if h_check != record.h:
                # 密码错误：返回 Fail，ctr 已递减但不重置
                payload = encode_rec_res("Fail")
                msg, c_att = self.attest.attest(payload, ssid, idc)
                return msg, c_dec + c_h + c_att

            record.ctr = CTR_MAX  # 密码正确 → 重置 ctr
            mask, c_h2 = self.ro_h.eval(sid, record.s2, pw_prime)
            K_masked = self.aes.xor_mask(mask, record.c)  # K = c ⊕ H(s₂, pw)
            aes_ct, c_aes = self.aes.enc(ksym, K_masked)   # 以 ksym 加密 K 返回 C'
            payload = encode_rec_res("Succ", aes_ct.serialize())
            msg, c_att = self.attest.attest(payload, ssid, idc)
            total = c_dec + c_h + c_h2 + c_aes + c_att
            self.cost += total
            return msg, total
        finally:
            # Rec 完成 → 销毁临时 skEnc
            self._sessions.pop(key, None)

    # ─────────────────────────────────────────────────────────────────────────
    # π_OPRF-PPKR 协议 — Fig. 4 灰色方框
    # ─────────────────────────────────────────────────────────────────────────

    def oprf_init_oprf(
        self, ssid: SSID, idc: IDC, blinded: OPRFBlindedInput
    ) -> tuple[AttestedMessage, CostCounter]:
        """Fig. 4 Init（OPRF 段）：对盲化输入求值并生成 pkEnc。

        阶段: Init 第 1 轮（HSM 侧，对应 Client 的 ``init_blind``）

        输入:
            ssid:   本次 Init 会话标识。
            idc:    客户端身份标识。
            blinded: Client 盲化后的 OPRF 输入 a。

        输出:
            AttestedMessage: 载荷 ``{"type":"oprf_eval","b":...,"pkEnc":...}``。
            CostCounter:     OPRF 求值 + DHIES 密钥生成 + 签名开销。

        副作用: 创建 phase="oprf_init" 会话，保存 k_OPRF 与临时 pkEnc/skEnc。
        """
        k_oprf, _ = self.oprf.generate_key()
        evaluated, c_eval = self.oprf.server_evaluate(blinded, k_oprf)  # b = a^k_OPRF
        pk_enc, sk_enc, c_kg = self.dhies.keygen()
        # 创建 OPRF Init 会话：保存 k_OPRF 与 pkEnc/skEnc，待 InitFinish 持久化
        self._sessions[self._session_key(ssid)] = HSMSession(
            ssid=ssid,
            idc=idc,
            phase="oprf_init",
            ephemeral=EphemeralPKE(pk=pk_enc, sk=sk_enc),
            k_oprf=k_oprf,
        )
        payload = encode_oprf_eval(evaluated.serialize(), pk_enc.serialize())
        msg, c_att = self.attest.attest(payload, ssid, idc)
        total = c_eval + c_kg + c_att
        self.cost += total
        return msg, total

    def oprf_init_finish(
        self, ssid: SSID, idc: IDC, C: DHIESCiphertext
    ) -> tuple[AttestedMessage, CostCounter]:
        """Fig. 4 InitFinish：解密绑定密文并持久化 OPRF-PPKR 用户文件。

        阶段: Init 第 2–3 轮（HSM 侧，对应 Client 的 ``init_on_oprf_response`` → ``init_finish``）

        输入:
            ssid: 必须与 OPRF Init 阶段一致的会话标识。
            idc:  客户端身份标识。
            C:    Client 用 pkEnc 加密的 DHIES 密文，明文为 (SSID, pk_C, c_AE)。

        输出:
            AttestedMessage: 载荷 ``{"type":"InitRes","result":"Succ"|"Fail"}``。
            CostCounter:     解密 + 签名开销。

        副作用: 成功时写入 ``OPRFPPKRFile``；无论成败均在 finally 中清除会话。
        """
        from crypto.group import GROUP

        key = self._session_key(ssid)
        try:
            session = self._sessions.get(key)
            # OPRF Init 会话须含 skEnc 与 k_OPRF
            if not session or not session.ephemeral or not session.k_oprf:
                return self._fail_init(ssid, idc)

            pt, c_dec = self.dhies.dec(session.ephemeral.sk, C)
            if pt is None:
                return self._fail_init(ssid, idc)

            ssid_prime, pk_c_raw, c_ae = unpack_oprf_init_payload(pt)
            if ssid != ssid_prime:
                return self._fail_init(ssid, idc)  # SSID 绑定校验失败

            pk_c = SchnorrPublicKey(y=GROUP.deserialize_point(pk_c_raw))
            # 写入 Fig. 4 用户文件 ⟨File, IDC, pk_C, c, k_OPRF, ctr⟩
            self.storage.store_oprf_ppkr(
                OPRFPPKRFile(
                    idc=idc,
                    pk_c=pk_c,
                    c=c_ae,              # Client 用 ρ 加密的 AE 密文
                    k_oprf=session.k_oprf,
                    ctr=CTR_MAX,
                )
            )
            payload = encode_init_res("Succ")
            msg, c_att = self.attest.attest(payload, ssid, idc)
            total = c_dec + c_att
            self.cost += total
            return msg, total
        finally:
            # InitFinish 完成 → 销毁临时 skEnc 与内存中的 k_OPRF（已持久化）
            self._sessions.pop(key, None)

    def oprf_rec_evaluate(
        self, ssid: SSID, idc: IDC, blinded: OPRFBlindedInput
    ) -> tuple[AttestedMessage, CostCounter]:
        """Fig. 4 Rec（OPRF 段）：用存储的 k_OPRF 对盲化输入 a' 求值。

        阶段: Rec 第 1 轮（HSM 侧，对应 Client 的 ``rec_blind``）

        输入:
            ssid:    本次 Rec 会话标识。
            idc:     客户端身份标识。
            blinded: Client 盲化后的 OPRF 输入 a'。

        输出:
            AttestedMessage: 载荷 ``{"type":"oprf_rec_eval","b_prime":...,"c":...}``；
                记录不存在或 ctr=0 时返回 ``RecRes: Fail/DelRec``。
            CostCounter: OPRF 求值 + 签名开销。

        副作用: 递减 ctr；ctr=0 时删除 OPRF 记录。本阶段无会话状态依赖。
        """
        record = self.storage.retrieve_oprf_ppkr(idc)
        if record is None:
            return self._fail_rec(ssid, idc, "Fail")

        if record.ctr == 0:
            self.storage.delete_oprf(idc)
            return self._fail_rec(ssid, idc, "DelRec")

        record.ctr -= 1  # Rec 尝试递减计数器
        # 用存储的 k_OPRF 对盲化 a' 求值 → b'（Rec 阶段无 _sessions 依赖）
        evaluated, c_eval = self.oprf.server_evaluate(blinded, record.k_oprf)
        payload = encode_oprf_rec_eval(evaluated.serialize(), record.c.serialize())
        msg, c_att = self.attest.attest(payload, ssid, idc)
        total = c_eval + c_att
        self.cost += total
        return msg, total

    def oprf_rec_verify(
        self,
        ssid: SSID,
        idc: IDC,
        a_prime: bytes,
        b_prime: bytes,
        c_ser: bytes,
        sigma: bytes,
    ) -> tuple[AttestedMessage, CostCounter]:
        """Fig. 4 RecSign：验证 Client 对恢复消息的 Schnorr 签名。

        阶段: Rec 第 2–3 轮（HSM 侧，对应 Client 的 ``rec_sign`` → ``rec_finish``）

        输入:
            ssid:    本次 Rec 会话标识。
            idc:     客户端身份标识。
            a_prime: Client 盲化 OPRF 输入的序列化字节。
            b_prime: HSM OPRF 求值输出的序列化字节。
            c_ser:   存储的 AE 密文 c 的序列化字节。
            sigma:   Client 用 sk_C 对 (a', b', c, IDC, SSID) 的 Schnorr 签名。

        输出:
            AttestedMessage: 载荷 ``{"type":"RecRes","result":"Succ"|"Fail"}``。
            CostCounter:     Schnorr 验证 + 签名开销。

        副作用: 验证成功时将 ctr 重置为 CTR_MAX。
        """
        from crypto.aes_gcm import deserialize_aes
        from crypto.serialize import pack_rec_sign_message

        record = self.storage.retrieve_oprf_ppkr(idc)
        if record is None:
            return self._fail_rec(ssid, idc, "Fail")

        c_ae = deserialize_aes(c_ser)
        # 重构 RecSign 签名消息 m = (a', IDC, SSID, b', c)
        message = pack_rec_sign_message(a_prime, idc, ssid, b_prime, c_ae)
        sig = deserialize_schnorr_sig(sigma)
        ok, c_vfy = self.schnorr.verify(record.pk_c, message, sig)

        if ok:
            record.ctr = CTR_MAX  # 签名验证通过 → 重置猜测计数器
            result = "Succ"
        else:
            result = "Fail"  # σ 无效，ctr 已在 oprf_rec_evaluate 中递减

        payload = encode_rec_res(result)
        msg, c_att = self.attest.attest(payload, ssid, idc)
        total = c_vfy + c_att
        self.cost += total
        return msg, total

    # ─────────────────────────────────────────────────────────────────────────
    # 辅助接口与内部失败处理
    # ─────────────────────────────────────────────────────────────────────────

    def leak_files(self) -> list:
        """返回用户文件存储的快照副本（供安全实验/泄露模拟使用）。

        输出: 深拷贝的 ``EncPwPlusFile`` 与 ``OPRFPPKRFile`` 列表。
        """
        return self.storage.leak_all()

    def _fail_init(self, ssid: SSID, idc: IDC) -> tuple[AttestedMessage, CostCounter]:
        """构造 Init 失败响应（内部辅助，不暴露给 Server 直接调用）。"""
        payload = encode_init_res("Fail")
        msg, c_att = self.attest.attest(payload, ssid, idc)  # 失败响应同样需 ↪ x 签名
        return msg, c_att

    def _fail_rec(self, ssid: SSID, idc: IDC, result: str) -> tuple[AttestedMessage, CostCounter]:
        """构造 Rec 失败/删除响应（内部辅助，result 可为 Fail 或 DelRec）。"""
        payload = encode_rec_res(result)
        msg, c_att = self.attest.attest(payload, ssid, idc)
        return msg, c_att
