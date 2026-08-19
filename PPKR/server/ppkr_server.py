"""PPKR 服务器中继层 — Client 与 HSM 之间的消息转发。

Server 不持有密码学秘密，仅根据 phase 路由至 HSM。
线格式：PBCS/PAEE 风格二进制（opcode + u16 LV raw）；body 字段为 bytes。
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from common.attested_wire import wrap_attested
from config import IDC, SID, SSID
from crypto.dhies import DHIESCiphertext
from crypto.oprf_2hashdh import OPRFBlindedInput
from crypto.group import GROUP
from hsm.hsm_core import HSMCore
from protocols.messages import ProtocolMessage


def _body_bytes(body: dict, key: str) -> bytes:
    v = body[key]
    return v if isinstance(v, bytes) else bytes(v)


@dataclass
class PPKRServer:
    """PPKR 服务器 (S)：在 Client 与 HSM 之间透明转发协议消息。"""

    sid: SID
    hsm: HSMCore = field(default_factory=HSMCore)

    def new_ssid(self) -> SSID:
        return SSID(str(uuid.uuid4()))

    @property
    def hsm_attestation_pk(self):
        return self.hsm.attestation_public_key

    def encpw_handle(self, msg: ProtocolMessage) -> dict:
        """处理 π_encPw+ 各阶段，返回扁平 attested 字段。"""
        ssid, idc = msg.ssid, msg.idc
        if msg.phase == "InitS":
            attested, _ = self.hsm.encpw_get_pk(ssid, idc)
            return wrap_attested(attested)
        if msg.phase == "Init":
            C = DHIESCiphertext(raw=_body_bytes(msg.body, "C"))
            attested, _ = self.hsm.encpw_init(self.sid, ssid, idc, C)
            return wrap_attested(attested)
        if msg.phase == "RecS":
            attested, _ = self.hsm.encpw_rec_get_pk(ssid, idc)
            return wrap_attested(attested)
        if msg.phase == "Rec":
            C = DHIESCiphertext(raw=_body_bytes(msg.body, "C"))
            attested, _ = self.hsm.encpw_rec(self.sid, ssid, idc, C)
            return wrap_attested(attested)
        raise ValueError(f"unknown encPw+ phase: {msg.phase}")

    def oprf_handle(self, msg: ProtocolMessage) -> dict:
        """处理 π_OPRF-PPKR 各阶段，返回扁平 attested 字段。"""
        ssid, idc = msg.ssid, msg.idc
        if msg.phase == "Init":
            blinded = OPRFBlindedInput(a=GROUP.deserialize_point(_body_bytes(msg.body, "a")))
            attested, _ = self.hsm.oprf_init_oprf(ssid, idc, blinded)
            return wrap_attested(attested)
        if msg.phase == "InitFinish":
            C = DHIESCiphertext(raw=_body_bytes(msg.body, "C"))
            attested, _ = self.hsm.oprf_init_finish(ssid, idc, C)
            return wrap_attested(attested)
        if msg.phase == "Rec":
            blinded = OPRFBlindedInput(
                a=GROUP.deserialize_point(_body_bytes(msg.body, "a_prime"))
            )
            attested, _ = self.hsm.oprf_rec_evaluate(ssid, idc, blinded)
            return wrap_attested(attested)
        if msg.phase == "RecSign":
            attested, _ = self.hsm.oprf_rec_verify(
                ssid,
                idc,
                _body_bytes(msg.body, "a_prime") if msg.body.get("a_prime") else b"",
                _body_bytes(msg.body, "b_prime") if msg.body.get("b_prime") else b"",
                _body_bytes(msg.body, "c"),
                _body_bytes(msg.body, "sigma"),
            )
            return wrap_attested(attested)
        raise ValueError(f"unknown OPRF-PPKR phase: {msg.phase}")

    def leak_hsm_files(self) -> list:
        return self.hsm.leak_files()
