"""本地端到端 PPKR 仿真（无 HTTP）— 快速验证协议正确性。

与 HTTP 模式对比::

    run_local.py (本模块)
        Client + Server + HSM 同进程，直接调用 ``server.encpw_handle`` / ``oprf_handle``
        无网络延迟，适合 smoke test

    serve.py + run_client.py
        Client 经 HTTP 与 Server 通信，模拟分布式部署

在项目根目录运行::

    python run_local.py
"""

from __future__ import annotations

import path_setup  # noqa: F401  — 确保根目录在 sys.path

from config import IDC, SID
from protocols.encpw_plus import EncPwPlusClient
from protocols.oprf_ppkr import OPRFPPKRClient
from server.ppkr_server import PPKRServer
from common.attested_wire import attested_raw


def run_encpw_plus(pw: str = "correcthorse", idc: str = "alice") -> bytes:
    """完整执行 π_encPw+ Init + Rec（各 2 次 Fig.1 交互 + 本地 finish）。

    Returns:
        Rec 阶段恢复的密钥 bytes

    Raises:
        RuntimeError: Init 或 Rec 失败
    """
    # 同进程构造 Server 与 Client，HSM 逻辑内嵌于 PPKRServer
    sid = SID("server-1")
    server = PPKRServer(sid=sid)
    client = EncPwPlusClient(sid=sid, idc=IDC(idc), hsm_pk=server.hsm_attestation_pk)

    # ── Init（2 轮交互；init_finish 本地无网络）──
    ssid = client.new_ssid()
    r1 = server.encpw_handle(client.init_start(ssid))
    msg2, K, _ = client.init_on_pk(attested_raw(r1), ssid, pw)
    r3 = server.encpw_handle(msg2)
    result, _ = client.init_finish(attested_raw(r3), ssid, K)
    if result == "Fail":
        raise RuntimeError("Init failed")

    # ── Rec（2 轮交互 + 本地 finish）──
    # 用同一密码恢复 K；ssid 必须新建，避免与 Init 会话混淆
    ssid2 = client.new_ssid()
    r1 = server.encpw_handle(client.rec_start(ssid2))
    msg2, ksym, _ = client.rec_on_pk(attested_raw(r1), ssid2, pw)
    r3 = server.encpw_handle(msg2)
    K_rec, _ = client.rec_finish(attested_raw(r3), ssid2, ksym)
    if isinstance(K_rec, str):
        raise RuntimeError(f"Rec failed: {K_rec}")
    return K_rec


def run_oprf_ppkr(pw: str = "correcthorse", idc: str = "bob") -> bytes:
    """完整执行 π_OPRF-PPKR Init + Rec（各 2 次 Fig.1 交互 + 本地 finish）。

    Returns:
        Rec 阶段最终密钥 bytes

    Raises:
        RuntimeError: Init 或 Rec 任一步失败
    """
    sid = SID("server-1")
    server = PPKRServer(sid=sid)
    client = OPRFPPKRClient(sid=sid, idc=IDC(idc), hsm_pk=server.hsm_attestation_pk)

    # ── Init：2 轮交互（OPRF + InitFinish）+ 本地 init_finish ──
    ssid = client.new_ssid()
    msg1, state, K, _ = client.init_blind(ssid, pw)
    r1 = server.oprf_handle(msg1)
    msg2, K, _ = client.init_on_oprf_response(attested_raw(r1), ssid, state, K)
    r2 = server.oprf_handle(msg2)
    result, _ = client.init_finish(attested_raw(r2), ssid, K)
    if result == "Fail":
        raise RuntimeError("OPRF Init failed")

    # ── Rec：2 轮交互（OPRF + RecSign）+ 本地 rec_finish ──
    ssid2 = client.new_ssid()
    msg1, state, _ = client.rec_blind(ssid2, pw)
    r1 = server.oprf_handle(msg1)
    from common.payload_codec import decode_payload
    from hsm.attest import AttestedMessage

    att = AttestedMessage.deserialize(attested_raw(r1))
    payload = decode_payload(att.payload)
    K_rec, sk_c, a_prime, b_prime, _ = client.rec_on_oprf_response(
        attested_raw(r1), ssid2, state
    )
    if K_rec is None:
        raise RuntimeError("OPRF Rec decrypt failed")
    msg2, _ = client.rec_sign(ssid2, a_prime, b_prime, payload["c"], sk_c)
    r2 = server.oprf_handle(msg2)
    final, _ = client.rec_finish(attested_raw(r2), ssid2, K_rec)
    if isinstance(final, str):
        raise RuntimeError(f"OPRF Rec failed: {final}")
    return final


if __name__ == "__main__":
    # 日常主测 π_OPRF-PPKR；顺带冒烟 encPw+
    K3 = run_oprf_ppkr()
    print("OPRF-PPKR OK, key length:", len(K3))

    K1 = run_encpw_plus()
    print("encPw+ OK, key length:", len(K1))
