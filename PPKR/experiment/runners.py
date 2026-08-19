"""带计量的协议 Runner — 实验框架核心执行层。

与 ``run_local.py`` / TCP 客户端不同，Runner 在**单进程内**直接调用
``PPKRServer`` 与协议 Client，无网络开销，仅用于功能/CostCounter 对照（非论文延迟主结果）。

架构::

    ProtocolRunner (抽象基类)
        ├── EncPwPlusRunner   — π_encPw+ (Lev-2)
        └── OPRFPPKRRunner    — π_OPRF-PPKR (Lev-3)

每次 ``run_init`` / ``run_rec``：
    1. 重置 ``server.hsm.cost = CostCounter()``
    2. 逐步驱动 Client ↔ Server 消息交换
    3. 累计 client_cost、hsm_cost、comm_bytes、latency_ms
    4. 返回 ``PhaseMetrics``

扩展新方案：继承 ``ProtocolRunner``，实现 ``run_init`` / ``run_rec``，
并注册到 ``RUNNERS`` 字典。
"""

from __future__ import annotations

import json
import time
from abc import ABC, abstractmethod

from config import CostCounter, IDC, SID
from experiment.metrics import PhaseMetrics, TrialMetrics
from hsm.attest import AttestedMessage
from protocols.encpw_plus import EncPwPlusClient
from protocols.oprf_ppkr import OPRFPPKRClient
from server.ppkr_server import PPKRServer
from common.attested_wire import attested_raw

# 轮数对齐 PAEE Fig.1：一次 Client↔Server 交互算 1（不含 HELLO；不含本地 *_finish）
INIT_ROUNDS = {"encpw_plus": 2, "oprf_ppkr": 2}
REC_ROUNDS = {"encpw_plus": 2, "oprf_ppkr": 2}


def _msg_bytes(msg) -> int:
    """统计 Client 发出消息的近似字节（进程内对照用）。"""
    n = 0
    for v in (msg.body or {}).values():
        if isinstance(v, bytes):
            n += len(v)
        elif isinstance(v, str):
            n += len(v.encode())
    return n + 64  # phase/sid/ssid/idc 粗估


def _attested_bytes(data: dict) -> int:
    """统计 Server 返回 attested 响应的字节长度。"""
    return len(attested_raw(data))


class ProtocolRunner(ABC):
    """协议 Runner 抽象基类；子类实现具体方案的 Init/Rec 驱动逻辑。"""

    name: str
    display_name: str
    security_level: str

    @abstractmethod
    def run_init(self, pw: str, idc: str) -> tuple[PhaseMetrics, bytes | None]:
        """执行 Init 阶段，返回 phase 指标与存储密钥 K（成功时）。"""

    @abstractmethod
    def run_rec(self, pw: str, idc: str) -> tuple[PhaseMetrics, bytes | None]:
        """执行 Rec 阶段；需同 idc 下先前 Init 已成功。"""

    def run_trial(self, trial_id: int, pw: str, idc: str) -> TrialMetrics:
        """完整单次试验：Init → Rec，并校验密钥一致性。"""
        init_m, K = self.run_init(pw, idc)
        if not init_m.success:
            empty = PhaseMetrics(phase="Rec", success=False, rounds=REC_ROUNDS[self.name], latency_ms=0.0)
            return TrialMetrics(
                protocol=self.name,
                trial_id=trial_id,
                password=pw,
                idc=idc,
                init=init_m,
                rec=empty,
                key_match=False,
            )
        rec_m, K_rec = self.run_rec(pw, idc)
        key_match = K_rec is not None and K is not None and K_rec == K
        return TrialMetrics(
            protocol=self.name,
            trial_id=trial_id,
            password=pw,
            idc=idc,
            init=init_m,
            rec=rec_m,
            key_match=key_match,
        )


class EncPwPlusRunner(ProtocolRunner):
    """π_encPw+ (Lev-2) 进程内 Runner。"""

    name = "encpw_plus"
    display_name = "π_encPw+ (Lev-2)"
    security_level = "Lev-2"

    def __init__(self) -> None:
        self.sid = SID("server-1")
        self._server: PPKRServer | None = None
        self._client: EncPwPlusClient | None = None
        self._K: bytes | None = None

    def _setup(self, idc: str) -> None:
        """为给定 idc 创建新的 Server + Client 实例。"""
        self._server = PPKRServer(sid=self.sid)
        self._client = EncPwPlusClient(
            sid=self.sid, idc=IDC(idc), hsm_pk=self._server.hsm_attestation_pk
        )

    def run_init(self, pw: str, idc: str) -> tuple[PhaseMetrics, bytes | None]:
        """驱动 encPw+ Init 三阶段（InitS → Init → finish）。"""
        self._setup(idc)
        assert self._server and self._client
        server, client = self._server, self._client
        server.hsm.cost = CostCounter()

        t0 = time.perf_counter()
        c_cost = CostCounter()
        comm = 0
        try:
            ssid = client.new_ssid()
            m0 = client.init_start(ssid)
            comm += _msg_bytes(m0)
            r1 = server.encpw_handle(m0)
            comm += _attested_bytes(r1)

            m1, K, c1 = client.init_on_pk(attested_raw(r1), ssid, pw)
            comm += _msg_bytes(m1)
            c_cost += c1

            r2 = server.encpw_handle(m1)
            comm += _attested_bytes(r2)

            result, c2 = client.init_finish(attested_raw(r2), ssid, K)
            c_cost += c2
            elapsed = (time.perf_counter() - t0) * 1000

            ok = result != "Fail"
            self._K = K if ok else None
            return (
                PhaseMetrics(
                    phase="Init",
                    success=ok,
                    rounds=INIT_ROUNDS[self.name],
                    latency_ms=elapsed,
                    client_cost=c_cost,
                    hsm_cost=server.hsm.cost,
                    comm_bytes=comm,
                ),
                self._K,
            )
        except Exception as e:
            elapsed = (time.perf_counter() - t0) * 1000
            return (
                PhaseMetrics(
                    phase="Init",
                    success=False,
                    rounds=INIT_ROUNDS[self.name],
                    latency_ms=elapsed,
                    client_cost=c_cost,
                    hsm_cost=server.hsm.cost,
                    comm_bytes=comm,
                    error=str(e),
                ),
                None,
            )

    def run_rec(self, pw: str, idc: str) -> tuple[PhaseMetrics, bytes | None]:
        """驱动 encPw+ Rec 三阶段（RecS → Rec → finish）。"""
        assert self._server and self._client
        server, client = self._server, self._client
        server.hsm.cost = CostCounter()

        t0 = time.perf_counter()
        c_cost = CostCounter()
        comm = 0
        try:
            ssid = client.new_ssid()
            m0 = client.rec_start(ssid)
            comm += _msg_bytes(m0)
            r1 = server.encpw_handle(m0)
            comm += _attested_bytes(r1)

            m1, ksym, c1 = client.rec_on_pk(attested_raw(r1), ssid, pw)
            comm += _msg_bytes(m1)
            c_cost += c1

            r2 = server.encpw_handle(m1)
            comm += _attested_bytes(r2)

            result, c2 = client.rec_finish(attested_raw(r2), ssid, ksym)
            c_cost += c2
            elapsed = (time.perf_counter() - t0) * 1000

            ok = isinstance(result, bytes)
            return (
                PhaseMetrics(
                    phase="Rec",
                    success=ok,
                    rounds=REC_ROUNDS[self.name],
                    latency_ms=elapsed,
                    client_cost=c_cost,
                    hsm_cost=server.hsm.cost,
                    comm_bytes=comm,
                ),
                result if ok else None,
            )
        except Exception as e:
            elapsed = (time.perf_counter() - t0) * 1000
            return (
                PhaseMetrics(
                    phase="Rec",
                    success=False,
                    rounds=REC_ROUNDS[self.name],
                    latency_ms=elapsed,
                    client_cost=c_cost,
                    hsm_cost=server.hsm.cost,
                    comm_bytes=comm,
                    error=str(e),
                ),
                None,
            )


class OPRFPPKRRunner(ProtocolRunner):
    """π_OPRF-PPKR (Lev-3) 进程内 Runner。"""

    name = "oprf_ppkr"
    display_name = "π_OPRF-PPKR (Lev-3)"
    security_level = "Lev-3"

    def __init__(self) -> None:
        self.sid = SID("server-1")
        self._server: PPKRServer | None = None
        self._client: OPRFPPKRClient | None = None

    def _setup(self, idc: str) -> None:
        """为给定 idc 创建新的 Server + Client 实例。"""
        self._server = PPKRServer(sid=self.sid)
        self._client = OPRFPPKRClient(
            sid=self.sid, idc=IDC(idc), hsm_pk=self._server.hsm_attestation_pk
        )

    def run_init(self, pw: str, idc: str) -> tuple[PhaseMetrics, bytes | None]:
        """驱动 OPRF Init（盲化 → InitFinish → finish）。"""
        self._setup(idc)
        assert self._server and self._client
        server, client = self._server, self._client
        server.hsm.cost = CostCounter()

        t0 = time.perf_counter()
        c_cost = CostCounter()
        comm = 0
        try:
            ssid = client.new_ssid()
            m0, state, K, c0 = client.init_blind(ssid, pw)
            comm += _msg_bytes(m0)
            c_cost += c0

            r1 = server.oprf_handle(m0)
            comm += _attested_bytes(r1)

            m1, K, c1 = client.init_on_oprf_response(
                attested_raw(r1), ssid, state, K
            )
            comm += _msg_bytes(m1)
            c_cost += c1

            r2 = server.oprf_handle(m1)
            comm += _attested_bytes(r2)

            result, c2 = client.init_finish(attested_raw(r2), ssid, K)
            c_cost += c2
            elapsed = (time.perf_counter() - t0) * 1000

            ok = result != "Fail"
            return (
                PhaseMetrics(
                    phase="Init",
                    success=ok,
                    rounds=INIT_ROUNDS[self.name],
                    latency_ms=elapsed,
                    client_cost=c_cost,
                    hsm_cost=server.hsm.cost,
                    comm_bytes=comm,
                ),
                K if ok else None,
            )
        except Exception as e:
            elapsed = (time.perf_counter() - t0) * 1000
            return (
                PhaseMetrics(
                    phase="Init",
                    success=False,
                    rounds=INIT_ROUNDS[self.name],
                    latency_ms=elapsed,
                    client_cost=c_cost,
                    hsm_cost=server.hsm.cost,
                    comm_bytes=comm,
                    error=str(e),
                ),
                None,
            )

    def run_rec(self, pw: str, idc: str) -> tuple[PhaseMetrics, bytes | None]:
        """驱动 OPRF Rec（盲化求值 → RecSign → finish）。"""
        assert self._server and self._client
        server, client = self._server, self._client
        server.hsm.cost = CostCounter()

        t0 = time.perf_counter()
        c_cost = CostCounter()
        comm = 0
        try:
            ssid = client.new_ssid()
            m0, state, c0 = client.rec_blind(ssid, pw)
            comm += _msg_bytes(m0)
            c_cost += c0

            r1 = server.oprf_handle(m0)
            comm += _attested_bytes(r1)

            K_rec, sk_c, a_prime, b_prime, c1 = client.rec_on_oprf_response(
                attested_raw(r1), ssid, state
            )
            c_cost += c1
            if K_rec is None:
                raise RuntimeError("AE decrypt failed")

            att = AttestedMessage.deserialize(attested_raw(r1))
            from common.payload_codec import decode_payload

            payload = decode_payload(att.payload)
            m1, c2 = client.rec_sign(
                ssid, a_prime, b_prime, payload["c"], sk_c
            )
            # a_prime / b_prime 已在 rec_sign body 中
            comm += _msg_bytes(m1)
            c_cost += c2

            r2 = server.oprf_handle(m1)
            comm += _attested_bytes(r2)

            final, c3 = client.rec_finish(attested_raw(r2), ssid, K_rec)
            c_cost += c3
            elapsed = (time.perf_counter() - t0) * 1000

            ok = isinstance(final, bytes)
            return (
                PhaseMetrics(
                    phase="Rec",
                    success=ok,
                    rounds=REC_ROUNDS[self.name],
                    latency_ms=elapsed,
                    client_cost=c_cost,
                    hsm_cost=server.hsm.cost,
                    comm_bytes=comm,
                ),
                final if ok else None,
            )
        except Exception as e:
            elapsed = (time.perf_counter() - t0) * 1000
            return (
                PhaseMetrics(
                    phase="Rec",
                    success=False,
                    rounds=REC_ROUNDS[self.name],
                    latency_ms=elapsed,
                    client_cost=c_cost,
                    hsm_cost=server.hsm.cost,
                    comm_bytes=comm,
                    error=str(e),
                ),
                None,
            )


# 协议名 → Runner 类 注册表（compare.py 通过 get_runner 查找）
RUNNERS: dict[str, type[ProtocolRunner]] = {
    "encpw_plus": EncPwPlusRunner,
    "oprf_ppkr": OPRFPPKRRunner,
    # 在此注册你自己的方案，例如:
    # "my_scheme": MySchemeRunner,
}


def get_runner(name: str) -> ProtocolRunner:
    """按协议名实例化对应 Runner。"""
    if name not in RUNNERS:
        raise KeyError(f"Unknown protocol: {name}. Available: {list(RUNNERS)}")
    return RUNNERS[name]()
