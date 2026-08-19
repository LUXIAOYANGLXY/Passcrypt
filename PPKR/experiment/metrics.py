"""实验指标数据类型 — 单次 phase、完整 trial、聚合统计。

实验框架数据流::

    ProtocolRunner.run_trial()
        → PhaseMetrics (Init) + PhaseMetrics (Rec)
        → TrialMetrics
        → aggregate_trials() → AggregateMetrics
        → ReportGenerator 输出 CSV / Markdown / LaTeX

各指标含义：
    latency_ms  — wall-clock（``time.perf_counter()``）
    client_cost / hsm_cost — 逻辑操作计数（``CostCounter``）
    comm_bytes  — 该 phase 累计消息字节数（Client 发出 + Server 响应）
"""

from __future__ import annotations

from dataclasses import dataclass, field

from config import CostCounter


@dataclass
class PhaseMetrics:
    """单阶段（Init 或 Rec）的测量结果。"""

    phase: str
    success: bool
    rounds: int
    latency_ms: float
    client_cost: CostCounter = field(default_factory=CostCounter)
    hsm_cost: CostCounter = field(default_factory=CostCounter)
    comm_bytes: int = 0
    error: str | None = None


@dataclass
class TrialMetrics:
    """一次完整试验：Init + Rec + 密钥一致性校验。"""

    protocol: str
    trial_id: int
    password: str
    idc: str
    init: PhaseMetrics
    rec: PhaseMetrics
    key_match: bool = False

    @property
    def total_latency_ms(self) -> float:
        """Init 与 Rec 延迟之和（毫秒）。"""
        return self.init.latency_ms + self.rec.latency_ms

    @property
    def full_success(self) -> bool:
        """Init、Rec 均成功且 Init/Rec 派生密钥一致。"""
        return self.init.success and self.rec.success and self.key_match


@dataclass
class AggregateMetrics:
    """多轮 trial 聚合后的统计摘要（供报告与 cost audit 使用）。"""

    protocol: str
    n_trials: int
    init_success_rate: float
    rec_success_rate: float
    full_success_rate: float
    key_match_rate: float
    init_latency_mean_ms: float
    init_latency_std_ms: float
    rec_latency_mean_ms: float
    rec_latency_std_ms: float
    total_latency_mean_ms: float
    total_latency_std_ms: float
    init_rounds: int
    rec_rounds: int
    client_init_cost: CostCounter
    client_rec_cost: CostCounter
    hsm_init_cost: CostCounter
    hsm_rec_cost: CostCounter
    comm_init_bytes_mean: float
    comm_rec_bytes_mean: float
