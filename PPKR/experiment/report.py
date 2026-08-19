"""聚合 trial 结果并生成论文对比表格（CSV / Markdown / LaTeX）。

输入：``AggregateMetrics`` 列表 + ``ProtocolRunner`` 元信息
输出目录默认 ``experiment/output/``：
    comparison_table.csv   — 汇总表
    comparison_table.md    — 含论文 Table 3 参考值
    comparison_table.tex   — LaTeX 表格片段
    raw_trials.csv         — 每轮 trial 原始延迟数据
"""

from __future__ import annotations

import csv
import statistics
from datetime import datetime
from pathlib import Path

from config import CostCounter
from experiment.metrics import AggregateMetrics, TrialMetrics
from experiment.runners import ProtocolRunner


def _mean_std(values: list[float]) -> tuple[float, float]:
    """计算均值与标准差；空列表或单元素时返回合理默认值。"""
    if not values:
        return 0.0, 0.0
    if len(values) == 1:
        return values[0], 0.0
    return statistics.mean(values), statistics.stdev(values)


def _avg_cost(costs: list[CostCounter]) -> CostCounter:
    """对多个 CostCounter 取算术平均（四舍五入为整数）。"""
    if not costs:
        return CostCounter()
    n = len(costs)
    return CostCounter(
        exp=round(sum(c.exp for c in costs) / n),
        mult=round(sum(c.mult for c in costs) / n),
        hash=round(sum(c.hash for c in costs) / n),
        aes=round(sum(c.aes for c in costs) / n),
        sig=round(sum(c.sig for c in costs) / n),
    )


def aggregate_trials(protocol: str, trials: list[TrialMetrics]) -> AggregateMetrics:
    """将同一协议的多次 trial 聚合为 ``AggregateMetrics``。"""
    init_ok = [t.init.success for t in trials]
    rec_ok = [t.rec.success for t in trials]
    full_ok = [t.full_success for t in trials]
    key_ok = [t.key_match for t in trials]

    init_lat = [t.init.latency_ms for t in trials]
    rec_lat = [t.rec.latency_ms for t in trials if t.init.success]
    total_lat = [t.total_latency_ms for t in trials if t.full_success]

    init_lat_m, init_lat_s = _mean_std(init_lat)
    rec_lat_m, rec_lat_s = _mean_std(rec_lat)
    total_lat_m, total_lat_s = _mean_std(total_lat)

    successful = [t for t in trials if t.init.success]
    return AggregateMetrics(
        protocol=protocol,
        n_trials=len(trials),
        init_success_rate=sum(init_ok) / len(trials),
        rec_success_rate=sum(rec_ok) / max(len([t for t in trials if t.init.success]), 1),
        full_success_rate=sum(full_ok) / len(trials),
        key_match_rate=sum(key_ok) / len(trials),
        init_latency_mean_ms=init_lat_m,
        init_latency_std_ms=init_lat_s,
        rec_latency_mean_ms=rec_lat_m,
        rec_latency_std_ms=rec_lat_s,
        total_latency_mean_ms=total_lat_m,
        total_latency_std_ms=total_lat_s,
        init_rounds=trials[0].init.rounds if trials else 0,
        rec_rounds=trials[0].rec.rounds if trials else 0,
        client_init_cost=_avg_cost([t.init.client_cost for t in successful]),
        client_rec_cost=_avg_cost([t.rec.client_cost for t in successful if t.rec.success]),
        hsm_init_cost=_avg_cost([t.init.hsm_cost for t in successful]),
        hsm_rec_cost=_avg_cost([t.rec.hsm_cost for t in successful if t.rec.success]),
        comm_init_bytes_mean=statistics.mean([t.init.comm_bytes for t in successful]) if successful else 0,
        comm_rec_bytes_mean=statistics.mean(
            [t.rec.comm_bytes for t in successful if t.rec.success]
        )
        if any(t.rec.success for t in successful)
        else 0,
    )


def _cost_str(c: CostCounter) -> str:
    """将 CostCounter 格式化为人类可读字符串（仅非零项）。"""
    parts = []
    if c.exp:
        parts.append(f"{c.exp} Exp")
    if c.mult:
        parts.append(f"{c.mult} Mult")
    if c.hash:
        parts.append(f"{c.hash} Hash")
    if c.aes:
        parts.append(f"{c.aes} AES")
    if c.sig:
        parts.append(f"{c.sig} Sig")
    return ", ".join(parts) if parts else "0"


def _fmt_ms(mean: float, std: float) -> str:
    """延迟 mean ± std 格式化。"""
    return f"{mean:.2f} ± {std:.2f}"


def _pct(rate: float) -> str:
    """比率转百分比字符串。"""
    return f"{rate * 100:.1f}%"


class ReportGenerator:
    """实验报告生成器：写入多种格式的对比表格。"""

    def __init__(self, output_dir: Path) -> None:
        """指定输出目录（不存在则自动创建）。"""
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def write_all(
        self,
        aggregates: list[AggregateMetrics],
        runners: dict[str, ProtocolRunner],
        wrong_pw_results: dict[str, float],
        meta: dict,
    ) -> dict[str, Path]:
        """生成全部报告文件，返回 {格式名: 路径} 字典。"""
        paths = {}
        paths["csv"] = self._write_csv(aggregates, runners)
        paths["markdown"] = self._write_markdown(aggregates, runners, wrong_pw_results, meta)
        paths["latex"] = self._write_latex(aggregates, runners, wrong_pw_results, meta)
        paths["raw_csv"] = self._write_raw_trials(meta.get("all_trials", []))
        return paths

    def _write_csv(self, aggregates: list[AggregateMetrics], runners: dict[str, ProtocolRunner]) -> Path:
        """写入汇总 CSV（comparison_table.csv）。"""
        path = self.output_dir / "comparison_table.csv"
        headers = [
            "Protocol",
            "Security Level",
            "Init Rounds",
            "Rec Rounds",
            "Init Latency (ms)",
            "Rec Latency (ms)",
            "Total Latency (ms)",
            "Init Success Rate",
            "Rec Success Rate",
            "Full Success Rate",
            "Key Match Rate",
            "Client Init Cost",
            "Client Rec Cost",
            "HSM Init Cost",
            "HSM Rec Cost",
            "Comm Init (bytes)",
            "Comm Rec (bytes)",
        ]
        with path.open("w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(headers)
            for agg in aggregates:
                r = runners[agg.protocol]
                w.writerow(
                    [
                        r.display_name,
                        r.security_level,
                        agg.init_rounds,
                        agg.rec_rounds,
                        _fmt_ms(agg.init_latency_mean_ms, agg.init_latency_std_ms),
                        _fmt_ms(agg.rec_latency_mean_ms, agg.rec_latency_std_ms),
                        _fmt_ms(agg.total_latency_mean_ms, agg.total_latency_std_ms),
                        _pct(agg.init_success_rate),
                        _pct(agg.rec_success_rate),
                        _pct(agg.full_success_rate),
                        _pct(agg.key_match_rate),
                        _cost_str(agg.client_init_cost),
                        _cost_str(agg.client_rec_cost),
                        _cost_str(agg.hsm_init_cost),
                        _cost_str(agg.hsm_rec_cost),
                        f"{agg.comm_init_bytes_mean:.0f}",
                        f"{agg.comm_rec_bytes_mean:.0f}",
                    ]
                )
        return path

    def _write_raw_trials(self, trials: list[TrialMetrics]) -> Path:
        """写入每轮 trial 原始数据（raw_trials.csv）。"""
        path = self.output_dir / "raw_trials.csv"
        headers = [
            "protocol",
            "trial_id",
            "idc",
            "init_success",
            "rec_success",
            "key_match",
            "init_latency_ms",
            "rec_latency_ms",
            "total_latency_ms",
            "init_comm_bytes",
            "rec_comm_bytes",
        ]
        with path.open("w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(headers)
            for t in trials:
                w.writerow(
                    [
                        t.protocol,
                        t.trial_id,
                        t.idc,
                        t.init.success,
                        t.rec.success,
                        t.key_match,
                        f"{t.init.latency_ms:.3f}",
                        f"{t.rec.latency_ms:.3f}",
                        f"{t.total_latency_ms:.3f}",
                        t.init.comm_bytes,
                        t.rec.comm_bytes,
                    ]
                )
        return path

    def _write_markdown(
        self,
        aggregates: list[AggregateMetrics],
        runners: dict[str, ProtocolRunner],
        wrong_pw_results: dict[str, float],
        meta: dict,
    ) -> Path:
        """写入 Markdown 报告（含论文 Table 3 参考值与说明）。"""
        path = self.output_dir / "comparison_table.md"
        lines = [
            "# PPKR 对比实验结果",
            "",
            f"生成时间: {meta.get('timestamp', '')}",
            f"试验次数: {meta.get('trials_per_protocol', '')} / 协议",
            f"密码: `{meta.get('password', '')}`",
            "",
            "## 表1：性能与成功率对比（统一指标）",
            "",
            "| 方案 | 安全级别 | Init轮数 | Rec轮数 | Init延迟(ms) | Rec延迟(ms) | 总延迟(ms) | Init成功率 | Rec成功率 | 密钥一致性 |",
            "|------|----------|----------|---------|--------------|-------------|------------|------------|-----------|------------|",
        ]
        for agg in aggregates:
            r = runners[agg.protocol]
            lines.append(
                f"| {r.display_name} | {r.security_level} | {agg.init_rounds} | {agg.rec_rounds} | "
                f"{_fmt_ms(agg.init_latency_mean_ms, agg.init_latency_std_ms)} | "
                f"{_fmt_ms(agg.rec_latency_mean_ms, agg.rec_latency_std_ms)} | "
                f"{_fmt_ms(agg.total_latency_mean_ms, agg.total_latency_std_ms)} | "
                f"{_pct(agg.init_success_rate)} | {_pct(agg.rec_success_rate)} | "
                f"{_pct(agg.key_match_rate)} |"
            )

        lines += [
            "",
            "## 表2：密码学操作开销（对齐论文 Table 3 风格）",
            "",
            "| 方案 | 阶段 | 角色 | Exp | Mult | Hash | AES |",
            "|------|------|------|-----|------|------|-----|",
        ]
        for agg in aggregates:
            r = runners[agg.protocol]
            for phase, role, cost in [
                ("Init", "Client", agg.client_init_cost),
                ("Init", "HSM", agg.hsm_init_cost),
                ("Rec", "Client", agg.client_rec_cost),
                ("Rec", "HSM", agg.hsm_rec_cost),
            ]:
                lines.append(
                    f"| {r.display_name} | {phase} | {role} | "
                    f"{cost.exp} | {cost.mult} | {cost.hash} | {cost.aes} |"
                )

        lines += [
            "",
            "## 表3：各阶段通信量与运行时间（多次试验取平均）",
            "",
            "| 方案 | 阶段 | 延迟 mean±std (ms) | 通信量 mean (bytes) | 轮数 |",
            "|------|------|--------------------|---------------------|------|",
        ]
        for agg in aggregates:
            r = runners[agg.protocol]
            lines.append(
                f"| {r.display_name} | Init | "
                f"{_fmt_ms(agg.init_latency_mean_ms, agg.init_latency_std_ms)} | "
                f"{agg.comm_init_bytes_mean:.0f} | {agg.init_rounds} |"
            )
            lines.append(
                f"| {r.display_name} | Rec | "
                f"{_fmt_ms(agg.rec_latency_mean_ms, agg.rec_latency_std_ms)} | "
                f"{agg.comm_rec_bytes_mean:.0f} | {agg.rec_rounds} |"
            )
            lines.append(
                f"| {r.display_name} | Total | "
                f"{_fmt_ms(agg.total_latency_mean_ms, agg.total_latency_std_ms)} | "
                f"{agg.comm_init_bytes_mean + agg.comm_rec_bytes_mean:.0f} | "
                f"{agg.init_rounds + agg.rec_rounds} |"
            )

        lines += [
            "",
            "## 表4：错误密码拒绝率",
            "",
            "| 方案 | 错误密码拒绝率 |",
            "|------|----------------|",
        ]
        for agg in aggregates:
            r = runners[agg.protocol]
            reject = wrong_pw_results.get(agg.protocol, 0.0)
            lines.append(f"| {r.display_name} | {_pct(reject)} |")

        lines += [
            "",
            "## 论文 Table 3 参考值（Faller et al. CCS 2024）",
            "",
            "| 方案 | Init Client | Init HSM | Rec Client | Rec HSM | Init轮 | Rec轮 |",
            "|------|-------------|----------|------------|---------|-------|-------|",
            "| π_encPw+ | 2Exp,3Hash,1AES | 2Exp,5Hash,1AES | 2Exp,3Hash,2AES | 2Exp,5Hash,2AES | 3 | 3 |",
            "| π_OPRF-PPKR | 5Exp,5Hash,2AES | 2Exp,3Hash,1AES | 3Exp,3Hash,1AES | 2Exp,1Hash,1Mult | 3 | 3 |",
            "",
            "## 说明",
            "",
            "- **阶段**：Init（初始化）、Rec（恢复）；各阶段延迟与通信量分别统计后对试验次数取平均。",
            "- **延迟**：含 Client↔Server TCP 往返（须先启动 `serve.py`，`--host`/`--port` 或 `--url` 指定 Server）。",
            "- **通信量**：该阶段全部 TCP wire 字节之和（含 4 字节长度头）。",
            "- **轮数**：对齐 PAEE Fig.1——一次 Client↔Server 交互算 1 轮（不含 HELLO；"
            "不含本地 `*_finish`）。Init/Rec 各 2。",
            "- **操作开销**：TCP 模式下 Client 侧 CostCounter；HSM 侧在网络路径不可见故记 0。",
            "  完整逻辑开销审计见开发用进程内 runners（非论文延迟主结果）。",
            "- **接入自有方案**：在 `experiment/runners.py` 继承 `ProtocolRunner` 并注册到 `RUNNERS`。",
        ]

        path.write_text("\n".join(lines), encoding="utf-8")
        return path

    def _write_latex(
        self,
        aggregates: list[AggregateMetrics],
        runners: dict[str, ProtocolRunner],
        wrong_pw_results: dict[str, float],
        meta: dict,
    ) -> Path:
        """写入 LaTeX 表格片段（comparison_table.tex）。"""
        path = self.output_dir / "comparison_table.tex"
        lines = [
            "% PPKR comparison experiment — paste into thesis",
            f"% Generated: {meta.get('timestamp', '')}",
            "",
            r"\begin{table}[htbp]",
            r"\centering",
            r"\caption{PPKR方案性能与成功率对比实验}",
            r"\label{tab:ppkr-comparison}",
            r"\begin{tabular}{lccccccc}",
            r"\toprule",
            r"方案 & 级别 & $R_{\text{init}}$ & $R_{\text{rec}}$ "
            r"& $T_{\text{init}}$(ms) & $T_{\text{rec}}$(ms) & 成功率 & 密钥一致 \\",
            r"\midrule",
        ]
        for agg in aggregates:
            r = runners[agg.protocol]
            lines.append(
                f"{r.display_name} & {r.security_level} & {agg.init_rounds} & {agg.rec_rounds} & "
                f"{agg.init_latency_mean_ms:.1f}$\\pm${agg.init_latency_std_ms:.1f} & "
                f"{agg.rec_latency_mean_ms:.1f}$\\pm${agg.rec_latency_std_ms:.1f} & "
                f"{agg.full_success_rate * 100:.1f}\\% & {agg.key_match_rate * 100:.1f}\\% \\\\"
            )
        lines += [
            r"\bottomrule",
            r"\end{tabular}",
            r"\end{table}",
            "",
            r"\begin{table}[htbp]",
            r"\centering",
            r"\caption{密码学操作开销对比（平均单次试验）}",
            r"\label{tab:ppkr-cost}",
            r"\begin{tabular}{llcccc}",
            r"\toprule",
            r"方案 & 阶段/角色 & Exp & Mult & Hash & AES \\",
            r"\midrule",
        ]
        for agg in aggregates:
            r = runners[agg.protocol]
            rows = [
                ("Init/Client", agg.client_init_cost),
                ("Init/HSM", agg.hsm_init_cost),
                ("Rec/Client", agg.client_rec_cost),
                ("Rec/HSM", agg.hsm_rec_cost),
            ]
            for i, (label, cost) in enumerate(rows):
                prefix = r.display_name if i == 0 else ""
                lines.append(
                    f"{prefix} & {label} & {cost.exp} & {cost.mult} & {cost.hash} & {cost.aes} \\\\"
                )
            lines.append(r"\midrule")
        lines[-1] = r"\bottomrule"
        lines += [r"\end{tabular}", r"\end{table}"]
        path.write_text("\n".join(lines), encoding="utf-8")
        return path
