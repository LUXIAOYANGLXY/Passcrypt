"""PPKR 对比实验（仅 TCP 网络测量）→ MD/CSV/LaTeX/Excel 同源指标。

必须先启动 Server。测量 Init/Rec 延迟与通信量（含 TCP 往返）。

用法::

    python serve.py --port 8765
    python -m experiment.compare --host 127.0.0.1 --port 8765 --trials 20
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from client.ppkr_http_client import EncPwPlusHttpSession, OPRFPPKRHttpSession
from common.endpoint import DEFAULT_HOST, DEFAULT_PORT, check_server as tcp_check, resolve_endpoint
from config import CostCounter
from experiment.metrics import PhaseMetrics, TrialMetrics
from experiment.report import ReportGenerator, aggregate_trials
from experiment.runners import INIT_ROUNDS, REC_ROUNDS, RUNNERS, ProtocolRunner, get_runner
from logging_config import setup_logger

log = setup_logger("COMPARE-TCP")


def check_server(host: str, port: int) -> None:
    """实验前确认 TCP Server 可达。"""
    tcp_check(host, port)


def _session(protocol: str, idc: str, password: str, host: str, port: int):
    """构造 TCP 会话；compare 仅走网络路径，不调用进程内 Runner。"""
    if protocol == "encpw_plus":
        return EncPwPlusHttpSession(idc=idc, password=password, host=host, port=port)
    return OPRFPPKRHttpSession(idc=idc, password=password, host=host, port=port)


def run_tcp_trial(
    protocol: str, trial_id: int, password: str, idc: str, host: str, port: int
) -> TrialMetrics:
    """单次含 TCP 网络的 Init+Rec trial。"""
    session = _session(protocol, idc, password, host, port)
    session.client.cost = CostCounter()

    try:
        K, init_m = session.run_init_metrics()
        init_cost = session.client.cost
        session.client.cost = CostCounter()
        K_rec, rec_m = session.run_rec_metrics()
        rec_cost = session.client.cost
        key_match = K == K_rec
        init_phase = PhaseMetrics(
            phase="Init",
            success=True,
            rounds=INIT_ROUNDS[protocol],
            latency_ms=init_m["latency_ms"],
            client_cost=init_cost,
            hsm_cost=CostCounter(),
            comm_bytes=init_m["comm_bytes"],
        )
        rec_phase = PhaseMetrics(
            phase="Rec",
            success=True,
            rounds=REC_ROUNDS[protocol],
            latency_ms=rec_m["latency_ms"],
            client_cost=rec_cost,
            hsm_cost=CostCounter(),
            comm_bytes=rec_m["comm_bytes"],
        )
        return TrialMetrics(
            protocol=protocol,
            trial_id=trial_id,
            password=password,
            idc=idc,
            init=init_phase,
            rec=rec_phase,
            key_match=key_match,
        )
    except Exception as e:
        log.error("trial 失败 idc=%s: %s", idc, e)
        empty = PhaseMetrics(
            phase="Init",
            success=False,
            rounds=INIT_ROUNDS[protocol],
            latency_ms=0.0,
            error=str(e),
        )
        empty_rec = PhaseMetrics(
            phase="Rec",
            success=False,
            rounds=REC_ROUNDS[protocol],
            latency_ms=0.0,
            error=str(e),
        )
        return TrialMetrics(
            protocol=protocol,
            trial_id=trial_id,
            password=password,
            idc=idc,
            init=empty,
            rec=empty_rec,
            key_match=False,
        )
    finally:
        session.close()


def run_correct_password_trials(
    protocol: str, n: int, password: str, idc_prefix: str, host: str, port: int
) -> list[TrialMetrics]:
    """对正确密码跑 n 次 TCP trial，每次使用独立 idc。"""
    trials = []
    for i in range(n):
        t = run_tcp_trial(protocol, i + 1, password, f"{idc_prefix}_{i}", host, port)
        trials.append(t)
    return trials


def run_wrong_password_rejection(
    protocol: str, password: str, idc: str, host: str, port: int
) -> float:
    """错密拒绝率：Init 用正确密码，Rec 前篡改 password，期望 Rec 失败。"""
    session = _session(protocol, idc, password, host, port)
    try:
        session.run_init()
        session.password = "wrong_password_!!!"
        try:
            session.run_rec()
            return 0.0
        except RuntimeError:
            return 1.0
    except Exception:
        return 0.0
    finally:
        session.close()


def print_summary(aggregates, runners, wrong_pw, paths, endpoint: str):
    print("\n" + "=" * 72)
    print("  PPKR 对比实验（仅 TCP 网络）")
    print(f"  Server: {endpoint}")
    print("=" * 72)
    for agg in aggregates:
        r = runners[agg.protocol]
        print(f"\n【{r.display_name}】 n={agg.n_trials}")
        print(f"  轮数: Init={agg.init_rounds}, Rec={agg.rec_rounds}")
        print(
            f"  Init 延迟: {agg.init_latency_mean_ms:.2f} ± {agg.init_latency_std_ms:.2f} ms"
            f"  通信: {agg.comm_init_bytes_mean:.0f} B"
        )
        print(
            f"  Rec  延迟: {agg.rec_latency_mean_ms:.2f} ± {agg.rec_latency_std_ms:.2f} ms"
            f"  通信: {agg.comm_rec_bytes_mean:.0f} B"
        )
        print(
            f"  成功率: 完整={agg.full_success_rate*100:.1f}%  "
            f"密钥一致={agg.key_match_rate*100:.1f}%  "
            f"错密拒绝={wrong_pw[agg.protocol]*100:.1f}%"
        )
    print("\n" + "-" * 72)
    for k, p in paths.items():
        print(f"  {k}: {p}")
    print("=" * 72 + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="PPKR TCP 对比实验（仅含网络）")
    parser.add_argument("--trials", type=int, default=20)
    parser.add_argument("--password", type=str, default="benchmark_pw_2024")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--url", default=None, help="兼容写法 host:port 或 http://host:port")
    parser.add_argument(
        "--protocols",
        nargs="+",
        default=["oprf_ppkr"],
        help="默认仅测 π_OPRF-PPKR（日常主测）；全面对比时: --protocols oprf_ppkr encpw_plus",
        choices=list(RUNNERS.keys()),
    )
    parser.add_argument("--output", type=str, default=str(ROOT / "experiment" / "output"))
    args = parser.parse_args()

    host, port = resolve_endpoint(host=args.host, port=args.port, url=args.url)
    check_server(host, port)
    endpoint = f"{host}:{port}"
    log.info("仅测量含 TCP 的数据 %s trials=%d", endpoint, args.trials)

    output_dir = Path(args.output)
    all_trials: list[TrialMetrics] = []
    aggregates = []
    runners_map: dict[str, ProtocolRunner] = {}
    wrong_pw: dict[str, float] = {}

    print(f"TCP comparison: {args.trials} trials × {len(args.protocols)} @ {endpoint}")

    for name in args.protocols:
        runners_map[name] = get_runner(name)
        trials = run_correct_password_trials(
            name, args.trials, args.password, idc_prefix=f"tcp_{name}", host=host, port=port
        )
        all_trials.extend(trials)
        aggregates.append(aggregate_trials(name, trials))
        wrong_pw[name] = run_wrong_password_rejection(
            name, args.password, f"tcp_{name}_reject", host, port
        )

    meta = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "trials_per_protocol": args.trials,
        "password": args.password,
        "all_trials": all_trials,
        "url": endpoint,
        "network": True,
    }

    reporter = ReportGenerator(output_dir)
    paths = reporter.write_all(aggregates, runners_map, wrong_pw, meta)
    print_summary(aggregates, runners_map, wrong_pw, paths, endpoint)


if __name__ == "__main__":
    main()
