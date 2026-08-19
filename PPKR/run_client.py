"""PPKR TCP 客户端 — 连接 ``server/tcp_server.py``，支持重复试验。

TCP 实验流程::

    终端1: python serve.py
    终端2: python run_client.py --password mypass --idc bob

默认协议为 **π_OPRF-PPKR**（日常主测）；Lev-2 用 ``--protocol encpw_plus``。
默认端点 ``127.0.0.1:8765``（与 WBPv1 一致）；亦可用 ``--url host:port``。
"""

from __future__ import annotations

import argparse
import statistics
import sys
import time

import path_setup  # noqa: F401

from client.ppkr_http_client import EncPwPlusHttpSession, OPRFPPKRHttpSession
from common.endpoint import DEFAULT_HOST, DEFAULT_PORT, resolve_endpoint
from config import CostCounter, format_cost_latency
from logging_config import setup_logger

log = setup_logger("CLIENT")


def _make_session(protocol: str, idc: str, password: str, host: str, port: int):
    """按协议名构造对应的 TCP 会话对象。"""
    if protocol == "encpw_plus":
        return EncPwPlusHttpSession(idc=idc, password=password, host=host, port=port)
    return OPRFPPKRHttpSession(idc=idc, password=password, host=host, port=port)


def run_single(protocol: str, idc: str, password: str, host: str, port: int, phase: str) -> dict:
    """执行单次试验（init / rec / full 阶段之一），返回结果字典。"""
    session = _make_session(protocol, idc, password, host, port)
    try:
        session.client.cost = CostCounter()
        t0 = time.perf_counter()
        if phase == "init":
            K = session.run_init()
            real_ms = (time.perf_counter() - t0) * 1000
            return {
                "success": True,
                "key_match": True,
                "latency_ms": real_ms,
                "cost": session.client.cost,
                "K": K,
            }
        if phase == "rec":
            K = session.run_rec()
            real_ms = (time.perf_counter() - t0) * 1000
            return {
                "success": True,
                "key_match": True,
                "latency_ms": real_ms,
                "cost": session.client.cost,
                "K": K,
            }
        K_init, K_rec = session.run_full()
        real_ms = (time.perf_counter() - t0) * 1000
        match = K_init == K_rec
        return {
            "success": match,
            "key_match": match,
            "latency_ms": real_ms,
            "cost": session.client.cost,
            "K_init": K_init,
            "K_rec": K_rec,
        }
    finally:
        session.close()


def run_trials(protocol: str, idc: str, password: str, host: str, port: int, trials: int, phase: str) -> None:
    """重复执行 n 次 trial，汇总成功率、延迟统计与平均操作计数。"""
    log.info(
        "开始重复试验 trials=%d protocol=%s phase=%s %s:%d",
        trials,
        protocol,
        phase,
        host,
        port,
    )
    results: list[dict] = []

    for i in range(1, trials + 1):
        trial_idc = f"{idc}_{i}" if trials > 1 else idc
        log.info("---------- 第 %d/%d 次 trial idc=%s ----------", i, trials, trial_idc)
        try:
            r = run_single(protocol, trial_idc, password, host, port, phase)
            results.append(r)
            log.info(
                "第 %d 次成功 %s 密钥一致=%s",
                i,
                format_cost_latency(r.get("cost", CostCounter()), r["latency_ms"]),
                r.get("key_match", True),
            )
        except RuntimeError as e:
            log.error("第 %d 次失败: %s", i, e)
            results.append({"success": False, "key_match": False, "latency_ms": 0.0, "cost": CostCounter()})

    ok = [r for r in results if r["success"]]
    latencies = [r["latency_ms"] for r in ok]
    success_rate = len(ok) / trials
    log.info("========== 试验汇总 ==========")
    log.info("总次数: %d  成功: %d  成功率: %.1f%%", trials, len(ok), success_rate * 100)
    if latencies:
        log.info(
            "延迟(ms): mean=%.2f  std=%.2f  min=%.2f  max=%.2f",
            statistics.mean(latencies),
            statistics.stdev(latencies) if len(latencies) > 1 else 0.0,
            min(latencies),
            max(latencies),
        )
        avg_cost = CostCounter()
        for r in ok:
            c = r.get("cost", CostCounter())
            avg_cost = avg_cost + c
        if ok:
            n = len(ok)
            avg_cost = CostCounter(
                exp=round(avg_cost.exp / n),
                mult=round(avg_cost.mult / n),
                hash=round(avg_cost.hash / n),
                aes=round(avg_cost.aes / n),
                sig=round(avg_cost.sig / n),
            )
            log.info(
                "操作计数(均值): exp=%d hash=%d sig=%d mult=%d aes=%d",
                avg_cost.exp,
                avg_cost.hash,
                avg_cost.sig,
                avg_cost.mult,
                avg_cost.aes,
            )
    if success_rate < 1.0:
        sys.exit(1)


def main() -> None:
    """解析 CLI 参数，执行单次或多次 TCP 客户端试验。"""
    parser = argparse.ArgumentParser(description="PPKR TCP 客户端")
    parser.add_argument("--protocol", choices=["encpw_plus", "oprf_ppkr"], default="oprf_ppkr")
    parser.add_argument("--password", "-p", default="demo_password")
    parser.add_argument("--idc", default="bob")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--url", default=None, help="兼容写法，如 127.0.0.1:8765 或 http://host:port")
    parser.add_argument("--phase", choices=["full", "init", "rec"], default="full")
    parser.add_argument("--trials", "-n", type=int, default=1, help="重复执行次数（默认1，实验用30）")
    args = parser.parse_args()

    host, port = resolve_endpoint(host=args.host, port=args.port, url=args.url)
    log.info(
        "连接 %s:%d  protocol=%s  idc=%s  phase=%s  trials=%d",
        host,
        port,
        args.protocol,
        args.idc,
        args.phase,
        args.trials,
    )

    if args.trials > 1:
        run_trials(args.protocol, args.idc, args.password, host, port, args.trials, args.phase)
        return

    try:
        r = run_single(args.protocol, args.idc, args.password, host, port, args.phase)
        if args.phase == "full":
            log.info("密钥一致: %s", r["key_match"])
            if not r["key_match"]:
                sys.exit(1)
        elif args.phase == "init":
            log.info("Init K = %s", r["K"].hex())
        else:
            log.info("Rec K = %s", r["K"].hex())
    except RuntimeError as e:
        log.error("错误: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
