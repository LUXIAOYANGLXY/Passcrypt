# -*- coding: utf-8 -*-
"""
experiment/tcp_benchmark.py
===========================
【实验一】协议阶段延迟与通信量（口令长度 16；**不对明文加密**）。

口径：真实 TCP；**不传 π**；密钥封装 ct1=AES-256-GCM；空明文 m=∅（无文件 AE）。
  τ=H5(kMAC,(ct0,ct1,ct2))，ct2 为空文件密文；ENC_COMMIT 不上传 ct2。
  **真实往返 = Fig.1 论文箭头**：
    Reg=2，Ext=1，Enc_proto=Ext(1)+COMMIT(1)=2，Dec_proto=Ext(1)+DEC(1)=2
  pk/ctx 线上传输但报告通信量剔除。

用法::
    python -m experiment.tcp_benchmark --trials 20 --host 35.78.207.231 --port 5202
    python -m experiment.tcp_benchmark --trials 20 --auto-server
"""

from __future__ import annotations

import argparse
import csv
import logging
import os
import secrets
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from experiment.tcp_benchmark_lib import (  # noqa: E402
    check_server,
    mean_std,
    start_auto_server,
    write_xlsx_summary,
)

log = logging.getLogger("paee.bench")
DISPLAY = "PAEE (Fig.1)"  # 报告/Excel 中的方案显示名
DEFAULT_PASSWORD_LEN = 16
# 实验一默认不对明文加密（空 m）；文件加解密见实验三/四
DEFAULT_PLAINTEXT_MB = 0.0



def _make_password(length: int) -> str:
    return "a" * length


def _gen_plaintext(size_mb: float) -> bytes:
    n = int(size_mb * 1024 * 1024)
    if n <= 0:
        return b""
    chunk = 8 * 1024 * 1024
    parts: List[bytes] = []
    left = n
    while left > 0:
        k = min(chunk, left)
        parts.append(os.urandom(k))
        left -= k
    return b"".join(parts)


def run_trials(
    n: int,
    *,
    host: str,
    port: int,
    password: str,
    id_prefix: str,
    lambda_bytes: int,
    plaintext: bytes,
) -> List[Dict[str, Any]]:
    """
    跑 n 次独立 trial。
    每次：长连接 → Reg → Enc → Dec；建连在各阶段计时外。
    报告通信量不含 pk/ctx。
    """
    from net.client_api import PAEEClientSession
    from net.client_metrics import (
        decrypt_compare_metrics,
        encrypt_compare_metrics,
        register_metrics,
    )
    from paee.params import Setup

    pp = Setup(lambda_bytes)
    rows: List[Dict[str, Any]] = []

    for i in range(1, n + 1):
        uid = f"{id_prefix}_{i}"
        log.info("---------- protocol trial %d/%d id=%s ----------", i, n, uid)
        sess = PAEEClientSession(host, port, pp)
        try:
            sess.connect()
            _pk, reg_m = register_metrics(
                host, port, pp, uid, password, session=sess
            )
            enc = encrypt_compare_metrics(
                host,
                port,
                pp,
                _pk,
                uid,
                password,
                plaintext=plaintext,
                session=sess,
            )
            dec = decrypt_compare_metrics(
                host,
                port,
                pp,
                _pk,
                uid,
                password,
                local_ct2=enc["ct"].ct2,
                session=sess,
            )
            assert dec["plaintext"] == plaintext
            # 实验一报告协议口径（剔除文件 AE）；空 m 时与 full 几乎相同
            ep, dp = enc["enc_proto"], dec["dec_proto"]
            rows.append(
                {
                    "display": DISPLAY,
                    "trial_id": i,
                    "id": uid,
                    "success": True,
                    "reg_latency_ms": reg_m["latency_ms"],
                    "reg_comm_bytes": reg_m["comm_bytes"],
                    "ext_latency_ms": enc["ext"]["latency_ms"],
                    "ext_comm_bytes": enc["ext"]["comm_bytes"],
                    "enc_proto_latency_ms": ep["latency_ms"],
                    "enc_proto_comm_bytes": ep["comm_bytes"],
                    "dec_proto_latency_ms": dp["latency_ms"],
                    "dec_proto_comm_bytes": dp["comm_bytes"],
                    "error": "",
                }
            )
            log.info(
                "OK reg=%.1fms enc_proto=%.1fms/%dB dec_proto=%.1fms/%dB |pt|=%d",
                reg_m["latency_ms"],
                ep["latency_ms"],
                ep["comm_bytes"],
                dp["latency_ms"],
                dp["comm_bytes"],
                len(plaintext),
            )
        except Exception as e:  # noqa: BLE001
            log.error("trial %d fail: %s", i, e)
            rows.append(
                {
                    "display": DISPLAY,
                    "trial_id": i,
                    "id": uid,
                    "success": False,
                    "reg_latency_ms": 0.0,
                    "reg_comm_bytes": 0,
                    "ext_latency_ms": 0.0,
                    "ext_comm_bytes": 0,
                    "enc_proto_latency_ms": 0.0,
                    "enc_proto_comm_bytes": 0,
                    "dec_proto_latency_ms": 0.0,
                    "dec_proto_comm_bytes": 0,
                    "error": str(e),
                }
            )
        finally:
            sess.close()
    return rows


def aggregate(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    """对成功 trial 按阶段求 mean±std。"""
    ok = [r for r in rows if r["success"]]

    def pack(key: str) -> Tuple[float, float]:
        return mean_std([float(r[key]) for r in ok])

    phases = {}
    for name, lat_k, comm_k, rounds in [
        ("Reg(一次性)", "reg_latency_ms", "reg_comm_bytes", 2),
        ("Ext", "ext_latency_ms", "ext_comm_bytes", 1),
        ("Enc_proto≈Init", "enc_proto_latency_ms", "enc_proto_comm_bytes", 2),
        ("Dec_proto≈Rec", "dec_proto_latency_ms", "dec_proto_comm_bytes", 2),
    ]:
        lm, ls = pack(lat_k)
        cm, cs = pack(comm_k)
        phases[name] = {
            "rounds": rounds,
            "latency_mean_ms": lm,
            "latency_std_ms": ls,
            "comm_mean_bytes": cm,
            "comm_std_bytes": cs,
        }
    return {
        "display": DISPLAY,
        "n_trials": len(rows),
        "n_success": len(ok),
        "success_rate": (len(ok) / len(rows)) if rows else 0.0,
        "phases": phases,
    }


def write_outputs(
    agg: Dict[str, Any],
    raw: List[Dict[str, Any]],
    out_dir: Path,
    *,
    endpoint: str,
    timestamp: str,
    password_len: int = DEFAULT_PASSWORD_LEN,
    plaintext_mb: float = DEFAULT_PLAINTEXT_MB,
) -> None:
    """写 md / csv / xlsx 三份结果到 out_dir。"""
    out_dir.mkdir(parents=True, exist_ok=True)
    no_pt = plaintext_mb <= 0
    note = (
        "【实验一】长连接；建连不计时；**不传π**；二进制线协议；"
        "**真实往返=论文箭头**；**pk/ctx线上传输但不计入通信量**；"
        f"口令长度={password_len}；"
        + (
            "**不对明文加密**（m=∅，无文件 AE）；"
            if no_pt
            else f"明文={plaintext_mb}MB；"
        )
        + "密钥封装 ct1=**AES-256-GCM**；"
        "报告 Enc_proto/Dec_proto（协议侧，不含大文件 SE）；"
        "τ=H5(kMAC,(ct0,ct1,ct2))；ENC_COMMIT不上传ct2；"
        "Enc_proto=Ext+Wrap(GCM)+H5+COMMIT；"
        "Dec_proto=Ext+取材料+验τ（至 dek）；"
        "Reg仅一次性参考。"
    )
    # Markdown 摘要表
    md = out_dir / "tcp_network_benchmark.md"
    lines = [
        "# PAEE TCP 基准（对标 Init/Rec）",
        "",
        f"生成时间: {timestamp}",
        f"trials={agg['n_trials']} success={agg['n_success']} ({agg['success_rate']*100:.1f}%)",
        f"Server: `{endpoint}`",
        "",
        note,
        "",
        "| 阶段 | 轮数 | 延迟 mean±std (ms) | 通信量 mean±std (B) |",
        "|------|------|--------------------|---------------------|",
    ]
    for phase, p in agg["phases"].items():
        lines.append(
            f"| {phase} | {p['rounds']} | "
            f"{p['latency_mean_ms']:.2f} ± {p['latency_std_ms']:.2f} | "
            f"{p['comm_mean_bytes']:.1f} ± {p['comm_std_bytes']:.1f} |"
        )
    md.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # 原始 CSV
    csv_path = out_dir / "tcp_network_benchmark.csv"
    if raw:
        with csv_path.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(raw[0].keys()))
            w.writeheader()
            w.writerows(raw)

    # Excel：汇总行 + 原始明细
    phase_rows = []
    for phase, p in agg["phases"].items():
        phase_rows.append(
            [
                agg["display"],
                phase,
                agg["n_trials"],
                agg["n_success"],
                round(agg["success_rate"] * 100, 1),
                p["rounds"],
                round(p["latency_mean_ms"], 3),
                round(p["latency_std_ms"], 3),
                round(p["comm_mean_bytes"], 1),
                round(p["comm_std_bytes"], 1),
                endpoint,
                note,
                timestamp,
            ]
        )
    write_xlsx_summary(
        out_dir / "tcp_network_benchmark.xlsx",
        phase_rows,
        raw,
        raw_headers=[
            "方案",
            "trial_id",
            "id",
            "success",
            "Reg延迟(ms)",
            "Ext延迟(ms)",
            "Enc_proto延迟(ms)",
            "Dec_proto延迟(ms)",
            "Reg通信(B)",
            "Ext通信(B)",
            "Enc_proto通信(B)",
            "Dec_proto通信(B)",
            "error",
        ],
        raw_map=lambda r: [
            r["display"],
            r["trial_id"],
            r["id"],
            r["success"],
            round(r["reg_latency_ms"], 3),
            round(r["ext_latency_ms"], 3),
            round(r["enc_proto_latency_ms"], 3),
            round(r["dec_proto_latency_ms"], 3),
            r["reg_comm_bytes"],
            r["ext_comm_bytes"],
            r["enc_proto_comm_bytes"],
            r["dec_proto_comm_bytes"],
            r["error"],
        ],
    )
    log.info("wrote outputs under %s", out_dir)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="PAEE TCP protocol benchmark")
    parser.add_argument("--trials", type=int, default=20)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5202)
    parser.add_argument("--auto-server", action="store_true", help="线程内自动起 Server")
    parser.add_argument(
        "--password-len",
        type=int,
        default=DEFAULT_PASSWORD_LEN,
        help=f"口令长度（默认 {DEFAULT_PASSWORD_LEN}，用字符 a 填充）",
    )
    parser.add_argument(
        "--password",
        default=None,
        help="显式口令（若设置则忽略 --password-len）",
    )
    parser.add_argument(
        "--plaintext-mb",
        type=float,
        default=DEFAULT_PLAINTEXT_MB,
        help=(
            f"明文大小 MB（默认 {DEFAULT_PLAINTEXT_MB}=不对明文加密；"
            "实验一应用 0；大文件见实验三）"
        ),
    )
    parser.add_argument("--id-prefix", default="tcp_paee")
    parser.add_argument("--out-dir", default=str(ROOT / "experiment" / "output"))
    parser.add_argument("-q", "--quiet", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.WARNING if args.quiet else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    from main import load_config

    cfg = load_config()
    lambda_bytes = int(cfg["crypto"]["lambda_bytes"])
    password = args.password if args.password is not None else _make_password(
        args.password_len
    )
    run_tag = datetime.now().strftime("%Y%m%d%H%M%S") + secrets.token_hex(2)
    id_prefix = f"{args.id_prefix}_{run_tag}"
    log.info(
        "password_len=%d plaintext_mb=%s id_prefix=%s",
        len(password.encode("utf-8")),
        args.plaintext_mb,
        id_prefix,
    )
    plaintext = _gen_plaintext(args.plaintext_mb)

    stop = None
    host, port = args.host, args.port
    if args.auto_server:
        host, port, stop = start_auto_server(ROOT / "data" / "bench_server")
    else:
        check_server(host, port)

    try:
        raw = run_trials(
            args.trials,
            host=host,
            port=port,
            password=password,
            id_prefix=id_prefix,
            lambda_bytes=lambda_bytes,
            plaintext=plaintext,
        )
    finally:
        if stop is not None:
            stop.set()

    agg = aggregate(raw)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    write_outputs(
        agg,
        raw,
        Path(args.out_dir),
        endpoint=f"{host}:{port}",
        timestamp=ts,
        password_len=len(password.encode("utf-8")),
        plaintext_mb=args.plaintext_mb,
    )

    print(f"\n=== {DISPLAY} protocol (vs Init/Rec) ===")
    print(
        f"  password_len={len(password.encode('utf-8'))}  "
        f"plaintext={args.plaintext_mb} MB"
    )
    for phase, p in agg["phases"].items():
        print(
            f"  {phase:18s}  {p['latency_mean_ms']:8.2f}±{p['latency_std_ms']:6.2f} ms  "
            f"{p['comm_mean_bytes']:8.1f}±{p['comm_std_bytes']:6.1f} B"
        )
    return 0 if agg["n_success"] == agg["n_trials"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
