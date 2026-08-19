# -*- coding: utf-8 -*-
"""
experiment/file_size_proto_bench_tau_ct2.py
==========================================
【文件大小实验·副本】与 file_size_proto_bench 相同，仅改一处：

  τ := H4(ct, k2, ct2)   # 绑定明文 m 的 AES-CTR 密文 ct2

默认实验仍为 τ = H4(ct, k2)（不含 ct2）。
ct2 仅本地保存，不上云；Take 验签时须提供同一 ct2。

用法::
  python -m experiment.file_size_proto_bench_tau_ct2 --trials 3 --auto-server
  python -m experiment.file_size_proto_bench_tau_ct2 --trials 3 --host <IP> --port 20202 --real-s3
  python -m experiment.file_size_proto_bench_tau_ct2 --trials 1 --sizes 1 --auto-server
"""

from __future__ import annotations

from typing import List, Optional

from experiment.file_size_proto_bench import main as _main


def main(argv: Optional[List[str]] = None) -> int:
    return _main(
        argv,
        tau_bind_ct2=True,
        out_stem="file_size_proto_tau_ct2_benchmark",
        id_prefix_base="fsize_ct2",
        description=(
            "E2SE file-size proto bench (τ=H4(ct,k2,ct2); ct2 local only)"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
