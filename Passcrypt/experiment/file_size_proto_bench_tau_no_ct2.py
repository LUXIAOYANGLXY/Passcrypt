# -*- coding: utf-8 -*-
"""
experiment/file_size_proto_bench_tau_no_ct2.py
=============================================
【实验三·副本】与实验三相同，仅改一处：

  τ := H5(kMAC, (ct0, ct1))   # 不含 ct2

其余不变：不传 π；ct2 本地不上云；口令 16；文件大小扫描；含 TCP。

用法::
    python -m experiment.file_size_proto_bench_tau_no_ct2 --trials 3 --host <IP> --port 5202
"""

from __future__ import annotations

from typing import List, Optional

from experiment.file_size_proto_bench import main as _main


def main(argv: Optional[List[str]] = None) -> int:
    return _main(
        argv,
        tau_bind_ct2=False,
        out_stem="file_size_proto_tau_no_ct2_benchmark",
        id_prefix_base="fsize_nct2",
        description=(
            "PAEE file-size proto bench (τ=H5(kMAC,(ct0,ct1)), no ct2 in τ)"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
