# -*- coding: utf-8 -*-
"""
experiment/file_size_crypto_bench_tau_no_ct2.py
===============================================
【实验四·副本】与实验四相同，仅改一处：

  τ := H5(kMAC, (ct0, ct1))   # 不含 ct2

其余不变：无网络；不传/不算 π；口令 16；文件大小扫描。

用法::
    python -m experiment.file_size_crypto_bench_tau_no_ct2 --trials 5
"""

from __future__ import annotations

from typing import List, Optional

from experiment.file_size_crypto_bench import main as _main


def main(argv: Optional[List[str]] = None) -> int:
    return _main(
        argv,
        tau_bind_ct2=False,
        out_stem="file_size_crypto_tau_no_ct2_benchmark",
        id_prefix_base="cryptof_nct2",
        description=(
            "PAEE file-size crypto bench (τ=H5(kMAC,(ct0,ct1)), no ct2 in τ)"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
