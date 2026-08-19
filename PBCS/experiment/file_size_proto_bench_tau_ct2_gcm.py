# -*- coding: utf-8 -*-
"""
experiment/file_size_proto_bench_tau_ct2_gcm.py
==============================================
τ 绑定 ct2 + 明文 AES-GCM：

  τ := H4(ct, k2, ct2)，ct2 ← AES-256-GCM(m)

用法::
  python -m experiment.file_size_proto_bench_tau_ct2_gcm --trials 3 --auto-server
"""

from __future__ import annotations

from typing import List, Optional

from experiment.file_size_proto_bench import main as _main


def main(argv: Optional[List[str]] = None) -> int:
    return _main(
        argv,
        tau_bind_ct2=True,
        file_cipher="gcm",
        out_stem="file_size_proto_tau_ct2_gcm_benchmark",
        id_prefix_base="fsize_ct2_gcm",
        description=(
            "E2SE file-size (τ=H4(ct,k2,ct2); plaintext AES-256-GCM)"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
