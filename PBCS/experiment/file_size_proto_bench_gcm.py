# -*- coding: utf-8 -*-
"""
experiment/file_size_proto_bench_gcm.py
=======================================
【文件大小实验·明文 AES-GCM 对照】与 file_size_proto_bench 相同，仅改：

  明文 m 用 AES-256-GCM 加密（nonce(12)‖ct‖tag(16)）
  默认实验仍为 AES-CTR。

用法::
  python -m experiment.file_size_proto_bench_gcm --trials 3 --auto-server
  python -m experiment.file_size_proto_bench_gcm --trials 3 --host <IP> --port 20202 --real-s3
  python -m experiment.file_size_proto_bench_gcm --trials 1 --sizes 1 --auto-server
"""

from __future__ import annotations

from typing import List, Optional

from experiment.file_size_proto_bench import main as _main


def main(argv: Optional[List[str]] = None) -> int:
    return _main(
        argv,
        file_cipher="gcm",
        out_stem="file_size_proto_gcm_benchmark",
        id_prefix_base="fsize_gcm",
        description="E2SE file-size proto bench (plaintext AES-256-GCM)",
    )


if __name__ == "__main__":
    raise SystemExit(main())
