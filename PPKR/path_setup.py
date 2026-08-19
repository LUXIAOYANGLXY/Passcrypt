"""将项目根目录加入 ``sys.path``，供各入口脚本在 import 前调用。

典型用法::

    import path_setup  # noqa: F401  — 副作用：插入 ROOT 到 sys.path

HTTP 入口（``serve.py`` / ``run_client.py``）与本地入口（``run_local.py``）
均依赖此模块，确保 ``from config import ...`` 等根级 import 可用。
"""

from __future__ import annotations

import sys
from pathlib import Path

# 项目根目录（本文件所在目录）
ROOT = Path(__file__).resolve().parent

# insert(0, ...) 使 ROOT 优先于 cwd 被搜索，保证 ``from config import`` 等根级包可用
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
