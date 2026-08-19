#!/usr/bin/env python3
"""Start Server (HSM in-process). WBP-inspired baseline."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.app import main

if __name__ == "__main__":
    main()
