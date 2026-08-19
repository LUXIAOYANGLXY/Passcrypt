"""Server 端请求与会话耗时统计。

配合 ``server/tcp_server.py``（及遗留 ``server/app.py``）使用：
    - ``record_request`` — 记录单次协议 RPC 的 wall-clock 延迟
    - ``begin_session`` / ``end_session`` — 从 Init 首消息到 Rec 末消息的端到端会话耗时

完整会话结束时与 Server 退出时输出 ``summary_lines()``；亦可经 Client STATS 查询。
"""

from __future__ import annotations

import statistics
import time
from dataclasses import dataclass, field


@dataclass
class RequestStats:
    request_latencies_ms: list[float] = field(default_factory=list)
    session_latencies_ms: list[float] = field(default_factory=list)
    session_starts: dict[tuple[str, str], float] = field(default_factory=dict)

    def begin_session(self, protocol: str, idc: str) -> None:
        key = (protocol, idc)
        if key not in self.session_starts:
            self.session_starts[key] = time.perf_counter()

    def record_request(self, latency_ms: float) -> None:
        self.request_latencies_ms.append(latency_ms)

    def end_session(self, protocol: str, idc: str) -> float | None:
        key = (protocol, idc)
        t0 = self.session_starts.pop(key, None)
        if t0 is None:
            return None
        latency_ms = (time.perf_counter() - t0) * 1000
        self.session_latencies_ms.append(latency_ms)
        return latency_ms

    def _format_stats(self, latencies: list[float], label: str) -> str:
        if not latencies:
            return f"{label}: (无数据)"
        if len(latencies) == 1:
            return f"{label}: n=1 mean={latencies[0]:.2f} ms"
        return (
            f"{label}: n={len(latencies)} "
            f"mean={statistics.mean(latencies):.2f} ms "
            f"std={statistics.stdev(latencies):.2f} ms "
            f"min={min(latencies):.2f} ms "
            f"max={max(latencies):.2f} ms"
        )

    def summary_lines(self) -> list[str]:
        return [
            self._format_stats(self.request_latencies_ms, "单请求耗时"),
            self._format_stats(self.session_latencies_ms, "完整会话耗时"),
        ]
