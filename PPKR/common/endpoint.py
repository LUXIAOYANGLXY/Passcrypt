"""TCP 端点解析与探测（对齐 WBPv1 默认 127.0.0.1:8765）。

兼容旧 CLI 的 ``--url http://host:port`` 写法，也支持 ``--host`` / ``--port``。
"""

from __future__ import annotations

import socket
from urllib.parse import urlparse


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765


def resolve_endpoint(
    *,
    host: str | None = None,
    port: int | None = None,
    url: str | None = None,
    base_url: str | None = None,
) -> tuple[str, int]:
    """解析 (host, port)。``url`` / ``base_url`` 优先于 host/port。"""
    raw = url or base_url
    if raw:
        return _parse_url(raw)
    return host or DEFAULT_HOST, int(port) if port is not None else DEFAULT_PORT


def _parse_url(raw: str) -> tuple[str, int]:
    s = raw.strip()
    if "://" not in s:
        s = "tcp://" + s
    parsed = urlparse(s)
    h = parsed.hostname or DEFAULT_HOST
    p = parsed.port if parsed.port is not None else DEFAULT_PORT
    return h, p


def check_server(host: str, port: int, timeout: float = 5.0) -> None:
    """探测 TCP Server 是否可连接。"""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
    except OSError as e:
        raise RuntimeError(
            f"无法连接 Server {host}:{port}\n请先启动: python serve.py\n原因: {e}"
        ) from e
