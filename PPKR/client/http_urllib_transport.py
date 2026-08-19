"""遗留 Flask/HTTP 传输层 — 仅用于与 TCP 公平对照实验。

日常路径请用 ``client.tcp_transport``。通信量口径：HTTP 请求体 + 响应体
（不含 HTTP 头），与迁移前 ``http_benchmark`` 一致。
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any

from common.attested_wire import attested_raw
from logging_config import setup_logger
from protocols.messages import ProtocolMessage

log = setup_logger("CLIENT-HTTP")


class PPKRUrllibHttpTransport:
    """对接 ``server/app.py`` 的 REST 传输。"""

    def __init__(self, base_url: str = "http://127.0.0.1:5002") -> None:
        self.base_url = base_url.rstrip("/")
        self.comm_bytes: int = 0
        log.info("HTTP(urllib) 传输层 base_url=%s", self.base_url)

    def reset_comm(self) -> None:
        self.comm_bytes = 0

    def get_hsm_pubkey_hex(self) -> str:
        url = f"{self.base_url}/api/v1/hsm_pubkey"
        with urllib.request.urlopen(url, timeout=30) as resp:
            raw = resp.read()
            data = json.loads(raw.decode())
        self.comm_bytes += len(raw)
        return data["pk"]

    def post_encpw(self, msg: ProtocolMessage) -> dict[str, Any]:
        return self._post("/api/v1/encpw_plus", msg)

    def post_oprf(self, msg: ProtocolMessage) -> dict[str, Any]:
        return self._post("/api/v1/oprf_ppkr", msg)

    def _post(self, path: str, msg: ProtocolMessage) -> dict[str, Any]:
        url = f"{self.base_url}{path}"
        body = msg.to_json().encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                raw = resp.read()
                result = json.loads(raw.decode())
            self.comm_bytes += len(body) + len(raw)
            return result
        except urllib.error.HTTPError as e:
            detail = e.read().decode() if e.fp else str(e)
            raise RuntimeError(f"HTTP {e.code} {url}: {detail}") from e
        except urllib.error.URLError as e:
            raise RuntimeError(
                f"无法连接 HTTP Server {url}，请先: python -m server.app"
            ) from e

    def attested_bytes(self, response: dict[str, Any]) -> bytes:
        return attested_raw(response)
