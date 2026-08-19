"""
WBP demo (Davies et al. Crypto'23 Fig.4/5): Server subprocess + Client.

Topology: Client --TCP--> Server (HSM module in-process)
"""

from __future__ import annotations

import logging
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from client.app import Client

log = logging.getLogger("wbp.demo")

HOST = "127.0.0.1"
SERVER_PORT = 8765


def _wait_port(host: str, port: int, proc: subprocess.Popen, timeout: float = 8.0) -> None:
    import socket

    deadline = time.time() + timeout
    last: Exception | None = None
    while time.time() < deadline:
        if proc.poll() is not None:
            out = proc.stdout.read() if proc.stdout else ""
            raise RuntimeError(f"server exited early:\n{out}")
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return
        except OSError as e:
            last = e
            time.sleep(0.1)
    raise RuntimeError(f"port {port} not ready: {last}")


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    log.info("WBP DFG+23 demo (Server + Client; HSM in-process)")

    server_proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "server.app",
            "--host",
            HOST,
            "--port",
            str(SERVER_PORT),
        ],
        cwd=str(ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        _wait_port(HOST, SERVER_PORT, server_proc)
        log.info("Server up pid=%s (HSM in-process)", server_proc.pid)

        client = Client("demo-user", HOST, SERVER_PORT, password="demo-password")
        client.connect()
        try:
            init_r = client.init()
            log.info("INIT => %s", init_r)
            if not init_r.ok:
                raise SystemExit(f"init failed: {init_r.error}")
            rec_r = client.recover()
            log.info("RECOVER => %s", rec_r)
            if not rec_r.ok:
                raise SystemExit(f"recover failed: {rec_r.error}")
            if init_r.backup_key != rec_r.backup_key:
                raise SystemExit("key mismatch")
            log.info("SUCCESS: Fig.4/5 round-trip; K matched")
        finally:
            client.close()
    finally:
        server_proc.terminate()
        try:
            out, _ = server_proc.communicate(timeout=3)
            if out:
                log.info("server log:\n%s", out)
        except subprocess.TimeoutExpired:
            server_proc.kill()


if __name__ == "__main__":
    main()
