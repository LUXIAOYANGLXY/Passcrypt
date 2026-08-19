"""启动 PPKR TCP Server 的便捷入口（在项目根目录运行）。

典型双终端用法::

    终端1: python serve.py
    终端2: python run_client.py --password mypass
    # 默认协议 π_OPRF-PPKR；Lev-2 加 --protocol encpw_plus

线格式对齐 PAEE/PBCS：``opcode ‖ [u16_be len ‖ field]*``（默认 127.0.0.1:8765）。
与旧版 4B+JSON+Base64 **不兼容**。
"""

import argparse
import socket
import sys

import path_setup  # noqa: F401

from logging_config import setup_logger
from server.tcp_server import DEFAULT_HOST, DEFAULT_PORT, TcpServer

log = setup_logger("SERVER")


def _ensure_port_free(host: str, port: int) -> None:
    """探测端口是否可绑定；已被占用则打印提示并退出。"""
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind((host, port))
    except OSError:
        log.error("无法绑定 %s:%d（端口已被占用）。", host, port)
        log.error("请先关闭旧 Server，或换端口启动: python serve.py --port 8766")
        log.error("Client 对应使用: python run_client.py --host 127.0.0.1 --port 8766 ...")
        sys.exit(1)
    finally:
        probe.close()


def main() -> None:
    """解析 CLI 参数并启动 TCP Server。"""
    parser = argparse.ArgumentParser(description="PPKR TCP Server（PAEE/PBCS 二进制成帧）")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args()

    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(line_buffering=True)
        except Exception:
            pass

    _ensure_port_free(args.host, args.port)
    log.info(
        "PPKR TCP Server 启动 %s:%d （PID=%d，等待 Client 连接）",
        args.host,
        args.port,
        __import__("os").getpid(),
    )
    log.info("线格式: opcode + u16 LV；HELLO → ENCPW/OPRF；Ctrl+C 停止")
    server = TcpServer(args.host, args.port)
    try:
        server.start()
    except KeyboardInterrupt:
        log.info("Server shutting down")
        server.stop()


if __name__ == "__main__":
    main()
