"""统一日志配置：Server / Client 双端实时输出。

``FlushStreamHandler`` 每次写入后立即 flush，便于双终端观察 TCP 往返。

日志前缀约定：
    [SERVER] — ``serve.py`` / ``server/tcp_server.py``
    [CLIENT] — ``run_client.py`` / ``client/tcp_transport.py``
"""

from __future__ import annotations

import logging
import sys


class FlushStreamHandler(logging.StreamHandler):
    """每次 ``emit`` 后立即 flush，避免 Flask 多线程环境下日志延迟。

    Werkzeug 在 worker 线程处理请求时，默认 StreamHandler 可能缓冲 stdout，
    导致 Client 已 POST 完成而 Server 日志尚未出现在终端；flush 保证实时可观测。
    """

    def emit(self, record: logging.LogRecord) -> None:
        super().emit(record)
        self.flush()


def setup_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    """创建或复用具名 logger，绑定 FlushStreamHandler 与统一格式。

    Args:
        name: logger 名称（如 ``"SERVER"`` / ``"CLIENT"``）
        level: 最低日志级别，默认 INFO

    Returns:
        配置完毕的 ``logging.Logger`` 实例（重复调用同名 logger 不会重复添加 handler）
    """
    # Python 3.7+：行缓冲 stdout，与 FlushStreamHandler 配合减少日志粘包
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(line_buffering=True)
        except Exception:
            pass

    logger = logging.getLogger(name)
    # 幂等：run_client / serve 可能多次 import，避免重复 handler 导致双份日志
    if logger.handlers:
        return logger
    logger.setLevel(level)
    handler = FlushStreamHandler(sys.stdout)
    handler.setFormatter(
        logging.Formatter(
            fmt="%(asctime)s [%(name)s] %(levelname)s %(message)s",
            datefmt="%H:%M:%S",
        )
    )
    logger.addHandler(handler)
    # 不向 root logger 传播，防止与第三方库默认格式混杂
    logger.propagate = False
    return logger
