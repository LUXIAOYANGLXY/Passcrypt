"""PPKR TCP Server — Client↔Server 中继（PAEE/PBCS 二进制帧）。

HSM 仍为进程内模块；Server 只做 HELLO + phase 转发。
默认监听 127.0.0.1:8765。
"""

from __future__ import annotations

import socket
import threading
import time
from typing import Any

from common.messages import Message, MessageType, recv_message, send_message
from config import IDC, SID, SSID
from logging_config import setup_logger
from protocols.messages import ProtocolMessage
from server.ppkr_server import PPKRServer
from server.request_stats import RequestStats

log = setup_logger("SERVER")

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765

_SESSION_START = {
    "encPw+": {"InitS"},
    "OPRF-PPKR": {"Init"},
}
_SESSION_END = {
    "encPw+": {"Rec"},
    "OPRF-PPKR": {"RecSign"},
}


class TcpServer:
    """多线程 TCP 接受循环；每连接独立处理 HELLO + 协议请求。"""

    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> None:
        self.host = host
        self.port = port
        self.ppkr = PPKRServer(sid=SID("server-1"))
        self.stats = RequestStats()
        self._sock: socket.socket | None = None
        self._stop = threading.Event()

    def start(self) -> None:
        """绑定端口并循环 accept（timeout 便于响应 stop）。"""
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(8)
        self._sock.settimeout(1.0)
        log.info(
            "PPKR TCP Server listening on %s:%d (binary wire, PAEE/PBCS-style)",
            self.host,
            self.port,
        )
        log.info("耗时统计可经 Client STATS 消息查询；Ctrl+C 退出打印汇总")
        while not self._stop.is_set():
            try:
                conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(
                target=self._handle_client, args=(conn, addr), daemon=True
            ).start()

    def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        if self.stats.request_latencies_ms or self.stats.session_latencies_ms:
            log.info("========== Server 退出汇总 ==========")
            for line in self.stats.summary_lines():
                log.info(line)

    def _handle_client(self, conn: socket.socket, addr: Any) -> None:
        idc: str | None = None
        log.info("client connection from %s", addr)
        try:
            with conn:
                while True:
                    msg = recv_message(conn, role="server")
                    if msg.type == MessageType.HELLO:
                        idc = str(msg.payload.get("idc", ""))
                        if not idc:
                            send_message(
                                conn,
                                Message(
                                    MessageType.ERROR,
                                    msg.ssid,
                                    {"error": "missing idc"},
                                ),
                                role="server",
                            )
                            return
                        pk = self.ppkr.hsm_attestation_pk.serialize()
                        send_message(
                            conn,
                            Message(
                                MessageType.HELLO_ACK,
                                msg.ssid,
                                {"idc": idc, "pk": pk},
                            ),
                            role="server",
                        )
                        continue

                    if idc is None:
                        send_message(
                            conn,
                            Message(
                                MessageType.ERROR,
                                msg.ssid,
                                {"error": "not authenticated (send HELLO first)"},
                            ),
                            role="server",
                        )
                        return

                    reply = self._dispatch(idc, msg)
                    if reply is not None:
                        send_message(conn, reply, role="server")
        except ConnectionError:
            log.info("client IDC=%s disconnected", idc)
        except Exception:
            log.exception("handler error IDC=%s", idc)

    def _dispatch(self, idc: str, msg: Message) -> Message:
        if msg.type == MessageType.ENCPW:
            return self._on_protocol("encPw+", msg, self.ppkr.encpw_handle, MessageType.ENCPW_RESP)
        if msg.type == MessageType.OPRF:
            return self._on_protocol("OPRF-PPKR", msg, self.ppkr.oprf_handle, MessageType.OPRF_RESP)
        if msg.type == MessageType.STATS:
            return Message(
                MessageType.STATS_RESP,
                msg.ssid,
                {
                    "requests": len(self.stats.request_latencies_ms),
                    "sessions": len(self.stats.session_latencies_ms),
                    "request_latencies_ms": self.stats.request_latencies_ms,
                    "session_latencies_ms": self.stats.session_latencies_ms,
                },
            )
        if msg.type == MessageType.LEAK:
            files = self.ppkr.leak_hsm_files()
            return Message(
                MessageType.LEAK_RESP,
                msg.ssid,
                {"leaked_count": len(files)},
            )
        return Message(
            MessageType.ERROR,
            msg.ssid,
            {"error": f"unexpected message {msg.type}"},
        )

    def _on_protocol(
        self,
        protocol: str,
        msg: Message,
        handler,
        resp_type: str,
    ) -> Message:
        """将 payload 还原为 ProtocolMessage，转发 HSM，返回 attested。"""
        p = msg.payload
        wire_idc = str(p.get("idc", ""))
        body = {
            k: v
            for k, v in p.items()
            if k not in ("phase", "sid", "ssid", "idc")
        }
        proto_msg = ProtocolMessage(
            phase=str(p.get("phase", "")),
            sid=SID(str(p.get("sid", "server-1"))),
            ssid=SSID(msg.ssid or str(p.get("ssid", ""))),
            idc=IDC(wire_idc),
            body=body,
        )

        if proto_msg.phase in _SESSION_START.get(protocol, set()):
            self.stats.begin_session(protocol, proto_msg.idc)

        t0 = time.perf_counter()
        log.info(
            "[%s] TCP 收到 phase=%s ssid=%s idc=%s",
            protocol,
            proto_msg.phase,
            proto_msg.ssid,
            proto_msg.idc,
        )
        try:
            result = handler(proto_msg)
        except Exception as e:
            log.exception("[%s] handler failed", protocol)
            return Message(MessageType.ERROR, msg.ssid, {"error": str(e)})

        elapsed_ms = (time.perf_counter() - t0) * 1000
        self.stats.record_request(elapsed_ms)
        resp_bytes = len(result.get("payload", b"")) + len(result.get("sig", b""))
        log.info(
            "[%s] 完成 phase=%s payload+sig≈%d B 耗时=%.2f ms",
            protocol,
            proto_msg.phase,
            resp_bytes,
            elapsed_ms,
        )

        if proto_msg.phase in _SESSION_END.get(protocol, set()):
            session_ms = self.stats.end_session(protocol, proto_msg.idc)
            if session_ms is not None:
                log.info(
                    "[%s] 完整会话结束 idc=%s 会话耗时=%.2f ms",
                    protocol,
                    proto_msg.idc,
                    session_ms,
                )
                for line in self.stats.summary_lines():
                    log.info(line)

        return Message(resp_type, msg.ssid, result)


def main(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> None:
    server = TcpServer(host, port)
    try:
        server.start()
    except KeyboardInterrupt:
        log.info("Server shutting down")
        server.stop()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="PPKR TCP Server")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args()
    main(args.host, args.port)
