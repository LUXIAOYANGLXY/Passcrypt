"""
WBP Server (Davies et al. Crypto'23) — Client↔Server TCP relay.

HSM is an in-process module (deployment simplification; protocol follows Fig.4/5).
Server only maps IDC↔aid and forwards; it does not open E or learn K / K_export.
"""

from __future__ import annotations

import argparse
import logging
import socket
import threading
import uuid
from typing import Any

from common.messages import Message, MessageType, recv_message, send_message
from hsm.service import HsmService

log = logging.getLogger("wbp.server")

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765


class Server:
    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> None:
        self.host = host
        self.port = port
        self.hsm = HsmService()
        self.acc: dict[str, str] = {}
        self._sessions: dict[tuple[str, str], str] = {}
        self._sock: socket.socket | None = None
        self._stop = threading.Event()

    def start(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(8)
        self._sock.settimeout(1.0)
        log.info(
            "Server listening on %s:%d (WBP DFG+23, HSM in-process)",
            self.host,
            self.port,
        )
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
                        bundle = self.hsm.public_bundle()
                        send_message(
                            conn,
                            Message(
                                MessageType.HELLO_ACK,
                                msg.ssid,
                                {"idc": idc, **bundle},
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
                                {"error": "not authenticated"},
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

    def _dispatch(self, idc: str, msg: Message) -> Message | None:
        key = (idc, msg.ssid)
        handlers = {
            MessageType.INIT_REQ: self._on_init_req,
            MessageType.INIT_UPLOAD: self._on_init_upload,
            MessageType.REC_REQ: self._on_rec_req,
            MessageType.REC_CONFIRM: self._on_rec_confirm,
        }
        handler = handlers.get(msg.type)
        if handler is None:
            return Message(
                MessageType.ERROR,
                msg.ssid,
                {"error": f"unexpected message {msg.type.value}"},
            )

        if msg.type in (MessageType.INIT_REQ, MessageType.REC_REQ):
            self._sessions[key] = msg.type.value

        expected = {
            MessageType.INIT_UPLOAD: MessageType.INIT_REQ.value,
            MessageType.REC_CONFIRM: MessageType.REC_REQ.value,
        }
        if msg.type in expected and self._sessions.get(key) != expected[msg.type]:
            return Message(
                MessageType.ERROR,
                msg.ssid,
                {"error": "out-of-order or unknown ssid"},
            )
        return handler(idc, msg)

    def _on_init_req(self, idc: str, msg: Message) -> Message:
        a1 = str(msg.payload.get("a1", ""))
        if not a1:
            return Message(
                MessageType.INIT_RESULT, msg.ssid, {"ok": False, "error": "missing a1"}
            )
        aid_old = self.acc.get(idc)
        aid_new = uuid.uuid4().hex
        self.acc[idc] = aid_new
        log.info("Fig.4 INIT IDC=%s -> HSM aid=%s", idc, aid_new)
        out = self.hsm.init_eval(aid_new, aid_old, a1)
        if not out.get("ok"):
            return Message(MessageType.INIT_RESULT, msg.ssid, out)
        return Message(
            MessageType.INIT_HSM_RESP,
            msg.ssid,
            {
                "aid": out["aid"],
                "b1": out["b1"],
                "n1": out["n1"],
                "sigma": out["sigma"],
            },
        )

    def _on_init_upload(self, idc: str, msg: Message) -> Message:
        e_pke = str(msg.payload.get("E", ""))
        opaque_upload = str(msg.payload.get("opaque_upload", ""))
        aid = self.acc.get(idc)
        if not aid:
            return Message(
                MessageType.INIT_RESULT, msg.ssid, {"ok": False, "error": "no aid"}
            )
        if not e_pke or not opaque_upload:
            return Message(
                MessageType.INIT_RESULT,
                msg.ssid,
                {"ok": False, "error": "missing E or opaque_upload"},
            )
        log.info("Fig.4 INIT_UPLOAD IDC=%s aid=%s -> HSM", idc, aid)
        out = self.hsm.store_init(aid, e_pke, opaque_upload)
        self._sessions.pop((idc, msg.ssid), None)
        return Message(MessageType.INIT_RESULT, msg.ssid, out)

    def _on_rec_req(self, idc: str, msg: Message) -> Message:
        aid = self.acc.get(idc)
        if not aid:
            return Message(
                MessageType.REC_RESULT,
                msg.ssid,
                {"ok": False, "error": "unknown idc"},
            )
        a2 = str(msg.payload.get("a2", ""))
        log.info("Fig.5 REC IDC=%s aid=%s -> HSM", idc, aid)
        out = self.hsm.rec_eval(aid, a2)
        if out.get("deleted"):
            self.acc.pop(idc, None)
            return Message(MessageType.REC_RESULT, msg.ssid, out)
        if not out.get("ok"):
            return Message(MessageType.REC_RESULT, msg.ssid, out)
        return Message(
            MessageType.REC_HSM_RESP,
            msg.ssid,
            {"aid": out["aid"], "b2": out["b2"], "sigma": out["sigma"]},
        )

    def _on_rec_confirm(self, idc: str, msg: Message) -> Message:
        aid = self.acc.get(idc)
        if not aid:
            return Message(
                MessageType.REC_RESULT,
                msg.ssid,
                {"ok": False, "error": "unknown idc"},
            )
        t_c = str(msg.payload.get("t_c", ""))
        log.info("Fig.5 REC_CONFIRM IDC=%s aid=%s -> HSM", idc, aid)
        out = self.hsm.confirm(aid, t_c)
        self._sessions.pop((idc, msg.ssid), None)
        if not out.get("ok"):
            return Message(MessageType.REC_RESULT, msg.ssid, out)
        return Message(
            MessageType.REC_KEY,
            msg.ssid,
            {"ok": True, "c": out["c"], "aid": out["aid"]},
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="WBP Server (DFG+23, HSM in-process)"
    )
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    server = Server(args.host, args.port)
    try:
        server.start()
    except KeyboardInterrupt:
        log.info("Server shutting down")
        server.stop()


if __name__ == "__main__":
    main()
