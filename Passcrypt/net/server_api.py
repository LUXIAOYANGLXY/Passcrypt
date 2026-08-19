# -*- coding: utf-8 -*-
"""
net/server_api.py
=================
服务器端 Fig.1 会话处理。

Reg：REG_BLIND(id,a,ctx) → REG_EVAL(pk,ã) → COMMIT → ACK
  pk/ctx 线上传输，报告通信量可剔除。
Ext：EXT_BLIND(id,a) → EXT_EVAL(ã)；ctx 不上线。
"""

from __future__ import annotations

import socket
from typing import Any, Dict

from net import messages as M
from net.framing import recv_msg, send_msg
from paee import serde
from paee.protocol import PAEEServerState
from storage.local import LocalStore


class PAEEServer:
    def __init__(self, state: PAEEServerState, store: LocalStore):
        self.state = state
        self.store = store

    def handle(self, conn: socket.socket) -> None:
        while True:
            try:
                msg = recv_msg(conn)
            except ConnectionError:
                return
            t = msg.get("type")
            if t == M.REG_BLIND:
                self._reg(conn, msg)
            elif t == M.EXT_BLIND:
                self._ext(conn, msg)
            elif t == M.ENC_COMMIT:
                self._enc(conn, msg)
            elif t == M.DEC_REQ:
                self._dec(conn, msg)
            else:
                send_msg(conn, {"type": M.ERR, "code": "BAD_TYPE", "msg": str(t)})
                return

    def _reg(self, conn: socket.socket, msg: Dict[str, Any]) -> None:
        id = msg["id"]
        ctx = serde.u64(msg["ctx"])
        if not self.state.SReg_accept_ctx(id, ctx):
            send_msg(conn, {"type": M.ERR, "code": "ID_EXISTS"})
            return

        a = serde.import_a(msg["a"])
        a_tilde = self.state.SReg_eval(id, a)
        if a_tilde is None:
            send_msg(conn, {"type": M.ERR, "code": "EVAL_FAIL"})
            return
        send_msg(
            conn,
            {
                "type": M.REG_EVAL,
                "pk": serde.export_pk(self.state.sk),
                "a_tilde": serde.export_a_tilde(a_tilde),
            },
        )

        commit = recv_msg(conn)
        if commit.get("type") != M.REG_COMMIT or commit.get("id") != id:
            send_msg(conn, {"type": M.ERR, "code": "BAD_COMMIT"})
            return
        c = serde.u64(commit["c"])
        if not self.state.SReg_store(id, c):
            send_msg(conn, {"type": M.ERR, "code": "STORE_FAIL"})
            return
        self.store.put_record(self.state.records[id])
        send_msg(conn, {"type": M.REG_ACK, "ok": True})

    def _ext(self, conn: socket.socket, msg: Dict[str, Any]) -> None:
        id = msg["id"]
        if id not in self.state.records:
            rec = self.store.get_record(id)
            if rec is None:
                send_msg(conn, {"type": M.ERR, "code": "UNKNOWN_ID"})
                return
            self.state.records[id] = rec

        a = serde.import_a(msg["a"])
        a_tilde = self.state.SExt_eval(id, a)
        if a_tilde is None:
            send_msg(conn, {"type": M.ERR, "code": "EVAL_FAIL"})
            return
        send_msg(
            conn,
            {
                "type": M.EXT_EVAL,
                "a_tilde": serde.export_a_tilde(a_tilde),
            },
        )

    def _enc(self, conn: socket.socket, msg: Dict[str, Any]) -> None:
        id = msg["id"]
        if id not in self.state.records:
            rec = self.store.get_record(id)
            if rec:
                self.state.records[id] = rec
        c_prime = serde.u64(msg["c_prime"])
        ct = serde.import_ct(msg["ct"])
        ok = self.state.Enc_store(id, c_prime, ct)
        if not ok:
            send_msg(conn, {"type": M.ENC_ACK, "ok": False})
            return
        self.store.put_ct(id, ct)
        send_msg(conn, {"type": M.ENC_ACK, "ok": True})

    def _dec(self, conn: socket.socket, msg: Dict[str, Any]) -> None:
        id = msg["id"]
        if id not in self.state.ciphertexts:
            ct = self.store.get_ct(id)
            if ct:
                self.state.ciphertexts[id] = ct
        out = self.state.SDec(id)
        if out is None:
            send_msg(conn, {"type": M.ERR, "code": "DEC_FAIL"})
            return
        ct, d = out
        send_msg(
            conn,
            {
                "type": M.DEC_RESP,
                "ct": serde.export_ct_server(ct),
                "d": serde.export_g(d),
            },
        )
