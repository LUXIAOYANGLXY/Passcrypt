# -*- coding: utf-8 -*-
"""
net/client_api.py
=================
客户端 Fig.1：Reg / Ext / Enc / Dec。

- pk：Reg 时线上随 REG_EVAL 下发；**报告通信量剔除**
- ctx：Client 采样并本地保存；Reg 时随 BLIND 提交；**报告通信量剔除**
- Ext：仅 BLIND↔EVAL(ã)
"""

from __future__ import annotations

import os
import socket
from typing import Dict, Optional, Tuple

from net import messages as M
from net.framing import recv_msg, send_msg
from paee import protocol, serde
from paee.params import PublicParams
from paee.types import Ciphertext, ExtState, ServerKey


def ctx_wire_bytes(ctx: bytes) -> int:
    """REG_BLIND 中 ctx 字段线字节（1B 长度 + 载荷）；统计时扣除。"""
    if len(ctx) > 255:
        raise ValueError("ctx too long for wire")
    return 1 + len(ctx)


def pk_wire_bytes() -> int:
    """REG_EVAL 中 K‖X 字段线字节（各 1+33）；统计时扣除。"""
    return (1 + 33) + (1 + 33)


def _connect(host: str, port: int) -> socket.socket:
    s = socket.create_connection((host, port), timeout=60)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return s


class PAEEClientSession:
    def __init__(self, host: str, port: int, pp: PublicParams):
        self.host = host
        self.port = port
        self.pp = pp
        self.sock: Optional[socket.socket] = None
        self._ctx_by_id: Dict[str, bytes] = {}

    def connect(self) -> "PAEEClientSession":
        if self.sock is not None:
            return self
        self.sock = _connect(self.host, self.port)
        return self

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def __enter__(self) -> "PAEEClientSession":
        return self.connect()

    def __exit__(self, *exc) -> None:
        self.close()

    def _sock(self) -> socket.socket:
        if self.sock is None:
            raise RuntimeError("session not connected; call connect() first")
        return self.sock

    def set_ctx(self, id: str, ctx: bytes) -> None:
        self._ctx_by_id[id] = ctx

    def get_ctx(self, id: str) -> Optional[bytes]:
        return self._ctx_by_id.get(id)

    def register(self, id: str, pw: str) -> Tuple[ServerKey, bytes]:
        """
        Reg（2 往返）：BLIND(id,a,ctx) → EVAL(pk,ã) → COMMIT → ACK。
        pk 线上返回；返回 (pk, ctx)。
        """
        sock = self._sock()
        ctx = os.urandom(self.pp.lambda_bytes)
        st = protocol.CReg_blind(pw)
        send_msg(
            sock,
            {
                "type": M.REG_BLIND,
                "id": id,
                "a": serde.export_a(st.a),
                "ctx": serde.b64(ctx),
            },
        )
        ev = recv_msg(sock)
        if ev.get("type") != M.REG_EVAL:
            raise RuntimeError(ev)
        pk = serde.import_pk(ev["pk"])
        a_tilde = serde.import_a_tilde(ev["a_tilde"])

        c = protocol.CReg_finalize_c(self.pp, id, pw, ctx, st, a_tilde, pk.K)
        if c is None:
            raise RuntimeError("Reg finalize failed")

        send_msg(sock, {"type": M.REG_COMMIT, "id": id, "c": serde.b64(c)})
        ack = recv_msg(sock)
        if not ack.get("ok"):
            raise RuntimeError(ack)

        self._ctx_by_id[id] = ctx
        return pk, ctx

    def extract_token(
        self,
        pk: ServerKey,
        id: str,
        pw: str,
        *,
        ctx: Optional[bytes] = None,
    ) -> ExtState:
        use_ctx = ctx if ctx is not None else self._ctx_by_id.get(id)
        if use_ctx is None:
            raise RuntimeError(
                f"missing ctx for id={id!r}; register first or pass/set_ctx"
            )

        sock = self._sock()
        st = protocol.CReg_blind(pw)
        send_msg(sock, {"type": M.EXT_BLIND, "id": id, "a": serde.export_a(st.a)})
        ev = recv_msg(sock)
        if ev.get("type") != M.EXT_EVAL:
            raise RuntimeError(ev)
        a_tilde = serde.import_a_tilde(ev["a_tilde"])
        est = protocol.CExt(self.pp, id, pw, use_ctx, st, a_tilde, pk.K)
        if est is None:
            raise RuntimeError("Ext failed")
        return est

    def enc_commit(
        self,
        pk: ServerKey,
        id: str,
        pw: str,
        estext: ExtState,
        plaintext: bytes,
    ) -> Ciphertext:
        out = protocol.CEnc(self.pp, pk, id, pw, estext, plaintext)
        if out is None:
            raise RuntimeError("Enc returned ⊥")
        c_prime, ct = out
        sock = self._sock()
        send_msg(
            sock,
            {
                "type": M.ENC_COMMIT,
                "id": id,
                "c_prime": serde.b64(c_prime),
                "ct": serde.export_ct_server(ct),
            },
        )
        ack = recv_msg(sock)
        if not ack.get("ok"):
            raise RuntimeError(ack)
        return ct

    def encrypt(
        self,
        pk: ServerKey,
        id: str,
        pw: str,
        plaintext: bytes,
        *,
        ctx: Optional[bytes] = None,
    ) -> Ciphertext:
        est = self.extract_token(pk, id, pw, ctx=ctx)
        return self.enc_commit(pk, id, pw, est, plaintext)

    def decrypt(
        self,
        pk: ServerKey,
        id: str,
        pw: str,
        *,
        local_ct2: bytes | None = None,
        ctx: Optional[bytes] = None,
    ) -> bytes:
        est = self.extract_token(pk, id, pw, ctx=ctx)
        sock = self._sock()
        send_msg(sock, {"type": M.DEC_REQ, "id": id})
        resp = recv_msg(sock)
        if resp.get("type") != M.DEC_RESP:
            raise RuntimeError(resp)
        ct = serde.import_ct(resp["ct"])
        if local_ct2 is not None:
            ct = serde.merge_local_ct2(ct, local_ct2)
        d = serde.import_g(resp["d"])
        m = protocol.CDec(self.pp, pw, est, ct, d)
        if m is None:
            raise RuntimeError("Dec returned ⊥")
        return m


def register(
    host: str,
    port: int,
    pp: PublicParams,
    id: str,
    pw: str,
) -> Tuple[ServerKey, bytes]:
    with PAEEClientSession(host, port, pp) as sess:
        return sess.register(id, pw)


def extract_token(
    host: str,
    port: int,
    pk: ServerKey,
    id: str,
    pw: str,
    pp: PublicParams | None = None,
    *,
    ctx: Optional[bytes] = None,
) -> ExtState:
    from paee.params import Setup

    if pp is None:
        pp = Setup(32)
    with PAEEClientSession(host, port, pp) as sess:
        if ctx is not None:
            sess.set_ctx(id, ctx)
        return sess.extract_token(pk, id, pw, ctx=ctx)


def encrypt(
    host: str,
    port: int,
    pp: PublicParams,
    pk: ServerKey,
    id: str,
    pw: str,
    plaintext: bytes,
    *,
    ctx: Optional[bytes] = None,
) -> Ciphertext:
    with PAEEClientSession(host, port, pp) as sess:
        if ctx is not None:
            sess.set_ctx(id, ctx)
        return sess.encrypt(pk, id, pw, plaintext, ctx=ctx)


def decrypt(
    host: str,
    port: int,
    pp: PublicParams,
    pk: ServerKey,
    id: str,
    pw: str,
    *,
    local_ct2: bytes | None = None,
    ctx: Optional[bytes] = None,
) -> bytes:
    with PAEEClientSession(host, port, pp) as sess:
        if ctx is not None:
            sess.set_ctx(id, ctx)
        return sess.decrypt(pk, id, pw, local_ct2=local_ct2, ctx=ctx)
