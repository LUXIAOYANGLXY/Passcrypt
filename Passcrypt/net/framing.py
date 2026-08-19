# -*- coding: utf-8 -*-
"""
net/framing.py
==============
TCP 消息收发：PBCS/E2SE 风格二进制线协议。

线格式（见 wire_codec.py）：
  opcode(1) ‖ [len(1) ‖ field]* … ‖ 少量定长字段

无外层总长度头；按 opcode 流式读完一条消息（对齐 PBCS AuthServer）。
通信量统计：wire_metering 累计实际收发字节。
"""

from __future__ import annotations

import socket
import struct
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Dict, Iterator, Optional

from net import messages as M
from net import wire_codec as WC


@dataclass
class WireMeter:
    """单线程测量窗口：累计本窗口内发送/接收的 wire 字节。"""

    sent: int = 0
    recv: int = 0

    @property
    def total(self) -> int:
        return self.sent + self.recv

    def reset(self) -> None:
        self.sent = 0
        self.recv = 0


_tls = threading.local()


def _active_meter() -> Optional[WireMeter]:
    return getattr(_tls, "meter", None)


@contextmanager
def wire_metering(meter: Optional[WireMeter] = None) -> Iterator[WireMeter]:
    m = meter if meter is not None else WireMeter()
    prev = getattr(_tls, "meter", None)
    _tls.meter = m
    try:
        yield m
    finally:
        _tls.meter = prev


def _recvexact(conn: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf.extend(chunk)
    return bytes(buf)


def send_msg(conn: socket.socket, obj: Dict[str, Any]) -> int:
    """编码并发送一条二进制消息；返回 wire 字节数。"""
    data = WC.encode_message(obj)
    conn.sendall(data)
    m = _active_meter()
    if m is not None:
        m.sent += len(data)
    return len(data)


def recv_msg(conn: socket.socket) -> Dict[str, Any]:
    """
    阻塞接收一条完整二进制消息并解码为业务 dict。
    先读 opcode，再按类型读字段，拼成完整缓冲后 decode。
    """
    raw = bytearray()
    op_b = _recvexact(conn, 1)
    raw.extend(op_b)
    op = op_b[0]
    if op not in WC.OP_TO_TYPE:
        raise ValueError(f"unknown opcode: 0x{op:02x}")
    t = WC.OP_TO_TYPE[op]

    def take_lv() -> None:
        lb = _recvexact(conn, 1)
        raw.extend(lb)
        n = lb[0]
        if n:
            raw.extend(_recvexact(conn, n))

    def take_u8() -> None:
        raw.extend(_recvexact(conn, 1))

    def take_u64() -> None:
        raw.extend(_recvexact(conn, 8))

    if t in (M.REG_REQ, M.EXT_REQ, M.DEC_REQ):
        take_lv()
    elif t == M.REG_CTX:
        take_lv()
        take_lv()
        take_lv()
    elif t == M.REG_BLIND:
        take_lv()  # id
        take_lv()  # a
        take_lv()  # ctx
    elif t == M.EXT_BLIND:
        take_lv()
        take_lv()
    elif t == M.REG_EVAL:
        take_lv()  # K
        take_lv()  # X
        take_lv()  # a_tilde
    elif t == M.EXT_EVAL:
        take_lv()
    elif t == M.REG_COMMIT:
        take_lv()
        take_lv()
    elif t in (M.REG_ACK, M.ENC_ACK):
        take_u8()
    elif t == M.EXT_CTX:
        take_lv()
    elif t == M.ENC_COMMIT:
        take_lv()
        take_lv()
        take_lv()
        take_lv()
        take_lv()
        take_u64()
    elif t == M.DEC_RESP:
        take_lv()
        take_lv()
        take_lv()
        take_u64()
        take_lv()
    elif t == M.ERR:
        take_lv()
        take_lv()
    else:
        raise ValueError(f"recv not implemented for {t}")

    m = _active_meter()
    if m is not None:
        m.recv += len(raw)
    return WC.decode_message(bytes(raw))
