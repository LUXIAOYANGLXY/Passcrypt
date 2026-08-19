# -*- coding: utf-8 -*-
"""
net/client_metrics.py
=====================
带 TCP 延迟与通信量统计的 Fig.1 客户端 API（供 experiment/tcp_benchmark 使用）。

口径：
  Enc_proto = Ext + Enc（不含 SE.Enc(dek,m)；同连接）
  Dec_proto = Ext + Dec 至 dek（不含解 ct2；同连接）

建连可置于计时外：传入已 connect 的 PAEEClientSession，
或由本模块在进入 wire_metering 之前先 connect。
"""

from __future__ import annotations

import time
from typing import Any, Dict, Optional, Tuple

from net import messages as M
from net.client_api import PAEEClientSession
from net.framing import recv_msg, send_msg, wire_metering
from paee import envelope, hashgroup, serde
from paee.params import PublicParams
from paee.types import Ciphertext, ExtState, ServerKey


def _metrics(t0: float, meter) -> Dict[str, Any]:
    """从计时起点与 WireMeter 生成 latency_ms / comm_bytes。"""
    return {
        "latency_ms": (time.perf_counter() - t0) * 1000.0,
        "comm_bytes": int(meter.total),
    }


def _session(
    host: str,
    port: int,
    pp: PublicParams,
    sess: Optional[PAEEClientSession] = None,
) -> Tuple[PAEEClientSession, bool]:
    """
    返回 (session, owned)。
    owned=True：本函数新建的会话，调用方 finally 中应 close。
    """
    if sess is not None:
        sess.connect()
        return sess, False
    s = PAEEClientSession(host, port, pp)
    s.connect()
    return s, True


def register_metrics(
    host: str,
    port: int,
    pp: PublicParams,
    id: str,
    pw: str,
    *,
    session: Optional[PAEEClientSession] = None,
) -> Tuple[ServerKey, Dict[str, Any]]:
    """计量 Reg；报告通信量剔除 pk 与 ctx。"""
    from net.client_api import ctx_wire_bytes, pk_wire_bytes

    sess, owned = _session(host, port, pp, session)
    try:
        with wire_metering() as meter:
            t0 = time.perf_counter()
            pk_out, ctx = sess.register(id, pw)
            meta = _metrics(t0, meter)
        meta["comm_bytes"] = max(
            0, int(meta["comm_bytes"]) - ctx_wire_bytes(ctx) - pk_wire_bytes()
        )
        meta["rounds"] = 2
        return pk_out, meta
    finally:
        if owned:
            sess.close()


def extract_token_metrics(
    host: str,
    port: int,
    pk: ServerKey,
    id: str,
    pw: str,
    pp: PublicParams | None = None,
    *,
    session: Optional[PAEEClientSession] = None,
    ctx: Optional[bytes] = None,
) -> Tuple[ExtState, Dict[str, Any]]:
    """计量 Ext（1 往返 = 论文箭头；ctx 本地）。"""
    from paee.params import Setup

    if pp is None:
        pp = Setup(32)
    sess, owned = _session(host, port, pp, session)
    try:
        if ctx is not None:
            sess.set_ctx(id, ctx)
        with wire_metering() as meter:
            t0 = time.perf_counter()
            est = sess.extract_token(pk, id, pw, ctx=ctx)
            meta = _metrics(t0, meter)
        meta["rounds"] = 1
        return est, meta
    finally:
        if owned:
            sess.close()


def enc_commit_split_metrics(
    host: str,
    port: int,
    pp: PublicParams,
    pk: ServerKey,
    id: str,
    pw: str,
    estext: ExtState,
    plaintext: bytes,
    *,
    session: Optional[PAEEClientSession] = None,
    tau_bind_ct2: bool = True,
) -> Tuple[Ciphertext, bytes, Dict[str, Any]]:
    """
    本地 Enc + ENC_COMMIT，并拆出：
      wrap_ms / encm_ms / proto_ms（总时间减去文件 AE encm）。
    协议对比应用空 plaintext，使 encm≈0。
    tau_bind_ct2=False：τ := H5(kMAC,(ct0,ct1))，H5 不扫 ct2。
    """
    sess, owned = _session(host, port, pp, session)
    try:
        with wire_metering() as meter:
            t0 = time.perf_counter()
            c_prime = hashgroup.H4(
                id, estext.ctx, pw, estext.sigma, pp.lambda_bytes
            )
            t_w0 = time.perf_counter()
            dek, ct0, ct1, kMAC, _ = envelope.Wrap(pp, pk, id, pw, estext.tk)
            wrap_ms = (time.perf_counter() - t_w0) * 1000.0
            t_e0 = time.perf_counter()
            ct2 = envelope.Encm(dek, plaintext)  # 大文件路径才显著
            encm_ms = (time.perf_counter() - t_e0) * 1000.0
            tau = hashgroup.H5(
                kMAC,
                ct0,
                ct1,
                ct2,
                pp.lambda_bytes,
                bind_ct2=tau_bind_ct2,
            )
            ct = Ciphertext(ct0=ct0, ct1=ct1, ct2=ct2, tau=tau)
            sock = sess._sock()
            send_msg(
                sock,
                {
                    "type": M.ENC_COMMIT,
                    "id": id,
                    "c_prime": serde.b64(c_prime),
                    # wire 不上传 ct2 本体
                    "ct": serde.export_ct_server(ct),
                },
            )
            ack = recv_msg(sock)
            if not ack.get("ok"):
                raise RuntimeError(ack)
            total_ms = (time.perf_counter() - t0) * 1000.0
            # H5 计入 proto_ms；encm_ms 仅 SE.Enc(dek,m)
            proto_ms = total_ms - encm_ms  # Wrap+H5+commit 网络（不含纯 Encm）
            meta = {
                "latency_ms": total_ms,
                "comm_bytes": int(meter.total),
                "rounds": 1,
                "wrap_ms": wrap_ms,
                "encm_ms": encm_ms,
                "proto_ms": proto_ms,
            }
            return ct, dek, meta
    finally:
        if owned:
            sess.close()


def enc_proto_only_metrics(
    host: str,
    port: int,
    pp: PublicParams,
    pk: ServerKey,
    id: str,
    pw: str,
    estext: ExtState,
    *,
    session: Optional[PAEEClientSession] = None,
) -> Tuple[Ciphertext, bytes, Dict[str, Any]]:
    """Enc 提交空 m（Enc_proto 口径）。"""
    return enc_commit_split_metrics(
        host, port, pp, pk, id, pw, estext, b"", session=session
    )


def encrypt_compare_metrics(
    host: str,
    port: int,
    pp: PublicParams,
    pk: ServerKey,
    id: str,
    pw: str,
    plaintext: bytes | None = None,
    *,
    session: Optional[PAEEClientSession] = None,
    tau_bind_ct2: bool = True,
) -> Dict[str, Any]:
    """
    Ext + Enc 同连接。
    默认 τ=H5(kMAC,(ct0,ct1,ct2))；tau_bind_ct2=False 时不含 ct2。
    ENC_COMMIT / 通信量不含 ct2 本体。
    enc_full = Ext + Wrap + Encm + H5 + 提交网络。
    """
    sess, owned = _session(host, port, pp, session)
    try:
        est, ext_m = extract_token_metrics(
            host, port, pk, id, pw, pp, session=sess
        )
        m = b"" if plaintext is None else plaintext
        ct, dek, commit_m = enc_commit_split_metrics(
            host,
            port,
            pp,
            pk,
            id,
            pw,
            est,
            m,
            session=sess,
            tau_bind_ct2=tau_bind_ct2,
        )
        enc_proto = {
            "latency_ms": ext_m["latency_ms"] + commit_m["proto_ms"],
            "comm_bytes": ext_m["comm_bytes"] + commit_m["comm_bytes"],
            "rounds": ext_m["rounds"] + commit_m["rounds"],
        }
        enc_full = {
            "latency_ms": ext_m["latency_ms"] + commit_m["latency_ms"],
            "comm_bytes": ext_m["comm_bytes"] + commit_m["comm_bytes"],
            "rounds": enc_proto["rounds"],
            "encm_ms": commit_m["encm_ms"],
        }
        return {
            "ct": ct,
            "dek": dek,
            "estext": est,
            "ext": ext_m,
            "commit": commit_m,
            "enc_proto": enc_proto,
            "enc_full": enc_full,
        }
    finally:
        if owned:
            sess.close()


def decrypt_compare_metrics(
    host: str,
    port: int,
    pp: PublicParams,
    pk: ServerKey,
    id: str,
    pw: str,
    *,
    local_ct2: bytes | None = None,
    session: Optional[PAEEClientSession] = None,
    tau_bind_ct2: bool = True,
) -> Dict[str, Any]:
    """
    Ext + Dec 同连接。
    local_ct2：Client 本地 ct2（不上云时必填）；与 Server 的 (ct0,ct1,τ,d) 合并后验 τ 解密。
    tau_bind_ct2 须与 Enc 一致。
    """
    sess, owned = _session(host, port, pp, session)
    try:
        est, ext_m = extract_token_metrics(
            host, port, pk, id, pw, pp, session=sess
        )
        with wire_metering() as meter:
            t0 = time.perf_counter()
            sock = sess._sock()
            send_msg(sock, {"type": M.DEC_REQ, "id": id})
            resp = recv_msg(sock)
            if resp.get("type") != M.DEC_RESP:
                raise RuntimeError(resp)
            ct = serde.import_ct(resp["ct"])
            if local_ct2 is not None:
                ct = serde.merge_local_ct2(ct, local_ct2)
            d = serde.import_g(resp["d"])
            parts = envelope.client_dec_parts(
                pp, pw, est, ct, d, tau_bind_ct2=tau_bind_ct2
            )
            if parts is None:
                raise RuntimeError("Dec returned ⊥")
            m, dek, open_ms, dec_m_ms = parts
            wall_ms = (time.perf_counter() - t0) * 1000.0
            tcp_and_open = wall_ms - dec_m_ms  # 协议侧至 dek（含验 τ）
            sdec = {
                "latency_ms": wall_ms,
                "comm_bytes": int(meter.total),
                "rounds": 1,
                "proto_ms": tcp_and_open,
                "dec_m_ms": dec_m_ms,
                "open_ms": open_ms,
            }
        dec_proto = {
            "latency_ms": ext_m["latency_ms"] + sdec["proto_ms"],
            "comm_bytes": ext_m["comm_bytes"] + sdec["comm_bytes"],
            "rounds": ext_m["rounds"] + sdec["rounds"],
        }
        dec_full = {
            "latency_ms": ext_m["latency_ms"] + sdec["latency_ms"],
            "comm_bytes": dec_proto["comm_bytes"],
            "rounds": dec_proto["rounds"],
            "dec_m_ms": sdec["dec_m_ms"],
        }
        return {
            "plaintext": m,
            "dek": dek,
            "ext": ext_m,
            "sdec": sdec,
            "dec_proto": dec_proto,
            "dec_full": dec_full,
        }
    finally:
        if owned:
            sess.close()


def enc_commit_metrics(
    host: str,
    port: int,
    pp: PublicParams,
    pk: ServerKey,
    id: str,
    pw: str,
    estext: ExtState,
    plaintext: bytes,
    *,
    session: Optional[PAEEClientSession] = None,
) -> Tuple[Ciphertext, Dict[str, Any]]:
    """兼容旧接口：只返回 ct 与 commit meta。"""
    ct, _dek, meta = enc_commit_split_metrics(
        host, port, pp, pk, id, pw, estext, plaintext, session=session
    )
    return ct, meta


def encrypt_metrics(
    host: str,
    port: int,
    pp: PublicParams,
    pk: ServerKey,
    id: str,
    pw: str,
    plaintext: bytes,
    *,
    session: Optional[PAEEClientSession] = None,
) -> Tuple[Ciphertext, Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
    """兼容旧接口：ct, enc_full, ext, commit。"""
    r = encrypt_compare_metrics(
        host, port, pp, pk, id, pw, plaintext, session=session
    )
    return r["ct"], r["enc_full"], r["ext"], r["commit"]


def decrypt_metrics(
    host: str,
    port: int,
    pp: PublicParams,
    pk: ServerKey,
    id: str,
    pw: str,
    *,
    session: Optional[PAEEClientSession] = None,
) -> Tuple[bytes, Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
    """兼容旧接口：plaintext, dec_full, ext, sdec。"""
    r = decrypt_compare_metrics(host, port, pp, pk, id, pw, session=session)
    return r["plaintext"], r["dec_full"], r["ext"], r["sdec"]
