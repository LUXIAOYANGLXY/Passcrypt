"""Flask HTTP API — 本地 PPKR Server 仿真层。

HTTP 通信流程（Client ↔ Server ↔ HSM）::

    Client (run_client.py)
        │  GET  /api/v1/hsm_pubkey          获取 HSM Schnorr 认证公钥
        │  POST /api/v1/encpw_plus          π_encPw+ 各 phase 消息
        │  POST /api/v1/oprf_ppkr           π_OPRF-PPKR 各 phase 消息
        ▼
    Server (本模块 app.py + ppkr_server.py)
        │  解析 JSON → ProtocolMessage
        │  按 phase 路由至 PPKRServer → HSMCore
        │  返回 {"attested": "<hex>"} 认证响应
        ▼
    HSM (hsm/hsm_core.py)
        执行 ElGamal / OPRF / Schnorr 等密码学运算

会话边界：
    encPw+     — InitS/Init 开始，Rec 结束
    OPRF-PPKR  — Init 开始，RecSign 结束

辅助端点：
    POST /api/v1/sim/leak  — 模拟 HSM 文件泄露（安全实验）
    GET  /api/v1/stats     — 返回累积请求/会话延迟 JSON
"""

from __future__ import annotations

import atexit
import json
import logging
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
# 直接 ``python server/app.py`` 时 cwd 可能不在项目根，需手动插入 ROOT 以保证 import
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from flask import Flask, jsonify, request

from common.wire_codec import b64e
from config import SID
from logging_config import setup_logger
from protocols.messages import ProtocolMessage
from server.ppkr_server import PPKRServer
from server.request_stats import RequestStats

log = setup_logger("SERVER")
# 压低 Werkzeug 访问日志，避免与业务 log 重复刷屏
logging.getLogger("werkzeug").setLevel(logging.WARNING)
app = Flask(__name__)
# Flask 默认 logger 会重复输出；清空并禁止 propagate，统一走 setup_logger
app.logger.handlers.clear()
app.logger.propagate = False

# 进程内单例：所有 HTTP 请求共享同一 HSM 状态（模拟真实 Server↔HSM 绑定）
_server = PPKRServer(sid=SID("server-1"))
_stats = RequestStats()

# 完整会话的 wall-clock 统计：从首 phase 到末 phase（见 _maybe_begin/end_session）
_SESSION_START_PHASES = {
    "encPw+": {"InitS"},       # encPw+ Init 子协议起点
    "OPRF-PPKR": {"Init"},     # OPRF Init 子协议起点（盲化 POST）
}
_SESSION_END_PHASES = {
    "encPw+": {"Rec"},         # Rec 提交密文后 HSM 完成恢复
    "OPRF-PPKR": {"RecSign"},  # Schnorr 验签通过后 Rec 结束
}


def _log_stats_summary(title: str = "Server 耗时统计") -> None:
    """将 RequestStats 摘要写入日志。"""
    log.info("========== %s ==========", title)
    for line in _stats.summary_lines():
        log.info(line)


@atexit.register
def _on_shutdown() -> None:
    """进程退出时打印累积耗时汇总（Ctrl+C 或正常结束）。"""
    # 无样本则跳过，避免空实验退出时输出无意义汇总
    if _stats.request_latencies_ms or _stats.session_latencies_ms:
        _log_stats_summary("Server 退出汇总")


@app.before_request
def _log_request_in() -> None:
    """记录进入的 API 请求（方法 + 路径）。"""
    # 仅记录 /api/ 前缀，过滤 Flask 静态资源等噪声
    if request.path.startswith("/api/"):
        log.info("<- HTTP %s %s", request.method, request.path)


@app.after_request
def _log_request_out(response):
    """记录 API 响应状态码。"""
    if request.path.startswith("/api/"):
        log.info("-> HTTP %s %s status=%s", request.method, request.path, response.status_code)
    return response


def _maybe_begin_session(protocol: str, msg: ProtocolMessage) -> None:
    """若当前 phase 为会话起点，则开始计时。"""
    # 按 (protocol, idc) 区分并发用户；同一 idc 重复 Init 时 begin_session 只记最早起点
    if msg.phase in _SESSION_START_PHASES.get(protocol, set()):
        _stats.begin_session(protocol, msg.idc)


def _maybe_end_session(protocol: str, msg: ProtocolMessage) -> None:
    """若当前 phase 为会话终点，则结束计时并打印会话摘要。"""
    if msg.phase not in _SESSION_END_PHASES.get(protocol, set()):
        return
    session_ms = _stats.end_session(protocol, msg.idc)
    if session_ms is not None:
        log.info(
            "[%s] 完整会话结束 idc=%s ssid=%s 会话耗时=%.2f ms",
            protocol,
            msg.idc,
            msg.ssid,
            session_ms,
        )
        # 每次完整 Init+Rec 结束后刷新累计统计，便于长跑实验观察
        _log_stats_summary("累计耗时统计")


def _handle_protocol(protocol: str, handler):
    """通用协议 POST 处理：解析消息 → 转发 HSM → 记录耗时 → 返回 JSON。

    Args:
        protocol: 协议显示名（``"encPw+"`` / ``"OPRF-PPKR"``）
        handler: ``PPKRServer.encpw_handle`` 或 ``oprf_handle``

    Returns:
        Flask ``jsonify({"attested": hex})`` 响应
    """
    # HTTP JSON → ProtocolMessage：此后进入协议层，不再接触原始 request 对象
    data = request.get_json()
    msg = ProtocolMessage.from_json(json.dumps(data))
    _maybe_begin_session(protocol, msg)

    t0 = time.perf_counter()
    log.info(
        "[%s] 收到 Client 消息 phase=%s ssid=%s idc=%s body_keys=%s",
        protocol,
        msg.phase,
        msg.ssid,
        msg.idc,
        list(msg.body.keys()),
    )
    # handler 为 encpw_handle / oprf_handle：Server 仅路由，密码学在 HSMCore
    result = handler(msg)
    elapsed_ms = (time.perf_counter() - t0) * 1000
    _stats.record_request(elapsed_ms)

    attested_len = len(result.get("attested", "")) // 2 if result.get("attested") else 0
    log.info(
        "[%s] 转发 HSM 完成 phase=%s ssid=%s idc=%s 响应=%d bytes 单请求耗时=%.2f ms",
        protocol,
        msg.phase,
        msg.ssid,
        msg.idc,
        attested_len,
        elapsed_ms,
    )
    _maybe_end_session(protocol, msg)
    return jsonify(result)


@app.route("/api/v1/hsm_pubkey", methods=["GET"])
def hsm_pubkey():
    """返回 HSM Schnorr 认证公钥（Client 启动时首次调用）。

    不经 _handle_protocol：无 phase/ssid，Client 用此公钥验证所有后续 attested。
    """
    t0 = time.perf_counter()
    # 从 HSMCore 读取长期认证公钥，Server 本身不生成密钥
    pk = b64e(_server.hsm_attestation_pk.serialize())
    elapsed_ms = (time.perf_counter() - t0) * 1000
    _stats.record_request(elapsed_ms)
    log.info("返回 HSM 认证公钥 (%d bytes) 单请求耗时=%.2f ms", len(pk) // 2, elapsed_ms)
    return jsonify({"pk": pk})


@app.route("/api/v1/encpw_plus", methods=["POST"])
def encpw_plus():
    """π_encPw+ 协议消息入口（InitS / Init / RecS / Rec）。"""
    # 所有 phase 共用同一路由，由 msg.phase 在 PPKRServer.encpw_handle 内分发
    return _handle_protocol("encPw+", _server.encpw_handle)


@app.route("/api/v1/oprf_ppkr", methods=["POST"])
def oprf_ppkr():
    """π_OPRF-PPKR 协议消息入口（Init / InitFinish / Rec / RecSign）。"""
    return _handle_protocol("OPRF-PPKR", _server.oprf_handle)


@app.route("/api/v1/sim/leak", methods=["POST"])
def sim_leak():
    """模拟 HSM 持久化文件泄露（论文安全分析实验辅助）。"""
    # 直接调用 HSMCore.leak_files，不经过协议 phase 路由
    files = _server.leak_hsm_files()
    log.info("模拟 HSM 文件泄露，泄露 %d 条记录", len(files))
    return jsonify({"leaked_count": len(files)})


@app.route("/api/v1/stats", methods=["GET"])
def stats():
    """返回 Server 累积的请求/会话延迟原始数据（JSON）。"""
    # 供外部脚本拉取原始样本，与日志中的 summary_lines 摘要互补
    return jsonify(
        {
            "requests": len(_stats.request_latencies_ms),
            "sessions": len(_stats.session_latencies_ms),
            "request_latencies_ms": _stats.request_latencies_ms,
            "session_latencies_ms": _stats.session_latencies_ms,
        }
    )


if __name__ == "__main__":
    log.info("PPKR Server 启动 http://127.0.0.1:5000")
    # threaded=True：并发处理多 Client 请求；debug=False 避免 reloader 双进程
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
