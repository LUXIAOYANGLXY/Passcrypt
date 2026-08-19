"""协议消息类型定义 — Client ↔ Server 统一传输格式。

本模块定义 PPKR 论文（Faller et al., CCS 2024）中 Client 与 Server 交互的
统一消息封装。所有协议（π_encPw+、π_OPRF-PPKR）均通过 ``ProtocolMessage``
在 HTTP 层传输；Server 根据 ``phase`` 字段路由至 HSM 对应处理逻辑。

架构角色
--------
- **Client (IDC)**：构造并发送 ``ProtocolMessage``，验证 HSM 认证响应。
- **Server (S)**：透明转发，不解析密码学载荷，按 phase 调用 HSM 接口。
- **HSM**：执行 Fig. 3/4 灰色方框内的密钥操作，返回 ``AttestedMessage``。

会话生命周期
------------
每条消息均携带 ``ssid``（单次 Init/Rec 会话标识）与 ``idc``（客户端身份）。
``sid`` 标识服务器实例，``phase`` 标识当前协议轮次，``body`` 承载该轮的
密码学载荷（密文、OPRF 盲化值、签名等）。同一 SSID 的三轮消息构成完整会话。

消息字段与论文符号对应
----------------------
    sid   → 服务器标识 SID
    ssid  → 单次会话标识 SSID（每次 Init/Rec 独立生成）
    idc   → 客户端身份标识 IDC
    phase → 协议阶段名（Init、Rec、InitS、InitFinish、RecSign 等）
    body  → 阶段相关的密码学载荷字典
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum

from config import IDC, SID, SSID


# ─────────────────────────────────────────────────────────────────────────────
# 协议阶段枚举
# ─────────────────────────────────────────────────────────────────────────────


class Phase(str, Enum):
    """协议阶段枚举（论文 Fig. 3/4 中的消息标签）。

    注：实际传输使用字符串 phase 字段，本枚举供类型提示与文档参考。
    """

    INIT = "Init"        # Fig. 3 Init / Fig. 4 Init(OPRF) 或 InitFinish 前的盲化轮
    REC = "Rec"          # Fig. 3 Rec / Fig. 4 Rec(OPRF) 或 RecSign 前的盲化轮
    INIT_RES = "InitRes" # Fig. 3/4 Init 最终响应（HSM → Client，经认证）
    REC_RES = "RecRes"   # Fig. 3/4 Rec 最终响应（Succ / Fail / DelRec）


# ─────────────────────────────────────────────────────────────────────────────
# 统一协议消息容器
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class ProtocolMessage:
    """Client ↔ Server 之间的统一协议消息容器。

    序列化为 JSON 后经 HTTP POST 发送；Server 反序列化后按 ``phase`` 分发至
    ``PPKRServer.encpw_handle`` 或 ``PPKRServer.oprf_handle``。
    """

    phase: str
    sid: SID
    ssid: SSID
    idc: IDC
    body: dict

    def to_json(self) -> str:
        """将消息序列化为 JSON 字符串，供 HTTP 传输层使用。

        阶段: Client 发送前 / Server 响应前。

        输入: 本对象各字段（phase, sid, ssid, idc, body）。

        输出: UTF-8 JSON 字符串。
        """
        # 五元组 (phase, sid, ssid, idc, body) 完整序列化，Server 按 phase 路由
        return json.dumps(
            {
                "phase": self.phase,   # 协议轮次标签，对应 Fig. 3/4 消息名
                "sid": self.sid,       # 服务器实例标识
                "ssid": self.ssid,     # 单次 Init/Rec 会话标识，贯穿三轮
                "idc": self.idc,       # 客户端身份
                "body": self.body,     # 该轮密码学载荷（密文、盲化值、签名等）
            }
        )

    @staticmethod
    def from_json(data: str) -> ProtocolMessage:
        """从 JSON 字符串反序列化协议消息（Server 端入口）。

        阶段: Server 收到 HTTP POST 请求后。

        输入:
            data: Client 发送的 JSON 字符串。

        输出:
            ProtocolMessage: 含 phase/sid/ssid/idc/body 的完整消息对象。
        """
        obj = json.loads(data)
        # Server 不解析 body 内密码学细节，仅按 phase 转发至 HSM 对应处理器
        return ProtocolMessage(
            phase=obj["phase"],
            sid=obj["sid"],
            ssid=obj["ssid"],
            idc=obj["idc"],
            body=obj["body"],
        )
