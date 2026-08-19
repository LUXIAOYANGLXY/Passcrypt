"""兼容入口：默认通信已改为 TCP，转发至 ``client.tcp_transport``。

历史名 ``PPKRHttpTransport`` / ``http_transport`` 仍可导入；
实际为 opcode + u16 LV binary over TCP（对齐 PAEE/PBCS）。
遗留 Flask HTTP 实现见 ``server/app.py``（需自行对接，非默认路径）。
"""

from client.tcp_transport import PPKRHttpTransport, PPKRTcpTransport, parse_endpoint

__all__ = ["PPKRHttpTransport", "PPKRTcpTransport", "parse_endpoint"]
