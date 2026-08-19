# -*- coding: utf-8 -*-
"""
net/messages.py
===============
Fig.1 协议消息 type 字符串常量（业务层）。
线上映射为 PBCS 风格 opcode，见 ``net/wire_codec.py``。
"""

# -------- Reg：注册（论文 2 往返）--------
REG_REQ = "REG_REQ"  # 保留 opcode；协议路径不再使用
REG_CTX = "REG_CTX"  # 保留；pk/ctx 已并入 REG_EVAL
REG_BLIND = "REG_BLIND"  # C→S：id, a, ctx（报告通信量剔除 ctx）
REG_EVAL = "REG_EVAL"  # S→C：K, X, ã（报告通信量剔除 pk）
REG_COMMIT = "REG_COMMIT"  # C→S：提交 c
REG_ACK = "REG_ACK"  # S→C：确认

# -------- Ext：提取令牌（1 往返；ctx 本地）--------
EXT_REQ = "EXT_REQ"  # 保留；协议路径不再使用
EXT_CTX = "EXT_CTX"  # 保留；ctx 由 Client 本地持有
EXT_BLIND = "EXT_BLIND"  # C→S：id+a
EXT_EVAL = "EXT_EVAL"  # S→C：ã

# -------- Enc：提交密文 --------
ENC_COMMIT = "ENC_COMMIT"  # C→S：{id, c_prime, ct0,ct1,tau,ct2_len}
ENC_ACK = "ENC_ACK"  # S→C：是否接受

# -------- Dec：解密协助 --------
DEC_REQ = "DEC_REQ"  # C→S：{id}
DEC_RESP = "DEC_RESP"  # S→C：{ct0,ct1,tau,ct2_len,d}

# -------- 错误 --------
ERR = "ERR"  # S→C：错误码与说明
