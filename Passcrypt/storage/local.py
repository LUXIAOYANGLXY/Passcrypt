# -*- coding: utf-8 -*-
"""
storage/local.py
================
本地版持久化：把 Fig.1 的 sk / rec / ct 存到文件系统。

目录布局（相对 local_root）：
  keys/server_sk.json          — sk=(k,x) 与 pk=(K,X)
  records/{id}.json            — rec=(id,ctx,c)
  objects/{id}/ct.json         — ct=(ct0,ct1,ct2,τ)

云部署时可替换为 S3 等后端，只要保持同样语义接口即可。
"""

from __future__ import annotations

import json  # JSON 文件读写
from pathlib import Path  # 路径操作
from typing import Optional

from paee import serde  # Fig.1 对象 ↔ dict
from paee.types import Ciphertext, PasswordRecord, ServerKey


class LocalStore:
    """基于本地磁盘的简单 KV 存储。"""

    def __init__(self, root: str | Path):
        self.root = Path(root)  # 存储根目录
        self.keys = self.root / "keys"  # 服务器密钥目录
        self.records = self.root / "records"  # 口令记录目录
        self.objects = self.root / "objects"  # 密文对象目录
        # 确保目录存在
        for d in (self.keys, self.records, self.objects):
            d.mkdir(parents=True, exist_ok=True)

    def save_sk(self, sk: ServerKey) -> None:
        """把 SerKGen 生成的密钥写入磁盘；同时写带外分发用的 server_pk.json。"""
        path = self.keys / "server_sk.json"
        path.write_text(json.dumps(serde.export_sk(sk), indent=2), encoding="utf-8")
        self.save_pk(sk)

    def save_pk(self, sk: ServerKey) -> None:
        """仅公钥 pk=(K,X)，供 Client 带外加载（不进 TCP）。"""
        path = self.keys / "server_pk.json"
        path.write_text(json.dumps(serde.export_pk(sk), indent=2), encoding="utf-8")

    def load_pk(self) -> Optional[ServerKey]:
        """加载带外公钥；无则尝试从 sk 文件导出。"""
        path = self.keys / "server_pk.json"
        if path.exists():
            return serde.import_pk(json.loads(path.read_text(encoding="utf-8")))
        sk = self.load_sk()
        if sk is None:
            return None
        return ServerKey(k=0, x=0, K=sk.K, X=sk.X)

    def load_sk(self) -> Optional[ServerKey]:
        """加载已有服务器密钥；不存在则返回 None（由上层 SerKGen）。"""
        path = self.keys / "server_sk.json"
        if not path.exists():
            return None
        return serde.import_sk(json.loads(path.read_text(encoding="utf-8")))

    def put_record(self, rec: PasswordRecord) -> None:
        """持久化 rec := (id, ctx, c)。"""
        path = self.records / f"{_safe(rec.id)}.json"
        path.write_text(json.dumps(serde.export_rec(rec), indent=2), encoding="utf-8")

    def get_record(self, id: str) -> Optional[PasswordRecord]:
        """按 id 读取口令记录。"""
        path = self.records / f"{_safe(id)}.json"
        if not path.exists():
            return None
        return serde.import_rec(json.loads(path.read_text(encoding="utf-8")))

    def put_ct(self, id: str, ct: Ciphertext) -> None:
        """持久化 ct := (ct0, ct1, ct2, τ)。"""
        d = self.objects / _safe(id)
        d.mkdir(parents=True, exist_ok=True)
        (d / "ct.json").write_text(json.dumps(serde.export_ct(ct), indent=2), encoding="utf-8")

    def get_ct(self, id: str) -> Optional[Ciphertext]:
        """读取用户密文。"""
        path = self.objects / _safe(id) / "ct.json"
        if not path.exists():
            return None
        return serde.import_ct(json.loads(path.read_text(encoding="utf-8")))


def _safe(id: str) -> str:
    """
    把任意 id 映射为安全文件名：
    仅保留字母数字与 -_，其余替换为下划线，避免路径穿越。
    """
    return "".join(c if c.isalnum() or c in "-_" else "_" for c in id)
