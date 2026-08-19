#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
main.py
=======
PassCrypt-PAEE 本地单服务器命令行入口（严格按 Fig.1 流程）。

用法：
  python main.py server
  python main.py client register --id alice --password secret
  python main.py client encrypt  --id alice --password secret --in file.bin
  python main.py client decrypt  --id alice --password secret --out out.bin
  python main.py demo --in file.bin
"""

from __future__ import annotations

import argparse  # 命令行参数解析
import hashlib  # demo 中打印明文哈希对比
import socket  # 服务器监听套接字
import threading  # 每连接一线程；demo 后台起 server
import time  # demo 等待 server 就绪
from pathlib import Path  # 路径与文件读写

import yaml  # 读取 config.yaml

from net.client_api import decrypt, encrypt, register  # 客户端 Fig.1 API
from net.server_api import PAEEServer  # 服务器会话处理
from paee.params import SerKGen, Setup  # Setup / SerKGen
from paee.protocol import PAEEServerState  # 服务器协议状态
from storage.local import LocalStore  # 本地磁盘存储


def load_config(path: str = "config.yaml") -> dict:
    """加载 YAML 配置（网络地址、存储根目录、λ 等）。"""
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def run_server(cfg: dict) -> None:
    """
    启动 Fig.1 Storage Server：
      1) Setup / 加载或生成 SerKGen 密钥
      2) 从磁盘恢复已有 rec/ct
      3) 监听 TCP，接受连接并处理 Reg/Ext/Enc/Dec
    """
    host = cfg["network"]["host"]  # 本地版默认 127.0.0.1
    port = int(cfg["network"]["port"])  # 默认 5202
    store = LocalStore(cfg["storage"]["local_root"])  # 数据目录
    pp = Setup(cfg["crypto"]["lambda_bytes"])  # 公开参数
    sk = store.load_sk()  # 尝试加载已有 sk
    if sk is None:
        sk = SerKGen(pp)  # 首次运行：生成 (k,x)/(K,X)
        store.save_sk(sk)
        print("[SERVER] generated new sk=(k,x), pk=(K,X)")
    else:
        store.save_pk(sk)  # 确保带外 pk 文件存在
        print("[SERVER] loaded sk from disk")
    print(f"[SERVER] pk also at {store.keys / 'server_pk.json'} (Reg sends on wire)")
    state = PAEEServerState(pp, sk)  # 内存协议状态
    # ---- 启动时灌入已有记录，避免重启丢内存 ----
    for p in Path(store.records).glob("*.json"):
        from paee import serde
        import json

        rec = serde.import_rec(json.loads(p.read_text(encoding="utf-8")))
        state.records[rec.id] = rec  # 恢复 rec
        ct = store.get_ct(rec.id)
        if ct:
            state.ciphertexts[rec.id] = ct  # 恢复 ct

    srv = PAEEServer(state, store)  # 绑定存储
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # 便于重启绑定
        s.bind((host, port))
        s.listen(8)  # 小队列即可
        from crypto_backend import group as bg

        print(f"[SERVER] group backend={bg.ACTIVE_BACKEND} ({bg.BACKEND_NAME}) curve={pp.curve}")
        print(f"[SERVER] Fig.1 PAEE (3HashSDHI) listening on {host}:{port}")
        while True:
            conn, addr = s.accept()  # 阻塞接受
            print(f"[SERVER] connection from {addr}")
            # 每连接一守护线程，互不影响
            threading.Thread(target=_serve_one, args=(srv, conn), daemon=True).start()


def _serve_one(srv: PAEEServer, conn: socket.socket) -> None:
    """单连接处理包装：自动关闭套接字并打印异常。"""
    with conn:
        try:
            srv.handle(conn)  # 进入消息循环
        except Exception as exc:
            print(f"[SERVER] handler error: {exc}")


def run_client(cfg: dict, args: argparse.Namespace) -> None:
    """
    客户端子命令分发：
      register / encrypt / decrypt
    公钥 pk 缓存在 client_work/{id}_pk.json（非秘密，仅方便本地使用）。
    """
    host = cfg["network"]["host"]
    port = int(cfg["network"]["port"])
    pp = Setup(cfg["crypto"]["lambda_bytes"])
    Path(cfg["paths"]["client_work"]).mkdir(parents=True, exist_ok=True)

    if args.action == "register":
        pk, ctx = register(host, port, pp, args.id, args.password)
        _save_pk(cfg, args.id, pk)
        _save_ctx(cfg, args.id, ctx)
        print(f"[CLIENT] Reg ok for id={args.id} (pk+ctx cached locally)")
    elif args.action == "encrypt":
        pk = _load_pk(cfg, args.id)
        ctx = _load_ctx(cfg, args.id)
        data = Path(args.infile).read_bytes()
        ct = encrypt(host, port, pp, pk, args.id, args.password, data, ctx=ctx)
        ct2_path = Path(cfg["paths"]["client_work"]) / f"{args.id}_ct2.bin"
        ct2_path.write_bytes(ct.ct2)
        print(
            f"[CLIENT] Enc ok; |ct2|={len(ct.ct2)} (local {ct2_path.name}) "
            f"tau={ct.tau.hex()[:16]}..."
        )
    elif args.action == "decrypt":
        pk = _load_pk(cfg, args.id)
        ctx = _load_ctx(cfg, args.id)
        ct2_path = Path(cfg["paths"]["client_work"]) / f"{args.id}_ct2.bin"
        local_ct2 = ct2_path.read_bytes() if ct2_path.is_file() else None
        m = decrypt(
            host,
            port,
            pp,
            pk,
            args.id,
            args.password,
            local_ct2=local_ct2,
            ctx=ctx,
        )
        out = Path(args.outfile)
        out.write_bytes(m)
        print(f"[CLIENT] Dec ok → {out} ({len(m)} bytes)")
    else:
        raise SystemExit(f"unknown action {args.action}")


def _pk_path(cfg: dict, id: str) -> Path:
    return Path(cfg["paths"]["client_work"]) / f"{id}_pk.json"


def _ctx_path(cfg: dict, id: str) -> Path:
    return Path(cfg["paths"]["client_work"]) / f"{id}_ctx.bin"


def _save_pk(cfg, id, pk) -> None:
    import json
    from paee import serde

    _pk_path(cfg, id).write_text(
        json.dumps(serde.export_pk(pk), indent=2), encoding="utf-8"
    )


def _load_pk(cfg, id):
    import json
    from paee import serde

    path = _pk_path(cfg, id)
    if not path.is_file():
        raise SystemExit(f"missing local pk {path}; run register first")
    return serde.import_pk(json.loads(path.read_text(encoding="utf-8")))


def _save_ctx(cfg, id: str, ctx: bytes) -> None:
    _ctx_path(cfg, id).write_bytes(ctx)


def _load_ctx(cfg, id: str) -> bytes:
    path = _ctx_path(cfg, id)
    if not path.is_file():
        raise SystemExit(f"missing local ctx {path}; run register first")
    return path.read_bytes()


def run_demo(cfg: dict, infile: str) -> None:
    """
    一键演示：后台线程起本地 server，前台跑完整
      Reg → Enc → Dec
    并用 SHA-256 核对明文是否一致。
    """
    host = "127.0.0.1"  # demo 强制本机
    # 选空闲端口，避免与残留 server 抢 5202
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as _tmp:
        _tmp.bind((host, 0))
        port = _tmp.getsockname()[1]
    # 浅拷贝配置，避免污染调用方；改用独立 demo 存储目录
    cfg = dict(cfg)
    cfg["storage"] = dict(cfg["storage"])
    cfg["storage"]["local_root"] = "./data/demo_server"
    cfg["network"] = dict(cfg["network"])
    cfg["network"]["host"] = host
    cfg["network"]["port"] = port

    # 清空上次 demo 数据，保证可重复
    import shutil

    root = Path(cfg["storage"]["local_root"])
    if root.exists():
        shutil.rmtree(root)

    # 后台启动服务器
    t = threading.Thread(target=run_server, args=(cfg,), daemon=True)
    t.start()
    time.sleep(0.6)  # 等待 listen 就绪

    pp = Setup(cfg["crypto"]["lambda_bytes"])
    Path(cfg["paths"]["client_work"]).mkdir(parents=True, exist_ok=True)
    uid = "demo_user"  # 固定演示账号
    pw = "demo-password-16b"
    # 若提供输入文件则加密该文件，否则用内置短消息
    data = Path(infile).read_bytes() if infile else b"hello Fig.1 PAEE"

    print(f"[DEMO] server {host}:{port}")
    from net.client_api import PAEEClientSession

    time.sleep(0.2)  # listen 已就绪；pk 由 Reg 线上下发
    with PAEEClientSession(host, port, pp) as sess:
        print("[DEMO] Reg...")
        pk, _ctx = sess.register(uid, pw)
        print("[DEMO] Enc...")
        ct = sess.encrypt(pk, uid, pw, data)
        print("[DEMO] Dec...")
        m = sess.decrypt(pk, uid, pw, local_ct2=ct.ct2)
    ok = m == data  # 明文是否一致
    print(f"[DEMO] plaintext match: {ok}")
    print(f"[DEMO] sha256 in ={hashlib.sha256(data).hexdigest()}")
    print(f"[DEMO] sha256 out={hashlib.sha256(m).hexdigest()}")
    if not ok:
        raise SystemExit(1)  # 失败退出码非 0


def main() -> None:
    """解析 CLI 并分发到 server / client / demo。"""
    parser = argparse.ArgumentParser(description="PassCrypt PAEE (Fig.1)")
    sub = parser.add_subparsers(dest="cmd", required=True)  # 必选子命令

    sub.add_parser("server")  # 启动服务器

    c = sub.add_parser("client")  # 客户端
    c.add_argument("action", choices=["register", "encrypt", "decrypt"])
    c.add_argument("--id", required=True)  # 用户 id
    c.add_argument("--password", required=True)  # 口令 pw
    c.add_argument("--in", dest="infile")  # 加密输入文件
    c.add_argument("--out", dest="outfile")  # 解密输出文件

    d = sub.add_parser("demo")  # 一键演示
    d.add_argument("--in", dest="infile", default="")

    args = parser.parse_args()
    cfg = load_config()  # 读配置

    if args.cmd == "server":
        run_server(cfg)
    elif args.cmd == "client":
        if args.action == "encrypt" and not args.infile:
            raise SystemExit("--in required")
        if args.action == "decrypt" and not args.outfile:
            raise SystemExit("--out required")
        run_client(cfg, args)
    elif args.cmd == "demo":
        run_demo(cfg, args.infile)


if __name__ == "__main__":
    # 脚本直接运行时进入 CLI
    main()
