"""HSM 长期认证密钥持久化存储模块。

管理 HSM Schnorr 签名密钥的生命周期：首次启动时生成并写入磁盘，
后续重启从 ``hsm_attest.json`` 加载，保证 Client 持有的 HSM 公钥
在进程重启后仍然有效。

HSM 角色
--------
本模块仅服务于 ``HSMAttestation``：提供 HSM 用于 ↪ x 签名的长期密钥对。
该密钥与单次 Init/Rec 会话无关，跨所有协议阶段和会话共享。

会话生命周期
------------
长期密钥独立于 SSID 会话：会话创建/销毁不影响认证密钥的加载与使用。
"""

from __future__ import annotations

import json
from pathlib import Path

from crypto.group import GROUP, Scalar
from crypto.schnorr import Schnorr, SchnorrPublicKey, SchnorrSecretKey

# ─────────────────────────────────────────────────────────────────────────────
# 默认密钥文件路径
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_KEY_DIR = Path(__file__).resolve().parent / "keys"
KEY_FILE = "hsm_attest.json"


# ─────────────────────────────────────────────────────────────────────────────
# HSM 密钥存储类
# ─────────────────────────────────────────────────────────────────────────────


class HSMKeyStore:
    """HSM Schnorr 认证密钥的磁盘读写管理器。

    密钥以 JSON 格式存储于 ``{key_dir}/hsm_attest.json``，
    包含公钥点 y 与私钥标量 x 的十六进制编码。
    """

    def __init__(self, key_dir: Path | None = None) -> None:
        """初始化密钥存储路径。

        输入:
            key_dir: 密钥目录；默认使用 ``hsm/keys/``。
        """
        self.key_dir = key_dir or DEFAULT_KEY_DIR
        self.key_path = self.key_dir / KEY_FILE

    def load_or_create(self, schnorr: Schnorr) -> tuple[SchnorrPublicKey, SchnorrSecretKey]:
        """加载已有密钥，或在不存在时生成新密钥并持久化。

        阶段: ``HSMAttestation`` 初始化时调用（HSM 启动阶段）。

        输入:
            schnorr: Schnorr 签名方案实例，用于密钥生成。

        输出:
            (SchnorrPublicKey, SchnorrSecretKey): HSM 长期认证密钥对。
        """
        if self.key_path.is_file():
            return self._load()  # 重启后加载已有长期密钥，保证 Client 公钥不变
        self.key_dir.mkdir(parents=True, exist_ok=True)
        pk, sk, _ = schnorr.keygen()
        self._save(pk, sk)  # 首次启动：生成并持久化 HSM 认证密钥对
        return pk, sk

    def _save(self, pk: SchnorrPublicKey, sk: SchnorrSecretKey) -> None:
        """将密钥对序列化写入 JSON 文件（内部方法）。"""
        data = {
            "pk": pk.y.serialize().hex(),  # 椭圆曲线公钥点
            "sk": sk.x.value.to_bytes(32, "big").hex(),  # 私钥标量（32 字节大端）
        }
        self.key_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def _load(self) -> tuple[SchnorrPublicKey, SchnorrSecretKey]:
        """从 JSON 文件反序列化密钥对（内部方法）。"""
        data = json.loads(self.key_path.read_text(encoding="utf-8"))
        pk = SchnorrPublicKey(y=GROUP.deserialize_point(bytes.fromhex(data["pk"])))
        sk = SchnorrSecretKey(x=Scalar(int.from_bytes(bytes.fromhex(data["sk"]), "big")))
        return pk, sk
