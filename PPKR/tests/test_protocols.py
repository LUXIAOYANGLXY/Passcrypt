"""PPKR 协议与密码学原语单元测试。

覆盖范围
--------
1. **原语层**：DHIES / ElGamal 往返、畸形密文拒绝、AES 反序列化校验、
   Schnorr 签名、RFC 9380 hash-to-curve 标准向量。
2. **HSM 行为**：会话在 Init/Rec 后清理、认证密钥跨实例持久化、
   ``leak_hsm_files`` 深拷贝隔离。
3. **协议层**：π_encPw+ / π_OPRF-PPKR 完整 Init→Rec 流程、错误密码、
   CTR 耗尽触发 DelRec、Lev-2 不存储明文密码。

运行::

    python -m pytest tests/ -v
"""

from __future__ import annotations

import pytest

from config import CTR_MAX, IDC, SID
from crypto.dhies import DHIES, DHIESCiphertext
from crypto.elgamal import ElGamal, deserialize_elgamal
from crypto.schnorr import Schnorr
from protocols.encpw_plus import EncPwPlusClient
from protocols.oprf_ppkr import OPRFPPKRClient
from run_local import run_encpw_plus, run_oprf_ppkr
from server.ppkr_server import PPKRServer
from common.attested_wire import attested_raw


def test_dhies_roundtrip():
    """DHIES 加解密往返：明文应完整恢复。"""
    dh = DHIES()
    pk, sk, _ = dh.keygen()
    pt = b"hello ppkr test payload"
    ct, _ = dh.enc(pk, pt)
    out, _ = dh.dec(sk, ct)
    assert out == pt


def test_elgamal_serialize_roundtrip():
    """ElGamal 线格式序列化/反序列化后仍可正确解密。"""
    eg = ElGamal()
    pk, sk, _ = eg.keygen()
    pt = b"elgamal payload"
    ct, _ = eg.enc(pk, pt)
    wire = ct.serialize()
    ct2 = deserialize_elgamal(wire)
    out, _ = eg.dec(sk, ct2)
    assert out == pt


def test_dhies_malformed_ciphertext_returns_none():
    """畸形 DHIES 密文（过短或截断）应返回 None，而非抛异常。"""
    dh = DHIES()
    pk, sk, _ = dh.keygen()
    pt = b"hello ppkr test payload"
    ct, _ = dh.enc(pk, pt)
    out, _ = dh.dec(sk, DHIESCiphertext(raw=b"\x00"))
    assert out is None
    out2, _ = dh.dec(sk, DHIESCiphertext(raw=ct.raw[:-5]))
    assert out2 is None


def test_deserialize_aes_rejects_short_input():
    """AES-GCM 反序列化对空/过短输入应抛出 ValueError。"""
    from crypto.aes_gcm import deserialize_aes

    with pytest.raises(ValueError):
        deserialize_aes(b"")


def test_leak_all_deepcopy_isolation():
    """leak_hsm_files 返回深拷贝：修改泄漏快照不影响 HSM 内真实存储。"""
    sid = SID("srv")
    server = PPKRServer(sid=sid)
    client = EncPwPlusClient(sid=sid, idc=IDC("leak_snap_user"), hsm_pk=server.hsm_attestation_pk)
    ssid = client.new_ssid()
    r1 = server.encpw_handle(client.init_start(ssid))
    msg2, K, _ = client.init_on_pk(attested_raw(r1), ssid, "leak_snap")
    server.encpw_handle(msg2)

    leaked = server.leak_hsm_files()
    assert len(leaked) >= 1
    leaked[0].ctr = 0  # 仅改快照
    live = server.hsm.storage.retrieve_encpw_plus("leak_snap_user")
    assert live is not None
    assert live.ctr == 10  # 真实记录仍为 CTR_MAX


def test_hash_to_curve_rfc9380_vector():
    """RFC 9380 P-256 hash-to-curve 官方测试向量应精确匹配。"""
    from crypto.hash_to_curve import RFC9380_TEST_DST, hash_to_curve_p256

    x, y = hash_to_curve_p256(b"abc", dst=RFC9380_TEST_DST)
    assert x == int("0bb8b87485551aa43ed54f009230450b492fead5f1cc91658775dac4a3388a0f", 16)
    assert y == int("5c41b3d0731a27a7b14bc0bf0ccded2d8751f83493404c84a88e71ffd424212e", 16)


def test_hsm_session_cleared_after_init():
    """encPw+ Init 完成后，HSM 应清除对应 SSID 的临时会话。"""
    sid = SID("srv")
    server = PPKRServer(sid=sid)
    client = EncPwPlusClient(sid=sid, idc=IDC("sess_u"), hsm_pk=server.hsm_attestation_pk)
    ssid = client.new_ssid()
    r1 = server.encpw_handle(client.init_start(ssid))
    assert ssid in server.hsm._sessions  # InitS 后会话存在
    msg2, K, _ = client.init_on_pk(attested_raw(r1), ssid, "pw")
    server.encpw_handle(msg2)
    assert ssid not in server.hsm._sessions  # Init 完成后已清理


def test_hsm_attest_key_persistence(tmp_path):
    """HSM 认证 Schnorr 密钥应持久化到 key_dir，重启后公钥不变。"""
    from crypto.schnorr import Schnorr
    from hsm.attest import HSMAttestation

    s = Schnorr()
    a1 = HSMAttestation(s, key_dir=tmp_path)
    pk1 = a1.public_key.serialize().hex()
    a2 = HSMAttestation(Schnorr(), key_dir=tmp_path)
    pk2 = a2.public_key.serialize().hex()
    assert pk1 == pk2


def test_schnorr_roundtrip():
    """Schnorr 签名与验签应对同一消息返回 True。"""
    s = Schnorr()
    pk, sk, _ = s.keygen()
    msg = b"transcript binding"
    sig, _ = s.sign(sk, pk, msg)
    ok, _ = s.verify(pk, msg, sig)
    assert ok


def test_encpw_plus_init_rec():
    """π_encPw+ 本地端到端：Init 后 Rec 应恢复 32 字节对称密钥 K（AES-256）。"""
    K = run_encpw_plus(pw="testpassword123", idc="user1")
    assert len(K) == 32


def test_encpw_plus_wrong_password_fails():
    """Rec 阶段提交错误密码应返回 Fail，不泄露 K。"""
    sid = SID("srv")
    server = PPKRServer(sid=sid)
    client = EncPwPlusClient(sid=sid, idc=IDC("u1"), hsm_pk=server.hsm_attestation_pk)
    pw = "right_password"

    ssid = client.new_ssid()
    r1 = server.encpw_handle(client.init_start(ssid))
    msg2, K, _ = client.init_on_pk(attested_raw(r1), ssid, pw)
    r3 = server.encpw_handle(msg2)
    client.init_finish(attested_raw(r3), ssid, K)

    ssid2 = client.new_ssid()
    r1 = server.encpw_handle(client.rec_start(ssid2))
    msg2, ksym, _ = client.rec_on_pk(attested_raw(r1), ssid2, "wrong")
    r3 = server.encpw_handle(msg2)
    result, _ = client.rec_finish(attested_raw(r3), ssid2, ksym)
    assert result == "Fail"


def test_encpw_plus_ctr_deletion():
    """连续 CTR_MAX 次错误 Rec 后，第 CTR_MAX+1 次应返回 DelRec（记录删除）。"""
    sid = SID("srv")
    server = PPKRServer(sid=sid)
    client = EncPwPlusClient(sid=sid, idc=IDC("u2"), hsm_pk=server.hsm_attestation_pk)
    pw = "pw"

    ssid = client.new_ssid()
    r1 = server.encpw_handle(client.init_start(ssid))
    msg2, K, _ = client.init_on_pk(attested_raw(r1), ssid, pw)
    r3 = server.encpw_handle(msg2)
    client.init_finish(attested_raw(r3), ssid, K)

    for i in range(CTR_MAX):
        ssid2 = client.new_ssid()
        r1 = server.encpw_handle(client.rec_start(ssid2))
        msg2, ksym, _ = client.rec_on_pk(attested_raw(r1), ssid2, "bad")
        r3 = server.encpw_handle(msg2)
        result, _ = client.rec_finish(attested_raw(r3), ssid2, ksym)
        assert result == "Fail"

    ssid3 = client.new_ssid()
    r1 = server.encpw_handle(client.rec_start(ssid3))
    msg2, ksym, _ = client.rec_on_pk(attested_raw(r1), ssid3, "bad")
    r3 = server.encpw_handle(msg2)
    result, _ = client.rec_finish(attested_raw(r3), ssid3, ksym)
    assert result == "DelRec"


def test_oprf_ppkr_init_rec():
    """π_OPRF-PPKR 本地端到端：Init 后 Rec 应恢复 32 字节对称密钥 K（AES-256）。"""
    K = run_oprf_ppkr(pw="oprf_secret", idc="user3")
    assert len(K) == 32


def test_hsm_leak_does_not_expose_plaintext_encpw():
    """Lev-2 泄漏快照中不应含明文密码字段；仅保留哈希表示 h。"""
    sid = SID("srv")
    server = PPKRServer(sid=sid)
    run_encpw_plus(pw="leak_test", idc="leak_user")
    # 复用同一 Server 实例完成 Init，再检查泄漏内容
    ssid = __import__("uuid").uuid4()
    client = EncPwPlusClient(sid=sid, idc=IDC("leak_user"), hsm_pk=server.hsm_attestation_pk)
    ssid = client.new_ssid()
    r1 = server.encpw_handle(client.init_start(ssid))
    msg2, K, _ = client.init_on_pk(attested_raw(r1), ssid, "leak_test")
    server.encpw_handle(msg2)

    leaked = server.leak_hsm_files()
    assert len(leaked) >= 1
    f = leaked[0]
    assert not hasattr(f, "pw")  # 无明文密码属性
    assert f.h  # 存在密码哈希表示
