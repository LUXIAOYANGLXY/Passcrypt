# -*- coding: utf-8 -*-
"""本地协议与原语对照测试（Fig.1 v2）。"""

from __future__ import annotations

import unittest

from crypto_backend import group as bg
from paee import dleq, envelope, hashgroup, oprf, se
from paee.params import SerKGen, Setup
from paee.protocol import PAEEServerState
from paee import serde


class TestSE(unittest.TestCase):
    def test_gcm_roundtrip(self):
        key = b"\x11" * 32
        blob = se.SE_Enc(key, b"payload")
        self.assertEqual(se.SE_Dec(key, blob), b"payload")

    def test_gcm_bad_key(self):
        key = b"\x11" * 32
        blob = se.SE_Enc(key, b"x")
        self.assertIsNone(se.SE_Dec(b"\x22" * 32, blob))

    def test_ctr_roundtrip(self):
        key = b"\x33" * 32
        blob = se.SE_Enc_CTR(key, b"hello ctr plaintext")
        self.assertEqual(se.SE_Dec_CTR(key, blob), b"hello ctr plaintext")
        self.assertEqual(len(blob), 16 + len(b"hello ctr plaintext"))

    def test_ctr_empty(self):
        key = b"\x44" * 32
        blob = se.SE_Enc_CTR(key, b"")
        self.assertEqual(se.SE_Dec_CTR(key, blob), b"")


class TestGroup(unittest.TestCase):
    def test_mul_add(self):
        P = bg.g_mul(bg.g, 7)
        Q = bg.g_mul(bg.g, 3)
        self.assertTrue(bg.g_eq(bg.g_add(P, Q), bg.g_mul(bg.g, 10)))

    def test_hash_to_g(self):
        a = bg.hash_to_g(b"msg")
        self.assertTrue(bg.is_in_g(a))


class TestLocalProtocol(unittest.TestCase):
    def test_reg_enc_dec(self):
        pp = Setup(32)
        sk = SerKGen(pp)
        state = PAEEServerState(pp, sk)
        uid, pw = "u1", "test-pass-16chars"
        ctx = state.SReg_issue_ctx(uid)
        st = oprf.blind(pw)
        a_tilde = state.SReg_eval(uid, st.a)
        est = oprf.finalize(uid, ctx, pw, st, a_tilde, sk.K)
        c = oprf.derive_c(uid, ctx, pw, est.sigma)
        self.assertTrue(state.SReg_store(uid, c))

        m = b"file-bytes-xyz"
        c_prime, ct = envelope.Enc(pp, sk, uid, pw, est, m)
        self.assertTrue(state.Enc_store(uid, c_prime, ct))
        ct2, d = state.SDec(uid)
        self.assertEqual(envelope.client_dec(pp, pw, est, ct2, d), m)

    def test_wrong_c_prime(self):
        pp = Setup(32)
        sk = SerKGen(pp)
        state = PAEEServerState(pp, sk)
        uid, pw = "u2", "test-pass-16chars"
        ctx = state.SReg_issue_ctx(uid)
        st = oprf.blind(pw)
        a_tilde = state.SReg_eval(uid, st.a)
        est = oprf.finalize(uid, ctx, pw, st, a_tilde, sk.K)
        c = oprf.derive_c(uid, ctx, pw, est.sigma)
        state.SReg_store(uid, c)
        c_prime, ct = envelope.Enc(pp, sk, uid, pw, est, b"m")
        self.assertFalse(state.Enc_store(uid, b"\x00" * 32, ct))
        self.assertTrue(state.Enc_store(uid, c_prime, ct))

    def test_pk_serde(self):
        pp = Setup(32)
        sk = SerKGen(pp)
        obj = serde.export_pk(sk)
        pk = serde.import_pk(obj)
        self.assertTrue(bg.g_eq(pk.K, sk.K))
        self.assertTrue(bg.g_eq(pk.X, sk.X))
        self.assertEqual(obj["ser_ver"], 10)


if __name__ == "__main__":
    unittest.main()
