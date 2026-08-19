# -*- coding: utf-8 -*-
"""Fig.1（v2）原语单测：3HashSDHI POPRF（无 π wire）+ DHIES 信封。"""

from __future__ import annotations

import unittest

from crypto_backend import codec, group as bg
from paee import dleq, envelope, hashgroup, oprf
from paee.params import SerKGen, Setup
from paee.protocol import PAEEServerState


class TestCodec(unittest.TestCase):
    def test_g_size(self):
        self.assertEqual(codec.G_SIZE, 33)
        self.assertEqual(codec.SER_VER, 10)
        self.assertEqual(bg.CURVE_NAME, "secp256r1")
        self.assertIn("openssl", bg.BACKEND_NAME)


class TestOPRF(unittest.TestCase):
    def test_roundtrip(self):
        pp = Setup(32)
        sk = SerKGen(pp)
        id, ctx, pw = "alice", b"\x01" * 32, "password-16chars!"
        st = oprf.blind(pw)
        a_tilde = oprf.server_eval(sk, id, ctx, st.a)
        self.assertIsNotNone(a_tilde)
        est = oprf.finalize(id, ctx, pw, st, a_tilde, sk.K, pp.lambda_bytes)
        self.assertIsNotNone(est)
        c = oprf.derive_c(id, ctx, pw, est.sigma, pp.lambda_bytes)
        self.assertEqual(len(est.tk), 32)
        self.assertEqual(len(c), 32)
        # 正确性：σ = H2(pw)^{1/(k+H1)}
        h1 = hashgroup.H1(id, ctx)
        kid = (sk.k + h1) % bg.p
        expect = bg.g_inv_pow(hashgroup.H2(pw), kid)
        self.assertTrue(bg.g_eq(est.sigma, expect))


class TestDLEQ(unittest.TestCase):
    """DLEQ 原语仍可用（单测）；协议路径默认不上线 π。"""

    def test_prove_vf(self):
        kid = 12345
        a = bg.hash_to_g(b"test-a")
        a_tilde = bg.g_inv_pow(a, kid)
        Y = bg.g_mul(bg.g, kid)
        pi = dleq.Prove(bg.g, Y, a_tilde, a, kid)
        self.assertTrue(dleq.Vf(bg.g, Y, a_tilde, a, pi))


class TestEnvelope(unittest.TestCase):
    def test_enc_dec(self):
        pp = Setup(32)
        sk = SerKGen(pp)
        state = PAEEServerState(pp, sk)
        id, pw = "carol", "carol-password-16"
        ctx = state.SReg_issue_ctx(id)
        st = oprf.blind(pw)
        a_tilde = state.SReg_eval(id, st.a)
        est = oprf.finalize(id, ctx, pw, st, a_tilde, sk.K, pp.lambda_bytes)
        c = oprf.derive_c(id, ctx, pw, est.sigma, pp.lambda_bytes)
        self.assertTrue(state.SReg_store(id, c))

        m = b"hello fig1 v2"
        out = envelope.Enc(pp, sk, id, pw, est, m)
        self.assertIsNotNone(out)
        c_prime, ct = out
        self.assertTrue(state.Enc_store(id, c_prime, ct))

        resp = state.SDec(id)
        self.assertIsNotNone(resp)
        ct2, d = resp
        m2 = envelope.client_dec(pp, pw, est, ct2, d)
        self.assertEqual(m2, m)

    def test_wrong_password(self):
        pp = Setup(32)
        sk = SerKGen(pp)
        state = PAEEServerState(pp, sk)
        id, pw = "dave", "correct-password!!"
        ctx = state.SReg_issue_ctx(id)
        st = oprf.blind(pw)
        a_tilde = state.SReg_eval(id, st.a)
        est = oprf.finalize(id, ctx, pw, st, a_tilde, sk.K)
        c = oprf.derive_c(id, ctx, pw, est.sigma)
        state.SReg_store(id, c)
        c_prime, ct = envelope.Enc(pp, sk, id, pw, est, b"secret")
        state.Enc_store(id, c_prime, ct)
        ct2, d = state.SDec(id)

        # 错误口令：Ext 得到不同 estext，验 τ 失败
        st2 = oprf.blind("wrong-password!!!!")
        a2 = oprf.server_eval(sk, id, ctx, st2.a)
        bad_est = oprf.finalize(id, ctx, "wrong-password!!!!", st2, a2, sk.K)
        self.assertIsNone(envelope.client_dec(pp, "wrong-password!!!!", bad_est, ct2, d))


if __name__ == "__main__":
    unittest.main()
