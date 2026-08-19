"""
WBP HSM module (DFG+23 Fig.4/5) — in-process inside Server.

Holds sk_Enc, sk_Sig; stores e = AE.Enc(K_export, K) after unwrapping E.
Never learns K_export or plaintext K.
"""

from __future__ import annotations

import logging
import secrets

from crypto import opaque_api as opaque
from crypto.primitives import (
    C_AAD,
    aesgcm_encrypt,
    b64d,
    b64e,
    ed25519_public_pem,
    ed25519_sign,
    generate_ed25519_keypair,
    generate_rsa_keypair,
    h3,
    rsa_decrypt,
    rsa_public_pem,
    unpack_e_payload,
)

from .store import AccountRecord, RecordStore

log = logging.getLogger("wbp.hsm")

CTR_LIMIT = 10


class HsmService:
    def __init__(self) -> None:
        self.store = RecordStore()
        self.opaque = opaque.OpaqueServer()
        self.rsa_sk, self.rsa_pk = generate_rsa_keypair()
        self.sig_sk, self.sig_pk = generate_ed25519_keypair()
        # aid -> {a1, b1, n1, tr_hsm}
        self._pending_init: dict[str, dict] = {}
        self._pending_rec: dict[str, object] = {}

    def public_bundle(self) -> dict[str, str]:
        """pk_HSM = {pk_Enc, pk_Sig} as distributed to clients (Fig.4)."""
        return {
            "enc_pem": rsa_public_pem(self.rsa_pk),
            "sig_pem": ed25519_public_pem(self.sig_pk),
        }

    def _sign(self, *parts: str) -> str:
        msg = "|".join(parts).encode("utf-8")
        return b64e(ed25519_sign(self.sig_sk, msg))

    def init_eval(
        self, aid_new: str, aid_old: str | None, a1_b64: str
    ) -> dict:
        """Fig.4: HSM OPRF/OPAQUE registration response + attestation σ."""
        log.info("Fig.4 init_eval aid_new=%s aid_old=%s", aid_new, aid_old)
        if aid_old:
            self.store.delete(aid_old)
            self._pending_init.pop(aid_old, None)

        if self.store.retrieve(aid_new) is not None:
            return {"ok": False, "error": "aid already exists"}

        try:
            req = opaque.RegistrationRequest.from_bytes(b64d(a1_b64))
            resp = self.opaque.create_registration_response(req, aid_new)
        except Exception as e:
            log.exception("OPAQUE register failed")
            return {"ok": False, "error": str(e)}

        n1 = secrets.token_hex(16)
        b1 = b64e(resp.to_bytes())
        tr_hsm = h3(a1_b64, b1, n1)
        sigma = self._sign(b1, n1, aid_new)
        self._pending_init[aid_new] = {
            "a1": a1_b64,
            "b1": b1,
            "n1": n1,
            "tr_hsm": tr_hsm,
        }
        return {"ok": True, "aid": aid_new, "b1": b1, "n1": n1, "sigma": sigma}

    def store_init(self, aid: str, e_pke_b64: str, opaque_upload_b64: str) -> dict:
        """Fig.4: Dec E, check tr_C == tr_HSM, store (file, e, ctr=10)."""
        log.info("Fig.4 store_init aid=%s", aid)
        pending = self._pending_init.pop(aid, None)
        if pending is None:
            return {"ok": False, "error": "no pending init"}

        try:
            upload = opaque.RegistrationUpload.from_bytes(b64d(opaque_upload_b64))
            password_file = self.opaque.finish_registration(upload)
            plaintext = rsa_decrypt(self.rsa_sk, b64d(e_pke_b64))
            # Optional AEAD layer under PKE for integrity of packed payload
            # Plaintext is pack_e_payload(e, tr_c) directly under RSA-OAEP.
            e_blob, tr_c = unpack_e_payload(plaintext)
            if tr_c != pending["tr_hsm"]:
                return {"ok": False, "error": "transcript mismatch (trC != trHSM)"}
        except Exception as e:
            log.exception("store_init failed")
            return {"ok": False, "error": str(e)}

        self.store.store(
            aid,
            AccountRecord(
                aid=aid,
                password_file=password_file.to_bytes(),
                e_blob=e_blob,
                ctr=CTR_LIMIT,
            ),
        )
        return {"ok": True, "aid": aid}

    def rec_eval(self, aid: str, a2_b64: str) -> dict:
        """Fig.5: ctr--, OPAQUE credential response + σ."""
        log.info("Fig.5 rec_eval aid=%s", aid)
        rec = self.store.retrieve(aid)
        if rec is None:
            return {"ok": False, "error": "no record"}

        if rec.ctr == 0:
            self.store.delete(aid)
            return {"ok": False, "deleted": True, "error": "ctr exhausted"}

        rec.ctr -= 1
        self.store.set_ctr(aid, rec.ctr)
        log.info("Fig.5 ctr decremented aid=%s ctr=%d", aid, rec.ctr)

        try:
            pf = opaque.PasswordFile.from_bytes(rec.password_file)
            creq = opaque.CredentialRequest.from_bytes(b64d(a2_b64))
            resp, login_state = self.opaque.create_credential_response(
                creq, aid, pf
            )
        except Exception as e:
            log.exception("OPAQUE login eval failed")
            return {"ok": False, "error": str(e)}

        b2 = b64e(resp.to_bytes())
        sigma = self._sign(b2, aid)
        self._pending_rec[aid] = login_state
        return {"ok": True, "aid": aid, "b2": b2, "sigma": sigma}

    def confirm(self, aid: str, t_c_b64: str) -> dict:
        """Fig.5: confirm login; ctr←10; c ← AE.Enc(shk, e)."""
        log.info("Fig.5 confirm aid=%s", aid)
        login_state = self._pending_rec.pop(aid, None)
        if login_state is None:
            return {"ok": False, "error": "no pending recovery"}

        rec = self.store.retrieve(aid)
        if rec is None:
            return {"ok": False, "error": "no record"}

        try:
            fin = opaque.CredentialFinalization.from_bytes(b64d(t_c_b64))
            session_keys = self.opaque.finish_login(fin, login_state)
            shk = session_keys.session_key
            c = b64e(aesgcm_encrypt(shk, rec.e_blob, aad=C_AAD))
        except Exception as e:
            log.exception("confirm failed")
            return {"ok": False, "error": str(e)}

        self.store.set_ctr(aid, CTR_LIMIT)
        return {"ok": True, "aid": aid, "c": c}
