"""
Cryptographic primitives for WBP (Davies et al., Crypto'23 / ePrint 2023/843).

Fig.4/5 use: AE (AES-GCM), PKE (RSA-OAEP), signatures (Ed25519 attestation),
plus OPAQUE via opaque-ke (opaque-snake). Hash H3 binds the OPRF transcript.
"""

from __future__ import annotations

import base64
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text.encode("ascii"))


def h3(*parts: bytes | str) -> bytes:
    """Transcript hash H3 from DFG+23 (SHA-256 over length-delimited parts)."""
    digest = hashes.Hash(hashes.SHA256())
    for p in parts:
        b = p.encode("utf-8") if isinstance(p, str) else p
        digest.update(len(b).to_bytes(4, "big"))
        digest.update(b)
    return digest.finalize()


def generate_rsa_keypair(bits: int = 2048) -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    private = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return private, private.public_key()


def generate_ed25519_keypair() -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    private = ed25519.Ed25519PrivateKey.generate()
    return private, private.public_key()


def rsa_public_pem(public: rsa.RSAPublicKey) -> str:
    return public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def load_rsa_public_pem(pem: str) -> rsa.RSAPublicKey:
    key = serialization.load_pem_public_key(pem.encode("ascii"))
    assert isinstance(key, rsa.RSAPublicKey)
    return key


def ed25519_public_pem(public: ed25519.Ed25519PublicKey) -> str:
    return public.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def load_ed25519_public_pem(pem: str) -> ed25519.Ed25519PublicKey:
    key = serialization.load_pem_public_key(pem.encode("ascii"))
    assert isinstance(key, ed25519.Ed25519PublicKey)
    return key


def rsa_encrypt(public: rsa.RSAPublicKey, plaintext: bytes) -> bytes:
    """PKE.Enc(pk_Enc_HSM, ·) in Fig.4 — RSA-OAEP-SHA256."""
    return public.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_decrypt(private: rsa.RSAPrivateKey, ciphertext: bytes) -> bytes:
    return private.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def ed25519_sign(private: ed25519.Ed25519PrivateKey, message: bytes) -> bytes:
    return private.sign(message)


def ed25519_verify(
    public: ed25519.Ed25519PublicKey, message: bytes, signature: bytes
) -> None:
    public.verify(signature, message)


def _aes_key(key: bytes) -> bytes:
    if len(key) in (16, 24, 32):
        return key
    digest = hashes.Hash(hashes.SHA256())
    digest.update(key)
    return digest.finalize()


def aesgcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """AE.Enc — returns nonce||ciphertext||tag."""
    key = _aes_key(key)
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def aesgcm_decrypt(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    key = _aes_key(key)
    nonce, ct = blob[:12], blob[12:]
    return AESGCM(key).decrypt(nonce, ct, aad)


# Packed plaintext inside E (Fig.4): e || trC  (e = AE.Enc(K_export, K))
E_MAGIC = b"WBP1"
E_AAD = b"wbp-dfg23-E"
K_AAD = b"wbp-dfg23-K"
C_AAD = b"wbp-dfg23-c"


def pack_e_payload(e: bytes, tr_c: bytes) -> bytes:
    if len(tr_c) != 32:
        raise ValueError("trC must be 32 bytes")
    return E_MAGIC + len(e).to_bytes(4, "big") + e + tr_c


def unpack_e_payload(blob: bytes) -> tuple[bytes, bytes]:
    if not blob.startswith(E_MAGIC):
        raise ValueError("bad E plaintext magic")
    elen = int.from_bytes(blob[4:8], "big")
    e = blob[8 : 8 + elen]
    tr_c = blob[8 + elen : 8 + elen + 32]
    if len(tr_c) != 32:
        raise ValueError("truncated trC")
    return e, tr_c
