"""
WBP-inspired baseline — OPAQUE via opaque-snake (opaque-ke), with export_key.

opaque-snake exposes export_key needed for AEAD(export_key, backup_key).
"""

from __future__ import annotations

from opaque_snake import (
    CredentialFinalization,
    CredentialRequest,
    CredentialResponse,
    OpaqueClient,
    OpaqueServer,
    PasswordFile,
    RegistrationRequest,
    RegistrationResponse,
    RegistrationUpload,
)

__all__ = [
    "OpaqueClient",
    "OpaqueServer",
    "CredentialFinalization",
    "CredentialRequest",
    "CredentialResponse",
    "PasswordFile",
    "RegistrationRequest",
    "RegistrationResponse",
    "RegistrationUpload",
]
