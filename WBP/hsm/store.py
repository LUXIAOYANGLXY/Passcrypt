"""In-process record store used only inside the HSM process."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AccountRecord:
    aid: str
    password_file: bytes  # OPAQUE PasswordFile.to_bytes()
    e_blob: bytes  # AEAD(export_key, backup_key) — HSM never learns export_key/K
    ctr: int = 10
    meta: dict[str, Any] = field(default_factory=dict)


class RecordStore:
    def __init__(self) -> None:
        self._records: dict[str, AccountRecord] = {}

    def store(self, aid: str, record: AccountRecord) -> None:
        self._records[aid] = record

    def retrieve(self, aid: str) -> AccountRecord | None:
        return self._records.get(aid)

    def delete(self, aid: str) -> None:
        self._records.pop(aid, None)

    def set_ctr(self, aid: str, ctr: int) -> None:
        rec = self._records.get(aid)
        if rec is None:
            raise KeyError(aid)
        rec.ctr = ctr
