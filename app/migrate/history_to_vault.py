from __future__ import annotations

import base64
from typing import Iterable

from app.config import LEGACY_SERVICE_NAME
from app.vault.models import VaultItemType
from app.vault.service import VaultLockedError, VaultService


def _load_keyring():
    import keyring

    return keyring


def _load_aesgcm():
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    return AESGCM


def _get_legacy_key() -> bytes | None:
    keyring = _load_keyring()
    key = keyring.get_password(LEGACY_SERVICE_NAME, "master")
    if key is None:
        return None
    return base64.b64decode(key.encode("ascii"))


def _decrypt_legacy(key: bytes, ciphertext: bytes, nonce: bytes, tag: bytes) -> str:
    aes = _load_aesgcm()(key)
    return aes.decrypt(nonce, ciphertext + tag, None).decode("utf-8")


def maybe_migrate_legacy_history(vault_service: VaultService) -> tuple[int, str | None]:
    db = vault_service.db
    if db.get_meta("legacy_history_migrated") == "true":
        return 0, None
    if not db.table_exists("pw_history"):
        db.set_meta("legacy_history_migrated", "true")
        return 0, None

    rows = db.legacy_history_rows()
    if not rows:
        db.set_meta("legacy_history_migrated", "true")
        return 0, None

    key = _get_legacy_key()
    if key is None:
        return 0, "Legacy history exists but keychain key is unavailable."

    try:
        migrated = 0
        for row in rows:
            pwd = _decrypt_legacy(key, row["ciphertext"], row["nonce"], row["tag"])
            payload = {
                "title": f"Imported password {row['created_at']}",
                "username": "",
                "password": pwd,
                "url": "",
                "notes": "Migrated from legacy Vaultlet password history.",
            }
            vault_service.add_item(VaultItemType.PASSWORD, payload)
            migrated += 1

        db.rename_legacy_history_backup()
        db.set_meta("legacy_history_migrated", "true")
        return migrated, None
    except VaultLockedError:
        return 0, "Vault is locked; unlock to run legacy history migration."
    except Exception as exc:
        return 0, str(exc)
