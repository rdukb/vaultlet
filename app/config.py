from __future__ import annotations

import os
from pathlib import Path

APP_NAME = "Vaultlet"
APP_ID = APP_NAME.lower()
LEGACY_SERVICE_NAME = f"{APP_NAME}-key"
VAULT_KEK_SERVICE_NAME = f"{APP_NAME}-vault-kek"
PASSKEY_USER = "local-user"

DB_DIR = Path.home() / f".{APP_ID}"
DB_PATH = Path(os.getenv("VAULTLET_DB_PATH", DB_DIR / "history.db"))

CLIPBOARD_CLEAR_SEC = 30
AUTO_LOCK_SECONDS = 5 * 60

BACKUP_SCHEMA_VERSION = 1


def ensure_data_dir() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
