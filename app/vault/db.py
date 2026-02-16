from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from app.config import BACKUP_SCHEMA_VERSION, DB_PATH


@dataclass(slots=True)
class EncryptedRow:
    id: str
    item_type: str
    ciphertext: bytes
    nonce: bytes
    tag: bytes
    created_at: str
    updated_at: str
    deleted_at: str | None


@dataclass(slots=True)
class VaultKeysRow:
    wrapped_dek_local_ct: bytes
    wrapped_dek_local_nonce: bytes
    wrapped_dek_local_tag: bytes
    wrapped_dek_recovery_ct: bytes
    wrapped_dek_recovery_nonce: bytes
    wrapped_dek_recovery_tag: bytes
    recovery_kdf_params: str


@dataclass(slots=True)
class PasskeyCredentialRow:
    id: int
    credential_id: bytes
    public_key_cose: bytes
    sign_count: int
    label: str | None
    aaguid: str | None
    created_at: str
    last_used_at: str | None
    revoked_at: str | None


class VaultDB:
    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = Path(db_path)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def initialize(self) -> None:
        with self.connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS vault_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS vault_keys (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    wrapped_dek_local_ct BLOB NOT NULL,
                    wrapped_dek_local_nonce BLOB NOT NULL,
                    wrapped_dek_local_tag BLOB NOT NULL,
                    wrapped_dek_recovery_ct BLOB NOT NULL,
                    wrapped_dek_recovery_nonce BLOB NOT NULL,
                    wrapped_dek_recovery_tag BLOB NOT NULL,
                    recovery_kdf_params TEXT NOT NULL
                );
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS vault_items (
                    id TEXT PRIMARY KEY,
                    item_type TEXT NOT NULL,
                    ciphertext BLOB NOT NULL,
                    nonce BLOB NOT NULL,
                    tag BLOB NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    deleted_at TEXT NULL
                );
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS passkey_credentials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    credential_id BLOB UNIQUE NOT NULL,
                    public_key_cose BLOB NOT NULL,
                    sign_count INTEGER NOT NULL,
                    label TEXT NULL,
                    aaguid TEXT NULL,
                    created_at TEXT NOT NULL,
                    last_used_at TEXT NULL,
                    revoked_at TEXT NULL
                );
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS pw_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    ciphertext BLOB NOT NULL,
                    nonce BLOB NOT NULL,
                    tag BLOB NOT NULL
                );
                """
            )
            cur.execute(
                "INSERT OR REPLACE INTO vault_meta (key, value) VALUES (?, ?)",
                ("backup_schema_version", str(BACKUP_SCHEMA_VERSION)),
            )
            conn.commit()

    def has_vault_keys(self) -> bool:
        with self.connect() as conn:
            row = conn.execute("SELECT 1 FROM vault_keys WHERE id = 1").fetchone()
            return row is not None

    def get_meta(self, key: str) -> str | None:
        with self.connect() as conn:
            row = conn.execute("SELECT value FROM vault_meta WHERE key = ?", (key,)).fetchone()
            return None if row is None else str(row["value"])

    def set_meta(self, key: str, value: str) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO vault_meta (key, value) VALUES (?, ?)",
                (key, value),
            )
            conn.commit()

    def upsert_vault_keys(self, row: VaultKeysRow) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO vault_keys (
                    id,
                    wrapped_dek_local_ct, wrapped_dek_local_nonce, wrapped_dek_local_tag,
                    wrapped_dek_recovery_ct, wrapped_dek_recovery_nonce, wrapped_dek_recovery_tag,
                    recovery_kdf_params
                ) VALUES (1, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    row.wrapped_dek_local_ct,
                    row.wrapped_dek_local_nonce,
                    row.wrapped_dek_local_tag,
                    row.wrapped_dek_recovery_ct,
                    row.wrapped_dek_recovery_nonce,
                    row.wrapped_dek_recovery_tag,
                    row.recovery_kdf_params,
                ),
            )
            conn.commit()

    def get_vault_keys(self) -> VaultKeysRow | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM vault_keys WHERE id = 1").fetchone()
            if row is None:
                return None
            return VaultKeysRow(
                wrapped_dek_local_ct=row["wrapped_dek_local_ct"],
                wrapped_dek_local_nonce=row["wrapped_dek_local_nonce"],
                wrapped_dek_local_tag=row["wrapped_dek_local_tag"],
                wrapped_dek_recovery_ct=row["wrapped_dek_recovery_ct"],
                wrapped_dek_recovery_nonce=row["wrapped_dek_recovery_nonce"],
                wrapped_dek_recovery_tag=row["wrapped_dek_recovery_tag"],
                recovery_kdf_params=str(row["recovery_kdf_params"]),
            )

    def insert_item_encrypted(
        self,
        item_id: str,
        item_type: str,
        ciphertext: bytes,
        nonce: bytes,
        tag: bytes,
        created_at: str,
        updated_at: str,
    ) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO vault_items (id, item_type, ciphertext, nonce, tag, created_at, updated_at, deleted_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
                """,
                (item_id, item_type, ciphertext, nonce, tag, created_at, updated_at),
            )
            conn.commit()

    def update_item_encrypted(
        self,
        item_id: str,
        ciphertext: bytes,
        nonce: bytes,
        tag: bytes,
        updated_at: str,
    ) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE vault_items
                SET ciphertext = ?, nonce = ?, tag = ?, updated_at = ?
                WHERE id = ? AND deleted_at IS NULL
                """,
                (ciphertext, nonce, tag, updated_at, item_id),
            )
            conn.commit()

    def get_item_encrypted(self, item_id: str) -> EncryptedRow | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM vault_items WHERE id = ? AND deleted_at IS NULL",
                (item_id,),
            ).fetchone()
            if row is None:
                return None
            return EncryptedRow(
                id=str(row["id"]),
                item_type=str(row["item_type"]),
                ciphertext=row["ciphertext"],
                nonce=row["nonce"],
                tag=row["tag"],
                created_at=str(row["created_at"]),
                updated_at=str(row["updated_at"]),
                deleted_at=row["deleted_at"],
            )

    def list_items_encrypted(self, include_deleted: bool = False) -> list[EncryptedRow]:
        query = "SELECT * FROM vault_items"
        if not include_deleted:
            query += " WHERE deleted_at IS NULL"
        query += " ORDER BY updated_at DESC"

        with self.connect() as conn:
            rows = conn.execute(query).fetchall()
            return [
                EncryptedRow(
                    id=str(row["id"]),
                    item_type=str(row["item_type"]),
                    ciphertext=row["ciphertext"],
                    nonce=row["nonce"],
                    tag=row["tag"],
                    created_at=str(row["created_at"]),
                    updated_at=str(row["updated_at"]),
                    deleted_at=row["deleted_at"],
                )
                for row in rows
            ]

    def soft_delete_item(self, item_id: str, deleted_at: str) -> None:
        with self.connect() as conn:
            conn.execute(
                "UPDATE vault_items SET deleted_at = ? WHERE id = ?",
                (deleted_at, item_id),
            )
            conn.commit()

    def wipe_vault(self) -> None:
        with self.connect() as conn:
            conn.execute("DELETE FROM vault_items")
            conn.execute("DELETE FROM vault_keys")
            conn.execute("DELETE FROM passkey_credentials")
            conn.execute("DELETE FROM vault_meta WHERE key != 'backup_schema_version'")
            conn.commit()

    def table_exists(self, table_name: str) -> bool:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name = ?",
                (table_name,),
            ).fetchone()
            return row is not None

    def legacy_history_rows(self) -> list[sqlite3.Row]:
        with self.connect() as conn:
            if not self.table_exists("pw_history"):
                return []
            return conn.execute(
                "SELECT id, created_at, size_bytes, ciphertext, nonce, tag FROM pw_history ORDER BY id"
            ).fetchall()

    def rename_legacy_history_backup(self) -> None:
        with self.connect() as conn:
            if not self.table_exists("pw_history"):
                return
            if self.table_exists("pw_history_legacy_backup"):
                conn.execute("DROP TABLE pw_history_legacy_backup")
            conn.execute("ALTER TABLE pw_history RENAME TO pw_history_legacy_backup")
            conn.commit()

    def add_passkey_credential(
        self,
        credential_id: bytes,
        public_key_cose: bytes,
        sign_count: int,
        label: str | None,
        aaguid: str | None,
        created_at: str,
    ) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO passkey_credentials (
                    credential_id, public_key_cose, sign_count, label, aaguid, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (credential_id, public_key_cose, sign_count, label, aaguid, created_at),
            )
            conn.commit()

    def list_passkeys(self, include_revoked: bool = False) -> list[PasskeyCredentialRow]:
        query = "SELECT * FROM passkey_credentials"
        if not include_revoked:
            query += " WHERE revoked_at IS NULL"
        query += " ORDER BY id"

        with self.connect() as conn:
            rows = conn.execute(query).fetchall()
            return [
                PasskeyCredentialRow(
                    id=int(row["id"]),
                    credential_id=row["credential_id"],
                    public_key_cose=row["public_key_cose"],
                    sign_count=int(row["sign_count"]),
                    label=row["label"],
                    aaguid=row["aaguid"],
                    created_at=str(row["created_at"]),
                    last_used_at=row["last_used_at"],
                    revoked_at=row["revoked_at"],
                )
                for row in rows
            ]

    def get_passkey_by_credential_id(self, credential_id: bytes) -> PasskeyCredentialRow | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM passkey_credentials WHERE credential_id = ? AND revoked_at IS NULL",
                (credential_id,),
            ).fetchone()
            if row is None:
                return None
            return PasskeyCredentialRow(
                id=int(row["id"]),
                credential_id=row["credential_id"],
                public_key_cose=row["public_key_cose"],
                sign_count=int(row["sign_count"]),
                label=row["label"],
                aaguid=row["aaguid"],
                created_at=str(row["created_at"]),
                last_used_at=row["last_used_at"],
                revoked_at=row["revoked_at"],
            )

    def update_passkey_sign_count(self, credential_id: bytes, sign_count: int, last_used_at: str) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE passkey_credentials
                SET sign_count = ?, last_used_at = ?
                WHERE credential_id = ?
                """,
                (sign_count, last_used_at, credential_id),
            )
            conn.commit()

    def revoke_passkey(self, passkey_row_id: int, revoked_at: str) -> None:
        with self.connect() as conn:
            conn.execute(
                "UPDATE passkey_credentials SET revoked_at = ? WHERE id = ?",
                (revoked_at, passkey_row_id),
            )
            conn.commit()

    def rename_passkey(self, passkey_row_id: int, label: str) -> None:
        with self.connect() as conn:
            conn.execute(
                "UPDATE passkey_credentials SET label = ? WHERE id = ?",
                (label, passkey_row_id),
            )
            conn.commit()
