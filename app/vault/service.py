from __future__ import annotations

import base64
import json
import time
import uuid
from pathlib import Path
from typing import Any

from app.config import AUTO_LOCK_SECONDS, BACKUP_SCHEMA_VERSION
from app.vault import crypto
from app.vault.crypto import RecoveryKDFParams, WrappedBlob
from app.vault.db import EncryptedRow, VaultDB, VaultKeysRow
from app.vault.models import ImportRecord, ImportReport, VaultItem, VaultItemType, utc_now_iso


class VaultLockedError(RuntimeError):
    pass


class VaultService:
    def __init__(self, db: VaultDB, auto_lock_seconds: int = AUTO_LOCK_SECONDS):
        self.db = db
        self.auto_lock_seconds = auto_lock_seconds
        self._dek: bytes | None = None
        self._last_activity = 0.0

    def initialize(self) -> None:
        self.db.initialize()

    def is_setup(self) -> bool:
        return self.db.has_vault_keys()

    def setup_new_vault(self) -> str:
        if self.is_setup():
            raise RuntimeError("Vault is already initialized.")

        dek = crypto.create_data_encryption_key()
        local_kek = crypto.get_or_create_local_kek()
        wrapped_local = crypto.wrap_dek(local_kek, dek)

        recovery_key = crypto.generate_recovery_key()
        recovery_params = crypto.default_recovery_params()
        recovery_kek = crypto.derive_recovery_kek(recovery_key, recovery_params)
        wrapped_recovery = crypto.wrap_dek(recovery_kek, dek)

        self.db.upsert_vault_keys(
            VaultKeysRow(
                wrapped_dek_local_ct=wrapped_local.ciphertext,
                wrapped_dek_local_nonce=wrapped_local.nonce,
                wrapped_dek_local_tag=wrapped_local.tag,
                wrapped_dek_recovery_ct=wrapped_recovery.ciphertext,
                wrapped_dek_recovery_nonce=wrapped_recovery.nonce,
                wrapped_dek_recovery_tag=wrapped_recovery.tag,
                recovery_kdf_params=recovery_params.to_json(),
            )
        )
        self.db.set_meta("vault_initialized_at", utc_now_iso())
        return recovery_key

    def unlock_with_local_kek(self) -> None:
        keys = self.db.get_vault_keys()
        if keys is None:
            raise RuntimeError("Vault is not initialized.")

        local_kek = crypto.get_or_create_local_kek()
        wrapped = WrappedBlob(
            ciphertext=keys.wrapped_dek_local_ct,
            nonce=keys.wrapped_dek_local_nonce,
            tag=keys.wrapped_dek_local_tag,
        )
        self._dek = crypto.unwrap_dek(local_kek, wrapped)
        self.touch()

    def unlock_with_recovery_key(self, recovery_key: str) -> None:
        keys = self.db.get_vault_keys()
        if keys is None:
            raise RuntimeError("Vault is not initialized.")

        params = RecoveryKDFParams.from_json(keys.recovery_kdf_params)
        recovery_kek = crypto.derive_recovery_kek(recovery_key, params)
        wrapped = WrappedBlob(
            ciphertext=keys.wrapped_dek_recovery_ct,
            nonce=keys.wrapped_dek_recovery_nonce,
            tag=keys.wrapped_dek_recovery_tag,
        )
        self._dek = crypto.unwrap_dek(recovery_kek, wrapped)
        self.db.set_meta("last_recovery_unlock_at", utc_now_iso())
        self.touch()

    def lock(self) -> None:
        self._dek = None
        self._last_activity = 0.0

    def touch(self) -> None:
        self._last_activity = time.monotonic()

    def _ensure_unlocked(self) -> bytes:
        if self._dek is None:
            raise VaultLockedError("Vault is locked.")

        elapsed = time.monotonic() - self._last_activity
        if self.auto_lock_seconds > 0 and elapsed > self.auto_lock_seconds:
            self.lock()
            raise VaultLockedError("Vault locked due to inactivity.")

        self.touch()
        return self._dek

    def is_unlocked_without_touch(self) -> bool:
        if self._dek is None:
            return False
        elapsed = time.monotonic() - self._last_activity
        if self.auto_lock_seconds > 0 and elapsed > self.auto_lock_seconds:
            self.lock()
            return False
        return True

    def is_unlocked(self) -> bool:
        try:
            self._ensure_unlocked()
            return True
        except VaultLockedError:
            return False

    def add_item(self, item_type: VaultItemType, payload: dict[str, Any]) -> VaultItem:
        dek = self._ensure_unlocked()
        item_id = str(uuid.uuid4())
        now = utc_now_iso()
        normalized = dict(payload)
        normalized.setdefault("title", "Untitled")
        normalized["created_at"] = now
        normalized["updated_at"] = now

        wrapped = crypto.encrypt_payload(dek, json.dumps(normalized, separators=(",", ":")).encode("utf-8"))
        self.db.insert_item_encrypted(
            item_id=item_id,
            item_type=item_type.value,
            ciphertext=wrapped.ciphertext,
            nonce=wrapped.nonce,
            tag=wrapped.tag,
            created_at=now,
            updated_at=now,
        )
        return VaultItem(id=item_id, item_type=item_type, payload=normalized, created_at=now, updated_at=now)

    def _row_to_item(self, dek: bytes, row: EncryptedRow) -> VaultItem:
        wrapped = WrappedBlob(ciphertext=row.ciphertext, nonce=row.nonce, tag=row.tag)
        payload = json.loads(crypto.decrypt_payload(dek, wrapped).decode("utf-8"))
        return VaultItem(
            id=row.id,
            item_type=VaultItemType(row.item_type),
            payload=payload,
            created_at=row.created_at,
            updated_at=row.updated_at,
            deleted_at=row.deleted_at,
        )

    def list_items(self) -> list[VaultItem]:
        dek = self._ensure_unlocked()
        rows = self.db.list_items_encrypted(include_deleted=False)
        return [self._row_to_item(dek, row) for row in rows]

    def get_item(self, item_id: str) -> VaultItem | None:
        dek = self._ensure_unlocked()
        row = self.db.get_item_encrypted(item_id)
        if row is None:
            return None
        return self._row_to_item(dek, row)

    def update_item(self, item_id: str, payload: dict[str, Any]) -> VaultItem:
        dek = self._ensure_unlocked()
        existing = self.get_item(item_id)
        if existing is None:
            raise RuntimeError("Secret was not found.")

        now = utc_now_iso()
        merged = dict(existing.payload)
        merged.update(payload)
        merged["updated_at"] = now

        wrapped = crypto.encrypt_payload(dek, json.dumps(merged, separators=(",", ":")).encode("utf-8"))
        self.db.update_item_encrypted(item_id, wrapped.ciphertext, wrapped.nonce, wrapped.tag, now)
        return VaultItem(id=item_id, item_type=existing.item_type, payload=merged, created_at=existing.created_at, updated_at=now)

    def delete_item(self, item_id: str) -> None:
        self._ensure_unlocked()
        self.db.soft_delete_item(item_id, utc_now_iso())

    def _normalized_duplicate_key(self, item: VaultItem | ImportRecord) -> tuple[str, ...]:
        if isinstance(item, VaultItem):
            item_type = item.item_type
            payload = item.payload
        else:
            item_type = item.item_type
            payload = item.payload

        if item_type == VaultItemType.PASSWORD:
            return (
                item_type.value,
                str(payload.get("title", "")).strip().lower(),
                str(payload.get("username", "")).strip().lower(),
                str(payload.get("url", "")).strip().lower(),
                str(payload.get("password", "")),
            )
        if item_type == VaultItemType.API_KEY:
            return (
                item_type.value,
                str(payload.get("title", "")).strip().lower(),
                str(payload.get("service", "")).strip().lower(),
                str(payload.get("api_key", "")),
            )

        return (
            item_type.value,
            str(payload.get("title", "")).strip().lower(),
            str(payload.get("content", "")),
        )

    def import_records(self, source: str, records: list[ImportRecord]) -> ImportReport:
        report = ImportReport(source=source)
        report.total_rows = len(records)

        existing = {self._normalized_duplicate_key(item) for item in self.list_items()}

        for rec in records:
            key = self._normalized_duplicate_key(rec)
            if key in existing:
                report.duplicates += 1
                continue
            try:
                self.add_item(rec.item_type, rec.payload)
                existing.add(key)
                report.imported += 1
            except Exception as exc:
                report.failed += 1
                report.messages.append(str(exc))

        return report

    def preview_import(self, records: list[ImportRecord]) -> tuple[int, int, int]:
        existing = {self._normalized_duplicate_key(item) for item in self.list_items()}
        duplicates = 0
        to_import = 0
        seen_new: set[tuple[str, ...]] = set()
        for rec in records:
            key = self._normalized_duplicate_key(rec)
            if key in existing or key in seen_new:
                duplicates += 1
            else:
                seen_new.add(key)
                to_import += 1
        return len(records), duplicates, to_import

    def export_backup(self, out_path: Path) -> Path:
        self._ensure_unlocked()
        keys = self.db.get_vault_keys()
        if keys is None:
            raise RuntimeError("Vault is not initialized.")

        rows = self.db.list_items_encrypted(include_deleted=False)
        payload = {
            "schema_version": BACKUP_SCHEMA_VERSION,
            "exported_at": utc_now_iso(),
            "vault_keys": {
                "wrapped_dek_local_ct": base64.b64encode(keys.wrapped_dek_local_ct).decode("ascii"),
                "wrapped_dek_local_nonce": base64.b64encode(keys.wrapped_dek_local_nonce).decode("ascii"),
                "wrapped_dek_local_tag": base64.b64encode(keys.wrapped_dek_local_tag).decode("ascii"),
                "wrapped_dek_recovery_ct": base64.b64encode(keys.wrapped_dek_recovery_ct).decode("ascii"),
                "wrapped_dek_recovery_nonce": base64.b64encode(keys.wrapped_dek_recovery_nonce).decode("ascii"),
                "wrapped_dek_recovery_tag": base64.b64encode(keys.wrapped_dek_recovery_tag).decode("ascii"),
                "recovery_kdf_params": keys.recovery_kdf_params,
            },
            "items": [
                {
                    "id": row.id,
                    "item_type": row.item_type,
                    "ciphertext": base64.b64encode(row.ciphertext).decode("ascii"),
                    "nonce": base64.b64encode(row.nonce).decode("ascii"),
                    "tag": base64.b64encode(row.tag).decode("ascii"),
                    "created_at": row.created_at,
                    "updated_at": row.updated_at,
                    "deleted_at": row.deleted_at,
                }
                for row in rows
            ],
        }

        out_path = Path(out_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return out_path

    def import_backup(self, in_path: Path, require_empty: bool = True) -> int:
        self._ensure_unlocked()
        in_path = Path(in_path)
        data = json.loads(in_path.read_text(encoding="utf-8"))

        if int(data.get("schema_version", 0)) != BACKUP_SCHEMA_VERSION:
            raise RuntimeError("Backup schema version mismatch.")

        if require_empty and self.db.list_items_encrypted(include_deleted=False):
            raise RuntimeError("Vault must be empty before importing an encrypted backup.")

        current_keys = self.db.get_vault_keys()
        if current_keys is None:
            raise RuntimeError("Vault must be initialized and unlocked before importing backup.")

        backup_keys = data.get("vault_keys", {})
        required_key_fields = {
            "wrapped_dek_recovery_ct",
            "wrapped_dek_recovery_nonce",
            "wrapped_dek_recovery_tag",
        }
        if not required_key_fields.issubset(set(backup_keys.keys())):
            raise RuntimeError("Backup is missing required key metadata.")

        if (
            backup_keys["wrapped_dek_recovery_ct"] != base64.b64encode(current_keys.wrapped_dek_recovery_ct).decode("ascii")
            or backup_keys["wrapped_dek_recovery_nonce"]
            != base64.b64encode(current_keys.wrapped_dek_recovery_nonce).decode("ascii")
            or backup_keys["wrapped_dek_recovery_tag"]
            != base64.b64encode(current_keys.wrapped_dek_recovery_tag).decode("ascii")
        ):
            raise RuntimeError(
                "Backup belongs to a different vault keyset. "
                "This v1 importer only supports backups created from the same vault."
            )

        count = 0
        for row in data.get("items", []):
            try:
                self.db.insert_item_encrypted(
                    item_id=str(row["id"]),
                    item_type=str(row["item_type"]),
                    ciphertext=base64.b64decode(row["ciphertext"].encode("ascii")),
                    nonce=base64.b64decode(row["nonce"].encode("ascii")),
                    tag=base64.b64decode(row["tag"].encode("ascii")),
                    created_at=str(row["created_at"]),
                    updated_at=str(row["updated_at"]),
                )
                count += 1
            except Exception:
                # Keep import resilient on duplicate IDs
                continue

        return count
