from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from app.vault.db import VaultDB
from app.vault.models import ImportRecord, VaultItemType
from app.vault.service import VaultService


class ServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tempdir.name) / "vault.db"
        self.db = VaultDB(self.db_path)
        self.service = VaultService(self.db, auto_lock_seconds=60)
        self.service.initialize()

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_setup_unlock_and_crud(self) -> None:
        with mock.patch("app.vault.crypto.get_or_create_local_kek", return_value=b"k" * 32):
            recovery = self.service.setup_new_vault()
            self.assertTrue(recovery)
            self.service.unlock_with_local_kek()

        item = self.service.add_item(
            VaultItemType.PASSWORD,
            {"title": "Email", "username": "alice", "password": "secret", "url": "", "notes": ""},
        )
        fetched = self.service.get_item(item.id)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.payload["username"], "alice")

    def test_import_duplicates_are_skipped(self) -> None:
        with mock.patch("app.vault.crypto.get_or_create_local_kek", return_value=b"k" * 32):
            self.service.setup_new_vault()
            self.service.unlock_with_local_kek()

        self.service.add_item(
            VaultItemType.PASSWORD,
            {
                "title": "GitHub",
                "username": "bob",
                "password": "p@ss",
                "url": "https://github.com",
                "notes": "",
            },
        )
        report = self.service.import_records(
            "test",
            [
                ImportRecord(
                    item_type=VaultItemType.PASSWORD,
                    payload={
                        "title": "GitHub",
                        "username": "bob",
                        "password": "p@ss",
                        "url": "https://github.com",
                        "notes": "",
                    },
                    source="test",
                )
            ],
        )
        self.assertEqual(report.duplicates, 1)
        self.assertEqual(report.imported, 0)

    def test_export_then_import_backup_same_vault(self) -> None:
        backup_path = Path(self.tempdir.name) / "backup.vaultlet.json"
        with mock.patch("app.vault.crypto.get_or_create_local_kek", return_value=b"k" * 32):
            self.service.setup_new_vault()
            self.service.unlock_with_local_kek()

        created = self.service.add_item(
            VaultItemType.SECURE_NOTE,
            {"title": "Note", "content": "Hello", "notes": ""},
        )
        self.assertTrue(created.id)
        self.service.export_backup(backup_path)

        with self.db.connect() as conn:
            conn.execute("DELETE FROM vault_items")
            conn.commit()

        count = self.service.import_backup(backup_path, require_empty=True)
        self.assertEqual(count, 1)
        restored = self.service.list_items()
        self.assertEqual(len(restored), 1)


if __name__ == "__main__":
    unittest.main()
