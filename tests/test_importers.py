from __future__ import annotations

import unittest

from app.importers.google_password_manager import GooglePasswordManagerImporter
from app.importers.lastpass import LastPassImporter


class ImporterTests(unittest.TestCase):
    def test_google_parse(self) -> None:
        importer = GooglePasswordManagerImporter()
        rows = [
            {"name": "Example", "url": "https://example.com", "username": "alice", "password": "secret", "note": "n"}
        ]
        records = importer.parse_rows(rows)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].payload["username"], "alice")

    def test_lastpass_parse(self) -> None:
        importer = LastPassImporter()
        rows = [
            {
                "name": "GitHub",
                "url": "https://github.com",
                "username": "bob",
                "password": "token",
                "extra": "2FA enabled",
            }
        ]
        records = importer.parse_rows(rows)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].payload["title"], "GitHub")


if __name__ == "__main__":
    unittest.main()
