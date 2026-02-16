from __future__ import annotations

import json

from app.importers.base import normalize_headers
from app.vault.models import ImportRecord, VaultItemType, utc_now_iso


class GooglePasswordManagerImporter:
    source_name = "Google Password Manager"
    REQUIRED = {"url", "username", "password"}
    HEADER_ALIASES = {
        "url": ["url", "website", "origin"],
        "username": ["username", "user name", "login"],
        "password": ["password", "pass"],
        "name": ["name", "title"],
        "note": ["note", "notes"],
    }

    def detect(self, headers: list[str]) -> bool:
        normalized = set(normalize_headers(headers))
        return self.REQUIRED.issubset(normalized)

    def _pick(self, row: dict[str, str], aliases: list[str]) -> str:
        for k, v in row.items():
            if k.strip().lower() in aliases:
                return v.strip()
        return ""

    def parse_rows(self, rows: list[dict[str, str]]) -> list[ImportRecord]:
        out: list[ImportRecord] = []
        for row in rows:
            url = self._pick(row, self.HEADER_ALIASES["url"])
            username = self._pick(row, self.HEADER_ALIASES["username"])
            password = self._pick(row, self.HEADER_ALIASES["password"])
            title = self._pick(row, self.HEADER_ALIASES["name"]) or url or "Imported Google Password"
            note = self._pick(row, self.HEADER_ALIASES["note"])

            extras = {
                k: v
                for k, v in row.items()
                if k.strip().lower() not in {"url", "username", "password", "name", "title", "note", "notes"}
                and v.strip()
            }
            notes = note
            if extras:
                suffix = "\n\nImported metadata: " + json.dumps(extras, ensure_ascii=True)
                notes = (notes + suffix).strip()

            payload = {
                "title": title,
                "username": username,
                "password": password,
                "url": url,
                "notes": notes,
                "created_at": utc_now_iso(),
                "updated_at": utc_now_iso(),
            }
            out.append(
                ImportRecord(
                    item_type=VaultItemType.PASSWORD,
                    payload=payload,
                    source=self.source_name,
                    raw=row,
                )
            )
        return out
