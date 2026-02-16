from __future__ import annotations

import json

from app.importers.base import normalize_headers
from app.vault.models import ImportRecord, VaultItemType, utc_now_iso


class LastPassImporter:
    source_name = "LastPass"
    REQUIRED = {"url", "username", "password"}
    HEADER_ALIASES = {
        "url": ["url", "website"],
        "username": ["username", "login"],
        "password": ["password"],
        "name": ["name", "title"],
        "notes": ["extra", "notes", "note"],
        "group": ["grouping", "group"],
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
            title = self._pick(row, self.HEADER_ALIASES["name"]) or url or "Imported LastPass Password"
            notes = self._pick(row, self.HEADER_ALIASES["notes"])
            group = self._pick(row, self.HEADER_ALIASES["group"])

            extras = {
                k: v
                for k, v in row.items()
                if k.strip().lower()
                not in {
                    "url",
                    "username",
                    "password",
                    "name",
                    "title",
                    "grouping",
                    "group",
                    "extra",
                    "notes",
                    "note",
                }
                and v.strip()
            }
            if group:
                extras["group"] = group

            merged_notes = notes
            if extras:
                suffix = "\n\nImported metadata: " + json.dumps(extras, ensure_ascii=True)
                merged_notes = (merged_notes + suffix).strip()

            payload = {
                "title": title,
                "username": username,
                "password": password,
                "url": url,
                "notes": merged_notes,
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
