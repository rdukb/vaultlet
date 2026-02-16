from __future__ import annotations

import csv
from pathlib import Path
from typing import Protocol

from app.vault.models import ImportRecord


class Importer(Protocol):
    source_name: str

    def detect(self, headers: list[str]) -> bool:
        ...

    def parse_rows(self, rows: list[dict[str, str]]) -> list[ImportRecord]:
        ...


def load_csv_rows(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with Path(path).open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        headers = [h or "" for h in (reader.fieldnames or [])]
        rows: list[dict[str, str]] = []
        for row in reader:
            rows.append({str(k or ""): str(v or "") for k, v in row.items()})
    return headers, rows


def normalize_headers(headers: list[str]) -> list[str]:
    return [h.strip().lower() for h in headers]
