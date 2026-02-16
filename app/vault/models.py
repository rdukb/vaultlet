from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class VaultItemType(str, Enum):
    PASSWORD = "password"
    API_KEY = "api_key"
    SECURE_NOTE = "secure_note"


@dataclass(slots=True)
class VaultItem:
    id: str
    item_type: VaultItemType
    payload: dict[str, Any]
    created_at: str
    updated_at: str
    deleted_at: str | None = None


@dataclass(slots=True)
class ImportRecord:
    item_type: VaultItemType
    payload: dict[str, Any]
    source: str
    raw: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class ImportReport:
    source: str
    total_rows: int = 0
    imported: int = 0
    duplicates: int = 0
    failed: int = 0
    messages: list[str] = field(default_factory=list)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
