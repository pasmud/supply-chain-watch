"""Data models for supply-chain metadata snapshots and findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Severity levels for findings."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]

    @classmethod
    def from_string(cls, value: str) -> "Severity":
        normalized = value.strip().lower()
        try:
            return cls(normalized)
        except ValueError as exc:
            allowed = ", ".join(s.value for s in cls)
            raise ValueError(f"invalid severity {value!r}; expected one of {allowed}") from exc


def _normalize_maintainer(entry: Any) -> dict[str, str]:
    if isinstance(entry, str):
        value = entry.strip()
        if not value:
            return {}
        if "<" in value and value.endswith(">"):
            name, _, email = value.partition("<")
            return {"name": name.strip(), "email": email[:-1].strip()}
        if "@" in value:
            return {"name": "", "email": value}
        return {"name": value, "email": ""}
    if isinstance(entry, dict):
        name = str(entry.get("name", "")).strip()
        email = str(entry.get("email", "")).strip()
        handle = str(entry.get("handle", "")).strip()
        if not name and handle:
            name = handle
        if not name and not email:
            return {}
        return {"name": name, "email": email}
    return {}
