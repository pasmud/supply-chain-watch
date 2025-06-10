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


def _normalize_maintainers(value: Any) -> list[dict[str, str]]:
    if value is None:
        return []
    if isinstance(value, (str, dict)):
        items = [value]
    elif isinstance(value, list):
        items = value
    else:
        return []
    normalized: list[dict[str, str]] = []
    seen_emails: set[str] = set()
    seen_names: set[str] = set()
    for item in items:
        maintainer = _normalize_maintainer(item)
        if not maintainer:
            continue
        email = maintainer.get("email", "").lower()
        name = maintainer.get("name", "").lower()
        if email:
            if email in seen_emails:
                continue
            seen_emails.add(email)
        else:
            if not name or name in seen_names:
                continue
            seen_names.add(name)
        normalized.append(maintainer)
    return normalized


def _normalize_dependencies(value: Any) -> dict[str, str]:
    if value is None:
        return {}
    if isinstance(value, dict):
        result: dict[str, str] = {}
        for name, spec in value.items():
            key = str(name).strip()
            if not key:
                continue
            result[key] = str(spec).strip() if spec is not None else ""
        return result
    if isinstance(value, list):
        result = {}
        for item in value:
            if isinstance(item, str):
                name = item.strip()
                if not name:
                    continue
                # simple forms: "pkg==1.0", "pkg>=1", or just "pkg"
                for sep in ("===", "==", ">=", "<=", "~=", "!=", ">", "<"):
                    if sep in name:
                        pkg, _, spec = name.partition(sep)
                        result[pkg.strip()] = f"{sep}{spec.strip()}"
                        break
                else:
                    result[name] = ""
            elif isinstance(item, dict):
                name = str(item.get("name", "")).strip()
                spec = str(item.get("version", item.get("spec", ""))).strip()
                if name:
                    result[name] = spec
        return result
    return {}


def _normalize_scripts(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    result: dict[str, str] = {}
    for name, command in value.items():
        key = str(name).strip()
        if not key:
            continue
        result[key] = str(command).strip() if command is not None else ""
    return result


def _normalize_string(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


@dataclass
class PackageSnapshot:
    """Normalized package metadata snapshot."""

    name: str
    version: str | None = None
    license: str | None = None
    repository: str | None = None
    homepage: str | None = None
