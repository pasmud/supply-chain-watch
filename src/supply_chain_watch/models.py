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
    description: str | None = None
    maintainers: list[dict[str, str]] = field(default_factory=list)
    dependencies: dict[str, str] = field(default_factory=dict)
    scripts: dict[str, str] = field(default_factory=dict)
    source: str | None = None
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_dict(cls, data: dict[str, Any], source: str | None = None) -> "PackageSnapshot":
        if not isinstance(data, dict):
            raise ValueError("package snapshot must be an object")
        name = _normalize_string(data.get("name"))
        if not name:
            raise ValueError("package snapshot missing required 'name' field")
        repository = _normalize_string(
            data.get("repository")
            if not isinstance(data.get("repository"), dict)
            else data.get("repository", {}).get("url")
        )
        return cls(
            name=name,
            version=_normalize_string(data.get("version")),
            license=_normalize_string(data.get("license")),
            repository=repository,
            homepage=_normalize_string(data.get("homepage")),
            description=_normalize_string(data.get("description")),
            maintainers=_normalize_maintainers(data.get("maintainers")),
            dependencies=_normalize_dependencies(data.get("dependencies")),
            scripts=_normalize_scripts(data.get("scripts")),
            source=source,
            raw=dict(data),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "license": self.license,
            "repository": self.repository,
            "homepage": self.homepage,
            "description": self.description,
            "maintainers": self.maintainers,
            "dependencies": self.dependencies,
            "scripts": self.scripts,
        }


@dataclass
class Finding:
    """A detected supply-chain indicator."""

    rule_id: str
    severity: Severity
    package: str
    message: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "package": self.package,
            "message": self.message,
            "details": self.details,
        }


@dataclass
class ScanReport:
    """Report produced by a scan."""

    packages_scanned: list[str]
    findings: list[Finding] = field(default_factory=list)
    baseline_source: str | None = None
