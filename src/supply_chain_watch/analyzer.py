"""Core analysis logic for detecting supply-chain indicators."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .models import Finding, PackageSnapshot, ScanReport, Severity

SUSPICIOUS_SCRIPT_PATTERNS: list[tuple[re.Pattern[str], str, Severity]] = [
    (re.compile(r"\bcurl\b[^\n|]*\|\s*(?:sh|bash|zsh)\b", re.I), "curl piped to shell", Severity.CRITICAL),
    (re.compile(r"\bwget\b[^\n|]*\|\s*(?:sh|bash|zsh)\b", re.I), "wget piped to shell", Severity.CRITICAL),
    (re.compile(r"\b(?:powershell|pwsh)\b.*(?:-enc|-encodedcommand|iex|invoke-expression)", re.I), "encoded PowerShell execution", Severity.CRITICAL),
    (re.compile(r"\b(?:nc|ncat|netcat)\b\s+.*\s+-e\s+", re.I), "netcat reverse-shell style flag", Severity.CRITICAL),
    (re.compile(r"\b(?:bash\s+-i|/dev/tcp/)\b", re.I), "interactive shell / dev tcp usage", Severity.CRITICAL),
    (re.compile(r"\bbase64\b.*\|\s*(?:sh|bash|python|node)\b", re.I), "decoded payload piped to interpreter", Severity.HIGH),
    (re.compile(r"\brm\s+-rf\s+/(?:\s|$)", re.I), "destructive root deletion command", Severity.CRITICAL),
    (re.compile(r"\b(?:curl|wget)\b[^\n]*https?://", re.I), "network download in script", Severity.MEDIUM),
    (re.compile(r"\b(?:chmod\s+\+x|chmod\s+777)\b", re.I), "permission escalation in script", Severity.MEDIUM),
]

LIFECYCLE_SCRIPTS = {"preinstall", "install", "postinstall", "prepare", "prepublish", "prepublishOnly"}


def load_snapshot_file(path: str | Path) -> list[PackageSnapshot]:
    """Load one or more package snapshots from a JSON file.

    Accepted formats:
    - a single package object
    - a list of package objects
    - an object with a "packages" list
    """
    file_path = Path(path)
    raw_text = file_path.read_text(encoding="utf-8")
    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON in {file_path}: {exc}") from exc

    items: Any
    if isinstance(data, dict) and "packages" in data:
        items = data["packages"]
        if not isinstance(items, list):
            raise ValueError(f"{file_path}: 'packages' must be a list")
    elif isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = [data]
    else:
        raise ValueError(f"{file_path}: expected object or list of package snapshots")

    snapshots: list[PackageSnapshot] = []
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            raise ValueError(f"{file_path}: package at index {index} must be an object")
        snapshots.append(PackageSnapshot.from_dict(item, source=str(file_path)))
    return snapshots


def _maintainer_identities(snapshot: PackageSnapshot) -> set[str]:
    identities: set[str] = set()
    for maintainer in snapshot.maintainers:
        email = maintainer.get("email", "").strip().lower()
        name = maintainer.get("name", "").strip().lower()
        if email:
            identities.add(f"email:{email}")
        elif name:
            identities.add(f"name:{name}")
    return identities


def _script_findings(snapshot: PackageSnapshot) -> list[Finding]:
    findings: list[Finding] = []
    for script_name, command in snapshot.scripts.items():
        lifecycle = script_name in LIFECYCLE_SCRIPTS
        for pattern, description, base_severity in SUSPICIOUS_SCRIPT_PATTERNS:
            if not pattern.search(command):
                continue
            severity = base_severity
            if lifecycle and severity.rank < Severity.HIGH.rank:
                severity = Severity.HIGH
            findings.append(
                Finding(
                    rule_id="SUSPICIOUS_SCRIPT",
                    severity=severity,
                    package=snapshot.name,
                    message=(
                        f"Suspicious script '{script_name}' contains {description}"
                        + (" in lifecycle hook" if lifecycle else "")
                    ),
                    details={
                        "script": script_name,
                        "command": command,
                        "pattern": description,
                        "lifecycle": lifecycle,
                    },
                )
            )
    return findings


def _metadata_completeness_findings(snapshot: PackageSnapshot) -> list[Finding]:
    findings: list[Finding] = []
    missing: list[str] = []
    if not snapshot.repository:
        missing.append("repository")
    if not snapshot.license:
        missing.append("license")
    if not snapshot.maintainers:
        missing.append("maintainers")
    if missing:
        findings.append(
            Finding(
                rule_id="MISSING_METADATA",
                severity=Severity.LOW,
                package=snapshot.name,
                message=f"Package metadata missing fields: {', '.join(missing)}",
                details={"missing_fields": missing},
            )
        )
