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
    return findings


def scan_snapshot(snapshots: list[PackageSnapshot]) -> ScanReport:
    """Scan snapshots for indicators that do not require a baseline."""
    report = ScanReport(packages_scanned=[s.name for s in snapshots])
    for snapshot in snapshots:
        report.findings.extend(_script_findings(snapshot))
        report.findings.extend(_metadata_completeness_findings(snapshot))
    report.findings.sort(key=lambda f: (-f.severity.rank, f.package, f.rule_id, f.message))
    return report


def _diff_maintainers(baseline: PackageSnapshot, current: PackageSnapshot) -> list[Finding]:
    old = _maintainer_identities(baseline)
    new = _maintainer_identities(current)
    if not old or old == new:
        if old and old == new:
            return []
        # no baseline maintainers -> cannot assert change, but current missing handled elsewhere
        if old and not new:
            return [
                Finding(
                    rule_id="MAINTAINERS_REMOVED",
                    severity=Severity.HIGH,
                    package=current.name,
                    message="All maintainers were removed from package metadata",
                    details={"previous": sorted(old), "current": []},
                )
            ]
        return []
    added = sorted(new - old)
    removed = sorted(old - new)
    findings: list[Finding] = []
    if removed and not new:
        findings.append(
            Finding(
                rule_id="MAINTAINERS_REMOVED",
                severity=Severity.HIGH,
                package=current.name,
                message="All maintainers were removed from package metadata",
                details={"previous": sorted(old), "current": []},
            )
        )
        return findings
    if added or removed:
        severity = Severity.HIGH if removed else Severity.MEDIUM
        findings.append(
            Finding(
                rule_id="MAINTAINER_CHANGE",
                severity=severity,
                package=current.name,
                message="Maintainer identities changed between snapshots",
                details={"added": added, "removed": removed},
            )
        )
    return findings


def _diff_dependencies(baseline: PackageSnapshot, current: PackageSnapshot) -> list[Finding]:
    findings: list[Finding] = []
    old = baseline.dependencies
    new = current.dependencies
    added = sorted(set(new) - set(old))
    removed = sorted(set(old) - set(new))
    changed = sorted(name for name in set(old) & set(new) if old[name] != new[name])

    for name in added:
        findings.append(
            Finding(
                rule_id="DEPENDENCY_ADDED",
                severity=Severity.MEDIUM,
                package=current.name,
                message=f"Dependency added: {name} {new[name]}".rstrip(),
                details={"dependency": name, "version": new[name]},
            )
        )
    for name in removed:
        findings.append(
            Finding(
                rule_id="DEPENDENCY_REMOVED",
                severity=Severity.LOW,
                package=current.name,
                message=f"Dependency removed: {name} {old[name]}".rstrip(),
                details={"dependency": name, "previous_version": old[name]},
            )
        )
    for name in changed:
        findings.append(
            Finding(
                rule_id="DEPENDENCY_CHANGED",
                severity=Severity.MEDIUM,
                package=current.name,
                message=f"Dependency version changed: {name} {old[name]!r} -> {new[name]!r}",
                details={"dependency": name, "previous": old[name], "current": new[name]},
            )
        )
    return findings


def _diff_simple_field(
    baseline: PackageSnapshot,
    current: PackageSnapshot,
    field: str,
    rule_id: str,
    severity: Severity,
    label: str,
) -> list[Finding]:
    old = getattr(baseline, field)
    new = getattr(current, field)
    if not old or not new or old == new:
        return []
    return [
        Finding(
            rule_id=rule_id,
            severity=severity,
            package=current.name,
            message=f"{label} changed: {old!r} -> {new!r}",
            details={"previous": old, "current": new},
        )
    ]


def _diff_scripts(baseline: PackageSnapshot, current: PackageSnapshot) -> list[Finding]:
    findings: list[Finding] = []
    old = baseline.scripts
    new = current.scripts
    for name in sorted(set(new) - set(old)):
        lifecycle = name in LIFECYCLE_SCRIPTS
        findings.append(
            Finding(
                rule_id="SCRIPT_ADDED",
                severity=Severity.HIGH if lifecycle else Severity.MEDIUM,
                package=current.name,
                message=f"Script added: {name}" + (" (lifecycle hook)" if lifecycle else ""),
                details={"script": name, "command": new[name], "lifecycle": lifecycle},
            )
        )
    for name in sorted(set(old) & set(new)):
        if old[name] == new[name]:
            continue
        lifecycle = name in LIFECYCLE_SCRIPTS
        findings.append(
            Finding(
                rule_id="SCRIPT_CHANGED",
                severity=Severity.HIGH if lifecycle else Severity.MEDIUM,
                package=current.name,
                message=f"Script changed: {name}" + (" (lifecycle hook)" if lifecycle else ""),
                details={
                    "script": name,
                    "previous": old[name],
                    "current": new[name],
                    "lifecycle": lifecycle,
                },
            )
        )
    return findings


def compare_snapshots(baseline: PackageSnapshot, current: PackageSnapshot) -> list[Finding]:
    """Compare two snapshots of the same package and return findings."""
    if baseline.name != current.name:
        raise ValueError(
            f"snapshot name mismatch: baseline={baseline.name!r}, current={current.name!r}"
        )
    findings: list[Finding] = []
    findings.extend(_diff_maintainers(baseline, current))
    findings.extend(_diff_dependencies(baseline, current))
    findings.extend(_diff_scripts(baseline, current))
    findings.extend(
        _diff_simple_field(
            baseline, current, "repository", "REPOSITORY_CHANGED", Severity.HIGH, "Repository URL"
        )
    )
    findings.extend(
        _diff_simple_field(
            baseline, current, "homepage", "HOMEPAGE_CHANGED", Severity.MEDIUM, "Homepage URL"
        )
    )
    findings.extend(
        _diff_simple_field(
            baseline, current, "license", "LICENSE_CHANGED", Severity.MEDIUM, "License"
        )
    )
    findings.extend(
        _diff_simple_field(
            baseline, current, "version", "VERSION_CHANGED", Severity.LOW, "Version"
        )
    )
    return findings


def analyze_snapshots(
    current_snapshots: list[PackageSnapshot],
    baseline_snapshots: list[PackageSnapshot] | None = None,
    baseline_source: str | None = None,
    current_source: str | None = None,
) -> ScanReport:
    """Analyze current snapshots, optionally comparing against a baseline."""
    report = ScanReport(
        packages_scanned=[s.name for s in current_snapshots],
        baseline_source=baseline_source,
        current_source=current_source,
    )

    # Single-snapshot checks (always run on current)
    for snapshot in current_snapshots:
        report.findings.extend(_script_findings(snapshot))
        report.findings.extend(_metadata_completeness_findings(snapshot))

    if baseline_snapshots is not None:
        baseline_by_name = {s.name: s for s in baseline_snapshots}
        current_by_name = {s.name: s for s in current_snapshots}

        for name in sorted(set(current_by_name) - set(baseline_by_name)):
            report.findings.append(
                Finding(
                    rule_id="NEW_PACKAGE",
                    severity=Severity.MEDIUM,
                    package=name,
                    message=f"Package appears in current snapshot but not baseline: {name}",
                    details={"name": name},
                )
            )
        for name in sorted(set(baseline_by_name) - set(current_by_name)):
            report.findings.append(
                Finding(
                    rule_id="PACKAGE_REMOVED",
                    severity=Severity.LOW,
                    package=name,
                    message=f"Package present in baseline but missing from current snapshot: {name}",
                    details={"name": name},
                )
            )
        for name in sorted(set(baseline_by_name) & set(current_by_name)):
            report.findings.extend(compare_snapshots(baseline_by_name[name], current_by_name[name]))

    report.findings.sort(key=lambda f: (-f.severity.rank, f.package, f.rule_id, f.message))
    return report
