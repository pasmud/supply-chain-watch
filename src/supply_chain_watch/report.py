"""Report formatting utilities."""

from __future__ import annotations

import json
from typing import Any

from .models import ScanReport, Severity


def report_to_dict(report: ScanReport) -> dict[str, Any]:
    """Convert a ScanReport to a JSON-serializable dict."""
    return report.to_dict()


def report_to_json(report: ScanReport, pretty: bool = False) -> str:
    """Render a report as JSON."""
    payload = report_to_dict(report)
    if pretty:
        return json.dumps(payload, indent=2, sort_keys=False) + "\n"
    return json.dumps(payload, separators=(",", ":"), sort_keys=False)


def _severity_label(severity: Severity) -> str:
    return severity.value.upper()


def report_to_text(report: ScanReport) -> str:
    """Render a human-readable text report."""
    lines: list[str] = []
    lines.append("Supply Chain Watch Report")
    lines.append("=========================")
    lines.append(f"Packages scanned: {len(report.packages_scanned)}")
    if report.baseline_source:
        lines.append(f"Baseline: {report.baseline_source}")
    if report.current_source:
        lines.append(f"Current:  {report.current_source}")
    lines.append("")
