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
