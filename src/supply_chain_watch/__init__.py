"""Supply-chain indicator watcher for package metadata changes."""

from .analyzer import analyze_snapshots, scan_snapshot
from .models import Finding, PackageSnapshot, ScanReport, Severity

__all__ = [
    "Finding",
    "PackageSnapshot",
    "ScanReport",
    "Severity",
    "analyze_snapshots",
    "scan_snapshot",
]

__version__ = "0.1.0"
