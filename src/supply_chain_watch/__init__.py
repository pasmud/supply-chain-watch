"""Supply-chain indicator watcher for package metadata changes."""

from .analyzer import analyze_snapshots, scan_snapshot
from .models import Finding, PackageSnapshot, ScanReport, Severity
