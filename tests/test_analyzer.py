"""Tests for the analyzer and detection rules."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from supply_chain_watch.analyzer import (
    analyze_snapshots,
    compare_snapshots,
    load_snapshot_file,
    scan_snapshot,
)
from supply_chain_watch.models import PackageSnapshot, Severity
