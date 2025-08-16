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


def snap(data: dict) -> PackageSnapshot:
    return PackageSnapshot.from_dict(data)


class LoadSnapshotFileTests(unittest.TestCase):
    def test_load_single_object(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "pkg.json"
            path.write_text(json.dumps({"name": "pkg", "version": "1.0.0"}), encoding="utf-8")
            snaps = load_snapshot_file(path)
            self.assertEqual(len(snaps), 1)
            self.assertEqual(snaps[0].name, "pkg")

    def test_load_packages_wrapper(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "pkgs.json"
            path.write_text(
                json.dumps({"packages": [{"name": "a"}, {"name": "b"}]}),
                encoding="utf-8",
            )
            snaps = load_snapshot_file(path)
            self.assertEqual([s.name for s in snaps], ["a", "b"])
