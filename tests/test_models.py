"""Tests for data models and normalization."""

from __future__ import annotations

import unittest

from supply_chain_watch.models import Finding, PackageSnapshot, ScanReport, Severity


class SeverityTests(unittest.TestCase):
    def test_rank_ordering(self) -> None:
        self.assertLess(Severity.LOW.rank, Severity.MEDIUM.rank)
        self.assertLess(Severity.MEDIUM.rank, Severity.HIGH.rank)
        self.assertLess(Severity.HIGH.rank, Severity.CRITICAL.rank)

    def test_from_string(self) -> None:
        self.assertEqual(Severity.from_string("HIGH"), Severity.HIGH)
        self.assertEqual(Severity.from_string(" low "), Severity.LOW)

    def test_from_string_invalid(self) -> None:
        with self.assertRaises(ValueError):
            Severity.from_string("severe")


class PackageSnapshotTests(unittest.TestCase):
    def test_from_dict_normalizes_fields(self) -> None:
        snapshot = PackageSnapshot.from_dict(
            {
                "name": "example-pkg",
                "version": "1.2.3",
                "license": "MIT",
                "repository": {"url": "https://github.com/example/example-pkg"},
                "maintainers": [
                    "Alice <alice@example.com>",
                    {"name": "Bob", "email": "bob@example.com"},
                    {"email": "alice@example.com"},
                ],
                "dependencies": ["requests==2.31.0", {"name": "urllib3", "version": ">=2.0"}],
                "scripts": {"postinstall": "node setup.js"},
            }
        )
        self.assertEqual(snapshot.name, "example-pkg")
        self.assertEqual(snapshot.repository, "https://github.com/example/example-pkg")
        self.assertEqual(len(snapshot.maintainers), 2)
        self.assertEqual(snapshot.dependencies["requests"], "==2.31.0")
        self.assertEqual(snapshot.dependencies["urllib3"], ">=2.0")
        self.assertEqual(snapshot.scripts["postinstall"], "node setup.js")

    def test_from_dict_requires_name(self) -> None:
        with self.assertRaises(ValueError):
            PackageSnapshot.from_dict({"version": "1.0.0"})

    def test_from_dict_rejects_non_object(self) -> None:
        with self.assertRaises(ValueError):
            PackageSnapshot.from_dict(["not", "an", "object"])  # type: ignore[arg-type]

    def test_to_dict_round_trip_shape(self) -> None:
        snapshot = PackageSnapshot.from_dict({"name": "pkg", "version": "0.1.0"})
        data = snapshot.to_dict()
        self.assertEqual(data["name"], "pkg")
        self.assertEqual(data["version"], "0.1.0")
        self.assertIn("dependencies", data)


class ScanReportTests(unittest.TestCase):
    def test_summary_counts(self) -> None:
        report = ScanReport(packages_scanned=["a", "b"])
        report.findings.append(
            Finding(rule_id="R1", severity=Severity.HIGH, package="a", message="m")
        )
        report.findings.append(
            Finding(rule_id="R2", severity=Severity.LOW, package="b", message="m")
        )
        summary = report.summary()
        self.assertEqual(summary["packages_scanned"], 2)
        self.assertEqual(summary["findings"], 2)
        self.assertEqual(summary["severity_counts"]["high"], 1)
        self.assertEqual(summary["severity_counts"]["low"], 1)
        self.assertFalse(report.ok)
        self.assertTrue(report.has_severity_at_or_above(Severity.HIGH))
        self.assertFalse(report.has_severity_at_or_above(Severity.CRITICAL))
