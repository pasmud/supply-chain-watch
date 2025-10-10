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
