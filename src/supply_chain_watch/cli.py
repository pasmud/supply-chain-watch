"""Command-line interface for supply-chain-watch."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from .analyzer import analyze_snapshots, load_snapshot_file
from .models import Severity
from .report import report_to_json, report_to_text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="supply-chain-watch",
        description="Watch package metadata snapshots for supply-chain risk indicators.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser(
        "scan",
        help="Scan a current snapshot file against an optional baseline snapshot file.",
        description=(
            "Scan package metadata JSON snapshots for supply-chain indicators. "
            "Provide --baseline to compare two snapshots and detect changes."
        ),
    )
    scan.add_argument("current", help="Path to current package snapshot JSON file")
    scan.add_argument(
        "--baseline",
        "-b",
        help="Path to baseline package snapshot JSON file for diff analysis",
    )
    scan.add_argument(
        "--format",
        "-f",
        choices=["json", "text"],
        default="json",
        help="Output format (default: json)",
    )
    scan.add_argument(
        "--output",
        "-o",
        help="Write report to this file instead of stdout",
    )
    scan.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )
    scan.add_argument(
        "--fail-on",
        choices=[s.value for s in Severity],
        help="Exit with code 2 if any finding meets or exceeds this severity",
    )

    return parser
