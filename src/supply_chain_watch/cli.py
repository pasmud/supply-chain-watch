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
