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


def _load_or_error(path: str) -> tuple[list, str | None]:
    try:
        return load_snapshot_file(path), None
    except (OSError, ValueError) as exc:
        return [], str(exc)


def cmd_scan(args: argparse.Namespace) -> int:
    errors: list[str] = []

    current_snapshots, err = _load_or_error(args.current)
    if err:
        errors.append(err)

    baseline_snapshots = None
    if args.baseline:
        baseline_snapshots, err = _load_or_error(args.baseline)
        if err:
            errors.append(err)

    if errors and not current_snapshots:
        # Cannot produce a meaningful report without current data.
        message = "; ".join(errors)
        if args.format == "json":
            sys.stdout.write(json.dumps({"error": message, "errors": errors}) + "\n")
        else:
            sys.stderr.write(f"error: {message}\n")
        return 1

    report = analyze_snapshots(
        current_snapshots=current_snapshots,
        baseline_snapshots=baseline_snapshots if args.baseline else None,
        baseline_source=str(Path(args.baseline)) if args.baseline else None,
        current_source=str(Path(args.current)),
    )
    report.errors.extend(errors)

    if args.format == "json":
        output = report_to_json(report, pretty=args.pretty)
    else:
        output = report_to_text(report)

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
    else:
        sys.stdout.write(output)

    if args.fail_on:
        threshold = Severity.from_string(args.fail_on)
        if report.has_severity_at_or_above(threshold):
            return 2
    if report.errors:
        return 1
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return cmd_scan(args)
    parser.print_help()
    return 1
