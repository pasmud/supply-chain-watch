# supply-chain-watch

`supply-chain-watch` is a small, offline-friendly Python tool for watching package
metadata snapshots for supply-chain risk indicators. It compares a current
package metadata snapshot against an optional baseline and emits a structured
report highlighting changes and suspicious signals.

The project is intentionally lightweight: it uses the Python standard library at
runtime, works from local JSON snapshots, and produces deterministic output
suitable for CI checks or manual review.

## Features

- **Snapshot diffing**: compare current vs. baseline package metadata.
- **Change detection**: maintainer changes, dependency additions/removals/version
  changes, repository/homepage/license/version changes, and script additions or
  edits.
- **Suspicious script indicators**: flags risky script patterns such as curl/wget
  piped to a shell, encoded PowerShell execution, reverse-shell style commands,
  and network downloads in lifecycle hooks.
- **Metadata hygiene checks**: reports missing repository/license/maintainer
  metadata.
- **CLI report output**: JSON (default) or human-readable text, with optional
  fail threshold for CI gating.
- **Offline deterministic tests**: no network access required.

## Install

From the repository root:

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -e .
```

Python 3.10+ is supported.

## Quick start

Scan a current snapshot with a baseline and emit text output:

```bash
PYTHONPATH=src python -m supply_chain_watch scan examples/current.json --baseline examples/baseline.json --format text
```

Emit JSON (useful for automation):

```bash
PYTHONPATH=src python -m supply_chain_watch scan examples/current.json --baseline examples/baseline.json --format json --pretty
```

Fail the command when findings meet or exceed a severity threshold:

```bash
PYTHONPATH=src python -m supply_chain_watch scan examples/current.json --baseline examples/baseline.json --fail-on high
```

Exit codes:
- `0` — scan completed; no errors and no threshold-triggering findings
- `1` — input/load/report error
- `2` — at least one finding met or exceeded `--fail-on`

## Snapshot format

Input files are JSON. The tool accepts:

