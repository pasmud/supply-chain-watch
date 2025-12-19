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

- a single package object
- a list of package objects
- an object with a `"packages"` list

Example package object:

```json
{
  "name": "acme-utils",
  "version": "2.5.0",
  "license": "MIT",
  "repository": "https://github.com/acme/acme-utils",
  "homepage": "https://acme.dev/acme-utils",
  "maintainers": [
    {"name": "Alice", "email": "alice@acme.dev"}
  ],
  "dependencies": {
    "requests": "==2.32.0"
  },
  "scripts": {
    "postinstall": "node setup.js"
  }
}
```

Notes:
- `repository` may be a string or an object containing `url`.
- `maintainers` may be strings (`"Alice <alice@example.com>"`), objects, or a
  mix.
- `dependencies` may be an object map or a list of requirement-like strings.

## Architecture / behavior

The package is organized as a small pipeline:

1. **Model normalization (`models.py`)**  
   Parses raw JSON objects into `PackageSnapshot` dataclasses. Normalization
   keeps comparisons deterministic (maintainer identity de-duplication,
   dependency/script mapping, repository URL extraction).

2. **Analysis (`analyzer.py`)**  
   Performs two classes of checks:
   - *Single-snapshot checks*: suspicious script patterns and missing metadata.
   - *Diff checks* (when `--baseline` is provided): maintainer identity changes,
     dependency add/remove/change, script add/change, repository/homepage/license
     changes, version changes, and package appearance/removal.

3. **Reporting (`report.py`)**  
   Converts findings into a machine-readable JSON structure or a human-readable
   text report. Reports include summary severity counts and detailed finding
   metadata.

4. **CLI (`cli.py`, `__main__.py`)**  
   Exposes the `scan` command and exit-code behavior for local use and CI.

### Rule IDs

| Rule ID | Meaning | Typical severity |
|---|---|---|
| `SUSPICIOUS_SCRIPT` | Script contains risky command pattern | medium–critical |
| `MISSING_METADATA` | Missing repository/license/maintainers | low |
| `MAINTAINER_CHANGE` | Maintainer identities added/removed | medium/high |
| `MAINTAINERS_REMOVED` | All maintainers removed | high |
| `DEPENDENCY_ADDED` | New dependency appeared | medium |
| `DEPENDENCY_REMOVED` | Dependency removed | low |
| `DEPENDENCY_CHANGED` | Dependency spec/version changed | medium |
| `SCRIPT_ADDED` | Script added (lifecycle scripts higher) | medium/high |
| `SCRIPT_CHANGED` | Script command changed | medium/high |
| `REPOSITORY_CHANGED` | Repository URL changed | high |
| `HOMEPAGE_CHANGED` | Homepage URL changed | medium |
| `LICENSE_CHANGED` | License changed | medium |
| `VERSION_CHANGED` | Version changed | low |
| `NEW_PACKAGE` | Package in current but not baseline | medium |
| `PACKAGE_REMOVED` | Package in baseline but not current | low |

## Development

Run tests:

```bash
PYTHONPATH=src python -m unittest discover -v
```

Or with pytest (if installed):

```bash
PYTHONPATH=src python -m pytest -q
```

Run the demo:

```bash
PYTHONPATH=src python -m supply_chain_watch scan examples/current.json --baseline examples/baseline.json --format text
```

## Limitations

- **Snapshot-based, not a registry client.** The tool does not fetch data from
  PyPI/npm/etc. You provide the metadata snapshots.
- **Heuristic indicators, not proof of compromise.** Findings are risk signals
  that should be reviewed in context.
- **No transitive dependency resolution.** Only metadata present in snapshots is
  analyzed.
- **Script analysis is pattern-based.** Obfuscated or novel malicious commands
  may evade simple pattern checks; benign commands may occasionally match.
- **Identity comparison is normalized but simple.** Maintainer matching is based
  on normalized email/name identities, not cryptographic identity proof.

## License

MIT. See [`LICENSE`](LICENSE).
