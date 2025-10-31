# Examples

This directory contains small, deterministic snapshot files for demonstrating
`supply-chain-watch`.

## Files

- `baseline.json` — known-good package metadata snapshot.
- `current.json` — newer snapshot with several supply-chain indicators.

## Demo

From the repository root:

```bash
PYTHONPATH=src python -m supply_chain_watch scan examples/current.json --baseline examples/baseline.json --format text
```

For machine-readable output:

```bash
PYTHONPATH=src python -m supply_chain_watch scan examples/current.json --baseline examples/baseline.json --format json --pretty
```

