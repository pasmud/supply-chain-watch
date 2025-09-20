"""CLI smoke and behavior tests."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"


def run_cli(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = str(SRC) + (os.pathsep + existing if existing else "")
    return subprocess.run(
        [sys.executable, "-m", "supply_chain_watch", *args],
        cwd=str(cwd or REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


class CLITests(unittest.TestCase):
    def test_help(self) -> None:
        result = run_cli("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("supply-chain-watch", result.stdout)
        self.assertIn("scan", result.stdout)

    def test_scan_json_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            current = Path(tmp) / "current.json"
            current.write_text(
                json.dumps(
                    {
                        "packages": [
                            {
                                "name": "pkg",
                                "version": "1.0.0",
                                "repository": "https://github.com/example/pkg",
                                "license": "MIT",
                                "maintainers": [{"email": "a@example.com"}],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            result = run_cli("scan", str(current), "--format", "json")
            self.assertEqual(result.returncode, 0, msg=result.stderr + result.stdout)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["summary"]["packages_scanned"], 1)
            self.assertEqual(payload["summary"]["findings"], 0)
