"""Core analysis logic for detecting supply-chain indicators."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .models import Finding, PackageSnapshot, ScanReport, Severity

SUSPICIOUS_SCRIPT_PATTERNS: list[tuple[re.Pattern[str], str, Severity]] = [
    (re.compile(r"\bcurl\b[^\n|]*\|\s*(?:sh|bash|zsh)\b", re.I), "curl piped to shell", Severity.CRITICAL),
    (re.compile(r"\bwget\b[^\n|]*\|\s*(?:sh|bash|zsh)\b", re.I), "wget piped to shell", Severity.CRITICAL),
    (re.compile(r"\b(?:powershell|pwsh)\b.*(?:-enc|-encodedcommand|iex|invoke-expression)", re.I), "encoded PowerShell execution", Severity.CRITICAL),
    (re.compile(r"\b(?:nc|ncat|netcat)\b\s+.*\s+-e\s+", re.I), "netcat reverse-shell style flag", Severity.CRITICAL),
    (re.compile(r"\b(?:bash\s+-i|/dev/tcp/)\b", re.I), "interactive shell / dev tcp usage", Severity.CRITICAL),
    (re.compile(r"\bbase64\b.*\|\s*(?:sh|bash|python|node)\b", re.I), "decoded payload piped to interpreter", Severity.HIGH),
    (re.compile(r"\brm\s+-rf\s+/(?:\s|$)", re.I), "destructive root deletion command", Severity.CRITICAL),
    (re.compile(r"\b(?:curl|wget)\b[^\n]*https?://", re.I), "network download in script", Severity.MEDIUM),
    (re.compile(r"\b(?:chmod\s+\+x|chmod\s+777)\b", re.I), "permission escalation in script", Severity.MEDIUM),
]

LIFECYCLE_SCRIPTS = {"preinstall", "install", "postinstall", "prepare", "prepublish", "prepublishOnly"}
