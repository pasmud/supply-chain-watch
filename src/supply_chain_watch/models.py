"""Data models for supply-chain metadata snapshots and findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Severity levels for findings."""
