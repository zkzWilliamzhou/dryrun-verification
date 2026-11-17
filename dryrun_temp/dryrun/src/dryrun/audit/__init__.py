"""Audit shell commands for dangerous patterns."""
from __future__ import annotations

from typing import List

from dryrun.audit.auditor import audit
from dryrun.core.types import Finding

__all__ = ["audit", "Finding"]
