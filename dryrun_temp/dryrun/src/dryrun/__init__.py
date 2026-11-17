"""dryrun — the universal --dry-run flag.

Explain, audit, and simulate any shell command before you run it.
"""
from __future__ import annotations

__version__ = "0.1.0"

from dryrun.core.types import (
    ChangeRecord,
    Explanation,
    ExplanationSegment,
    Finding,
    SimulationResult,
)

__all__ = [
    "__version__",
    "explain_command",
    "audit_command",
    "simulate",
    "Finding",
    "Explanation",
    "ExplanationSegment",
    "ChangeRecord",
    "SimulationResult",
]


def explain_command(command: str) -> Explanation:
    """Explain a command in plain English (dryrun.explain.explain)."""
    from dryrun.explain import explain as _explain

    return _explain(command)


def audit_command(command: str) -> list[Finding]:
    """Audit a command for dangerous patterns (dryrun.audit.audit)."""
    from dryrun.audit import audit as _audit

    return _audit(command)
