"""Core data types shared across all dryrun modules.

These types are the contract between the analysis layer (explain, audit),
the simulation engines, and the reporting layer. Treat them as frozen:
modules across the codebase import them by name.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

#: Severities ordered from most to least severe.
SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def severity_rank(severity: str) -> int:
    """Return the rank of a severity (0 = CRITICAL, 4 = INFO).

    Unknown severities sort as less severe than INFO.
    """
    try:
        return SEVERITY_ORDER.index(severity.upper())
    except ValueError:
        return len(SEVERITY_ORDER)


@dataclass
class Finding:
    """One audit finding for one rule that matched a command."""

    rule_id: str
    """Stable identifier, e.g. ``RM_RECURSIVE_FORCE``."""

    severity: str
    """One of :data:`SEVERITY_ORDER`."""

    title: str
    """One-line summary, e.g. ``recursive force-delete``."""

    detail: str
    """Plain-English explanation of why this rule fired and what is at risk."""

    command_index: int = 0
    """Index of the command within the parsed line (pipelines, ``&&`` lists)."""


@dataclass
class ExplanationSegment:
    """One unit of a plain-English command explanation."""

    kind: str
    """One of ``command``, ``flag``, ``arg``, ``operator``, ``redirect``,
    ``env``, ``substitution``, ``note``."""

    text: str
    """The human-readable description of this segment."""


@dataclass
class Explanation:
    """The full explanation of one command line."""

    command: str
    """The original command string."""

    summary: str
    """One or two sentences describing what the whole line does."""

    segments: list[ExplanationSegment] = field(default_factory=list)
    """Per-segment explanations, in command order."""


@dataclass
class ChangeRecord:
    """One filesystem change the simulated command would make."""

    op: str
    """One of ``create``, ``modify``, ``delete``, ``chmod``, ``rename``,
    ``mkdir``, ``rmdir``."""

    path: str
    """The real (absolute) path that would be affected."""

    detail: str = ""
    """Short human detail, e.g. ``3.2 kB`` or ``mode 0644 -> 0777``."""

    diff: Optional[str] = None
    """Unified diff for modified text files, when small enough to include."""


@dataclass
class SimulationResult:
    """Outcome of simulating one command with one engine."""

    engine: str
    """Engine name: ``trace`` or ``sandbox``."""

    command: str
    """The simulated command string."""

    returncode: Optional[int]
    """Exit status of the simulated command, or ``None`` if it could not run."""

    duration: float
    """Wall-clock duration of the simulation in seconds."""

    timed_out: bool
    """Whether the command was killed for exceeding the timeout."""

    changes: list[ChangeRecord] = field(default_factory=list)
    """Filesystem changes the command would make, in a stable order."""

    notes: list[str] = field(default_factory=list)
    """Honest caveats: effects the engine cannot see or guarantee."""

    stdout_tail: str = ""
    """Last kilobyte of the command's captured stdout (for context)."""

    stderr_tail: str = ""
    """Last kilobyte of the command's captured stderr (for context)."""
