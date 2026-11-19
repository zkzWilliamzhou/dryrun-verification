"""Human-readable output: plain ASCII text with optional ANSI color.

All output is ASCII-only when color is off; ANSI escapes are applied only
when the caller explicitly enables them.
"""
from __future__ import annotations

import os
import sys
import textwrap
from typing import IO, Optional, Sequence

from dryrun import __version__
from dryrun.core.types import (
    ChangeRecord,
    Explanation,
    Finding,
    SimulationResult,
    severity_rank,
)

#: Maximum line width for wrapped detail lines.
_LINE_WIDTH = 100

#: Maximum number of unified-diff lines rendered per change.
_MAX_DIFF_LINES = 12

_RESET = "\x1b[0m"

_SEVERITY_CODES = {
    "CRITICAL": "1;31",
    "HIGH": "31",
    "MEDIUM": "33",
    "LOW": "36",
    "INFO": "32",
}

_OP_MARKERS = {
    "create": "+",
    "mkdir": "+",
    "modify": "~",
    "chmod": "~",
    "delete": "-",
    "rmdir": "-",
    "rename": ">",
}

_MARKER_CODES = {"+": "32", "~": "33", "-": "31", ">": "36"}


def supports_color(stream: IO[str]) -> bool:
    """Return True when ``stream`` is a color-capable terminal."""
    isatty = getattr(stream, "isatty", None)
    if not isatty or not isatty():
        return False
    return os.environ.get("TERM", "") != "dumb"


def _paint(text: str, code: Optional[str], *, color: bool) -> str:
    """Wrap ``text`` in an ANSI sequence when color is on and a code exists."""
    if not color or code is None:
        return text
    return f"\x1b[{code}m{text}{_RESET}"


def print_explanation(explanation: Explanation, *, color: bool, stream: IO[str]) -> None:
    """Print the explanation section: summary plus one line per segment."""
    stream.write("Explanation\n")
    for line in textwrap.wrap(explanation.summary, width=_LINE_WIDTH - 2):
        stream.write(f"  {line}\n")
    for segment in explanation.segments:
        stream.write(f"  {segment.text}\n")


def print_findings(findings: Sequence[Finding], *, color: bool, stream: IO[str]) -> None:
    """Print audit findings sorted by severity, wrapped to 100 columns."""
    stream.write(f"Audit findings ({len(findings)})\n")
    ordered = sorted(
        findings, key=lambda finding: (severity_rank(finding.severity), finding.rule_id)
    )
    for finding in ordered:
        severity = finding.severity.upper()
        head = f"{severity:<8}  {finding.rule_id:<18}  "
        body = (
            f"{finding.title} - {finding.detail}" if finding.detail else finding.title
        )
        lines = textwrap.wrap(
            head + body,
            width=_LINE_WIDTH - 2,
            subsequent_indent=" " * len(head),
        ) or [head.rstrip()]
        painted = _paint(f"{severity:<8}", _SEVERITY_CODES.get(severity), color=color)
        stream.write(f"  {painted}  {finding.rule_id:<18}  {lines[0][len(head):]}\n")
        for line in lines[1:]:
            stream.write(f"  {line}\n")


def _change_summary(changes: Sequence[ChangeRecord]) -> str:
    """Summarize change counts as one sentence fragment."""
    counts: dict = {}
    for change in changes:
        counts[change.op] = counts.get(change.op, 0) + 1
    parts = []
    if counts.get("create"):
        parts.append(f"create {_plural(counts['create'], 'file')}")
    if counts.get("mkdir"):
        parts.append(f"create {_plural(counts['mkdir'], 'dir')}")
    if counts.get("modify"):
        parts.append(f"modify {counts['modify']}")
    if counts.get("chmod"):
        parts.append(f"chmod {counts['chmod']}")
    if counts.get("rename"):
        parts.append(f"rename {counts['rename']}")
    if counts.get("delete"):
        parts.append(f"delete {_plural(counts['delete'], 'file')}")
    if counts.get("rmdir"):
        parts.append(f"delete {_plural(counts['rmdir'], 'dir')}")
    return ", ".join(parts)


def _plural(count: int, noun: str) -> str:
    """Return a pluralized count such as '1 file' or '3 dirs'."""
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def _exit_status(result: SimulationResult) -> str:
    """Describe the simulated command's exit status for the header line."""
    if result.returncode is None:
        status = "exit unknown"
    else:
        status = f"exit {result.returncode}"
    if result.timed_out:
        status = f"timed out, {status}"
    return status


def _print_diff(diff: str, *, stream: IO[str]) -> None:
    """Render at most 12 unified-diff lines indented under the change."""
    lines = diff.split("\n")
    for line in lines[:_MAX_DIFF_LINES]:
        stream.write(f"       | {line}\n")
    if len(lines) > _MAX_DIFF_LINES:
        stream.write("       ... (diff truncated)\n")


def _print_change(record: ChangeRecord, *, color: bool, stream: IO[str]) -> None:
    """Print one change line plus its diff, when present."""
    marker = _OP_MARKERS.get(record.op, "?")
    painted = _paint(marker, _MARKER_CODES.get(marker), color=color)
    line = f"    {painted}  {record.path}"
    if record.detail:
        line += f" ({record.detail})"
    stream.write(line + "\n")
    if record.diff:
        _print_diff(record.diff, stream=stream)


_ENGINE_PROMISES = {
    # The trace engine shadows writes anywhere on the file system.
    "trace": "nothing will be touched",
    # The sandbox engine only observes effects inside the working
    # directory; writes outside it (absolute paths, symlink targets)
    # would escape the sandbox copy.
    "sandbox": (
        "preview covers the working directory only; writes outside it "
        "are not contained by this engine"
    ),
}


def print_simulation(
    result: SimulationResult, *, color: bool, stream: IO[str]
) -> None:
    """Print the full simulation block: header, changes, notes, footer."""
    promise = _ENGINE_PROMISES.get(
        result.engine, "changes are previewed, not applied"
    )
    stream.write(
        f"dryrun {__version__} - previewing with {result.engine} engine "
        f"({promise})\n"
    )
    stream.write(f"Simulation - {_exit_status(result)}, {result.duration:.1f}s\n")
    if result.changes:
        stream.write(f"  Would {_change_summary(result.changes)}:\n")
        for record in result.changes:
            _print_change(record, color=color, stream=stream)
    else:
        stream.write("  Would change nothing.\n")
    if result.notes:
        stream.write("  Notes\n")
        for note in result.notes:
            stream.write(f"    - {note}\n")
    verdict = _paint("Nothing was touched.", "1;32", color=color)
    stream.write(
        f'{verdict} Run for real with: dryrun --execute "{result.command}"\n'
    )


def print_execute_banner(command: str, *, color: bool, stream: IO[str]) -> None:
    """Print the warning banner shown before running a command for real."""
    banner = _paint("Running for real:", "1;33", color=color)
    stream.write(f"{banner} {command}\n")


def confirm_execute(command: str, *, stream: IO[str]) -> bool:
    """Prompt 'Run for real? [y/N] ' and return True only for y/yes."""
    stream.write("Run for real? [y/N] ")
    stream.flush()
    try:
        answer = sys.stdin.readline()
    except (EOFError, OSError):
        return False
    return answer.strip().lower() in ("y", "yes")
