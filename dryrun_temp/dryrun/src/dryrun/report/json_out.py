"""Machine-readable --json output: one stable payload schema, no ANSI."""
from __future__ import annotations

import json
from typing import IO, Optional, Sequence

from dryrun import __version__
from dryrun.core.types import (
    ChangeRecord,
    Explanation,
    Finding,
    SimulationResult,
    severity_rank,
)


def _explanation_json(explanation: Optional[Explanation]) -> Optional[dict]:
    """Convert an Explanation to its JSON shape, or None."""
    if explanation is None:
        return None
    segments = [
        {"kind": segment.kind, "text": segment.text}
        for segment in explanation.segments
    ]
    return {"summary": explanation.summary, "segments": segments}


def _finding_json(finding: Finding) -> dict:
    """Convert one Finding to its JSON shape."""
    return {
        "rule_id": finding.rule_id,
        "severity": finding.severity,
        "title": finding.title,
        "detail": finding.detail,
        "command_index": finding.command_index,
    }


def _change_json(change: ChangeRecord) -> dict:
    """Convert one ChangeRecord to its JSON shape."""
    return {
        "op": change.op,
        "path": change.path,
        "detail": change.detail,
        "diff": change.diff,
    }


def _simulation_json(result: Optional[SimulationResult]) -> Optional[dict]:
    """Convert a SimulationResult to its JSON shape, or None."""
    if result is None:
        return None
    return {
        "engine": result.engine,
        "returncode": result.returncode,
        "duration": result.duration,
        "timed_out": result.timed_out,
        "changes": [_change_json(change) for change in result.changes],
        "notes": list(result.notes),
        "stdout_tail": result.stdout_tail,
        "stderr_tail": result.stderr_tail,
    }


def build_payload(
    command: str,
    explanation: Optional[Explanation],
    findings: Sequence[Finding],
    result: Optional[SimulationResult],
    *,
    error: Optional[dict] = None,
) -> dict:
    """Assemble the exact --json payload for one dryrun invocation."""
    ordered = sorted(
        findings,
        key=lambda finding: (severity_rank(finding.severity), finding.rule_id),
    )
    payload = {
        "dryrun_version": __version__,
        "command": command,
        "explanation": _explanation_json(explanation),
        "audit": [_finding_json(finding) for finding in ordered],
        "simulation": _simulation_json(result),
    }
    if error is not None:
        payload["error"] = error
    return payload


def emit(payload: dict, stream: IO[str]) -> None:
    """Write the payload as pretty-printed JSON plus one trailing newline."""
    stream.write(json.dumps(payload, indent=2) + "\n")
