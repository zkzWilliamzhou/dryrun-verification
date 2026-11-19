"""The dryrun auditor: run every rule over a parsed command."""
from __future__ import annotations

from typing import List

from dryrun.audit.rules import (
    BACKGROUND_JOB,
    BACKGROUND_REDIRECT,
    RULES,
    normalize,
    raw_fork_bomb,
)
from dryrun.core.types import Finding, severity_rank
from dryrun.explain.parser import ShellParseError, parse


def audit(command: str) -> List[Finding]:
    """Audit a command line for dangerous patterns; never raises."""
    findings: List[Finding] = []
    seen = set()

    # The POSIX-subset parser cannot model shell function definitions, so the
    # canonical fork bomb ":(){ :|:& };:" arrives as harmless-looking words.
    # Scan the raw text first; rule-based detection below stays as backstop.
    fb = raw_fork_bomb(command)
    if fb is not None:
        findings.append(fb)
        seen.add((fb.rule_id, fb.command_index))

    try:
        cl = parse(command)
    except ShellParseError as exc:
        return [Finding(
            rule_id="UNPARSEABLE",
            severity="INFO",
            title="command could not be parsed",
            detail=f"the parser stopped at: {exc}. Structural rules "
                   f"did not run; treat the preview with extra care.",
            command_index=0,
        )]

    cmds = normalize(cl)

    for rule in RULES:
        try:
            hits = rule.match(cmds) if rule.match is not None else []
        except Exception:  # a broken rule must never break the audit
            continue
        for index in hits:
            key = (rule.rule_id, index)
            if key in seen:
                continue
            seen.add(key)
            findings.append(Finding(
                rule_id=rule.rule_id,
                severity=rule.severity,
                title=rule.title,
                detail=rule.detail,
                command_index=index,
            ))

    # Trailing-separator rules need the raw list, not the normalized view.
    if cl.trailing == "&" and cmds:
        has_write = any(
            op in (">", ">>", "&>") for c in cmds for op, _t in c.redirects)
        rule = BACKGROUND_REDIRECT if has_write else BACKGROUND_JOB
        findings.append(Finding(
            rule_id=rule.rule_id,
            severity=rule.severity,
            title=rule.title,
            detail=rule.detail,
            command_index=cmds[-1].index,
        ))

    findings.sort(key=lambda f: (severity_rank(f.severity), f.rule_id,
                                 f.command_index))
    return findings
