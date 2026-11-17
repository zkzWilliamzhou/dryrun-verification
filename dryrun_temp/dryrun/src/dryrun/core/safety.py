"""Preflight safety guards: refuse simulations that cannot be honest.

Checks run before any engine touches the filesystem: running as root,
privilege-elevation tools, and setuid binaries all refuse the simulation
with a :class:`SafetyError` carrying a user-facing message.
"""
from __future__ import annotations

import os
import shlex
import shutil
import stat
from typing import List

#: Tools that escalate privileges and therefore cannot be simulated honestly.
ELEVATION_TOOLS = {"sudo", "su", "doas", "pkexec", "newgrp"}

_BREAK_CHARS = frozenset("|&;()")


class SafetyError(Exception):
    """User-facing message; simulation refused."""


def _tokenize(command: str) -> List[str]:
    """Split into words and shell operator tokens, honoring quoting."""
    lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    return list(lexer)


def _is_segment_break(token: str) -> bool:
    """Return True for tokens made purely of command-separator punctuation."""
    return bool(token) and all(char in _BREAK_CHARS for char in token)


def _command_segments(tokens: List[str]) -> List[List[str]]:
    """Group tokens into simple commands split at pipes, lists, and parens."""
    segments: List[List[str]] = [[]]
    for token in tokens:
        if _is_segment_break(token):
            segments.append([])
        else:
            segments[-1].append(token)
    return segments


def _is_setuid(path: str) -> bool:
    """Return True when ``path`` exists and carries the setuid bit."""
    try:
        mode = os.stat(path).st_mode
    except OSError:
        return False
    return bool(mode & stat.S_ISUID)


def _check_root(allow_root: bool) -> None:
    """Refuse simulation when running as root without an explicit override."""
    if not allow_root and hasattr(os, "geteuid") and os.geteuid() == 0:
        raise SafetyError(
            "refusing to simulate: dryrun is running as root; "
            "pass --allow-root to override"
        )


def _check_elevation(segments: List[List[str]]) -> None:
    """Refuse simulation when any pipeline segment starts an elevation tool."""
    for segment in segments:
        if not segment:
            continue
        first = segment[0]
        if first in ELEVATION_TOOLS or os.path.basename(first) in ELEVATION_TOOLS:
            raise SafetyError(
                f"refusing to simulate: '{first}' escalates privileges and "
                "cannot be simulated honestly; use --audit-only for static "
                "analysis"
            )


def _check_setuid(tokens: List[str]) -> None:
    """Refuse simulation when any word resolves to a setuid binary."""
    for word in tokens:
        resolved = shutil.which(word)
        if resolved and _is_setuid(resolved):
            raise SafetyError(
                f"refusing to simulate: '{word}' resolves to setuid binary "
                f"'{resolved}'"
            )


def preflight(command: str, *, allow_root: bool = False) -> None:
    """Refuse unsafe simulations by raising SafetyError; return None otherwise.

    Best-effort: this function never lets anything except SafetyError escape,
    so unexpected internal failures also fail closed as a refusal.
    """
    try:
        _check_root(allow_root)
        try:
            tokens = _tokenize(command)
        except ValueError as exc:
            raise SafetyError(f"cannot parse command: {exc}") from exc
        segments = _command_segments(tokens)
        _check_elevation(segments)
        _check_setuid(tokens)
    except SafetyError:
        raise
    except Exception as exc:
        # Fail closed: a broken guard must never allow a simulation.
        raise SafetyError(f"preflight check failed: {exc}") from exc
