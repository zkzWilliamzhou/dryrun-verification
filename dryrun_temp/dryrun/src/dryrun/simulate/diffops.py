"""Shared diff-and-order policy for the simulation engines.

Both the trace engine and the sandbox engine turn two file trees into a
sorted list of :class:`~dryrun.core.types.ChangeRecord`. The rules for
rendering sizes, capping unified diffs, and ordering change records are
engine-independent policy: they live here, once, so a rule change cannot
drift between the two engines.
"""
from __future__ import annotations

import difflib
import os
from typing import List, Optional

from dryrun.core.types import ChangeRecord

#: Attach unified diffs only when both file versions stay below this size.
MAX_DIFF_BYTES = 256 * 1024

#: Cap stored unified diffs at this many characters.
MAX_DIFF_CHARS = 4096

#: Change sort order: removals first, creations and edits last.
OP_SORT_ORDER = {
    "delete": 0,
    "rmdir": 1,
    "rename": 2,
    "mkdir": 3,
    "create": 4,
    "modify": 5,
    "chmod": 6,
}


def human_size(size: int) -> str:
    """Render a byte count as B, KiB, or MiB."""
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KiB"
    return f"{size / (1024 * 1024):.1f} MiB"


def unified_diff(
    old_path: str,
    new_path: str,
    rel: str,
    *,
    old_size: Optional[int] = None,
    new_size: Optional[int] = None,
) -> Optional[str]:
    """Build a capped unified diff for a modified text file, or None.

    Sizes may be passed in when the caller already stat'ed both files;
    otherwise they are read here. Returns None for oversized, undecodable,
    or vanished files - never raises.
    """
    try:
        if old_size is None:
            old_size = os.path.getsize(old_path)
        if new_size is None:
            new_size = os.path.getsize(new_path)
    except OSError:
        return None
    if old_size >= MAX_DIFF_BYTES or new_size >= MAX_DIFF_BYTES:
        return None
    try:
        with open(old_path, "rb") as handle:
            old_text = handle.read().decode("utf-8")
        with open(new_path, "rb") as handle:
            new_text = handle.read().decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    lines = list(
        difflib.unified_diff(
            old_text.splitlines(),
            new_text.splitlines(),
            fromfile="a/" + rel,
            tofile="b/" + rel,
            lineterm="",
        )
    )
    if not lines:
        return None
    text = "\n".join(lines)
    if len(text) > MAX_DIFF_CHARS:
        text = text[:MAX_DIFF_CHARS].rstrip("\n") + "\n... (diff truncated)"
    return text


def sort_changes(changes: List[ChangeRecord]) -> List[ChangeRecord]:
    """Order records removals-first, creations and edits last, then by path."""
    return sorted(
        changes,
        key=lambda record: (OP_SORT_ORDER.get(record.op, 99), record.path),
    )
