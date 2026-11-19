"""Sandbox engine: run the command in a private copy of the tree, then diff.

The working directory is copied into a 0700 temp directory (reflink when
possible), the command runs there, and the two trees are compared to report
exactly what the command would have changed.
"""
from __future__ import annotations

import filecmp
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Dict, List, Optional, Tuple

from dryrun.core.proc import run_command
from dryrun.core.types import ChangeRecord, SimulationResult
from dryrun.simulate.base import EngineError
from dryrun.simulate.diffops import human_size, sort_changes, unified_diff

#: Refuse to copy trees larger than this (512 MiB by default).
DEFAULT_MAX_TREE_BYTES = 512 * 1024 * 1024

_Entry = Tuple[str, os.stat_result]


def _kind_of(st: os.stat_result) -> str:
    """Classify a lstat result as file, symlink, or dir."""
    if stat.S_ISLNK(st.st_mode):
        return "symlink"
    if stat.S_ISDIR(st.st_mode):
        return "dir"
    return "file"


def _walk_tree(root: str) -> Tuple[Dict[str, _Entry], List[str]]:
    """Map relpath to (kind, lstat) for every entry under ``root``."""
    entries: Dict[str, _Entry] = {}
    notes: List[str] = []

    def on_error(err: OSError) -> None:
        rel = os.path.relpath(err.filename, root) if err.filename else root
        notes.append(f"could not scan {rel}: {err.strerror or err}")

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False, onerror=on_error):
        for name in dirnames + filenames:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            try:
                st = os.lstat(full)
            except OSError as exc:
                notes.append(f"could not inspect {rel}: {exc.strerror or exc}")
                continue
            entries[rel] = (_kind_of(st), st)
    return entries, notes


def _copy_tree(src: str, dst: str) -> List[str]:
    """Copy ``src``'s contents into ``dst``; prefer cp -a with reflinks.

    ``--reflink=auto`` is a GNU-only option: BSD/macOS ``cp`` rejects it,
    which would force the slow Python fallback on every run and leak an
    environment-dependent note into results. Only pass it on Linux.
    """
    cp_error: Optional[str] = None
    cmd = ["cp", "-a"]
    if sys.platform.startswith("linux"):
        cmd.append("--reflink=auto")
    cmd += [src + "/.", dst + "/"]
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except OSError as exc:
        cp_error = str(exc)
    else:
        if proc.returncode == 0:
            return []
        cp_error = f"cp exited with status {proc.returncode}"
    try:
        shutil.copytree(
            src,
            dst,
            symlinks=True,
            ignore_dangling_symlinks=True,
            dirs_exist_ok=True,
        )
    except (OSError, shutil.Error) as exc:
        raise EngineError(f"could not copy working directory into sandbox: {exc}") from exc
    return [f"fast copy failed ({cp_error}); used slower python fallback"]


def _record_new(
    new_root: str, rel: str, path: str, entry: _Entry
) -> Tuple[ChangeRecord, Optional[str]]:
    """Build the change record for an entry that only exists in the sandbox."""
    kind, st = entry
    if kind == "dir":
        return ChangeRecord(op="mkdir", path=path), None
    if kind == "symlink":
        try:
            target = os.readlink(os.path.join(new_root, rel))
        except OSError as exc:
            return (
                ChangeRecord(op="create", path=path, detail="symlink"),
                f"could not read new symlink {rel}: {exc.strerror or exc}",
            )
        return ChangeRecord(op="create", path=path, detail=f"symlink -> {target}"), None
    return ChangeRecord(op="create", path=path, detail=human_size(st.st_size)), None


def _diff_same_kind(
    orig_root: str,
    new_root: str,
    rel: str,
    path: str,
    orig_entry: _Entry,
    new_entry: _Entry,
    changes: List[ChangeRecord],
    notes: List[str],
) -> None:
    """Append a record when two same-kind entries actually differ."""
    okind, ost = orig_entry
    _nkind, nst = new_entry
    orig_path = os.path.join(orig_root, rel)
    new_path = os.path.join(new_root, rel)
    if okind == "file":
        if ost.st_size == nst.st_size and ost.st_mtime_ns == nst.st_mtime_ns:
            return
        try:
            identical = filecmp.cmp(orig_path, new_path, shallow=False)
        except OSError as exc:
            notes.append(f"could not compare {rel}: {exc.strerror or exc}")
            return
        if not identical:
            changes.append(
                ChangeRecord(
                    op="modify",
                    path=path,
                    detail=f"{ost.st_size} -> {nst.st_size} bytes",
                    diff=unified_diff(
                        orig_path,
                        new_path,
                        rel,
                        old_size=ost.st_size,
                        new_size=nst.st_size,
                    ),
                )
            )
        return
    if okind == "symlink":
        try:
            old_target = os.readlink(orig_path)
            new_target = os.readlink(new_path)
        except OSError as exc:
            notes.append(f"could not read symlink {rel}: {exc.strerror or exc}")
            return
        if old_target != new_target:
            changes.append(
                ChangeRecord(
                    op="modify",
                    path=path,
                    detail=f"symlink {old_target} -> {new_target}",
                )
            )
        return
    if stat.S_IMODE(ost.st_mode) != stat.S_IMODE(nst.st_mode):
        changes.append(
            ChangeRecord(
                op="chmod",
                path=path,
                detail=(
                    f"mode {stat.S_IMODE(ost.st_mode):04o} -> "
                    f"{stat.S_IMODE(nst.st_mode):04o}"
                ),
            )
        )


def _diff_trees(
    orig_root: str,
    orig_map: Dict[str, _Entry],
    new_root: str,
    new_map: Dict[str, _Entry],
) -> Tuple[List[ChangeRecord], List[str]]:
    """Compare a pre-run tree with a post-run tree into sorted records."""
    changes: List[ChangeRecord] = []
    notes: List[str] = []
    for rel in sorted(set(orig_map) | set(new_map)):
        orig_entry = orig_map.get(rel)
        new_entry = new_map.get(rel)
        path = os.path.join(orig_root, rel)
        if new_entry is None:
            op = "rmdir" if orig_entry[0] == "dir" else "delete"
            changes.append(ChangeRecord(op=op, path=path))
        elif orig_entry is None:
            record, note = _record_new(new_root, rel, path, new_entry)
            changes.append(record)
            if note:
                notes.append(note)
        elif orig_entry[0] != new_entry[0]:
            if orig_entry[0] == "dir":
                changes.append(ChangeRecord(op="rmdir", path=path))
            else:
                changes.append(ChangeRecord(op="delete", path=path))
            record, note = _record_new(new_root, rel, path, new_entry)
            changes.append(record)
            if note:
                notes.append(note)
        else:
            _diff_same_kind(
                orig_root, new_root, rel, path, orig_entry, new_entry, changes, notes
            )
    changes = sort_changes(changes)
    return changes, notes


class SandboxEngine:
    """Portable engine: run the command in a copy of the working directory."""

    name = "sandbox"

    def __init__(self, *, max_tree_bytes: int = DEFAULT_MAX_TREE_BYTES) -> None:
        self.max_tree_bytes = max_tree_bytes

    def run(
        self,
        command: str,
        *,
        timeout: float = 10.0,
        cwd: Optional[str] = None,
    ) -> SimulationResult:
        """Simulate ``command`` by running it in a sandbox copy and diffing."""
        orig_cwd = os.path.abspath(cwd or os.getcwd())
        orig_map, notes = _walk_tree(orig_cwd)
        total = sum(
            st.st_size for kind, st in orig_map.values() if kind == "file"
        )
        if total > self.max_tree_bytes:
            raise EngineError(
                f"working directory is {human_size(total)}, exceeds sandbox "
                f"limit {human_size(self.max_tree_bytes)}; use --engine trace"
            )

        sandbox = tempfile.mkdtemp(prefix="dryrun-sandbox-", dir=tempfile.gettempdir())
        try:
            os.chmod(sandbox, 0o700)
            notes.extend(_copy_tree(orig_cwd, sandbox))
            try:
                proc = run_command(command, timeout=timeout, cwd=sandbox)
            except OSError as exc:
                raise EngineError(f"could not run command in sandbox: {exc}") from exc
            new_map, walk_notes = _walk_tree(sandbox)
            notes.extend(walk_notes)
            changes, diff_notes = _diff_trees(orig_cwd, orig_map, sandbox, new_map)
            notes.extend(diff_notes)
        finally:
            shutil.rmtree(sandbox, ignore_errors=True)

        result_notes = [
            "sandbox engine only observes effects inside the working directory"
        ]
        if proc.timed_out:
            result_notes.append(
                f"command timed out after {timeout:g}s and was killed"
            )
        elif proc.returncode not in (0, None):
            result_notes.append(f"command exited with status {proc.returncode}")
        return SimulationResult(
            engine=self.name,
            command=command,
            returncode=proc.returncode,
            duration=proc.duration,
            timed_out=proc.timed_out,
            changes=changes,
            notes=result_notes + notes,
            stdout_tail=proc.stdout,
            stderr_tail=proc.stderr,
        )
