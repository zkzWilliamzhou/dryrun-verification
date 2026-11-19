"""Subprocess wrapper: run shell commands with limits, timeout, group kill.

Output is captured to temp files (never pipes) so runaway writers such as
``yes`` cannot exhaust memory; only the last 4 KiB of each stream is kept.
"""
from __future__ import annotations

import os
import resource
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass
from typing import Callable, Iterable, Mapping, Optional

#: How many trailing bytes of stdout/stderr to keep.
_TAIL_BYTES = 4096

#: File-size cap for anything the child writes (2 GiB).
_FSIZE_LIMIT = 2 * 1024 * 1024 * 1024

#: Process-count cap for the child and its descendants.
_NPROC_LIMIT = 1024


@dataclass
class ProcResult:
    """Outcome of one monitored subprocess run."""

    returncode: Optional[int]
    """Exit status, negative when killed by a signal, or None when unknown."""

    stdout: str
    """Last 4096 chars of captured stdout."""

    stderr: str
    """Last 4096 chars of captured stderr."""

    duration: float
    """Wall-clock duration in seconds."""

    timed_out: bool
    """Whether the run exceeded its timeout and was killed."""


def apply_limits(timeout: float) -> None:
    """Apply child-side rlimits (CPU, file size, process count).

    Meant to run in a pre-exec hook; limits unsupported on the current
    platform are skipped so the run still proceeds.
    """
    cpu_seconds = max(int(timeout) + 2, 5)
    limits = (
        (resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds)),
        (resource.RLIMIT_FSIZE, (_FSIZE_LIMIT, _FSIZE_LIMIT)),
        (resource.RLIMIT_NPROC, (_NPROC_LIMIT, _NPROC_LIMIT)),
    )
    for which, value in limits:
        try:
            resource.setrlimit(which, value)
        except (OSError, ValueError):
            continue  # limit unavailable on this platform; skip it


def _shell_path() -> str:
    """Return the path of a POSIX shell, preferring bash."""
    for candidate in ("/bin/bash", "/usr/bin/bash", "/bin/sh"):
        if os.path.exists(candidate):
            return candidate
    return "/bin/sh"


def _child_setup(timeout: float, extra_preexec: Optional[Callable[[], None]]) -> None:
    """Run inside the child before exec: rlimits, then the caller's hook."""
    apply_limits(timeout)
    if extra_preexec is None:
        return
    try:
        extra_preexec()
    except Exception as exc:
        # A failing user hook must not zombie the child before exec; report
        # into the captured stderr (fd 2 is already redirected) and continue.
        try:
            os.write(2, f"dryrun: extra pre-exec hook failed: {exc}\n".encode())
        except OSError:
            return


def _kill_group(proc: subprocess.Popen) -> None:
    """Kill the whole process group of ``proc``; tolerate an already-dead one."""
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except ProcessLookupError:
        return  # the group is already gone; nothing left to signal


def _read_tail(path: str) -> str:
    """Return the last _TAIL_BYTES bytes of ``path``, decoded leniently."""
    try:
        with open(path, "rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - _TAIL_BYTES))
            data = handle.read(_TAIL_BYTES)
    except OSError:
        return ""
    return data.decode("utf-8", errors="replace")


def run_command(
    command: str,
    *,
    timeout: float = 10.0,
    cwd: Optional[str] = None,
    env: Optional[Mapping[str, str]] = None,
    pass_fds: Iterable[int] = (),
    extra_preexec: Optional[Callable[[], None]] = None,
    stdin_data: Optional[str] = None,
) -> ProcResult:
    """Run ``command`` under bash -c with limits, capture tails, kill on timeout.

    The child runs in a new session so the whole process group can be killed
    when the wall-clock timeout expires; stdout/stderr go to temp files.
    """
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    argv = [_shell_path(), "-c", command]
    child_env = dict(os.environ) if env is None else dict(env)

    out_fd, out_path = tempfile.mkstemp(prefix="dryrun-stdout-")
    err_fd, err_path = tempfile.mkstemp(prefix="dryrun-stderr-")
    try:
        try:
            start = time.monotonic()
            proc = subprocess.Popen(
                argv,
                cwd=cwd,
                env=child_env,
                stdout=out_fd,
                stderr=err_fd,
                stdin=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
                pass_fds=tuple(pass_fds),
                start_new_session=True,
                preexec_fn=lambda: _child_setup(timeout, extra_preexec),
            )
        finally:
            for fd in (out_fd, err_fd):
                try:
                    os.close(fd)
                except OSError:
                    pass  # already closed or never duplicated; nothing to do
        timed_out = False
        try:
            encoded = stdin_data.encode() if stdin_data is not None else None
            proc.communicate(encoded, timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_group(proc)
            proc.communicate()
        duration = time.monotonic() - start
        return ProcResult(
            returncode=proc.returncode,
            stdout=_read_tail(out_path),
            stderr=_read_tail(err_path),
            duration=duration,
            timed_out=timed_out,
        )
    finally:
        for path in (out_path, err_path):
            try:
                os.unlink(path)
            except OSError:
                pass  # best-effort temp cleanup; the file may already be gone
