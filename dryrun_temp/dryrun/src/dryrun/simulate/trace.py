"""LD_PRELOAD trace engine: run the command with file writes shadowed."""
from __future__ import annotations

import hashlib
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from typing import Dict, List, Optional, Tuple

from dryrun.core.proc import apply_limits
from dryrun.core.types import ChangeRecord, SimulationResult
from dryrun.simulate.base import EngineError
from dryrun.simulate.diffops import human_size, sort_changes, unified_diff

#: Suffix of the marker files the shim leaves for simulated deletions.
_TOMBSTONE_SUFFIX = ".dryrun-tombstone"

#: Pipe read size for the trace-log reader thread.
_READ_CHUNK = 65536

#: How long to wait for the reader thread to hit EOF after the child died.
_READER_JOIN_TIMEOUT = 2.0

#: stdout/stderr tails are capped at this many characters.
_MAX_TAIL_CHARS = 2000

#: Report at most this many device-write caveats / malformed trace lines.
_MAX_CAVEATS = 5

#: Seconds the compiler may take before the engine gives up.
_COMPILE_TIMEOUT = 120

#: Marker dropped into the shadow root before cleanup: the shim refuses
#: to recreate shadow directories once it is present, so orphan processes
#: left behind by the command cannot resurrect the shadow tree.
_CLOSED_SENTINEL = ".dryrun-closed"

#: Trace log operations emitted by the shim and their argument count.
_LOG_ARITY = {
    "W_OPEN": 2,
    "W_UNLINK": 1,
    "W_RMDIR": 1,
    "W_RENAME": 2,
    "W_MKDIR": 1,
    "W_CHMOD": 2,
    "W_TRUNC": 1,
    "W_SYMLINK": 2,
    "W_LINK": 2,
    "NOTE_DEV_WRITE": 1,
    "NOTE_PSEUDO_WRITE": 1,
}

#: One parsed trace line: (operation, first argument, second argument).
_TraceOp = Tuple[str, str, str]


def _same_bytes(path_a: str, path_b: str) -> bool:
    """Compare two regular files byte by byte (sizes are checked first)."""
    try:
        size_a = os.path.getsize(path_a)
        size_b = os.path.getsize(path_b)
    except OSError:
        return False
    if size_a != size_b:
        return False
    with open(path_a, "rb") as handle_a, open(path_b, "rb") as handle_b:
        while True:
            chunk_a = handle_a.read(_READ_CHUNK)
            chunk_b = handle_b.read(_READ_CHUNK)
            if chunk_a != chunk_b:
                return False
            if not chunk_a:
                return True


def _cache_dir() -> str:
    """Directory holding compiled shadow libraries (honors DRYRUN_CACHE_DIR)."""
    env = os.environ.get("DRYRUN_CACHE_DIR")
    if env:
        return env
    return os.path.join(os.path.expanduser("~"), ".cache", "dryrun")


def _shadowlib_source() -> str:
    """Absolute path of the shadowlib.c source shipped with the package."""
    package_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(package_root, "native", "shadowlib.c")


def _find_compiler() -> Optional[str]:
    """Return the path of a usable C compiler, or None."""
    return shutil.which("gcc") or shutil.which("cc")


def _close_quietly(fd: int) -> None:
    """Close a file descriptor, ignoring errors on already-closed fds."""
    try:
        os.close(fd)
    except OSError:
        pass


def _remove_quietly(path: str) -> None:
    """Unlink a scratch file, ignoring errors when it is already gone."""
    try:
        os.unlink(path)
    except OSError:
        pass


def _compile_shadowlib(source: str, dest: str) -> None:
    """Compile shadowlib.c into ``dest`` with the reference build flags."""
    compiler = _find_compiler()
    if compiler is None:
        raise EngineError("cannot compile shadowlib.so: no C compiler found")
    command = [
        compiler,
        "-O2",
        "-Wall",
        "-Wextra",
        "-fPIC",
        "-shared",
        "-o",
        dest,
        source,
        "-ldl",
        "-lpthread",
    ]
    try:
        proc = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=_COMPILE_TIMEOUT,
        )
    except subprocess.TimeoutExpired as exc:
        raise EngineError(
            f"cannot compile shadowlib.so: {compiler} timed out"
        ) from exc
    except OSError as exc:
        raise EngineError(f"cannot compile shadowlib.so: {exc}") from exc
    if proc.returncode != 0:
        stderr_lines = proc.stderr.decode("utf-8", errors="replace").splitlines()
        summary = stderr_lines[-1].strip() if stderr_lines else "no diagnostics"
        raise EngineError(
            f"cannot compile shadowlib.so: {summary[:200]} "
            f"(exit status {proc.returncode})"
        )


def shared_library() -> str:
    """Return the path to a compiled shadowlib.so, building it when missing.

    The library is content-addressed by the first 16 hex digits of the
    sha256 of shadowlib.c and cached under DRYRUN_CACHE_DIR (default
    ~/.cache/dryrun). Compilation writes a scratch file that is atomally
    renamed into place, so concurrent dryrun processes never observe a
    half-written library.
    """
    source = _shadowlib_source()
    with open(source, "rb") as handle:
        digest = hashlib.sha256(handle.read()).hexdigest()[:16]
    cache = _cache_dir()
    dest = os.path.join(cache, f"shadowlib-{digest}.so")
    if os.path.isfile(dest) and os.path.getsize(dest) > 0:
        return dest
    try:
        os.makedirs(cache, exist_ok=True)
    except OSError as exc:
        raise EngineError(f"cannot create cache directory {cache}: {exc}") from exc
    fd, scratch = tempfile.mkstemp(dir=cache, prefix=".shadowlib-", suffix=".tmp")
    os.close(fd)
    try:
        _compile_shadowlib(source, scratch)
    except BaseException:
        _remove_quietly(scratch)
        raise
    os.chmod(scratch, 0o444)
    os.replace(scratch, dest)
    return dest


def _drain_pipe(fd: int, sink: List[bytes]) -> None:
    """Read the trace pipe until EOF, appending chunks to ``sink``.

    Runs in a daemon thread so the shim's writes can never fill the pipe
    buffer and block the traced command.
    """
    while True:
        try:
            chunk = os.read(fd, _READ_CHUNK)
        except OSError:
            return
        if not chunk:
            return
        sink.append(chunk)


def _parse_trace_log(text: str) -> Tuple[List[_TraceOp], List[str]]:
    """Split trace text into valid ``(op, arg1, arg2)`` tuples and bad lines."""
    ops: List[_TraceOp] = []
    bad: List[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split("|")
        arity = _LOG_ARITY.get(parts[0])
        if arity is None or len(parts) != arity + 1 or not parts[1]:
            bad.append(line)
            continue
        ops.append((parts[0], parts[1], parts[2] if arity == 2 else ""))
    return ops, bad


def _scan_shadow_tree(
    shadow_root: str, unlink_paths: frozenset
) -> Tuple[Dict[str, os.stat_result], List[str], List[str]]:
    """Walk the shadow tree into live entries, tombstones, and scan notes.

    A ``*.dryrun-tombstone`` entry only counts as a simulated deletion when
    the shim actually logged a W_UNLINK/W_RMDIR for its base path; a real
    user file that happens to carry the suffix stays a normal entry.
    """
    live: Dict[str, os.stat_result] = {}
    tombstones: List[str] = []
    notes: List[str] = []

    def on_error(err: OSError) -> None:
        rel = os.path.relpath(err.filename, shadow_root) if err.filename else "."
        notes.append(f"could not scan shadow tree at {rel}: {err.strerror or err}")

    for dirpath, dirnames, filenames in os.walk(
        shadow_root, followlinks=False, onerror=on_error
    ):
        for name in dirnames + filenames:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, shadow_root)
            try:
                st = os.lstat(full)
            except OSError as exc:
                notes.append(
                    f"could not inspect shadow entry {rel}: {exc.strerror or exc}"
                )
                continue
            if (
                name.endswith(_TOMBSTONE_SUFFIX)
                and not stat.S_ISDIR(st.st_mode)
                and os.path.join("/", rel[: -len(_TOMBSTONE_SUFFIX)])
                in unlink_paths
            ):
                tombstones.append(rel[: -len(_TOMBSTONE_SUFFIX)])
            else:
                live[rel] = st
    return live, tombstones, notes


def _symlink_record(
    op: str,
    path: str,
    shadow_path: str,
    notes: List[str],
    original_targets: Dict[str, str],
) -> ChangeRecord:
    """Build a record for a shadow symlink, reading its target.

    The shim rewrites the target stored inside the shadow tree so it can
    never point outside it; the *original* target from the W_SYMLINK log
    is what the user actually asked for, so prefer it in the report.
    """
    target = original_targets.get(path)
    if target is None:
        try:
            target = os.readlink(shadow_path)
        except OSError as exc:
            reason = exc.strerror or exc
            notes.append(f"could not read shadow symlink {path}: {reason}")
            return ChangeRecord(op=op, path=path, detail="symlink")
    return ChangeRecord(op=op, path=path, detail=f"symlink -> {target}")


def _live_entry_records(
    rel: str,
    shadow_path: str,
    real_path: str,
    st: os.stat_result,
    rst: Optional[os.stat_result],
    chmod_paths: frozenset,
    notes: List[str],
    original_targets: Dict[str, str],
) -> List[ChangeRecord]:
    """Change records for one live shadow entry (real counterpart may miss)."""
    if rst is None:
        # Nothing exists in the real tree: the command would create this.
        if stat.S_ISDIR(st.st_mode):
            return [ChangeRecord(op="mkdir", path=real_path)]
        if stat.S_ISLNK(st.st_mode):
            return [_symlink_record(
                "create", real_path, shadow_path, notes, original_targets)]
        return [
            ChangeRecord(
                op="create", path=real_path, detail=human_size(st.st_size)
            )
        ]

    shadow_is_dir = stat.S_ISDIR(st.st_mode)
    real_is_dir = stat.S_ISDIR(rst.st_mode)
    if shadow_is_dir or real_is_dir:
        if shadow_is_dir != real_is_dir or stat.S_ISLNK(rst.st_mode):
            # Kind change (e.g. file replaced by a directory): the end
            # state is whatever the shadow holds now.
            if shadow_is_dir:
                return [ChangeRecord(op="mkdir", path=real_path)]
            if stat.S_ISLNK(st.st_mode):
                return [_symlink_record(
                    "create", real_path, shadow_path, notes, original_targets)]
            return [
                ChangeRecord(
                    op="create", path=real_path, detail=human_size(st.st_size)
                )
            ]
        # Directory in both trees: only an explicit chmod is a change.
        # Modes of materialized parent dirs are diff artifacts and ignored.
        if real_path in chmod_paths:
            old = stat.S_IMODE(rst.st_mode)
            new = stat.S_IMODE(st.st_mode)
            if old != new:
                return [
                    ChangeRecord(
                        op="chmod",
                        path=real_path,
                        detail=f"mode {old:04o} -> {new:04o}",
                    )
                ]
        return []

    if stat.S_ISLNK(st.st_mode) and stat.S_ISLNK(rst.st_mode):
        try:
            old_target = os.readlink(real_path)
            new_target = os.readlink(shadow_path)
        except OSError as exc:
            notes.append(
                f"could not read symlink {real_path}: {exc.strerror or exc}"
            )
            return []
        if old_target == new_target:
            return []
        return [
            ChangeRecord(
                op="modify",
                path=real_path,
                detail=f"symlink {old_target} -> {new_target}",
            )
        ]

    if not (stat.S_ISREG(st.st_mode) and stat.S_ISREG(rst.st_mode)):
        # Non-regular entries (FIFOs, sockets, devices): report the kind
        # change without trying to compare contents.
        return [
            ChangeRecord(op="create", path=real_path, detail="special file")
        ]

    old_mode = stat.S_IMODE(rst.st_mode)
    new_mode = stat.S_IMODE(st.st_mode)
    if not _same_bytes(real_path, shadow_path):
        return [
            ChangeRecord(
                op="modify",
                path=real_path,
                detail=f"{rst.st_size} -> {st.st_size} bytes",
                diff=unified_diff(real_path, shadow_path, rel),
            )
        ]
    if old_mode == new_mode:
        return []
    detail = f"mode {old_mode:04o} -> {new_mode:04o}"
    if real_path in chmod_paths:
        return [ChangeRecord(op="chmod", path=real_path, detail=detail)]
    return [ChangeRecord(op="modify", path=real_path, detail=detail)]


def _diff_shadow_tree(
    shadow_root: str, ops: List[_TraceOp]
) -> Tuple[List[ChangeRecord], List[str]]:
    """Turn the shadow tree plus the trace log into change records."""
    notes: List[str] = []
    chmod_paths = frozenset(
        arg1 for (op, arg1, _arg2) in ops if op == "W_CHMOD"
    )
    unlink_paths = frozenset(
        arg1 for (op, arg1, _arg2) in ops if op in ("W_UNLINK", "W_RMDIR")
    )
    # W_SYMLINK logs (original target, link path): the report should show
    # the target the user typed, not the shadow-internal rewrite.
    original_targets = {
        arg2: arg1 for (op, arg1, arg2) in ops if op == "W_SYMLINK"
    }
    live, tombstones, scan_notes = _scan_shadow_tree(shadow_root, unlink_paths)
    notes.extend(scan_notes)

    # (dedup key, record) pairs in chronological-ish order: deletions the
    # shim simulated, then live shadow entries, then log-ordered renames.
    keyed: List[Tuple[str, ChangeRecord]] = []
    for rel in sorted(tombstones):
        real_path = os.path.join("/", rel)
        try:
            rst = os.lstat(real_path)
        except OSError:
            rst = None
        op = "rmdir" if rst is not None and stat.S_ISDIR(rst.st_mode) else "delete"
        keyed.append((real_path, ChangeRecord(op=op, path=real_path)))
    for rel in sorted(live):
        st = live[rel]
        shadow_path = os.path.join(shadow_root, rel)
        real_path = os.path.join("/", rel)
        try:
            rst = os.lstat(real_path)
        except OSError:
            rst = None
        keyed.extend(
            (real_path, record)
            for record in _live_entry_records(
                rel, shadow_path, real_path, st, rst, chmod_paths, notes,
                original_targets,
            )
        )
    for op, arg1, arg2 in ops:
        if op == "W_RENAME":
            keyed.append(
                (
                    arg2,
                    ChangeRecord(op="rename", path=arg1, detail=f"-> {arg2}"),
                )
            )

    # Last operation wins for each affected path; renames are keyed by
    # their destination, which is the path that ends up existing.
    by_key: Dict[str, ChangeRecord] = {}
    for key, record in keyed:
        by_key.pop(key, None)
        by_key[key] = record
    changes = sort_changes(list(by_key.values()))
    return changes, notes


def _kill_process_group(proc: subprocess.Popen) -> None:
    """SIGKILL the whole process group of a start_new_session child."""
    try:
        os.killpg(proc.pid, signal.SIGKILL)
        return
    except OSError:
        pass
    try:
        proc.kill()
    except OSError:
        pass


def _first_word_statically_linked(command: str, workdir: str) -> bool:
    """Heuristic: does the first word of the command look static?

    Reads the ELF header of the resolved binary and looks for a
    ``PT_INTERP`` program header; dynamic executables carry one, static
    ones do not. Anything unclear counts as not static (no false alarm).
    """
    first = command.strip().split(None, 1)[0] if command.strip() else ""
    if not first or "/" not in first:
        resolved = shutil.which(first) if first else None
    else:
        resolved = os.path.join(workdir, first) if not os.path.isabs(
            first) else first
    if not resolved or not os.path.isfile(resolved):
        return False
    try:
        with open(resolved, "rb") as fh:
            header = fh.read(64)
            if len(header) < 64 or header[:4] != b"\x7fELF":
                return False
            is_64 = header[4] == 2
            phoff = int.from_bytes(
                header[32:40] if is_64 else header[28:32], "little")
            phentsize = int.from_bytes(
                header[54:56] if is_64 else header[42:44], "little")
            phnum = int.from_bytes(
                header[56:58] if is_64 else header[44:46], "little")
            fh.seek(phoff)
            phdrs = fh.read(phentsize * phnum)
    except OSError:
        return False
    for i in range(phnum):
        entry = phdrs[i * phentsize:(i + 1) * phentsize]
        if not entry:
            continue
        p_type = int.from_bytes(entry[:4], "little")
        if p_type == 3:  # PT_INTERP: only dynamic executables have it
            return False
    return phnum > 0


def _kill_shadow_orphans(shadow_root: str) -> None:
    """SIGKILL any surviving process still bound to this shadow tree.

    ``setsid`` descendants escape the process group kill, so scan
    ``/proc/*/environ`` for our DRYRUN_SHADOW value and reap them before
    the shadow tree is removed. Best effort; unreadable entries are ours
    only when they carry the marker.
    """
    marker = f"DRYRUN_SHADOW={shadow_root}\0".encode()
    for pid_dir in _proc_entries():
        try:
            with open(os.path.join(pid_dir, "environ"), "rb") as fh:
                if marker not in fh.read():
                    continue
            pid = int(os.path.basename(pid_dir))
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
        except (OSError, ValueError):
            continue


def _proc_entries() -> List[str]:
    """Numeric /proc/<pid> directories, tolerating a missing /proc."""
    try:
        names = os.listdir("/proc")
    except OSError:
        return []
    return [
        os.path.join("/proc", name)
        for name in names
        if name.isdigit()
    ]


class TraceEngine:
    """Engine that traces libc file operations through an LD_PRELOAD shim.

    The command runs for real, but every libc-level write is redirected
    into a copy-on-write "shadow tree" under a fresh temp directory, and
    destructive operations are virtualized with tombstone markers. The
    real file system is never touched; afterwards the shadow tree is
    diffed against reality to report exactly what the command would have
    changed anywhere on the system.
    """

    name = "trace"

    @staticmethod
    def available() -> bool:
        """Whether this platform can build and load the shim."""
        return sys.platform == "linux" and _find_compiler() is not None

    def run(
        self,
        command: str,
        *,
        timeout: float = 10.0,
        cwd: Optional[str] = None,
    ) -> SimulationResult:
        """Simulate ``command`` by tracing its file operations."""
        library = shared_library()
        shadow_root = tempfile.mkdtemp(prefix="dryrun-shadow-")
        workdir = os.path.abspath(cwd or os.getcwd())
        read_fd, write_fd = os.pipe()
        sink: List[bytes] = []
        reader = threading.Thread(
            target=_drain_pipe, args=(read_fd, sink), daemon=True
        )
        reader.start()
        write_open = True
        try:
            os.set_inheritable(write_fd, True)
            env = os.environ.copy()
            env["LD_PRELOAD"] = library
            env["DRYRUN_SHADOW"] = shadow_root
            env["DRYRUN_TRACE_FD"] = str(write_fd)
            env["DRYRUN_CWD"] = workdir
            started = time.monotonic()
            try:
                proc = subprocess.Popen(
                    ["bash", "-c", command],
                    cwd=workdir,
                    env=env,
                    start_new_session=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    pass_fds=(write_fd,),
                    preexec_fn=apply_limits(timeout),
                )
            except OSError as exc:
                raise EngineError(f"could not launch bash: {exc}") from exc
            os.close(write_fd)
            write_open = False
            timed_out = False
            try:
                stdout_bytes, stderr_bytes = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                _kill_process_group(proc)
                stdout_bytes, stderr_bytes = proc.communicate()
            duration = time.monotonic() - started

            reader.join(_READER_JOIN_TIMEOUT)
            log_text = b"".join(sink).decode("utf-8", errors="replace")
            ops, bad_lines = _parse_trace_log(log_text)
            changes, diff_notes = _diff_shadow_tree(shadow_root, ops)
            dev_writes: List[str] = []
            pseudo_writes: List[str] = []
            for op, arg1, _arg2 in ops:
                if op == "NOTE_DEV_WRITE" and arg1 not in dev_writes:
                    dev_writes.append(arg1)
                if op == "NOTE_PSEUDO_WRITE" and arg1 not in pseudo_writes:
                    pseudo_writes.append(arg1)

            notes: List[str] = ["engine=trace"]
            if not ops and not bad_lines:
                if proc.returncode == 0 and not timed_out:
                    if _first_word_statically_linked(command, workdir):
                        notes.append(
                            "WARNING: no file writes captured and the first "
                            "binary looks STATICALLY LINKED - its writes "
                            "bypass the tracer entirely; treat this preview "
                            "as blind, not as clean"
                        )
                    else:
                        notes.append(
                            "no file operations intercepted; the command may "
                            "be read-only, but raw syscalls or a statically "
                            "linked binary would also leave no trace"
                        )
                elif proc.returncode not in (0, None) and not timed_out:
                    notes.append(
                        "process failed without intercepted file operations; "
                        "the binary may be statically linked or bypass libc"
                    )
            if timed_out:
                notes.append(
                    f"command timed out after {timeout:g}s and was killed"
                )
            elif proc.returncode not in (0, None):
                notes.append(f"command exited with status {proc.returncode}")
            for path in dev_writes[:_MAX_CAVEATS]:
                notes.append(f"device write passed through unvirtualized: {path}")
            if len(dev_writes) > _MAX_CAVEATS:
                notes.append(f"... and {len(dev_writes) - _MAX_CAVEATS} more")
            for path in pseudo_writes[:_MAX_CAVEATS]:
                notes.append(f"write to pseudo-filesystem diverted to shadow: {path}")
            if len(pseudo_writes) > _MAX_CAVEATS:
                notes.append(f"... and {len(pseudo_writes) - _MAX_CAVEATS} more")
            for line in bad_lines[:_MAX_CAVEATS]:
                notes.append(f"ignored malformed trace line: {line[:160]}")
            if len(bad_lines) > _MAX_CAVEATS:
                notes.append(f"... and {len(bad_lines) - _MAX_CAVEATS} more")
            notes.extend(diff_notes)

            return SimulationResult(
                engine=self.name,
                command=command,
                returncode=proc.returncode,
                duration=duration,
                timed_out=timed_out,
                changes=changes,
                notes=notes,
                stdout_tail=stdout_bytes.decode("utf-8", errors="replace")[
                    -_MAX_TAIL_CHARS:
                ],
                stderr_tail=stderr_bytes.decode("utf-8", errors="replace")[
                    -_MAX_TAIL_CHARS:
                ],
            )
        finally:
            if write_open:
                _close_quietly(write_fd)
            if not reader.is_alive():
                _close_quietly(read_fd)
            # Close the shadow tree first: the shim then refuses (EIO) to
            # recreate shadow directories, so orphans cannot resurrect it.
            try:
                with open(
                    os.path.join(shadow_root, _CLOSED_SENTINEL), "wb"
                ) as marker:
                    marker.write(b"closed\n")
            except OSError:
                pass
            _kill_shadow_orphans(shadow_root)
            shutil.rmtree(shadow_root, ignore_errors=True)
