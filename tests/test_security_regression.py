"""Security regression tests: attacks found by the R2/R3 audits.

Each test reproduces a documented escape attempt against the trace
engine and asserts the promise holds: the real file system is never
modified, and the preview does not lie about what happened.
"""
import os
import shutil
import stat
import subprocess
import tempfile

import pytest

from dryrun.simulate.trace import (
    _first_word_statically_linked,
    TraceEngine,
)


def _snapshot(root: str) -> dict:
    """Full {path: (bytes, mode)} snapshot of a real directory."""
    snap = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            st = os.lstat(full)
            if stat.S_ISLNK(st.st_mode):
                snap[rel] = (os.readlink(full).encode(), stat.S_IMODE(st.st_mode))
            elif stat.S_ISREG(st.st_mode):
                with open(full, "rb") as fh:
                    snap[rel] = (fh.read(), stat.S_IMODE(st.st_mode))
            else:
                snap[rel] = (b"", stat.S_IMODE(st.st_mode))
    return snap


@pytest.fixture(scope="module")
def engine():
    if not TraceEngine.available():
        pytest.skip("trace engine unavailable")
    return TraceEngine()


@pytest.fixture()
def arena(tmp_path, monkeypatch):
    """Isolated compile cache + an attack arena with a victim file."""
    # The compile cache must live outside the arena: the integrity
    # snapshots below compare every file under the arena directory.
    cache = tempfile.mkdtemp(prefix="dryrun-test-cache-")
    monkeypatch.setenv("DRYRUN_CACHE_DIR", cache)
    victim = tmp_path / "victim.txt"
    victim.write_text("ORIGINAL")
    (tmp_path / "keep.txt").write_text("keep")
    return tmp_path, victim


class TestSymlinkEscape:
    """R3-B1: symlinks must never carry writes out of the shadow tree."""

    def test_write_through_absolute_symlink(self, engine, arena):
        tmp_path, victim = arena
        result = engine.run(
            f"ln -s {victim} l && echo PWNED > l", cwd=str(tmp_path)
        )
        assert victim.read_text() == "ORIGINAL"
        assert any(r.op == "create" and r.path.endswith("/l") for r in
                   result.changes), "the created link must be reported"

    def test_write_through_dangling_symlink(self, engine, arena):
        tmp_path, victim = arena
        outside = tmp_path / "created-outside"
        result = engine.run(
            f"ln -s {outside} pwn && echo PWNED > pwn", cwd=str(tmp_path)
        )
        assert not outside.exists()
        assert any("pwn" in r.path for r in result.changes)

    def test_symlink_chain(self, engine, arena):
        tmp_path, victim = arena
        result = engine.run(
            f"ln -s {victim} a; ln -s a b; echo PWNED > b", cwd=str(tmp_path)
        )
        assert victim.read_text() == "ORIGINAL"

    def test_relative_updir_symlink_escape(self, engine, arena):
        tmp_path, victim = arena
        result = engine.run(
            "ln -s ../../../../../..%s l && echo PWNED > l" % victim,
            cwd=str(tmp_path),
        )
        assert victim.read_text() == "ORIGINAL"

    def test_mkdir_through_directory_symlink(self, engine, arena):
        tmp_path, _victim = arena
        real_dir = tmp_path / "real-dir"
        real_dir.mkdir()
        result = engine.run(
            f"ln -s {real_dir} dlink && mkdir dlink/escaped-dir",
            cwd=str(tmp_path),
        )
        assert not (real_dir / "escaped-dir").exists()


class TestPseudoFilesystems:
    """R2-F1: /proc and /dev/shm must not be write passthroughs."""

    def test_proc_self_root_write(self, engine, arena):
        tmp_path, victim = arena
        result = engine.run(
            f"echo pwned > /proc/self/root{victim}", cwd=str(tmp_path)
        )
        assert victim.read_text() == "ORIGINAL"
        assert result.changes, "the diverted write must be reported"

    def test_dev_shm_write(self, engine, arena):
        tmp_path, _victim = arena
        target = "/dev/shm/dryrun-escape-test"
        result = engine.run(
            f"echo x > {target}", cwd=str(tmp_path)
        )
        assert not os.path.exists(target)
        assert result.changes

    def test_dev_shm_rename(self, engine, arena):
        tmp_path, _victim = arena
        source = "/dev/shm/dryrun-rename-src"
        dest = str(tmp_path / "moved")
        try:
            result = engine.run(
                f"touch {source} && mv {source} {dest}", cwd=str(tmp_path)
            )
            assert not os.path.exists(source)
            assert not os.path.exists(dest)
        finally:
            if os.path.exists(source):
                os.unlink(source)


class TestUntrackedFd:
    """R2-F3: metadata ops on untracked fds must fail closed."""

    def test_fchmod_on_untracked_fd(self, engine, arena):
        tmp_path, victim = arena
        os.chmod(victim, 0o644)
        result = engine.run(
            "python3 -c \"import os; fd=os.open('%s', os.O_WRONLY); "
            "os.fchmod(fd, 0o777)\"" % victim,
            cwd=str(tmp_path),
        )
        assert stat.S_IMODE(os.stat(victim).st_mode) == 0o644


class TestStaticBinaryWarning:
    """R3-B2/B3: silent blindness must be loud."""

    def test_static_helper_is_detected(self, engine, tmp_path, monkeypatch):
        monkeypatch.setenv(
            "DRYRUN_CACHE_DIR",
            tempfile.mkdtemp(prefix="dryrun-test-cache-"),
        )
        src = tmp_path / "staticw.c"
        src.write_text(
            "#include <stdio.h>\n"
            "int main(void){FILE*f=fopen(\"out.txt\",\"w\");"
            "if(f){fputs(\"PWN\",f);fclose(f);}return 0;}\n"
        )
        binary = tmp_path / "staticw"
        build = subprocess.run(
            ["gcc", "-static", "-o", str(binary), str(src)],
            capture_output=True,
        )
        if build.returncode != 0:
            pytest.skip("static libc unavailable")
        assert _first_word_statically_linked("./staticw", str(tmp_path))
        result = engine.run("./staticw", cwd=str(tmp_path))
        # Known engine limit: a static binary bypasses LD_PRELOAD, so the
        # write can reach the real fs. What the engine MUST do is warn.
        notes = " ".join(result.notes)
        assert "STATICALLY LINKED" in notes, notes
        shutil.rmtree(str(tmp_path / "out.txt"), ignore_errors=True)
        if (tmp_path / "out.txt").exists():
            (tmp_path / "out.txt").unlink()

    def test_dynamic_helper_not_flagged(self, tmp_path):
        assert not _first_word_statically_linked("ls", str(tmp_path))
        assert not _first_word_statically_linked("", str(tmp_path))


class TestOrphanCleanup:
    """R3-B5/B6: setsid orphans cannot outlive the simulation."""

    def test_setsid_orphan_never_touches_real_file(self, engine, arena):
        tmp_path, victim = arena
        # The orphan writes through a symlink after dryrun exits; with the
        # fixed shim it can only ever reach the (closed) shadow tree.
        result = engine.run(
            "ln -s %s l; setsid bash -c 'sleep 1; echo FINAL > l' "
            ">/dev/null 2>&1 &" % victim,
            cwd=str(tmp_path),
            timeout=8.0,
        )
        # Give the orphan its chance to misbehave, then check.
        import time as _time
        _time.sleep(1.5)
        assert victim.read_text() == "ORIGINAL"

    def test_no_shadow_tree_left_behind(self, engine, arena):
        tmp_path, _victim = arena
        before = set(os.listdir("/tmp"))
        engine.run("echo x > f.txt", cwd=str(tmp_path))
        after = set(os.listdir("/tmp"))
        leaked = {
            name for name in after - before
            if name.startswith("dryrun-shadow-")
        }
        assert not leaked


class TestFullFsIntegrity:
    """The headline invariant, on a compound hostile command."""

    def test_compound_attack_leaves_real_fs_untouched(self, engine, arena):
        tmp_path, victim = arena
        (tmp_path / "s.txt").write_text("s")
        (tmp_path / "f.txt").write_text("f")
        os.chmod(tmp_path / "f.txt", 0o644)
        before = _snapshot(str(tmp_path))
        engine.run(
            "echo x > a.txt && rm victim.txt && mkdir d && "
            "mv s.txt t.txt && chmod 777 f.txt",
            cwd=str(tmp_path),
        )
        assert _snapshot(str(tmp_path)) == before


class TestCriticalSkip:
    """R5 finding: simulating a CRITICAL command runs it for real.

    The simulator only virtualizes the file system. ``kill -9 -1``,
    fork bombs, and raw-device writes do damage the simulator cannot
    virtualize, so a CRITICAL audit finding must skip simulation.
    """

    def test_kill_all_is_never_simulated(self):
        import sys as _sys
        code_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"
        )
        _sys.path.insert(0, code_dir)
        from dryrun.cli import main

        proc = subprocess.run(
            [_sys.executable, "-m", "dryrun", "kill -9 -1"],
            capture_output=True, text=True, timeout=30,
            env={**os.environ, "PYTHONPATH": code_dir},
        )
        # The tool itself must survive (kill -9 -1 would have murdered
        # this very process tree if the simulation had run for real).
        assert proc.returncode == 0
        assert "Simulation skipped" in proc.stdout
        assert "CRITICAL" in proc.stdout

    def test_critical_json_reports_skip(self, tmp_path):
        env = {**os.environ,
               "PYTHONPATH": os.path.join(
                   os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "src")}
        proc = subprocess.run(
            ["python3", "-m", "dryrun", "--json", "dd if=/dev/zero of=/dev/sda"],
            capture_output=True, text=True, timeout=30, env=env,
            cwd=str(tmp_path),
        )
        import json as _json
        payload = _json.loads(proc.stdout)
        assert payload["error"]["type"] == "SimulationSkipped"

    def test_non_critical_still_simulates(self, tmp_path):
        env = {**os.environ,
               "PYTHONPATH": os.path.join(
                   os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "src")}
        proc = subprocess.run(
            ["python3", "-m", "dryrun", "echo hi > out.txt"],
            capture_output=True, text=True, timeout=60, env=env,
            cwd=str(tmp_path),
        )
        assert "Would create" in proc.stdout or "Would change" in proc.stdout
