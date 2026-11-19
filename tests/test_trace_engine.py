"""Tests for the LD_PRELOAD trace engine (shadowlib + TraceEngine)."""
from __future__ import annotations

import os
import stat

import pytest

from dryrun.simulate import trace as trace_module
from dryrun.simulate.trace import TraceEngine

pytestmark = pytest.mark.skipif(
    not TraceEngine.available(), reason="trace engine needs Linux and a C compiler"
)


@pytest.fixture(scope="module")
def _module_cache(tmp_path_factory):
    """One shared compile cache so the .so is built a single time."""
    return tmp_path_factory.mktemp("dryrun-trace-cache")


@pytest.fixture
def cache_dir(_module_cache, monkeypatch):
    """Isolate the engine's compile cache from the user's real one."""
    monkeypatch.setenv("DRYRUN_CACHE_DIR", str(_module_cache))
    return _module_cache


@pytest.fixture
def engine(cache_dir):
    return TraceEngine()


def _real(path) -> str:
    """Realpath of a tmp_path-based location (what the shim reports)."""
    return os.path.realpath(str(path))


def _snapshot(root: str) -> dict:
    """Full {relpath: (kind, payload, mode)} snapshot of a directory tree."""
    snap: dict = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            st = os.lstat(full)
            mode = stat.S_IMODE(st.st_mode)
            if stat.S_ISLNK(st.st_mode):
                snap[rel] = ("symlink", os.readlink(full), mode)
            elif stat.S_ISDIR(st.st_mode):
                snap[rel] = ("dir", "", mode)
            else:
                with open(full, "rb") as handle:
                    snap[rel] = ("file", handle.read(), mode)
    return snap


def test_available():
    assert TraceEngine.available() is True


def test_compile_cache(tmp_path, monkeypatch):
    cache = tmp_path / "cache"
    monkeypatch.setenv("DRYRUN_CACHE_DIR", str(cache))

    library = trace_module.shared_library()
    assert os.path.isfile(library)
    assert os.path.getsize(library) > 0
    assert library.startswith(str(cache))
    before = os.stat(library)

    def _boom(*_args, **_kwargs):
        raise AssertionError("a cache hit must not recompile")

    monkeypatch.setattr(trace_module, "_compile_shadowlib", _boom)
    assert trace_module.shared_library() == library
    after = os.stat(library)
    assert (after.st_mtime_ns, after.st_ino) == (before.st_mtime_ns, before.st_ino)


def test_create_preview(engine, tmp_path):
    result = engine.run("echo hi > newfile.txt", cwd=str(tmp_path))
    assert result.engine == "trace"
    assert result.returncode == 0
    assert not (tmp_path / "newfile.txt").exists()
    matches = [
        c
        for c in result.changes
        if c.path == os.path.join(_real(tmp_path), "newfile.txt")
    ]
    assert [c.op for c in matches] == ["create"]
    assert "engine=trace" in result.notes


def test_modify_preview(engine, tmp_path):
    (tmp_path / "data.txt").write_text("old")
    result = engine.run("echo new > data.txt", cwd=str(tmp_path))
    assert result.returncode == 0
    assert (tmp_path / "data.txt").read_text() == "old"
    matches = [
        c for c in result.changes if c.path == os.path.join(_real(tmp_path), "data.txt")
    ]
    assert [c.op for c in matches] == ["modify"]
    assert matches[0].detail == "3 -> 4 bytes"
    assert "-old" in (matches[0].diff or "")
    assert "+new" in (matches[0].diff or "")


def test_delete_preview(engine, tmp_path):
    (tmp_path / "victim.txt").write_text("doomed\n")
    result = engine.run("rm victim.txt", cwd=str(tmp_path))
    assert result.returncode == 0
    assert (tmp_path / "victim.txt").exists()
    matches = [
        c for c in result.changes
        if c.path == os.path.join(_real(tmp_path), "victim.txt")
    ]
    assert [c.op for c in matches] == ["delete"]


def test_rename_preview(engine, tmp_path):
    (tmp_path / "a.txt").write_text("content\n")
    result = engine.run("mv a.txt b.txt", cwd=str(tmp_path))
    assert result.returncode == 0
    assert (tmp_path / "a.txt").exists()
    assert not (tmp_path / "b.txt").exists()
    renames = [
        c for c in result.changes if c.op == "rename"
    ]
    assert len(renames) == 1
    assert renames[0].path == os.path.join(_real(tmp_path), "a.txt")
    assert renames[0].detail == f"-> {os.path.join(_real(tmp_path), 'b.txt')}"


def test_mkdir_preview(engine, tmp_path):
    result = engine.run("mkdir newdir", cwd=str(tmp_path))
    assert result.returncode == 0
    assert not (tmp_path / "newdir").exists()
    matches = [
        c for c in result.changes if c.path == os.path.join(_real(tmp_path), "newdir")
    ]
    assert [c.op for c in matches] == ["mkdir"]


def test_chmod_preview(engine, tmp_path):
    target = tmp_path / "f.txt"
    target.write_text("keep\n")
    os.chmod(target, 0o644)
    result = engine.run("chmod 600 f.txt", cwd=str(tmp_path))
    assert result.returncode == 0
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o644
    matches = [
        c for c in result.changes if c.path == os.path.join(_real(tmp_path), "f.txt")
    ]
    assert [c.op for c in matches] == ["chmod"]
    assert matches[0].detail == "mode 0644 -> 0600"


def test_real_fs_untouched(engine, tmp_path):
    (tmp_path / "victim.txt").write_text("victim\n")
    (tmp_path / "s.txt").write_text("source\n")
    ftxt = tmp_path / "f.txt"
    ftxt.write_text("flat\n")
    os.chmod(ftxt, 0o644)
    before = _snapshot(str(tmp_path))

    command = (
        "echo x > a.txt && rm victim.txt && mkdir d "
        "&& mv s.txt t.txt && chmod 777 f.txt"
    )
    result = engine.run(command, cwd=str(tmp_path))

    assert result.returncode == 0
    assert _snapshot(str(tmp_path)) == before
    base = _real(tmp_path)
    got = {
        (c.op, os.path.basename(c.path)): c for c in result.changes
    }
    assert set(got) == {
        ("create", "a.txt"),
        ("delete", "victim.txt"),
        ("mkdir", "d"),
        ("rename", "s.txt"),
        ("chmod", "f.txt"),
    }
    assert got[("rename", "s.txt")].detail == f"-> {os.path.join(base, 't.txt')}"
    assert stat.S_IMODE(os.stat(ftxt).st_mode) == 0o644


def test_devnull_passthrough(engine, tmp_path):
    result = engine.run("echo hi > /dev/null", cwd=str(tmp_path))
    assert result.returncode == 0
    assert result.changes == []
    assert any("device write" in note for note in result.notes)


def test_timeout(engine, tmp_path):
    result = engine.run("sleep 5", timeout=0.5, cwd=str(tmp_path))
    assert result.timed_out is True
    assert result.returncode not in (0, None)
    assert result.duration < 4.0
    assert not (tmp_path / "sleep").exists()


def test_stdout_tail(engine, tmp_path):
    result = engine.run("echo marker123", cwd=str(tmp_path))
    assert result.returncode == 0
    assert "marker123" in result.stdout_tail
    assert "no file operations intercepted" in " ".join(result.notes)


def test_last_op_wins(engine, tmp_path):
    result = engine.run("echo one > f.txt; echo two > f.txt", cwd=str(tmp_path))
    assert result.returncode == 0
    assert not (tmp_path / "f.txt").exists()
    matches = [
        c for c in result.changes if c.path == os.path.join(_real(tmp_path), "f.txt")
    ]
    assert [c.op for c in matches] == ["create"]


def test_symlink_preview(engine, tmp_path):
    result = engine.run("ln -s target.txt link.txt", cwd=str(tmp_path))
    assert result.returncode == 0
    assert not (tmp_path / "link.txt").exists()
    matches = [
        c for c in result.changes
        if c.path == os.path.join(_real(tmp_path), "link.txt")
    ]
    assert [c.op for c in matches] == ["create"]
    assert "target.txt" in matches[0].detail
