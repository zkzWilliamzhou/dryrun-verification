"""Tests for the sandbox simulation engine (real temp directories)."""
from __future__ import annotations

import pytest

from dryrun.simulate.base import EngineError
from dryrun.simulate.sandbox import SandboxEngine


def test_create_file(tmp_path):
    (tmp_path / "seed.txt").write_text("seed\n")
    result = SandboxEngine().run("echo hi > new.txt", timeout=10.0, cwd=str(tmp_path))
    assert [change.op for change in result.changes] == ["create"]
    assert result.changes[0].path == str(tmp_path / "new.txt")
    assert not (tmp_path / "new.txt").exists()


def test_delete_file(tmp_path):
    target = tmp_path / "existing.txt"
    target.write_text("data\n")
    result = SandboxEngine().run("rm existing.txt", timeout=10.0, cwd=str(tmp_path))
    assert [change.op for change in result.changes] == ["delete"]
    assert result.changes[0].path == str(target)
    assert target.exists()


def test_modify_with_diff(tmp_path):
    target = tmp_path / "existing.txt"
    target.write_text("line\n")
    result = SandboxEngine().run(
        "echo more >> existing.txt", timeout=10.0, cwd=str(tmp_path)
    )
    assert [change.op for change in result.changes] == ["modify"]
    change = result.changes[0]
    assert change.detail == "5 -> 10 bytes"
    assert "+more" in (change.diff or "")
    assert target.read_text() == "line\n"


def test_mkdir(tmp_path):
    result = SandboxEngine().run("mkdir d", timeout=10.0, cwd=str(tmp_path))
    assert [change.op for change in result.changes] == ["mkdir"]
    assert result.changes[0].path == str(tmp_path / "d")
    assert not (tmp_path / "d").exists()


def test_timeout_kills_command(tmp_path):
    result = SandboxEngine().run("sleep 3", timeout=0.5, cwd=str(tmp_path))
    assert result.timed_out is True
    assert result.duration < 2.5
    assert result.returncode is not None
    assert result.returncode != 0


def test_two_creates(tmp_path):
    result = SandboxEngine().run("touch a b", timeout=10.0, cwd=str(tmp_path))
    assert sorted(change.op for change in result.changes) == ["create", "create"]
    assert not (tmp_path / "a").exists()
    assert not (tmp_path / "b").exists()


def test_oversized_tree_refused(tmp_path):
    (tmp_path / "big.bin").write_bytes(b"x" * 1024)
    engine = SandboxEngine(max_tree_bytes=10)
    with pytest.raises(EngineError, match="exceeds sandbox limit"):
        engine.run("true", timeout=10.0, cwd=str(tmp_path))


def test_no_changes_and_base_note(tmp_path):
    result = SandboxEngine().run("true", timeout=10.0, cwd=str(tmp_path))
    assert result.changes == []
    assert result.returncode == 0
    assert result.notes == [
        "sandbox engine only observes effects inside the working directory"
    ]


def test_nonzero_exit_noted(tmp_path):
    result = SandboxEngine().run("exit 3", timeout=10.0, cwd=str(tmp_path))
    assert result.returncode == 3
    assert "command exited with status 3" in result.notes


def test_timeout_noted(tmp_path):
    result = SandboxEngine().run("sleep 3", timeout=0.5, cwd=str(tmp_path))
    assert any("timed out" in note for note in result.notes)


def test_changes_sorted_deletes_before_creates(tmp_path):
    target = tmp_path / "old.txt"
    target.write_text("x\n")
    result = SandboxEngine().run(
        "rm old.txt; echo new > fresh.txt", timeout=10.0, cwd=str(tmp_path)
    )
    assert [change.op for change in result.changes] == ["delete", "create"]


def test_large_diff_capped_at_4096_chars(tmp_path):
    target = tmp_path / "big.txt"
    target.write_text("start\n")
    result = SandboxEngine().run(
        'for i in $(seq 1 500); do echo "filler line $i"; done > big.txt',
        timeout=10.0,
        cwd=str(tmp_path),
    )
    modify = [c for c in result.changes if c.op == "modify"]
    assert len(modify) == 1
    diff = modify[0].diff or ""
    assert diff.endswith("... (diff truncated)")
    assert len(diff) < 4200
    assert "filler line 400" not in diff
