"""Direct tests for the shared diff-and-order seam (simulate/diffops)."""
import os

from dryrun.core.types import ChangeRecord
from dryrun.simulate.diffops import (
    MAX_DIFF_CHARS,
    human_size,
    sort_changes,
    unified_diff,
)


def test_human_size_units():
    assert human_size(0) == "0 B"
    assert human_size(512) == "512 B"
    assert human_size(2048) == "2.0 KiB"
    assert human_size(3 * 1024 * 1024) == "3.0 MiB"


def test_unified_diff_reports_changed_lines(tmp_path):
    old = tmp_path / "old.txt"
    new = tmp_path / "new.txt"
    old.write_text("alpha\nbeta\n", encoding="utf-8")
    new.write_text("alpha\ngamma\n", encoding="utf-8")
    text = unified_diff(str(old), str(new), "old.txt")
    assert text is not None
    assert "--- a/old.txt" in text
    assert "+++ b/old.txt" in text
    assert "-beta" in text
    assert "+gamma" in text


def test_unified_diff_none_for_identical_files(tmp_path):
    a = tmp_path / "a.txt"
    b = tmp_path / "b.txt"
    a.write_text("same\n", encoding="utf-8")
    b.write_text("same\n", encoding="utf-8")
    assert unified_diff(str(a), str(b), "a.txt") is None


def test_unified_diff_none_for_binary_content(tmp_path):
    a = tmp_path / "a.bin"
    b = tmp_path / "b.bin"
    a.write_bytes(b"\xff\xfe\x00\x01")
    b.write_bytes(b"\xff\xfe\x00\x02")
    assert unified_diff(str(a), str(b), "a.bin") is None


def test_unified_diff_none_when_file_missing(tmp_path):
    present = tmp_path / "present.txt"
    present.write_text("here\n", encoding="utf-8")
    assert unified_diff(str(present), str(tmp_path / "gone.txt"), "x") is None
    assert unified_diff(str(tmp_path / "gone.txt"), str(present), "x") is None


def test_unified_diff_oversize_short_circuits_without_reading(tmp_path):
    big = tmp_path / "big.txt"
    big.write_text("x", encoding="utf-8")
    small = tmp_path / "small.txt"
    small.write_text("y", encoding="utf-8")
    # Sizes passed in claim the old file is over the cap, so no read happens.
    assert (
        unified_diff(str(big), str(small), "big.txt", old_size=MAX_DIFF_CHARS * 999)
        is None
    )


def test_unified_diff_truncates_long_output(tmp_path):
    a = tmp_path / "a.txt"
    b = tmp_path / "b.txt"
    a.write_text("start\n" + "\n".join(f"old{i}" for i in range(4000)), encoding="utf-8")
    b.write_text("start\n" + "\n".join(f"new{i}" for i in range(4000)), encoding="utf-8")
    text = unified_diff(str(a), str(b), "a.txt")
    assert text is not None
    assert len(text) <= MAX_DIFF_CHARS + len("\n... (diff truncated)")
    assert text.endswith("... (diff truncated)")


def test_sort_changes_removals_first_then_path():
    records = [
        ChangeRecord(op="create", path="/p/b"),
        ChangeRecord(op="delete", path="/p/z"),
        ChangeRecord(op="modify", path="/p/a"),
        ChangeRecord(op="delete", path="/p/a"),
        ChangeRecord(op="chmod", path="/p/m"),
        ChangeRecord(op="rmdir", path="/p/d"),
    ]
    assert [r.op for r in sort_changes(records)] == [
        "delete",
        "delete",
        "rmdir",
        "create",
        "modify",
        "chmod",
    ]
    assert sort_changes(records)[0].path == "/p/a"
    assert sort_changes(records)[1].path == "/p/z"


def test_sort_changes_unknown_op_sorts_last():
    records = [
        ChangeRecord(op="teleport", path="/p/a"),
        ChangeRecord(op="chmod", path="/p/z"),
    ]
    assert [r.op for r in sort_changes(records)] == ["chmod", "teleport"]
