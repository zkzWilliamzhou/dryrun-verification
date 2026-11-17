"""Tests for the CLI: flags, exit codes, JSON output, and execution."""
from __future__ import annotations

import io
import json
import sys

import pytest

import dryrun.audit
import dryrun.cli as cli
import dryrun.core.proc as proc
import dryrun.explain
from dryrun.core.proc import ProcResult
from dryrun.core.types import Explanation, ExplanationSegment, Finding


def _patch_analysis(monkeypatch: pytest.MonkeyPatch, findings=()):
    """Replace the not-yet-implemented explain/audit entry points."""
    monkeypatch.setattr(
        dryrun.explain,
        "explain",
        lambda command: Explanation(
            command=command,
            summary="prints text to a file",
            segments=[ExplanationSegment(kind="command", text="echo: print text")],
        ),
    )
    monkeypatch.setattr(dryrun.audit, "audit", lambda command: list(findings))


def _critical_finding():
    return Finding(
        rule_id="RM_ROOT_PATH",
        severity="CRITICAL",
        title="rm targets the root filesystem",
        detail="this would delete everything",
        command_index=0,
    )


def test_version_flag(capsys):
    assert cli.main(["--version"]) == 0
    assert "dryrun 0.1.0" in capsys.readouterr().out


def test_usage_error_no_args(capsys):
    assert cli.main([]) == 3
    assert "usage" in capsys.readouterr().err.lower()


def test_unknown_engine_is_usage_error():
    assert cli.main(["--engine", "warp", "ls"]) == 3


def test_explain_only(monkeypatch, capsys):
    _patch_analysis(monkeypatch)
    assert cli.main(["--explain-only", "echo hi"]) == 0
    out = capsys.readouterr().out
    assert "Explanation" in out
    assert "prints text to a file" in out


def test_audit_only_clean(monkeypatch, capsys):
    _patch_analysis(monkeypatch)
    assert cli.main(["--audit-only", "echo hi"]) == 0
    assert "Audit: clean - no known dangerous patterns matched." in capsys.readouterr().out


def test_audit_only_threshold(monkeypatch):
    _patch_analysis(monkeypatch, findings=[_critical_finding()])
    code = cli.main(["--audit-only", "--fail-on", "critical", "rm -rf /"])
    assert code == 4


def test_explain_and_audit_only_conflict(monkeypatch):
    _patch_analysis(monkeypatch)
    assert cli.main(["--explain-only", "--audit-only", "echo hi"]) == 3


def test_json_payload_schema(monkeypatch, capsys, tmp_path):
    _patch_analysis(monkeypatch)
    monkeypatch.chdir(tmp_path)
    assert cli.main(["--json", "--engine", "sandbox", "echo hi > f.txt"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert set(payload) == {
        "dryrun_version",
        "command",
        "explanation",
        "audit",
        "simulation",
    }
    assert payload["dryrun_version"] == "0.1.0"
    assert payload["command"] == "echo hi > f.txt"
    assert payload["simulation"]["engine"] == "sandbox"
    assert [c["op"] for c in payload["simulation"]["changes"]] == ["create"]
    assert not (tmp_path / "f.txt").exists()


def test_json_safety_refusal(monkeypatch, capsys, tmp_path):
    _patch_analysis(monkeypatch)
    monkeypatch.chdir(tmp_path)
    code = cli.main(["--json", "--engine", "sandbox", "sudo rm -rf /"])
    assert code == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["simulation"] is None
    assert payload["error"]["type"] == "SafetyError"
    assert "audit-only" in payload["error"]["message"]


def test_text_safety_refusal(monkeypatch, capsys, tmp_path):
    _patch_analysis(monkeypatch)
    monkeypatch.chdir(tmp_path)
    assert cli.main(["--engine", "sandbox", "sudo whoami"]) == 1
    captured = capsys.readouterr()
    assert "refused:" in captured.err
    assert "audit-only" in captured.err


def test_full_text_run(monkeypatch, capsys, tmp_path):
    _patch_analysis(monkeypatch)
    monkeypatch.chdir(tmp_path)
    assert cli.main(["--engine", "sandbox", "echo hi > f.txt"]) == 0
    out = capsys.readouterr().out
    assert "previewing with sandbox engine" in out
    assert "Would create 1 file" in out
    assert "Nothing was touched." in out
    assert not (tmp_path / "f.txt").exists()


def test_fail_on_critical_after_simulation(monkeypatch, capsys, tmp_path):
    _patch_analysis(monkeypatch, findings=[_critical_finding()])
    monkeypatch.chdir(tmp_path)
    code = cli.main(["--fail-on", "critical", "--engine", "sandbox", "echo hi > f.txt"])
    assert code == 4
    assert "CRITICAL" in capsys.readouterr().out


def test_execute_blocked_by_critical(monkeypatch, capsys, tmp_path):
    _patch_analysis(monkeypatch, findings=[_critical_finding()])
    monkeypatch.chdir(tmp_path)
    code = cli.main(["--execute", "-y", "--engine", "sandbox", "echo hi > f.txt"])
    assert code == 2
    assert "CRITICAL" in capsys.readouterr().err


def test_execute_with_yes_runs_without_preload(monkeypatch, capsys, tmp_path):
    _patch_analysis(monkeypatch)
    monkeypatch.chdir(tmp_path)
    calls = {}

    def fake_run(command, **kwargs):
        calls["command"] = command
        calls["env"] = kwargs.get("env")
        calls["args"] = sorted(kwargs)
        return ProcResult(
            returncode=0, stdout="", stderr="", duration=0.01, timed_out=False
        )

    monkeypatch.setattr(proc, "run_command", fake_run)
    monkeypatch.setenv("LD_PRELOAD", "/bogus/libshadow.so")
    assert cli.main(["--execute", "-y", "--engine", "sandbox", "echo hi > f.txt"]) == 0
    out = capsys.readouterr().out
    assert calls["command"] == "echo hi > f.txt"
    assert calls["env"] is None
    assert "LD_PRELOAD" not in str(calls)
    assert "exit 0 in 0.0s" in out
    assert "Running for real:" in out


def test_execute_declined_at_prompt(monkeypatch, capsys, tmp_path):
    _patch_analysis(monkeypatch)
    monkeypatch.chdir(tmp_path)

    class FakeStdin(io.StringIO):
        def isatty(self):
            return True

    monkeypatch.setattr(sys, "stdin", FakeStdin("n\n"))
    assert cli.main(["--execute", "--engine", "sandbox", "echo hi"]) == 0
    assert "aborted - nothing was executed" in capsys.readouterr().out


def test_internal_error_is_contained(monkeypatch, capsys):
    def boom(command):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(dryrun.explain, "explain", boom)
    assert cli.main(["echo hi"]) == 1
    assert "internal error:" in capsys.readouterr().err


def test_broken_pipe_exits_quietly(tmp_path):
    """`dryrun ... | head` must not print an internal error (R6-F1)."""
    import os
    import subprocess

    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = {**os.environ, "PYTHONPATH": os.path.join(repo, "src")}
    # A real shell pipeline: dryrun's stdout feeds head, which exits after
    # 10 bytes and closes the pipe while dryrun is still writing.
    pipeline = (
        "python3 -m dryrun 'echo " + "word " * 500 + "' | head -c 10"
    )
    proc = subprocess.run(
        ["bash", "-c", pipeline],
        cwd=str(tmp_path),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=120,
    )
    assert "internal error" not in proc.stderr
    assert "BrokenPipeError" not in proc.stderr
