"""Tests for the text and JSON report renderers."""
from __future__ import annotations

import io
import json
import sys

from dryrun.core.types import (
    ChangeRecord,
    Explanation,
    ExplanationSegment,
    Finding,
    SimulationResult,
)
from dryrun.report.json_out import build_payload, emit
from dryrun.report.text import (
    confirm_execute,
    print_execute_banner,
    print_explanation,
    print_findings,
    print_simulation,
    supports_color,
)


def _finding(severity: str, rule_id: str = "RULE_X") -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        title="a title",
        detail="a detail",
        command_index=0,
    )


def _result(**overrides) -> SimulationResult:
    values = {
        "engine": "sandbox",
        "command": "echo hi > mod.txt",
        "returncode": 0,
        "duration": 0.4,
        "timed_out": False,
        "changes": [
            ChangeRecord(
                op="modify",
                path="/abs/mod.txt",
                detail="30 -> 34 bytes",
                diff="--- a/mod.txt\n+++ b/mod.txt\n@@ -1 +1 @@\n-old\n+new",
            )
        ],
        "notes": ["sandbox engine only observes effects inside the working directory"],
        "stdout_tail": "",
        "stderr_tail": "",
    }
    values.update(overrides)
    return SimulationResult(**values)


def test_plain_output_is_pure_ascii():
    stream = io.StringIO()
    explanation = Explanation(
        command="echo hi",
        summary="prints hi",
        segments=[ExplanationSegment(kind="command", text="echo: print text")],
    )
    findings = [_finding("CRITICAL", "RM_ROOT_PATH"), _finding("LOW")]
    print_explanation(explanation, color=False, stream=stream)
    print_findings(findings, color=False, stream=stream)
    print_simulation(_result(), color=False, stream=stream)
    print_execute_banner("echo hi", color=False, stream=stream)
    text = stream.getvalue()
    assert all(ord(char) < 128 for char in text)
    assert "Simulation - exit 0, 0.4s" in text
    assert "Nothing was touched." in text


def test_color_output_uses_ansi():
    stream = io.StringIO()
    print_findings([_finding("CRITICAL")], color=True, stream=stream)
    print_simulation(_result(), color=True, stream=stream)
    assert "\x1b[" in stream.getvalue()


def test_findings_sorted_by_severity_then_rule():
    stream = io.StringIO()
    findings = [
        _finding("LOW", "AAA"),
        _finding("CRITICAL", "ZZZ"),
        _finding("HIGH", "MMM"),
        _finding("CRITICAL", "AAA"),
    ]
    print_findings(findings, color=False, stream=stream)
    text = stream.getvalue()
    assert text.index("CRITICAL  AAA") < text.index("CRITICAL  ZZZ")
    assert text.index("CRITICAL  ZZZ") < text.index("HIGH")
    assert text.index("HIGH") < text.index("LOW")


def test_zero_changes_message():
    stream = io.StringIO()
    print_simulation(_result(changes=[]), color=False, stream=stream)
    assert "Would change nothing." in stream.getvalue()


def test_diff_render_truncated_to_12_lines():
    long_diff = "\n".join(
        ["--- a/f", "+++ b/f", "@@ -1 +1 @@"] + [f"+line {i}" for i in range(50)]
    )
    result = _result(
        changes=[ChangeRecord(op="modify", path="/f", detail="0 -> 1 bytes", diff=long_diff)]
    )
    stream = io.StringIO()
    print_simulation(result, color=False, stream=stream)
    text = stream.getvalue()
    assert "... (diff truncated)" in text
    assert "+line 8" in text
    assert "+line 40" not in text


def test_json_payload_schema_exact():
    explanation = Explanation(
        command="x",
        summary="s",
        segments=[ExplanationSegment(kind="command", text="echo: e")],
    )
    findings = [_finding("LOW"), _finding("CRITICAL", "AAA")]
    change = ChangeRecord(op="create", path="/tmp/f", detail="12 B")
    result = _result(changes=[change], returncode=1, timed_out=True)
    payload = build_payload("x", explanation, findings, result)
    assert set(payload) == {"dryrun_version", "command", "explanation", "audit", "simulation"}
    assert payload["dryrun_version"] == "0.1.0"
    assert set(payload["explanation"]) == {"summary", "segments"}
    assert set(payload["explanation"]["segments"][0]) == {"kind", "text"}
    assert set(payload["audit"][0]) == {"rule_id", "severity", "title", "detail", "command_index"}
    assert [f["severity"] for f in payload["audit"]] == ["CRITICAL", "LOW"]
    simulation = payload["simulation"]
    assert set(simulation) == {
        "engine",
        "returncode",
        "duration",
        "timed_out",
        "changes",
        "notes",
        "stdout_tail",
        "stderr_tail",
    }
    assert set(simulation["changes"][0]) == {"op", "path", "detail", "diff"}


def test_json_payload_null_fields_and_error():
    payload = build_payload("x", None, [], None, error={"type": "SafetyError", "message": "no"})
    assert payload["explanation"] is None
    assert payload["audit"] == []
    assert payload["simulation"] is None
    assert payload["error"] == {"type": "SafetyError", "message": "no"}


def test_emit_writes_pretty_json_with_newline():
    stream = io.StringIO()
    emit(build_payload("x", None, [], None), stream)
    text = stream.getvalue()
    assert text.endswith("\n")
    assert json.loads(text)["command"] == "x"
    assert "\n  \"command\"" in text


def test_emit_json_is_ascii():
    stream = io.StringIO()
    result = _result(stdout_tail="ok", stderr_tail="")
    emit(build_payload("x", None, [], result), stream)
    assert all(ord(char) < 128 for char in stream.getvalue())


class _FakeStdin(io.StringIO):
    def isatty(self):
        return True


def test_confirm_execute_acceptances(monkeypatch):
    for answer in ("y\n", "yes\n", "Y\n", "  YES  \n"):
        monkeypatch.setattr(sys, "stdin", _FakeStdin(answer))
        assert confirm_execute("ls", stream=io.StringIO()) is True


def test_confirm_execute_rejections(monkeypatch):
    for answer in ("n\n", "no\n", "\n", "", "yeah\n"):
        monkeypatch.setattr(sys, "stdin", _FakeStdin(answer))
        assert confirm_execute("ls", stream=io.StringIO()) is False


def test_supports_color():
    assert supports_color(io.StringIO()) is False


def test_supports_color_with_tty_and_term(monkeypatch):
    class FakeTty(io.StringIO):
        def isatty(self):
            return True

    monkeypatch.setenv("TERM", "xterm-256color")
    assert supports_color(FakeTty()) is True
    monkeypatch.setenv("TERM", "dumb")
    assert supports_color(FakeTty()) is False
