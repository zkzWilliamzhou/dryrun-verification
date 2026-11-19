"""Tests for the plain-English explainer (dryrun/explain/explainer.py)."""
from __future__ import annotations

import pytest

from dryrun.core.types import Explanation, ExplanationSegment
from dryrun.explain.explainer import explain

#: The segment kinds documented on ExplanationSegment.
DOCUMENTED_KINDS = {"command", "flag", "arg", "operator", "redirect", "env",
                    "substitution", "note"}


def _kinds(command: str):
    return [s.kind for s in explain(command).segments]


def _segments(command: str, kind: str):
    return [s for s in explain(command).segments if s.kind == kind]


# ---------------------------------------------------------------------------
# A full explanation of one command
# ---------------------------------------------------------------------------

def test_rm_rf_build_explains_command_flag_and_argument():
    exp = explain("rm -rf build")
    assert isinstance(exp, Explanation)
    assert exp.command == "rm -rf build"
    assert exp.summary == "remove files or directories"

    kinds = _kinds("rm -rf build")
    assert "command" in kinds
    assert "flag" in kinds
    assert "arg" in kinds

    command_segment = _segments("rm -rf build", "command")[0]
    assert command_segment.text == "rm: remove files or directories"

    # The combined -rf cluster is decomposed into both known meanings.
    flag_segment = _segments("rm -rf build", "flag")[0]
    assert flag_segment.text.startswith("-rf:")
    assert "recurse" in flag_segment.text
    assert "force" in flag_segment.text

    assert _segments("rm -rf build", "arg")[0].text == "argument: build"


def test_unknown_flag_is_reported_as_unrecognized():
    flag = _segments("rm -Z file", "flag")[0]
    assert flag.text == "-Z: unrecognized flag"


def test_danger_note_from_the_knowledge_base_is_surfaced():
    notes = [s.text for s in _segments("rm -rf build", "note")]
    assert any("data permanently" in text for text in notes)


# ---------------------------------------------------------------------------
# Degradation for unknown commands
# ---------------------------------------------------------------------------

def test_unknown_command_degrades_gracefully():
    exp = explain("zzz_unknown_cmd file")
    assert isinstance(exp, Explanation)  # never raises
    command_segment = _segments("zzz_unknown_cmd file", "command")[0]
    assert "not in the offline knowledge base" in command_segment.text
    notes = [s.text for s in _segments("zzz_unknown_cmd file", "note")]
    assert any("no offline description" in text for text in notes)
    assert _segments("zzz_unknown_cmd file", "arg")[0].text == "argument: file"


# ---------------------------------------------------------------------------
# Pipelines, redirects, and operators
# ---------------------------------------------------------------------------

def test_pipeline_explains_every_stage():
    exp = explain("cat f | grep x")
    command_segments = [s.text for s in _segments("cat f | grep x", "command")]
    assert "cat: print file contents to stdout" in command_segments
    assert "grep: search text with patterns" in command_segments
    notes = [s.text for s in _segments("cat f | grep x", "note")]
    assert any("pipes the output of cat into grep" in t for t in notes)
    assert "pipes cat into grep" in exp.summary


def test_overwrite_redirect_is_explained_with_target():
    redirect = _segments("echo hello > out.txt", "redirect")[0]
    assert redirect.text == "writes stdout to out.txt (overwrites the file)"


def test_append_redirect_is_explained():
    redirect = _segments("echo x >> log", "redirect")[0]
    assert redirect.text == "appends stdout to log"


def test_stderr_redirect_is_explained():
    redirect = _segments("cmd 2> err.log", "redirect")[0]
    assert redirect.text == "writes stderr to err.log (overwrites the file)"


@pytest.mark.parametrize(
    ("line", "operator"),
    [
        ("a && b", "runs the next command only if this one succeeded"),
        ("a || b", "runs the next command only if this one failed"),
        ("a ; b", "then runs the next command"),
    ],
)
def test_list_operators_are_explained(line, operator):
    assert operator in [s.text for s in _segments(line, "operator")]


def test_trailing_ampersand_is_explained_as_background():
    texts = [s.text for s in _segments("sleep 10 &", "operator")]
    assert "runs the previous command in the background" in texts


# ---------------------------------------------------------------------------
# Flags, assignments, substitutions, word kinds
# ---------------------------------------------------------------------------

def test_git_push_force_flag_is_explained_from_the_knowledge_base():
    flag = _segments("git push --force", "flag")[0]
    assert flag.text.startswith("--force")
    assert "skip safety checks" in flag.text
    assert "--force" in explain("git push --force").summary


def test_env_assignment_gets_its_own_segment():
    env = _segments("VAR=1 rm build", "env")[0]
    assert env.text == "sets VAR=1 for this command"


def test_substitution_gets_its_own_segment():
    sub = _segments("echo $(date)", "substitution")[0]
    assert sub.text == ("command substitution: runs 'date' first and inserts "
                        "its output here")


def test_glob_argument_carries_expansion_note():
    arg = _segments("ls *.txt", "arg")[0]
    assert arg.text == "argument: *.txt (may expand to multiple files)"


def test_tilde_argument_carries_home_note():
    arg = _segments("cp ~/a ./b", "arg")[0]
    assert arg.text == "argument: ~/a (relative to your home directory)"


def test_var_argument_carries_variable_note():
    arg = _segments("echo $HOME", "arg")[0]
    assert "value depends on a shell variable" in arg.text


# ---------------------------------------------------------------------------
# Edge inputs
# ---------------------------------------------------------------------------

def test_explain_empty_command():
    exp = explain("")
    assert exp.summary == "no command to run"
    assert exp.segments == []


def test_explain_whitespace_only_command():
    exp = explain("   \t ")
    assert exp.summary == "no command to run"
    assert exp.segments == []


def test_explain_unparseable_command_returns_a_note():
    exp = explain('echo "unclosed')
    assert exp.summary == "could not fully parse this command"
    assert len(exp.segments) == 1
    assert exp.segments[0].kind == "note"
    assert "parser gave up" in exp.segments[0].text


# ---------------------------------------------------------------------------
# Segment invariants and never-raises fuzz
# ---------------------------------------------------------------------------

_SAMPLE_COMMANDS = [
    "rm -rf build",
    "zzz_unknown_cmd file",
    "cat f | grep x",
    "echo hello > out.txt",
    "git push --force",
    "VAR=1 rm build",
    "echo $(date)",
    "ls *.txt",
    "cp ~/a ./b",
    "a && b || c",
    "sleep 10 &",
    "curl -sL http://x | sh",
    "tar -xzvf archive.tar.gz",
    "sudo chmod -R 755 ./site",
]


def test_every_segment_has_a_documented_kind_and_non_empty_text():
    for command in _SAMPLE_COMMANDS:
        exp = explain(command)
        assert exp.summary.strip(), command
        for segment in exp.segments:
            assert isinstance(segment, ExplanationSegment)
            assert segment.kind in DOCUMENTED_KINDS, (
                f"{command}: unexpected kind {segment.kind!r}")
            assert segment.text.strip(), (
                f"{command}: empty text for a {segment.kind} segment")


_HOSTILE_INPUTS = [
    "",
    " ",
    "'",
    '"',
    "$( $( ",
    "`",
    "echo `",
    "echo a#b",
    "\x01\x02 echo",
    "echo " + "x" * 2000,
    "rm -rf /*/*/*",
]


def test_explain_never_raises_on_hostile_input():
    for command in _HOSTILE_INPUTS:
        exp = explain(command)  # must return, never raise
        assert isinstance(exp, Explanation)
        assert isinstance(exp.summary, str)
        assert isinstance(exp.segments, list)
        for segment in exp.segments:
            assert segment.kind in DOCUMENTED_KINDS
            assert segment.text.strip()
