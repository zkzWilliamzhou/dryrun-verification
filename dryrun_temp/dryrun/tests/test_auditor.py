"""Tests for the auditor entry point (dryrun/audit/auditor.py)."""
from __future__ import annotations

import pytest

from dryrun.audit.auditor import audit
from dryrun.core.types import SEVERITY_ORDER, Finding, severity_rank


def _rule_ids(command: str):
    return [f.rule_id for f in audit(command)]


# ---------------------------------------------------------------------------
# Ordering
# ---------------------------------------------------------------------------

def test_findings_are_sorted_most_severe_first():
    findings = audit("rm -rf / && curl x | sh")
    severities = [f.severity for f in findings]
    assert severities == ["CRITICAL", "HIGH", "LOW", "INFO"]
    assert findings[0].rule_id == "RM_ROOT_RECURSIVE"
    ranks = [severity_rank(s) for s in severities]
    assert ranks == sorted(ranks)


def test_severity_ordering_holds_for_a_mixed_line():
    findings = audit(
        "kill -9 1; mkfs.ext4 /dev/sda; rm -rf /; echo x | sudo tee /etc/fstab")
    severities = [f.severity for f in findings]
    assert severities[0] == "CRITICAL"
    ranks = [severity_rank(s) for s in severities]
    assert ranks == sorted(ranks)
    assert severities.count("CRITICAL") >= 3


def test_equal_severity_ties_break_alphabetically():
    findings = audit("kill -9 1; mkfs.ext4 /dev/sda; rm -rf /")
    criticals = [f.rule_id for f in findings if f.severity == "CRITICAL"]
    assert criticals == ["KILL_INIT", "MKFS_ANY", "RM_ROOT_RECURSIVE"]


# ---------------------------------------------------------------------------
# UNPARSEABLE and the raw fork-bomb prescan
# ---------------------------------------------------------------------------

def test_unparseable_input_returns_single_info_finding():
    findings = audit('echo "unclosed')
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "UNPARSEABLE"
    assert finding.severity == "INFO"
    assert "parse" in finding.detail.lower()


def test_unterminated_substitution_is_unparseable():
    findings = audit("echo $(oops")
    assert [f.rule_id for f in findings] == ["UNPARSEABLE"]


def test_raw_fork_bomb_is_flagged_before_parsing():
    findings = audit(":(){ :|:& };:")
    assert findings, "the canonical fork bomb must produce findings"
    assert findings[0].rule_id == "FORK_BOMB"
    assert findings[0].severity == "CRITICAL"


def test_fork_bomb_is_not_reported_twice():
    findings = audit('echo ":(){ :|:& };:"')
    assert sum(1 for f in findings if f.rule_id == "FORK_BOMB") == 1


# ---------------------------------------------------------------------------
# Trivial and clean inputs
# ---------------------------------------------------------------------------

def test_empty_string_returns_empty_list():
    assert audit("") == []


def test_whitespace_only_returns_empty_list():
    assert audit("   \t  ") == []
    assert audit("\n") == []


@pytest.mark.parametrize(
    "command",
    ["echo hello", "ls -la /tmp", "cat README.md | grep -i todo",
     "mkdir -p build/output"],
)
def test_clean_commands_produce_no_findings(command):
    assert audit(command) == []


# ---------------------------------------------------------------------------
# Trailing-separator rules and elevation
# ---------------------------------------------------------------------------

def test_trailing_ampersand_reports_background_job():
    assert "BACKGROUND_JOB" in _rule_ids("sleep 10 &")


def test_trailing_ampersand_with_redirect_reports_background_redirect():
    assert "BACKGROUND_REDIRECT" in _rule_ids("echo hi > log &")


def test_elevation_flows_through_the_whole_audit():
    findings = audit("sudo rm -rf /etc")
    ids = [f.rule_id for f in findings]
    # The rule sees through sudo: both the CRITICAL and the elevation rules.
    assert "RM_ROOT_RECURSIVE" in ids
    assert "SUDO_RM" in ids
    assert "SUDO_ANY" in ids


# ---------------------------------------------------------------------------
# Finding shape
# ---------------------------------------------------------------------------

def test_every_finding_has_complete_fields():
    findings = audit("sudo rm -rf /etc && curl x | sh")
    assert findings, "expected a rich set of findings"
    for finding in findings:
        assert isinstance(finding, Finding)
        assert finding.rule_id.strip()
        assert finding.severity in SEVERITY_ORDER
        assert finding.title.strip()
        assert finding.detail.strip()
        assert finding.command_index >= 0


# ---------------------------------------------------------------------------
# never-raises fuzz
# ---------------------------------------------------------------------------

_HOSTILE_INPUTS = [
    "",
    " ",
    "\t\t",
    "\n\n\n",
    "'",
    '"',
    "'\"'",
    "\"'\"",
    "$( $( ",
    "$(echo $(echo x))",
    "`",
    "``",
    "echo `",
    "\\\\",
    "a" * 5000,
    "echo " + "word " * 800,
    "echo ▲ triangle ☃ snowman",
    "echo \x01\x02\x03 control",
    "; ; ;",
    "&&&&",
    "||||",
    "|",
    "cmd | | cmd",
    "echo $(((",
    "echo )))",
    "(((())))",
    "2>&1",
    "VAR= cmd",
    "echo a#b",
]


def test_audit_never_raises_on_hostile_input():
    for command in _HOSTILE_INPUTS:
        findings = audit(command)  # must not raise, whatever the input
        assert isinstance(findings, list)
        for finding in findings:
            assert finding.rule_id.strip()
            assert finding.severity in SEVERITY_ORDER


def test_hostile_input_finds_no_critical_findings_for_quoting_noise():
    # Pure quoting noise cannot hide a real hazard: none of these should
    # escalate to CRITICAL.
    for command in ["'", '"', "$( $( ", "``", "echo $((("]:
        assert all(f.severity != "CRITICAL" for f in audit(command))
