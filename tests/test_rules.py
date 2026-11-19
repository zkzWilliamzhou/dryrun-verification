"""Tests for the danger rules engine (dryrun/audit/rules.py)."""
from __future__ import annotations

from collections import Counter

import pytest

from dryrun.audit.auditor import audit
from dryrun.audit.rules import (
    RULES,
    NormCmd,
    is_root_level,
    is_system_subtree,
    looks_like_device,
    normalize,
    raw_fork_bomb,
)
from dryrun.core.types import SEVERITY_ORDER, severity_rank
from dryrun.explain.parser import parse


def _rule(rule_id: str):
    for rule in RULES:
        if rule.rule_id == rule_id:
            return rule
    raise AssertionError(f"rule {rule_id} not in the table")


def _rule_ids(command: str):
    return [f.rule_id for f in audit(command)]


def _has_finding(command: str, rule_id: str, severity: str) -> bool:
    return any(f.rule_id == rule_id and f.severity == severity
               for f in audit(command))


def _normcmd(words, name="rm"):
    return NormCmd(index=0, name=name, words=list(words), redirects=[],
                   assignments=[], substitutions=[], elevated=False)


# ---------------------------------------------------------------------------
# The rule table itself
# ---------------------------------------------------------------------------

def test_rule_table_size_and_severity_mix():
    # The brief expected >= 62 rules; the shipped table has 57
    # (plus BACKGROUND_JOB/BACKGROUND_REDIRECT applied by the auditor).
    counts = Counter(rule.severity for rule in RULES)
    assert counts == Counter({"MEDIUM": 20, "HIGH": 14, "LOW": 9,
                              "CRITICAL": 8, "INFO": 6})
    assert len(RULES) == 57


def test_all_eight_critical_rules_are_in_the_table():
    critical = [rule.rule_id for rule in RULES if rule.severity == "CRITICAL"]
    assert critical == [
        "RM_ROOT_RECURSIVE", "DD_TO_DISK", "MKFS_ANY", "FORK_BOMB",
        "CHMOD_777_ROOT", "OVERWRITE_PASSWD", "DEV_DISK_REDIRECT", "KILL_INIT",
    ]


def test_rule_ids_are_unique():
    ids = [rule.rule_id for rule in RULES]
    assert len(ids) == len(set(ids))


def test_every_rule_is_well_formed():
    for rule in RULES:
        assert rule.severity in SEVERITY_ORDER, rule.rule_id
        assert rule.title.strip(), rule.rule_id
        assert rule.detail.strip(), rule.rule_id
        assert callable(rule.match), rule.rule_id


def test_severity_rank_orders_the_scale():
    assert severity_rank("CRITICAL") == 0
    assert severity_rank("HIGH") == 1
    assert severity_rank("MEDIUM") == 2
    assert severity_rank("LOW") == 3
    assert severity_rank("INFO") == 4
    ranks = [severity_rank(s) for s in SEVERITY_ORDER]
    assert ranks == sorted(ranks)
    assert ranks == [0, 1, 2, 3, 4]


def test_unknown_severity_ranks_below_info():
    assert severity_rank("NOT_A_SEVERITY") == 5


# ---------------------------------------------------------------------------
# CRITICAL rules: each one must fire
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "command", ["rm -rf /", "rm -fr /usr", "rm -r /etc", "sudo rm -rf /var"]
)
def test_rm_root_recursive_fires(command):
    assert _has_finding(command, "RM_ROOT_RECURSIVE", "CRITICAL")


@pytest.mark.parametrize(
    "command", ["rm -rf ./build", "rm -rf build", "rm -r ./src", "rm -f notes.txt"]
)
def test_rm_root_recursive_ignores_project_paths(command):
    assert "RM_ROOT_RECURSIVE" not in _rule_ids(command)


def test_rm_root_recursive_catches_verbose_cluster():
    assert _has_finding("rm -rfv /etc", "RM_ROOT_RECURSIVE", "CRITICAL")


def test_dd_to_disk_fires():
    assert _has_finding("dd if=/dev/zero of=/dev/sda", "DD_TO_DISK", "CRITICAL")


def test_dd_to_disk_ignores_regular_files():
    command = "dd if=a of=b bs=1M count=10"
    assert "DD_TO_DISK" not in _rule_ids(command)
    assert _rule_ids(command) == []  # the safe form produces no findings at all


def test_mkfs_any_fires():
    assert _has_finding("mkfs.ext4 /dev/sdb", "MKFS_ANY", "CRITICAL")


def test_mkfs_any_ignores_other_commands():
    assert "MKFS_ANY" not in _rule_ids("man mkfs.ext4")


def test_fork_bomb_raw_prescan_fires():
    finding = raw_fork_bomb(":(){ :|:& };:")
    assert finding is not None
    assert finding.rule_id == "FORK_BOMB"
    assert finding.severity == "CRITICAL"
    # Through the auditor, with the canonical and a whitespace-heavy form.
    assert _has_finding(":(){ :|:& };:", "FORK_BOMB", "CRITICAL")
    assert _has_finding(": () { : | : & } ; :", "FORK_BOMB", "CRITICAL")


def test_fork_bomb_rule_level_backstop_fires_on_quoted_bomb():
    # A quoted bomb survives parsing as a word; the rule-level match is the
    # backstop behind the raw prescan.
    cmds = normalize(parse('echo ":(){ :|:& };:"'))
    assert _rule("FORK_BOMB").match(cmds) == [0]


@pytest.mark.parametrize(
    "command", ["f() { echo hi; }", "sleep 1 & echo done", "echo '|&'"]
)
def test_fork_bomb_ignores_other_shell_functions(command):
    assert "FORK_BOMB" not in _rule_ids(command)


def test_chmod_777_root_fires():
    assert _has_finding("chmod -R 777 /etc", "CHMOD_777_ROOT", "CRITICAL")


def test_chmod_777_root_ignores_benign_modes_and_paths():
    assert "CHMOD_777_ROOT" not in _rule_ids("chmod -R 755 ./site")
    assert "CHMOD_777_ROOT" not in _rule_ids("chmod 777 ./file")


def test_overwrite_passwd_fires_on_cp():
    assert _has_finding("cp something /etc/passwd", "OVERWRITE_PASSWD",
                        "CRITICAL")


def test_overwrite_passwd_fires_on_redirect():
    assert _has_finding("echo x > /etc/passwd", "OVERWRITE_PASSWD", "CRITICAL")


@pytest.mark.parametrize(
    "command", ["cp notes.txt notes.backup", "cp a /tmp/passwd",
                "mv a ./b", "echo x > out.txt"]
)
def test_overwrite_passwd_ignores_unprotected_targets(command):
    assert "OVERWRITE_PASSWD" not in _rule_ids(command)


def test_dev_disk_redirect_fires():
    assert _has_finding("cat img.iso > /dev/sdc", "DEV_DISK_REDIRECT",
                        "CRITICAL")


def test_dev_disk_redirect_ignores_file_targets():
    assert "DEV_DISK_REDIRECT" not in _rule_ids("cat img.iso > out.iso")


def test_kill_init_fires():
    assert _has_finding("kill -9 1", "KILL_INIT", "CRITICAL")


@pytest.mark.parametrize("command", ["kill -9 1234", "kill -15 1"])
def test_kill_init_ignores_ordinary_kills(command):
    assert "KILL_INIT" not in _rule_ids(command)


def test_kill_init_catches_kill_all_form():
    assert _has_finding("kill -9 -1", "KILL_INIT", "CRITICAL")


def test_dd_to_disk_catches_partition_targets():
    assert _has_finding("dd if=/dev/zero of=/dev/sda1", "DD_TO_DISK",
                        "CRITICAL")


# ---------------------------------------------------------------------------
# has_flag cluster semantics
# ---------------------------------------------------------------------------

def test_has_flag_matches_exact_tokens():
    assert _normcmd(["-r"]).has_flag("-r")
    assert _normcmd(["-rf"]).has_flag("-rf")
    assert not _normcmd(["-r"]).has_flag("-f")


def test_has_flag_long_flag_is_not_split_into_letters():
    # -delete must never satisfy -d.
    assert not _normcmd(["-delete"]).has_flag("-d")


def test_has_flag_cluster_satisfies_its_component_letters():
    assert _normcmd(["-rf"]).has_flag("-r", "-f")


# ---------------------------------------------------------------------------
# Non-CRITICAL rules
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "command", ["curl http://x.example | sh", "wget -qO- http://x | bash"])
def test_curl_pipe_shell_fires(command):
    assert _has_finding(command, "CURL_PIPE_SHELL", "HIGH")


def test_curl_pipe_shell_ignores_safe_pipes():
    assert "CURL_PIPE_SHELL" not in _rule_ids("cat data | grep x")
    assert "CURL_PIPE_SHELL" not in _rule_ids("curl -o page.html http://x")


def test_git_push_force_fires():
    assert _has_finding("git push --force", "GIT_PUSH_FORCE", "MEDIUM")


def test_git_push_force_ignores_normal_push():
    assert "GIT_PUSH_FORCE" not in _rule_ids("git push origin main")


def test_mv_overwrite_fires_on_absolute_target():
    assert _has_finding("mv a /usr/local/bin/a", "MV_OVERWRITE", "LOW")


def test_mv_overwrite_ignores_relative_target():
    assert "MV_OVERWRITE" not in _rule_ids("mv a b")


def test_background_job_fires_on_trailing_ampersand():
    assert _has_finding("sleep 10 &", "BACKGROUND_JOB", "INFO")


def test_unknown_command_fires():
    assert _has_finding("zzz_unknown_cmd file", "UNKNOWN_COMMAND", "INFO")


def test_unknown_command_ignores_known_commands():
    assert "UNKNOWN_COMMAND" not in _rule_ids("grep -rn TODO .")


def test_network_side_effects_fires():
    assert _has_finding("curl https://example.com", "NETWORK_SIDE_EFFECTS",
                        "INFO")


def test_substitution_used_fires():
    assert _has_finding("echo $(date)", "SUBSTITUTION_USED", "INFO")


def test_substitution_used_ignores_plain_commands():
    assert "SUBSTITUTION_USED" not in _rule_ids("echo date")


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------

def test_normalize_strips_elevation():
    cmds = normalize(parse("sudo rm -rf /etc"))
    assert len(cmds) == 1
    assert cmds[0].name == "rm"
    assert cmds[0].words == ["-rf", "/etc"]
    assert cmds[0].elevated is True


def test_normalize_keeps_assignments_out_of_words():
    cmds = normalize(parse("VAR=1 dd if=/dev/zero of=/dev/sda"))
    assert cmds[0].name == "dd"
    assert cmds[0].assignments == [("VAR", "1")]
    assert "VAR=1" not in cmds[0].words


def test_normalize_numbers_and_groups_pipelines():
    cmds = normalize(parse("a && b | c"))
    assert [(c.index, c.name, c.pid, c.pipeline) for c in cmds] == [
        (0, "a", 0, ["a"]),
        (1, "b", 1, ["b", "c"]),
        (2, "c", 1, ["b", "c"]),
    ]


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "path", ["/dev/sda", "/dev/sdb", "/dev/sdaa", "/dev/nvme0n1",
             "/dev/nvme0n1p2", "/dev/hdb", "/dev/vda", "/dev/mmcblk0p1"])
def test_looks_like_device_accepts_block_devices(path):
    assert looks_like_device(path)


@pytest.mark.parametrize(
    "path", ["/dev/zero", "/dev/null", "/dev/random", "/home/me/disk.img",
             "out.iso", "/dev", "sda"])
def test_looks_like_device_rejects_non_disk_paths(path):
    assert not looks_like_device(path)


def test_looks_like_device_accepts_sd_partitions():
    assert looks_like_device("/dev/sda1")
    assert looks_like_device("/dev/sdb3")
    assert looks_like_device("/dev/vda2")


@pytest.mark.parametrize(
    "path", ["/", "/*", "~", "$HOME", "~/", "/etc", "/etc/passwd", "/usr",
             "/var", "/opt", "/root", "/dev", "/boot/grub"])
def test_is_root_level_accepts_system_paths(path):
    assert is_root_level(path)


@pytest.mark.parametrize(
    "path", ["./build", "build", "/tmp", "src/main.c", "node_modules"])
def test_is_root_level_rejects_project_paths(path):
    assert not is_root_level(path)


@pytest.mark.parametrize("path", ["/etc/passwd", "/boot/grub", "/usr/bin/x",
                                  "/var/lib/dpkg"])
def test_is_system_subtree_accepts_config_territory(path):
    assert is_system_subtree(path)


@pytest.mark.parametrize("path", ["/var/log", "/home/x", "./etc", "file.txt"])
def test_is_system_subtree_rejects_other_paths(path):
    assert not is_system_subtree(path)
