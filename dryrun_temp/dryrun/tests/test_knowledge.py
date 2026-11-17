"""Tests for the offline command knowledge base (dryrun/explain/knowledge.py)."""
from __future__ import annotations

import re

import pytest

from dryrun.explain.knowledge import COMMANDS, CommandInfo, lookup

#: The commands the knowledge base is required to describe.
REQUIRED_COMMANDS = [
    "ls", "cat", "echo", "rm", "mv", "cp", "mkdir", "rmdir", "touch",
    "chmod", "chown", "dd", "curl", "wget", "git", "tar", "gzip", "grep",
    "sed", "find", "ssh", "ps", "kill", "bash", "python3", "make",
]


def test_required_commands_are_known():
    for name in REQUIRED_COMMANDS:
        info = lookup(name)
        assert info is not None, f"{name} missing from the knowledge base"
        assert info.summary.strip(), f"{name} has an empty summary"


@pytest.mark.parametrize("name", REQUIRED_COMMANDS)
def test_lookup_returns_well_formed_entry(name):
    info = lookup(name)
    assert isinstance(info, CommandInfo)
    assert info.name == name
    assert info.summary.strip()
    assert info.category.strip()


@pytest.mark.parametrize(
    "name", ["zzz_not_a_cmd", "definitely-not-a-command-42", "", "RM"]
)
def test_unknown_command_returns_none(name):
    # Lookup is by exact lowercase name; anything else is unknown.
    assert lookup(name) is None


def test_lookup_returns_the_table_entry():
    assert lookup("rm") is COMMANDS["rm"]


def test_knowledge_base_size():
    # The shipped table holds 195 commands; the brief's floor was >= 110.
    # Pin the current inventory so entries are only removed deliberately.
    assert len(COMMANDS) >= 195
    assert len(COMMANDS) >= 110


@pytest.mark.parametrize(
    ("name", "flag", "keyword"),
    [
        ("rm", "-r", "recurse"),
        ("rm", "-f", "force"),
        ("dd", "if=", "input"),
        ("dd", "of=", "output"),
        ("dd", "bs=", "block"),
        ("chmod", "-R", "recurse"),
        ("curl", "-o", "output"),
        ("curl", "-L", "redirect"),
        ("curl", "-s", "silent"),
        ("tar", "-x", "extract"),
        ("tar", "-c", "create"),
        ("tar", "-f", "archive"),
        ("git", "clone", "repositor"),
        ("git", "push", "publish"),
        ("git", "--force", "force"),
        ("ls", "-l", "long"),
        ("grep", "-i", "case"),
        ("mv", "-f", "force"),
        ("cp", "-r", "recurse"),
        ("mkdir", "-p", "parent"),
        ("wget", "-O", "file"),
        ("find", "-delete", "delete"),
        ("sed", "-i", "in place"),
        ("ssh", "-p", "port"),
        ("python3", "-c", "string"),
    ],
)
def test_flag_descriptions_are_present_and_specific(name, flag, keyword):
    info = lookup(name)
    assert info is not None
    description = info.flags.get(flag)
    assert description, f"{name} has no entry for flag {flag}"
    assert keyword in description, (
        f"{name} {flag} description {description!r} lacks keyword {keyword!r}")


def test_every_entry_has_complete_fields():
    # Whole-base consistency check: no half-filled entries may ship.
    for name, info in COMMANDS.items():
        assert isinstance(info.summary, str) and info.summary.strip(), name
        assert isinstance(info.category, str) and info.category.strip(), name
        assert info.name == name, f"{name} entry carries name {info.name!r}"
        for flag, description in info.flags.items():
            assert isinstance(flag, str) and flag, f"{name}:{flag}"
            assert isinstance(description, str) and description.strip(), (
                f"{name}:{flag} has an empty description")


#: A flag key is a dash-prefixed option, an option-assignment ("if="), or a
#: bare subcommand word (letters/digits/dots/plus with optional inner
#: hyphens, e.g. "clone", "dist-upgrade", "777", "+x", "..").
_BARE_KEY = re.compile(r"[A-Za-z0-9_.+]+(?:-[A-Za-z0-9_.+]+)*")


def test_flag_keys_use_recognized_shapes():
    for name, info in COMMANDS.items():
        for flag in info.flags:
            assert (flag.startswith("-") or flag.endswith("=")
                    or _BARE_KEY.fullmatch(flag)), (
                f"{name} has a flag key of unknown shape: {flag!r}")


def test_command_names_are_lowercase_words():
    for name in COMMANDS:
        assert name == name.lower(), name
        assert not re.search(r"\s", name), name
        assert "/" not in name, name


def test_shell_entries_carry_pipe_danger():
    # Piping downloaded bytes into a shell is the classic footgun; the
    # shell entries must call it out in their danger field.
    for name in ("bash", "sh", "dash", "zsh", "ksh"):
        info = lookup(name)
        assert info is not None, name
        assert info.danger.strip(), f"{name} lacks a danger note"


def test_danger_field_is_always_a_string():
    for info in COMMANDS.values():
        assert isinstance(info.danger, str)


def test_categories_cover_the_core_groups():
    categories = {info.category for info in COMMANDS.values()}
    assert {"files", "network", "system", "shell"} <= categories
    assert len(categories) >= 8
