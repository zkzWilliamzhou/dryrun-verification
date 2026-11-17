"""Tests for the preflight safety guards."""
from __future__ import annotations

import os

import pytest

from dryrun.core import safety
from dryrun.core.safety import SafetyError, preflight


def _as_non_root(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force the root check to see an unprivileged uid."""
    monkeypatch.setattr(os, "geteuid", lambda: 1000, raising=False)


def test_balanced_quotes_pass(monkeypatch):
    _as_non_root(monkeypatch)
    assert preflight("echo 'hello world' > out.txt") is None


def test_root_refused(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
    with pytest.raises(SafetyError, match="--allow-root"):
        preflight("ls")


def test_root_allowed_with_flag(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
    assert preflight("ls", allow_root=True) is None


@pytest.mark.parametrize("tool", ["sudo", "su", "doas", "pkexec", "newgrp"])
def test_elevation_tools_refused(monkeypatch, tool):
    _as_non_root(monkeypatch)
    with pytest.raises(SafetyError, match="--audit-only"):
        preflight(f"{tool} whoami")


def test_elevation_in_pipeline_refused(monkeypatch):
    _as_non_root(monkeypatch)
    with pytest.raises(SafetyError, match="--audit-only"):
        preflight("echo x | sudo tee /etc/fstab")


def test_elevation_after_list_operator_refused(monkeypatch):
    _as_non_root(monkeypatch)
    with pytest.raises(SafetyError, match="--audit-only"):
        preflight("true && su root -c ls")


def test_elevation_in_subshell_refused(monkeypatch):
    _as_non_root(monkeypatch)
    with pytest.raises(SafetyError, match="--audit-only"):
        preflight("(sudo whoami)")


def test_elevation_by_path_refused(monkeypatch):
    _as_non_root(monkeypatch)
    with pytest.raises(SafetyError, match="--audit-only"):
        preflight("/usr/bin/sudo whoami")


def test_elevation_word_as_argument_passes(monkeypatch):
    _as_non_root(monkeypatch)
    monkeypatch.setattr(safety.shutil, "which", lambda word: None)
    assert preflight("man sudo") is None


def test_setuid_binary_refused(monkeypatch):
    _as_non_root(monkeypatch)
    monkeypatch.setattr(safety, "_is_setuid", lambda path: True)
    with pytest.raises(SafetyError, match="setuid"):
        preflight("ls -la")


def test_setuid_not_flagged_for_normal_binaries(monkeypatch):
    _as_non_root(monkeypatch)
    monkeypatch.setattr(safety, "_is_setuid", lambda path: False)
    assert preflight("cp -a src dst") is None


def test_unbalanced_quotes_refused(monkeypatch):
    _as_non_root(monkeypatch)
    with pytest.raises(SafetyError, match="cannot parse command"):
        preflight('echo "unclosed')


def test_empty_command_passes(monkeypatch):
    _as_non_root(monkeypatch)
    assert preflight("") is None
