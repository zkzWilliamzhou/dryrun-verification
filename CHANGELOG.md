# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog 1.1](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-09

### Added

- **Explain layer**: POSIX-subset shell parser (pipelines, `&&`/`||` lists,
  redirects, `$(...)` substitutions, quoting, glob/var/tilde tagging without
  expansion) plus an offline knowledge base covering 195 commands with 424
  flag descriptions; unknown flags are reported as unrecognized instead of
  guessed.
- **Audit layer**: 57 danger rules — 8 CRITICAL, 14 HIGH, 20 MEDIUM, 9 LOW,
  6 INFO — matched against elevation-normalized commands (a leading
  `sudo`/`su` is stripped, so `rm` rules also fire on `sudo rm`), with an
  explicit `UNPARSEABLE` finding when the parser cannot read a line and a
  raw-text fork-bomb scan as backstop.
- **Simulate layer with two engines**: `trace` (LD_PRELOAD C shim compiled on
  demand with `gcc`, diverts writes to a copy-on-write shadow tree and
  virtualizes destructive operations, fails closed) and `sandbox` (copies the
  working directory into a `0700` temp directory with reflink when possible,
  runs the command there, diffs the trees; refuses trees over 512 MiB).
  `--engine auto` prefers trace and falls back to sandbox when trace is
  unavailable.
- **CLI** (`dryrun "<command>"`, also `python3 -m dryrun`): `--explain-only`,
  `--audit-only`, `--execute` with `--force` and `--yes`, `--engine
  {auto,trace,sandbox}`, `--timeout` (default 10 s), `--json`,
  `--no-color`, `--fail-on {critical,high,medium,low,info}`, `--allow-root`,
  `-V/--version`.
- **Stable exit codes for CI**: 0 preview completed, 1 simulation refused or
  failed, 2 `--execute` blocked by a CRITICAL finding, 3 usage error,
  4 `--fail-on` threshold tripped.
- **Preflight safety guards**: refuse simulation when running as root, when a
  segment starts with `sudo`/`su`/`doas`/`pkexec`/`newgrp`, or when a word
  resolves to a setuid binary; the guard fails closed.
- **Runtime containment for every child process**: process-group kill on
  timeout, rlimits (CPU, file size 2 GiB, process count 1024), output
  captured to temp files so runaway writers cannot exhaust memory.
- **Unified diffs** for modified text files in both text and `--json` output,
  capped at 4096 characters.
- **Test suite**: 58 tests (16 CLI, 13 reporting, 17 safety, 12 sandbox
  engine).
