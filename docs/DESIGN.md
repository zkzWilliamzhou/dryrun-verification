# dryrun — Design

`dryrun` is the universal `--dry-run` flag. Point it at any shell command and it
will (1) explain the command in plain English, (2) audit it for dangerous
patterns, and (3) simulate it so you see exactly which files it would create,
modify, or delete — without touching anything.

```
$ dryrun "rm -rf build"
⚠  HIGH  RM_RECURSIVE_FORCE — rm -rf deletes directories recursively, ignoring errors
▶  Simulation (trace engine): would delete 12 files, 3 dirs (3.2 MB)
    D  build/dist/app.js
    D  build/tmp/cache/…
✔  Nothing was touched.
```

## Why

Developers paste shell commands every day from AI chats, Stack Overflow, and
blog posts. A single typo in `rm -rf` has destroyed production machines. Some
tools ship a `--dry-run` flag; most do not. No existing tool previews the
filesystem effect of *any* command. `maybe` (2016, abandoned) reported write
calls but produced no diffs, no explanations, and no audits. `explainshell`
explains commands but only on the web and without simulation.

## Goals

- `dryrun "<command>"` → explanation + audit findings + faithful preview of
  filesystem changes, in one pass, fully offline.
- Zero configuration, zero runtime dependencies (Python 3.9+, standard library
  only; a tiny C shim compiled on demand for the trace engine).
- Machine-readable output (`--json`) and stable exit codes for CI.
- Honest reporting: filesystem effects are previewed faithfully; effects we
  cannot preview (network calls, process signals, side effects inside
  containers/VMs) are flagged, never faked.

## Non-goals (v0.1)

- Emulating a shell. For simulation the command runs under `bash -c`; the
  built-in parser is used only for static analysis (explain + audit).
- Simulating network side effects. A POST that was sent cannot be unsent, so
  the auditor flags network-touching constructs instead of pretending.
- Windows support. The sandbox engine is portable in principle; the trace
  engine is Linux-only (LD_PRELOAD).

## Anti-goals

- dryrun must never execute a command for real unless the user explicitly asks
  (`--execute`).
- dryrun must never claim safety it cannot prove. When the trace engine cannot
  intercept an effect (static binaries, `sudo`), it says so.

## Architecture

```
src/dryrun/
├── cli.py            # argparse CLI, exit codes, orchestration
├── core/
│   ├── types.py      # Finding, Explanation, ChangeRecord, SimulationResult
│   ├── safety.py     # preflight guards: root, sudo/su, setuid binaries
│   └── proc.py       # subprocess wrapper: bash -c, timeout, process-group kill, rlimits
├── explain/
│   ├── parser.py     # shell tokenizer + parser → AST (pipelines, lists, redirects)
│   ├── knowledge.py  # offline knowledge base: 100+ commands, common flags
│   └── explainer.py  # AST + knowledge → plain-English segments
├── audit/
│   ├── rules.py      # 60+ danger rules with severities
│   └── auditor.py    # AST walk → findings
├── simulate/
│   ├── base.py       # Engine protocol + engine selection
│   ├── sandbox.py    # copy-tree engine: run the command in a sandbox copy, diff trees
│   └── trace.py      # LD_PRELOAD engine: shadow filesystem, runs real code, diverts writes
├── native/
│   └── shadowlib.c   # LD_PRELOAD shim: diverts writes to a shadow tree, virtualizes
│                    #   destructive ops, logs every intercepted call
└── report/
    ├── text.py       # human output (ANSI colors, ASCII fallback)
    └── json_out.py   # --json output
```

### Trace engine (Linux, preferred)

A small C shim is compiled on demand (`gcc -O2 -fPIC -shared`) and injected via
`LD_PRELOAD`. It intercepts `open/openat/creat/fopen`, `unlink`, `rmdir`,
`mkdir`, `rename`, `chmod`, `truncate`, `symlink`, `link`:

- Any open with write intent is redirected to a **shadow tree** that mirrors
  absolute paths under a private directory. If the real file exists, it is
  copied into the shadow tree first (copy-on-write), so appends and in-place
  edits preview correctly.
- Destructive operations (`unlink`, `rmdir`, `rename`, `chmod`) are
  **virtualized**: they are logged and reported success without touching the
  real filesystem.
- Every intercepted operation is written to a log pipe for the Python side.
- If the shadow setup fails, the shim fails closed (the command sees an error)
  rather than silently writing for real.

After the command exits, the Python side diffs shadow-vs-real and parses the
log to produce `ChangeRecord`s (create / modify / delete / chmod / rename),
including unified diffs for modified text files. Static binaries (Go) bypass
`libc` and therefore bypass the shim; `auto` engine selection falls back to
the sandbox engine for them.

### Sandbox engine (portable fallback)

Copies the working directory into a private temp sandbox (reflink when the
filesystem supports it), runs the command there, and diffs the trees. Effects
outside the working directory are invisible to this engine; it says so in the
result notes.

### Safety model

- Preflight refuses: running as root (unless `--allow-root`), elevation tools
  (`sudo`, `su`, `doas`, `pkexec`), and setuid binaries. These cannot be
  simulated honestly; the CLI offers `--audit-only` instead.
- Every simulation runs with a wall-clock timeout (default 10 s), is killed by
  process group, and gets generous rlimits (CPU, file size, process count).
- Temp/shadow directories are created `0700` under the system temp dir and
  removed afterwards.
- Writes to `/dev`, `/proc`, `/sys` are diverted to the shadow tree like any
  other write (the trace engine) — they are never allowed through.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | simulation completed |
| 1 | simulation itself failed (engine error, command crashed the harness) |
| 2 | `--execute` blocked (CRITICAL audit finding) |
| 3 | usage error |
| 4 | `--fail-on` severity threshold tripped |

## Prior art & honesty

| Tool | Explains | Audits | Simulates | Diff preview | Status |
|------|----------|--------|-----------|--------------|--------|
| `maybe` | no | no | LD_PRELOAD report | no | abandoned 2016 |
| explainshell.com | yes (web) | no | no | no | web only |
| shellcheck | no | lint only (scripts) | no | no | active, different scope |
| dryrun | yes, offline | yes, 60+ rules | two engines | yes, unified diffs | this project |
