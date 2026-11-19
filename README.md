# dryrun — the universal `--dry-run` flag

`dryrun` takes any shell command and, in one pass: (1) explains it in plain
English, (2) audits it for dangerous patterns, and (3) simulates it so you see
exactly which files it would create, modify, or delete — without touching
anything. Fully offline, Python standard library only.

## Why

Developers paste shell commands every day from AI chats, Stack Overflow, and
blog posts. A single wrong path in `rm -rf` has destroyed production machines,
and generated commands arrive faster than they can be read. Some tools ship a
`--dry-run` flag; most do not. `dryrun` gives every command one: it runs on
`bash -c` like a normal invocation, diverts or isolates the writes, and reports
the diff. Exit codes are stable, so CI can branch on the result.

## 30 seconds

```bash
pip install -e .
dryrun "tar -xzf release.tar.gz"
```

Three real invocations and their output (v0.1.0, `sandbox` engine; output
sketch — paths abbreviated to the working directory, text elided only where
marked `…`):

**1. What would this archive extract?**

```console
$ dryrun "tar -xzf release.tar.gz"
Explanation
  archive and extract files
  tar: archive and extract files
  warning: extracting archives that contain absolute paths or .. can overwrite system files
  -xzf: -x extract from an archive; -z filter through gzip; -f use the given archive file
  argument: release.tar.gz
Audit: clean - no known dangerous patterns matched.
dryrun 0.1.0 - previewing with sandbox engine (nothing will be touched)
Simulation - exit 0, 0.0s
  Would create 1 file, create 1 dir:
    +  /demo/pkg
    +  /demo/pkg/config.ini (10 B)
  Notes
    - sandbox engine only observes effects inside the working directory
Nothing was touched. Run for real with: dryrun --execute "tar -xzf release.tar.gz"
```

**2. What would this edit change?**

```console
$ dryrun "sed -i s/world/dryrun/ notes.txt"
Explanation
  stream editor for filtering and transforming text. sed -i edit files in place (default writes to
  stdout)
  sed: stream editor for filtering and transforming text
  warning: with -i it rewrites the file directly; a bad pattern can mangle it
  -i: edit files in place (default writes to stdout)
  argument: s/world/dryrun/
  argument: notes.txt
Audit findings (1)
  MEDIUM    SED_INPLACE         sed edits files in place - sed -i rewrites the file itself; a wrong
                                pattern mangles content with no backup.
dryrun 0.1.0 - previewing with sandbox engine (nothing will be touched)
Simulation - exit 0, 0.0s
  Would modify 1:
    ~  /demo/notes.txt (12 -> 13 bytes)
       | --- a/notes.txt
       | +++ b/notes.txt
       | @@ -1,2 +1,2 @@
       |  hello
       | -world
       | +dryrun
  Notes
    - sandbox engine only observes effects inside the working directory
Nothing was touched. Run for real with: dryrun --execute "sed -i s/world/dryrun/ notes.txt"
```

**3. Is this install line safe?**

```console
$ dryrun "curl -s https://example.com/install.sh | bash"
Explanation
  pipes curl into bash
  …
Audit findings (2)
  HIGH      CURL_PIPE_SHELL     downloaded bytes piped into a shell - curl or wget feeds whatever
                                the server sends straight into a shell or interpreter; the bytes
                                execute without inspection.
  INFO      NETWORK_SIDE_EFFECTS  network effects cannot be previewed - this command talks to the
                                  network; requests it sends cannot be unsent, so no simulation can
                                  honestly preview them.
dryrun 0.1.0 - previewing with sandbox engine (nothing will be touched)
Simulation - exit 2, 1.4s
  Would change nothing.
  …
```

## Three layers, one pass

### Explain

A shell tokenizer and parser (pipelines, `&&`/`||` lists, redirects,
`$(...)` substitutions, quoting, globs/vars/tilde tagged but never expanded)
feed an offline knowledge base of **195 commands with 424 flag descriptions**.
Flags the base does not know are reported as `unrecognized flag` — the
explainer does not guess.

```console
$ dryrun "grep -c 404 app.log > counts.txt" --explain-only
Explanation
  search text with patterns
  grep: search text with patterns
  -c: count matches per file
  argument: 404
  argument: app.log
  writes stdout to counts.txt (overwrites the file)
```

### Audit

**57 rules: 8 CRITICAL, 14 HIGH, 20 MEDIUM, 9 LOW, 6 INFO.** Rules match
*normalized* commands — a leading `sudo`/`su` is stripped first, so the `rm`
rules also fire on `sudo rm`, the case where it matters most. If the parser
cannot read a line, the audit says so (`UNPARSEABLE`, INFO: "structural rules
did not run") instead of silently under-reporting.

```console
$ dryrun "sudo rm -rf /etc/app" --audit-only
Audit findings (4)
  CRITICAL  RM_ROOT_RECURSIVE   recursive delete of a system path - rm with recursive flags targets
                                a system-level path such as /, /etc, or /usr; running it can erase
                                the operating system or every user's data.
  HIGH      SUDO_RM             elevated delete - rm runs under sudo with root privileges; a wrong
                                path deletes system files that no backup covers.
  MEDIUM    SUDO_ANY            command runs with elevated privileges - sudo runs the rest of the
                                line as root; every effect applies system-wide and cannot be
                                simulated safely.
  LOW       RM_SINGLE           file deletion - rm removes files permanently; there is no trash can.
```

### Simulate

The command runs for real under `bash -c` — with every write diverted or
isolated — and you get the list of changes: `create`, `mkdir`, `modify`,
`chmod`, `rename`, `delete`, `rmdir`, with unified diffs for modified text
files (capped at 4096 characters). Effects the engine cannot observe are
listed under `Notes`, never hidden. `--json` emits the same data as one
machine-readable document for CI.

## Two simulation engines

|                        | `trace` (preferred on Linux)                 | `sandbox` (portable fallback)            |
| ---------------------- | -------------------------------------------- | ---------------------------------------- |
| How it works          | A C shim is compiled on demand (`gcc -O2 -fPIC -shared`) and injected via `LD_PRELOAD`; write-intent `open`/`creat`/`fopen` go to a **shadow tree** (existing files copied in first, so appends and in-place edits preview correctly); `unlink`, `rmdir`, `rename`, `chmod`, `truncate`, `symlink`, `link` are virtualized — logged and reported success without touching the real filesystem | The working directory is copied into a `0700` temp directory (`cp -a --reflink=auto` when the filesystem supports it), the command runs there, the trees are diffed |
| Filesystem coverage   | Whole filesystem — effects on any absolute path | Working directory only (stated in the result notes) |
| Requirements          | Linux + `gcc`                                 | Any system with `cp`/`shutil`; no compiler |
| Failure behavior      | Fails closed: if shadow setup fails, the command sees an error instead of silently writing for real | Refuses working directories over 512 MiB and suggests `--engine trace` |

`--engine auto` (the default) prefers `trace` and falls back to `sandbox`
when the trace engine is unavailable (no `gcc`, non-Linux, or a statically
linked target binary that bypasses `libc`).

## Exit codes

| Code | Meaning                                                              |
| ---- | -------------------------------------------------------------------- |
| 0    | Preview completed (or the user declined the `--execute` prompt)      |
| 1    | Simulation refused or failed: safety refusal (running as root, `sudo`/`su`/`doas`/`pkexec`/`newgrp`, setuid binary), engine error (e.g. working directory over the 512 MiB sandbox limit), or internal error |
| 2    | `--execute` blocked because a CRITICAL audit finding is present (override with `--force`) |
| 3    | Usage error (unknown flag, `--timeout` not positive)                 |
| 4    | A finding met the `--fail-on {critical,high,medium,low,info}` bar    |

CI example — fail the job when anything at HIGH or worse shows up:

```bash
dryrun "make install" --fail-on high   # exits 4 on HIGH/CRITICAL findings
```

## Running for real: `--execute`

By default `dryrun` never executes anything. With `--execute` it previews
first, then runs the command for real:

- A **CRITICAL** audit finding blocks execution and exits `2`. You must add
  `--force` to override — there is no prompt that accepts it implicitly.
- Without `--yes`, dryrun asks `Run for real? [y/N]` and only `y`/`yes`
  proceeds. If stdin is not a terminal and `--yes` is absent, it aborts with
  `aborted - nothing was executed` and exits `0`.
- The real run uses the same wall-clock `--timeout` (default 10 s) and exits
  with the command's own exit status.

## Limitations

Honest list, kept current with `docs/DESIGN.md`:

- **Network effects are not simulated.** A request that was sent cannot be
  unsent, so the auditor flags network-touching constructs
  (`NETWORK_SIDE_EFFECTS`, `CURL_PIPE_SHELL`, …) instead of pretending to
  preview them. During a preview, the simulated command still makes real
  network connections.
- **Statically linked binaries bypass `LD_PRELOAD`.** A Go binary makes
  syscalls directly, so the trace engine cannot see its writes; `auto`
  engine selection falls back to the sandbox engine for them.
- **The parser is a POSIX subset.** It handles pipelines, lists, redirects,
  and substitutions, but not shell function definitions or complex
  arithmetic. Unparseable lines get an explicit `UNPARSEABLE` finding stating
  that structural rules did not run.
- **The shadow tree is a copy, not a filesystem implementation.** fsync
  ordering, mount boundaries, and device-level semantics are not reproduced.
- **Elevation is refused, not simulated.** `sudo`, `su`, `doas`, `pkexec`,
  `newgrp`, and setuid binaries cannot be previewed honestly; dryrun refuses
  them with exit `1` and offers `--audit-only` for static analysis.
- **No Windows support.** The trace engine is Linux-only; the sandbox engine
  is the portable fallback.

## Related tools

| Tool           | Explains        | Audits          | Simulates               | Diff preview       | Status                    |
| -------------- | --------------- | --------------- | ----------------------- | ------------------ | ------------------------- |
| `maybe`        | no              | no              | LD_PRELOAD report       | no                 | abandoned 2016            |
| explainshell.com | yes (web only) | no              | no                      | no                 | web only                  |
| shellcheck     | no              | lint only (scripts) | no                   | no                 | active, different scope   |
| dryrun         | yes, offline    | yes, 57 rules   | two engines             | yes, unified diffs | this project              |

`maybe` reported write calls but produced no diffs, explanations, or audits.
explainshell explains commands but only on the web and without simulation.
shellcheck lints shell scripts — a complementary, pre-existing practice that
dryrun does not replace. dryrun combines the three layers offline.

## Requirements and license

- Python ≥ 3.9 on Linux. Install from a checkout: `pip install -e .`
  (provides the `dryrun` script; `python3 -m dryrun` also works).
- The `trace` engine additionally needs `gcc`; without it, `auto` uses the
  `sandbox` engine.
- Development: `pip install -e ".[dev]"` (pulls `pytest>=8`).
- License: MIT (see `LICENSE`).
