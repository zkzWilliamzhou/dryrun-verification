# Security policy

## Threat model

The user has a shell command they do not fully trust — pasted from an AI chat,
a blog post, or a pull request — and wants to know what it does before running
it. The protected asset is the user's filesystem, account, and machine. The
adversary is the author of that command (or anyone who controls the source the
command was copied from).

The attack surface is therefore **the simulated command's ability to cause
real effects while the user believes nothing is happening**. Both engines run
the command for real under `bash -c`; safety comes from diverting or isolating
its writes, and from refusing the cases where that diversion cannot be honest.

Out of scope: commands the user runs outside dryrun, a compromised dryrun
installation (protect your `pip` and your `PATH` yourself), and hardware-level
effects (e.g. `hdparm` firmware commands).

## Defense layers

### Layer 0 — preflight refusals (`src/dryrun/core/safety.py`)

Before any engine runs, dryrun refuses to simulate when:

- it is running as root (override: `--allow-root`),
- any command segment starts with an elevation tool: `sudo`, `su`, `doas`,
  `pkexec`, `newgrp`,
- any word on the line resolves (via `PATH`) to a **setuid binary**,
- the command cannot be tokenized at all.

The guard fails closed: an unexpected internal error in preflight also results
in a refusal, never in a silent pass. Refusals exit `1` with `refused:` on
stderr; `--audit-only` still works because it never runs the command.

### Layer 1 — engine isolation

- **trace engine:** a C shim injected with `LD_PRELOAD` intercepts
  `open`/`openat`/`creat`/`fopen`, `unlink`, `rmdir`, `mkdir`, `rename`,
  `chmod`, `truncate`, `symlink`, `link`. Write-intent opens are diverted into
  a private shadow tree; destructive operations are virtualized (logged and
  reported as success without touching the real filesystem). The shim **fails
  closed**: if the shadow setup fails, the command sees an error rather than
  silently writing for real.
- **`/dev`, `/proc`, `/sys` are never passed through.** Writes to these
  paths are diverted to the shadow tree like any other write (trace engine);
  nothing reaches the real device nodes or kernel interfaces.
- **sandbox engine:** the working directory is copied to a `0700` temp
  directory, the command runs there, and the temp directory is removed
  afterwards. The command never sees the original tree.

### Layer 2 — runtime containment (`src/dryrun/core/proc.py`)

Every child process:

- runs under `bash -c` in a new session, so the **whole process group** is
  killed with `SIGKILL` when the wall-clock timeout expires (default 10 s),
- gets rlimits: CPU time (timeout + 2 s, minimum 5 s), file size 2 GiB,
  process count 1024,
- writes stdout/stderr to temp files, **not pipes**, so a runaway writer like
  `yes` cannot exhaust memory; only the last 4 KiB of each stream is kept.

### Layer 3 — the `--execute` gate

dryrun never executes a command for real unless `--execute` is passed. Then:

- a CRITICAL audit finding blocks execution (exit `2`) until `--force` is
  given explicitly,
- without `--yes`, an interactive `Run for real? [y/N]` prompt must be
  answered; non-terminal stdin without `--yes` aborts the run.

## Known limitations

Read this section before trusting a preview:

- **`LD_PRELOAD` does not intercept statically linked binaries.** A Go binary
  calls the kernel directly, so the trace engine cannot see or divert its
  writes. `--engine auto` falls back to the sandbox engine for them; if you
  force `--engine trace` onto such a binary, its writes happen for real
  inside the shadow session's view. Prefer `auto`.
- **Simulation is not network sandboxing.** A simulated command still makes
  real network connections. dryrun flags network-touching commands
  (`NETWORK_SIDE_EFFECTS`) but does not block them — do not preview commands
  whose network side effects are themselves the attack.
- **The parser is a POSIX subset.** Function definitions and complex
  arithmetic are not modeled. When a line cannot be parsed, the audit reports
  `UNPARSEABLE` (INFO) and states that structural rules did not run — the
  audit is incomplete, and it says so. The raw-text fork-bomb scan
  (`raw_fork_bomb`) runs before parsing as a backstop for the classic
  `:(){ :|:& };:` construct that the parser cannot represent.
- **A diff is a diff, not a proof.** The shadow tree is a copy: fsync
  ordering, mount boundaries, and device-level semantics are not reproduced.

## Reporting a vulnerability

Please report privately and allow time for a fix before public disclosure.

- Open a GitHub issue at
  `https://github.com/dryrun-cli/dryrun/issues` (mark it as a security report
  in the title), or
- email **security@dryrun.dev** *(placeholder address — replace with the
  maintainer's real security contact before publishing this file)*.

Include the command you previewed, the dryrun version (`dryrun --version`),
your platform, and what you expected vs. what happened. Reports about the
limitations listed above are known issues, not new vulnerabilities — but
concrete reproductions are still welcome.
