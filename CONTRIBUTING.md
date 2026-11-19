# Contributing to dryrun

Read `docs/DESIGN.md` first — it is the source of truth for architecture,
engine behavior, and the honesty rules ("never claim safety you cannot
prove"). This file covers day-to-day mechanics.

## Development environment

```bash
git clone https://github.com/dryrun-cli/dryrun.git
cd dryrun
pip install -e ".[dev]"    # installs the dryrun script plus pytest>=8
pytest                     # 58 tests, ~2 s
```

The `conftest.py` at the repository root puts `src/` on `sys.path`, so
`pytest` works even without installing the package. Python ≥ 3.9 is the
minimum supported version — do not use syntax beyond it in `src/`.

## Workflow

- **Test-first.** Write the failing test that pins the behavior, then write
  the code. A bug fix arrives with the test that would have caught it.
- **Pure standard library.** Runtime code imports only the Python standard
  library; the single dev dependency is pytest. Adding any runtime dependency
  requires a written justification in the pull request: what it does, why the
  standard library cannot, and its size and license. Unjustified dependencies
  are rejected.
- **Honesty over coverage.** When a change cannot preview something
  faithfully, say so in the output (`Notes`, `UNPARSEABLE`, …) rather than
  pretending. A note is a feature.

## Code style

- 4-space indentation, 88-column lines.
- Type annotations on every function signature; docstrings on every module,
  class, and function (the existing code follows this — keep it that way).
- Text output stays ASCII when color is off (see `src/dryrun/report/text.py`).
- C code (`src/dryrun/native/`) must compile with `gcc -O2 -fPIC -shared
  -Wall -Wextra` with **zero warnings**.

## Adding an audit rule

Rules live in the `RULES` list in `src/dryrun/audit/rules.py`. Each entry is
a `Rule(rule_id, severity, title, detail, match)`:

1. Pick a stable `rule_id` in `UPPER_SNAKE_CASE` and a severity from
   `SEVERITY_ORDER` in `src/dryrun/core/types.py` — CRITICAL means
   system-scale destruction (e.g. `RM_ROOT_RECURSIVE`, `DD_TO_DISK`), HIGH
   means likely data loss or remote code execution (e.g. `CURL_PIPE_SHELL`),
   and lower levels mark risky-but-recoverable behavior.
2. Write the `match` function over **normalized** commands: the normalizer
   strips a leading `sudo`/`su`/`doas`/`pkexec`, so write the rule for the
   bare command and it also fires on the elevated form.
3. Keep `detail` plain English and specific about what is at risk.
4. Two tests are mandatory in the pull request: a **trigger test** (a command
   that must fire the rule) and a **counterexample test** (a near-miss
   command that must not — e.g. the rule for recursive `rm` must not fire on
   `rm single-file`). A rule without both is rejected.

## Adding a knowledge-base entry

Entries are `CommandInfo` records in `COMMANDS` in
`src/dryrun/explain/knowledge.py` (built with the `_c(...)` helper):

1. **Only verified flags.** A flag goes in only if you confirmed it against
   the tool's man page or official documentation. State the source (man page
   section or documentation URL) in the pull request description. If you are
   unsure, omit the flag — the explainer then prints `unrecognized flag`,
   which is the honest answer. Fabricated flag descriptions are the one edit
   category that gets reverted on sight.
2. One-line `summary`, a `category` matching the existing twelve, and a
   `danger` note when the command can destroy data.
3. Add a test asserting the entry explains (or correctly declines to
   explain) a representative invocation.

## Commits

- Subject line in the imperative: `Add rule for mkfs on mounted disks`, not
  `Added rule…` or `Adds rule…`.
- One line per commit subject, roughly 50–72 characters; use a body only when
  the *why* is not obvious from the diff.
- Do not commit generated files or editor state. Do not bump the version in
  a feature commit — version bumps are release commits, matched by a
  `CHANGELOG.md` entry.
