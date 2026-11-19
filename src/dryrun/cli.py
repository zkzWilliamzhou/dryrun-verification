"""Command-line interface: argument parsing, orchestration, exit codes."""
from __future__ import annotations

import argparse
import os
import sys
from typing import Optional, Sequence

from dryrun import __version__
from dryrun.core.safety import SafetyError
from dryrun.core.types import Explanation, Finding, severity_rank
from dryrun.report.json_out import build_payload, emit
from dryrun.report.text import (
    confirm_execute,
    print_execute_banner,
    print_explanation,
    print_findings,
    print_simulation,
    supports_color,
)
from dryrun.simulate.base import EngineError

EXIT_OK = 0
EXIT_SIM_FAILED = 1
EXIT_EXECUTE_BLOCKED = 2
EXIT_USAGE = 3
EXIT_AUDIT_THRESHOLD = 4

_FAIL_ON_CHOICES = ("critical", "high", "medium", "low", "info")
_ENGINE_CHOICES = ("auto", "trace", "sandbox")


class _UsageError(Exception):
    """Internal signal: argparse reported a usage problem."""


class _DryrunParser(argparse.ArgumentParser):
    """ArgumentParser that raises instead of exiting on usage errors."""

    def error(self, message: str) -> None:
        """Print usage plus the error to stderr and raise _UsageError."""
        self.print_usage(sys.stderr)
        sys.stderr.write(f"{self.prog}: error: {message}\n")
        raise _UsageError(message)


def _build_parser() -> _DryrunParser:
    """Build the dryrun argument parser."""
    parser = _DryrunParser(
        prog="dryrun",
        description=(
            "Explain, audit, and simulate a shell command before running it."
        ),
    )
    parser.add_argument(
        "command",
        help="shell command to preview (quote the whole command)",
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"dryrun {__version__}",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--explain-only",
        action="store_true",
        help="only explain the command; skip audit and simulation",
    )
    mode.add_argument(
        "--audit-only",
        action="store_true",
        help="only audit the command; skip explanation and simulation",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="run the command for real after previewing it",
    )
    parser.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="skip the confirmation prompt for --execute",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="allow --execute even when CRITICAL findings are present",
    )
    parser.add_argument(
        "--engine",
        choices=_ENGINE_CHOICES,
        default="auto",
        help="simulation engine (default: auto)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="wall-clock timeout for the simulation in seconds (default: 10)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print a single JSON document instead of text",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="disable ANSI colors in text output",
    )
    parser.add_argument(
        "--fail-on",
        choices=_FAIL_ON_CHOICES,
        default=None,
        help="exit with code 4 when a finding is at least this severe",
    )
    parser.add_argument(
        "--allow-root",
        action="store_true",
        help="allow simulation while running as root",
    )
    return parser


def _threshold_code(findings: Sequence[Finding], fail_on: Optional[str]) -> int:
    """Return EXIT_AUDIT_THRESHOLD when a finding meets the fail-on bar."""
    if not fail_on:
        return EXIT_OK
    bar = severity_rank(fail_on.upper())
    for finding in findings:
        if severity_rank(finding.severity) <= bar:
            return EXIT_AUDIT_THRESHOLD
    return EXIT_OK


def _refuse(
    args: argparse.Namespace,
    explanation: Optional[Explanation],
    findings: Sequence[Finding],
    error_type: str,
    message: str,
) -> int:
    """Report a refused or failed simulation, in text or JSON form."""
    if args.json:
        payload = build_payload(
            args.command,
            explanation,
            findings,
            None,
            error={"type": error_type, "message": message},
        )
        emit(payload, sys.stdout)
    else:
        prefix = "refused" if error_type == "SafetyError" else "simulation failed"
        sys.stderr.write(f"{prefix}: {message}\n")
    return EXIT_SIM_FAILED


def _execute(
    args: argparse.Namespace, findings: Sequence[Finding], *, color: bool
) -> int:
    """Run the command for real after CRITICAL checks and confirmation."""
    critical = any(
        finding.severity.upper() == "CRITICAL" for finding in findings
    )
    out = sys.stderr if args.json else sys.stdout
    if critical and not args.force:
        sys.stderr.write(
            "refusing --execute: CRITICAL audit finding present; "
            "rerun with --force to override\n"
        )
        return EXIT_EXECUTE_BLOCKED

    if not args.yes:
        confirmed = sys.stdin.isatty() and confirm_execute(
            args.command, stream=out
        )
        if not confirmed:
            out.write("aborted - nothing was executed\n")
            return EXIT_OK

    from dryrun.core.proc import run_command

    print_execute_banner(args.command, color=color, stream=out)
    proc = run_command(args.command, timeout=args.timeout, env=None)
    if proc.returncode not in (0, None) and proc.stderr.strip():
        out.write("  stderr (tail):\n")
        for line in proc.stderr.strip().splitlines()[-5:]:
            out.write(f"    {line}\n")
    out.write(f"exit {proc.returncode} in {proc.duration:.1f}s\n")
    if isinstance(proc.returncode, int):
        return proc.returncode
    return EXIT_SIM_FAILED


def _run(args: argparse.Namespace, *, color: bool) -> int:
    """Orchestrate explain, audit, simulate, and optional real execution."""
    from dryrun.audit import audit as run_audit
    from dryrun.explain import explain as run_explain

    explanation = None
    if not args.audit_only:
        explanation = run_explain(args.command)
        if not args.json:
            print_explanation(explanation, color=color, stream=sys.stdout)

    findings = run_audit(args.command)
    if not args.json:
        if findings:
            print_findings(findings, color=color, stream=sys.stdout)
        else:
            print(
                "Audit: clean - no known dangerous patterns matched.",
                file=sys.stdout,
            )

    if args.explain_only:
        return EXIT_OK
    if args.audit_only:
        return _threshold_code(findings, args.fail_on)

    critical = any(
        finding.severity.upper() == "CRITICAL" for finding in findings
    )
    if critical:
        # The simulator virtualizes the file system only. Commands the
        # audit rates CRITICAL (kill -9 -1, fork bombs, dd to a disk)
        # destroy things the simulator cannot virtualize: signals, the
        # process table, real devices. Running them "for preview" would
        # do real damage, so simulation is skipped outright.
        if args.json:
            emit(
                build_payload(
                    args.command,
                    explanation,
                    findings,
                    None,
                    error={
                        "type": "SimulationSkipped",
                        "message": (
                            "simulation skipped: CRITICAL audit finding - "
                            "the command's damage is not limited to files "
                            "the simulator can virtualize"
                        ),
                    },
                ),
                sys.stdout,
            )
        else:
            sys.stdout.write(
                "Simulation skipped: a CRITICAL audit finding means this "
                "command destroys things the simulator cannot virtualize "
                "(signals, processes, raw devices - only file writes are "
                "shadowed). Nothing was touched.\n"
            )
        if args.execute:
            return _execute(args, findings, color=color)
        return _threshold_code(findings, args.fail_on)

    from dryrun.simulate import simulate

    try:
        result = simulate(
            args.command,
            engine=args.engine,
            timeout=args.timeout,
            allow_root=args.allow_root,
        )
    except SafetyError as exc:
        return _refuse(args, explanation, findings, "SafetyError", str(exc))
    except EngineError as exc:
        return _refuse(args, explanation, findings, "EngineError", str(exc))

    if args.json:
        emit(build_payload(args.command, explanation, findings, result), sys.stdout)
    else:
        print_simulation(result, color=color, stream=sys.stdout)

    code = _threshold_code(findings, args.fail_on)
    if code != EXIT_OK:
        return code
    if not args.execute:
        return EXIT_OK
    return _execute(args, findings, color=color)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Parse arguments, run the dryrun pipeline, and return the exit code."""
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
        if args.timeout <= 0:
            parser.error("--timeout must be positive")
    except _UsageError:
        return EXIT_USAGE
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else EXIT_OK

    color = supports_color(sys.stdout) and not args.no_color and not args.json
    try:
        return _run(args, color=color)
    except BrokenPipeError:
        # The reader closed the pipe early (e.g. `dryrun ... | head`).
        # Exit quietly like any standard CLI tool: point stdout/stderr at
        # devnull so the interpreter's shutdown flush cannot raise again,
        # and report success - the preview ran, only the viewer walked away.
        devnull = os.open(os.devnull, os.O_WRONLY)
        try:
            os.dup2(devnull, sys.stdout.fileno())
            os.dup2(devnull, sys.stderr.fileno())
        finally:
            os.close(devnull)
        return EXIT_OK
    except Exception as exc:
        sys.stderr.write(f"internal error: {type(exc).__name__}: {exc}\n")
        return EXIT_SIM_FAILED
