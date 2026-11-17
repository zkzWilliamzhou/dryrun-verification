"""Simulation engine protocol and selection."""
from __future__ import annotations

from typing import Optional, Protocol, runtime_checkable

from dryrun.core.types import SimulationResult

ENGINE_NAMES = ("auto", "trace", "sandbox")


class EngineError(RuntimeError):
    """A simulation engine failed to run (not the simulated command failing)."""


@runtime_checkable
class Engine(Protocol):
    """A simulation engine runs a command and reports what it would change."""

    name: str

    def run(
        self,
        command: str,
        *,
        timeout: float = 10.0,
        cwd: Optional[str] = None,
    ) -> SimulationResult:
        ...


def get_engine(name: str) -> Engine:
    """Resolve an engine name to an engine instance.

    ``auto`` prefers the trace engine (faithful, whole-filesystem) and falls
    back to the sandbox engine when the trace engine is unavailable (no gcc,
    non-Linux, or a statically linked target binary).
    """
    if name == "sandbox":
        from dryrun.simulate.sandbox import SandboxEngine

        return SandboxEngine()
    if name == "trace":
        from dryrun.simulate.trace import TraceEngine

        return TraceEngine()
    if name == "auto":
        from dryrun.simulate.trace import TraceEngine

        if TraceEngine.available():
            return TraceEngine()
        from dryrun.simulate.sandbox import SandboxEngine

        return SandboxEngine()
    raise ValueError(
        f"unknown engine {name!r}; expected one of {', '.join(ENGINE_NAMES)}"
    )
