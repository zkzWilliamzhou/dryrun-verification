"""Public simulation API: preflight safety checks + engine dispatch."""
from __future__ import annotations

from typing import Optional

from dryrun.core.safety import preflight
from dryrun.core.types import SimulationResult
from dryrun.simulate.base import ENGINE_NAMES, get_engine


def simulate(
    command: str,
    *,
    engine: str = "auto",
    timeout: float = 10.0,
    cwd: Optional[str] = None,
    allow_root: bool = False,
) -> SimulationResult:
    """Simulate ``command`` and return what it would change.

    Raises :class:`dryrun.core.safety.SafetyError` when the command cannot be
    simulated safely (elevation tools, setuid binaries, running as root).
    """
    preflight(command, allow_root=allow_root)
    return get_engine(engine).run(command, timeout=timeout, cwd=cwd)
