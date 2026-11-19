"""Allow ``python -m dryrun``."""
from __future__ import annotations

from dryrun.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
