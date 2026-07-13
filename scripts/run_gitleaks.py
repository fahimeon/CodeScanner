#!/usr/bin/env python3
"""run_gitleaks.py — Phase 20-28 thin wrapper: run gitleaks over the cloned sample.

Working-tree scan (headline "currently exposed secret") by default; `--history`
runs the SEPARATE git-history scan over the bare mirror clones (results stored
under results/raw/gitleaks-history/). All logic lives in _scanner_runner.py.
Scans are OFFLINE in the locked-down container; repository code is never executed.
"""
import sys
from pathlib import Path

try:
    from . import _scanner_runner as runner  # type: ignore
except Exception:  # pragma: no cover
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _scanner_runner as runner  # type: ignore

if __name__ == "__main__":
    argv = sys.argv[1:]
    if "--history" in argv:
        argv = [a for a in argv if a != "--history"]
        raise SystemExit(runner.cli_main("gitleaks-history", argv))
    raise SystemExit(runner.cli_main("gitleaks", argv))
