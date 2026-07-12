#!/usr/bin/env python3
"""run_semgrep.py — Phase 20-28 thin wrapper: run semgrep over the cloned sample.

All logic lives in _scanner_runner.py (isolated docker run, immutable raw output,
execution records). This file only binds the scanner name. Scans are OFFLINE in
the locked-down container; repository code is never executed.
"""
import sys
from pathlib import Path

try:
    from . import _scanner_runner as runner  # type: ignore
except Exception:  # pragma: no cover
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _scanner_runner as runner  # type: ignore

if __name__ == "__main__":
    raise SystemExit(runner.cli_main("semgrep"))
