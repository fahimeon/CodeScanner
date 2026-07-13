#!/usr/bin/env python3
"""
redact_secrets.py — Phase 29-30 redact secret values from findings.

Defense-in-depth: even though gitleaks runs with --redact and the normalized
schema does not carry raw secret values, every finding is passed through the
shared redaction util before it can reach a redacted/published artifact, and any
finding that still contains a secret-like token is flagged. No plaintext secret
ever reaches results/redacted/.

Pure `redact_findings` split from I/O; unit-tested with synthetic (fake) secrets.

Input:  results/normalized/findings.json
Output: results/redacted/findings.json (+ .csv)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional

try:
    from . import _common as common  # type: ignore
    from . import redaction  # type: ignore
    from . import normalize_results as nr  # type: ignore
except Exception:  # pragma: no cover
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _common as common  # type: ignore
    import redaction  # type: ignore
    import normalize_results as nr  # type: ignore

STUDY_ROOT = common.STUDY_ROOT


# =========================================================================== #
# PURE
# =========================================================================== #
def redact_findings(findings: list[dict]) -> tuple[list[dict], int]:
    """Redact every finding; return (redacted, count_that_contained_a_secret)."""
    out: list[dict] = []
    leaked = 0
    for f in findings:
        # A pre-redaction scan of the string fields flags any residual secret.
        blob = " ".join(str(v) for v in f.values() if isinstance(v, str))
        if redaction.contains_unredacted_secret(blob):
            leaked += 1
        out.append(redaction.redact_record(f))
    return out, leaked


# =========================================================================== #
# main
# =========================================================================== #
def main(argv: Optional[list[str]] = None) -> int:
    argparse.ArgumentParser(description="Redact secrets from findings (Phase 29-30).").parse_args(argv)
    cfg = common.load_study_config()
    normalized = STUDY_ROOT / cfg["paths"]["results_normalized"] / "findings.json"
    out_dir = STUDY_ROOT / cfg["paths"]["results_redacted"]
    if not normalized.exists():
        print("ERROR: normalized findings not found. Run normalize_results.py first.", file=sys.stderr)
        return 2

    findings = common.read_json(normalized)
    redacted, leaked = redact_findings(findings)
    nr.write_findings(redacted, out_dir / "findings.json", out_dir / "findings.csv")

    print(f"Redacted {len(redacted)} findings -> {out_dir / 'findings.json'}")
    if leaked:
        print(f"  NOTE: {leaked} finding(s) contained a secret-like token and were redacted.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
