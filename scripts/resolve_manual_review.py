#!/usr/bin/env python3
"""
resolve_manual_review.py — Phase 17 manual-review resolution gate.

Security-lab / intentionally-vulnerable / tutorial / placeholder / ambiguous
deployment-match flags must NOT remain eligible automatically. This builds a
decision table with states PENDING / INCLUDE / EXCLUDE. New flagged repos start
PENDING; existing human decisions are preserved. `freeze` REFUSES while any
eligible repo is still PENDING (see freeze_population).

Pure item-building + decision merging split from I/O; unit-tested offline.

Output: data/processed/manual-review-decisions.csv
"""

from __future__ import annotations

import argparse
import csv
import os
import sys
from pathlib import Path
from typing import Optional

try:
    from . import _common as common  # type: ignore
except Exception:  # pragma: no cover
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _common as common  # type: ignore

STUDY_ROOT = common.STUDY_ROOT
DECISION_STATES = {"PENDING", "INCLUDE", "EXCLUDE"}
DECISION_FIELDS = ["repository_full_name", "flags", "decision", "resolved_by", "note"]


# =========================================================================== #
# PURE LOGIC
# =========================================================================== #
def review_flags_for(screen: dict, match: Optional[dict]) -> list[str]:
    """All manual-review flags for one repo (screening + deployment ambiguity)."""
    flags = list(screen.get("manual_review_flags") or [])
    m = match or {}
    if m.get("deployment_status") in ("PLACEHOLDER", "PROVIDER_PROTECTED"):
        flags.append("MANUAL_REVIEW_DEPLOYMENT_AMBIGUOUS")
    if m.get("availability_eligible") and not m.get("corresponds"):
        flags.append("MANUAL_REVIEW_DEPLOYMENT_MATCH_UNCONFIRMED")
    return sorted(set(flags))


def build_review_items(screening: dict, match: dict) -> dict:
    """{repo -> sorted flags} for every repo that has >=1 manual-review flag."""
    items: dict = {}
    for full, screen in screening.items():
        flags = review_flags_for(screen, match.get(full))
        if flags:
            items[full] = flags
    return items


def merge_decisions(items: dict, existing: dict) -> list[dict]:
    """New flagged repos -> PENDING; preserve prior INCLUDE/EXCLUDE decisions.
    A previously-decided repo whose flags CHANGED is reset to PENDING."""
    rows: list[dict] = []
    for full in sorted(items):
        flags = items[full]
        prev = existing.get(full)
        if prev and prev.get("decision") in ("INCLUDE", "EXCLUDE") \
                and prev.get("flags") == ";".join(flags):
            decision, by, note = prev["decision"], prev.get("resolved_by", ""), prev.get("note", "")
        else:
            decision, by, note = "PENDING", "", ""
        rows.append({"repository_full_name": full, "flags": ";".join(flags),
                     "decision": decision, "resolved_by": by, "note": note})
    return rows


def unresolved_pending(decisions: dict, eligible_repos: set) -> list[str]:
    """Eligible repos whose manual-review decision is still PENDING."""
    return sorted(full for full in eligible_repos
                  if decisions.get(full, {}).get("decision") == "PENDING")


def apply_decisions(eligible_records: list[dict], decisions: dict) -> tuple[list[dict], list[str]]:
    """Drop human-EXCLUDEd repos; return (kept, still_pending). Used by freeze."""
    kept, pending = [], []
    for r in eligible_records:
        full = r.get("repository_full_name")
        d = decisions.get(full, {}).get("decision")
        if d == "EXCLUDE":
            continue
        if d == "PENDING":
            pending.append(full)
        kept.append(r)
    return kept, sorted(pending)


# =========================================================================== #
# I/O
# =========================================================================== #
def read_decisions(path: Path) -> dict:
    if not path.exists():
        return {}
    with path.open(encoding="utf-8") as fh:
        return {row["repository_full_name"]: row for row in csv.DictReader(fh)}


def write_decisions(rows: list[dict], path: Path) -> None:
    common.ensure_dir(path.parent)
    tmp = path.with_suffix(".csv.tmp")
    with tmp.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=DECISION_FIELDS, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)
    os.replace(tmp, path)


def _index(path: Path, key: str = "repository_full_name") -> dict:
    if not path.exists():
        return {}
    return {r[key]: r for r in common.read_json(path)
            if isinstance(r, dict) and r.get(key)}


def main(argv: Optional[list[str]] = None) -> int:
    argparse.ArgumentParser(description="Build/refresh the manual-review decision table (Phase 17).").parse_args(argv)
    cfg = common.load_study_config()
    processed = STUDY_ROOT / cfg["paths"]["processed"]
    private = STUDY_ROOT / cfg["paths"]["private"]

    screening = _index(processed / "screening-results.json")
    match = _index(private / "deployment-eligibility.json")
    if not screening:
        print("ERROR: screening-results.json not found. Run 'make screen' first.", file=sys.stderr)
        return 2

    items = build_review_items(screening, match)
    decisions_path = processed / "manual-review-decisions.csv"
    rows = merge_decisions(items, read_decisions(decisions_path))
    write_decisions(rows, decisions_path)

    pending = sum(1 for r in rows if r["decision"] == "PENDING")
    print(f"Manual-review decisions: {len(rows)} flagged repositories -> {decisions_path}")
    print(f"  PENDING (must be resolved to INCLUDE/EXCLUDE before freeze): {pending}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
