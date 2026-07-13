#!/usr/bin/env python3
"""
deduplicate_findings.py — Phase 32 cross-scanner finding dedup + overlap (RQ11).

Collapses findings that multiple scanners report for the SAME issue into one
deduplicated finding, recording which scanners agreed. Overlap is MEASURED
(RQ11), never treated as independent confirmation: dependency findings match on
repo+package+advisory; code/config/secret findings match on repo+category+
file+line (+source for secrets). The representative keeps the highest normalized
severity; the union of agreeing scanners is retained.

Pure dedup + overlap logic split from I/O; unit-tested offline.

Input:  results/redacted/findings-classified.json
Output: results/deduplicated/findings.{json,csv} + overlap-summary.json
"""

from __future__ import annotations

import argparse
import csv
import os
import sys
from itertools import combinations
from pathlib import Path
from typing import Optional

try:
    from . import _common as common  # type: ignore
except Exception:  # pragma: no cover
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _common as common  # type: ignore

STUDY_ROOT = common.STUDY_ROOT
_SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1, "unknown": 0}
_BASE_SCANNER = {"gitleaks-history": "gitleaks"}   # collapse variant to its scanner for overlap

DEDUP_FIELDS = ["dedup_id", "repository_full_name", "anonymous_id", "category",
                "detection_reliability", "normalized_severity", "file", "line",
                "package", "rule_id", "title", "cwe", "scanners", "scanner_count",
                "duplicate_count", "commit_sha"]


# =========================================================================== #
# PURE
# =========================================================================== #
def dedup_key(f: dict) -> tuple:
    repo = f.get("repository_full_name")
    cat = f.get("category")
    if cat == "vulnerable_dependencies":
        return ("dep", repo, (f.get("package") or "").lower(), str(f.get("rule_id") or "").upper())
    # secrets are commit-specific: keep working-tree vs history separate.
    src = f.get("source") if cat in ("exposed_secrets", "hardcoded_credentials") else ""
    return ("code", repo, cat, f.get("file") or "", str(f.get("line") or ""), src)


def _sev_rank(f: dict) -> int:
    return _SEV_RANK.get(f.get("normalized_severity"), 0)


def _scanner_of(f: dict) -> str:
    s = f.get("scanner")
    return _BASE_SCANNER.get(s, s)


def deduplicate(findings: list[dict]) -> list[dict]:
    groups: dict = {}
    for f in findings:
        groups.setdefault(dedup_key(f), []).append(f)
    out: list[dict] = []
    for key, group in groups.items():
        rep = max(group, key=_sev_rank)
        scanners = sorted({_scanner_of(g) for g in group})
        out.append({
            "dedup_id": common.sha256_hex("|".join(str(x) for x in key)),
            "repository_full_name": rep.get("repository_full_name"),
            "anonymous_id": rep.get("anonymous_id"),
            "category": rep.get("category"),
            "detection_reliability": rep.get("detection_reliability"),
            "normalized_severity": rep.get("normalized_severity"),
            "file": rep.get("file"), "line": rep.get("line"),
            "package": rep.get("package"), "rule_id": rep.get("rule_id"),
            "title": rep.get("title"), "cwe": rep.get("cwe"),
            "scanners": ";".join(scanners),
            "scanner_count": len(scanners),
            "duplicate_count": len(group),
            "commit_sha": rep.get("commit_sha"),
        })
    return sorted(out, key=lambda r: (r["repository_full_name"] or "", r["category"] or ""))


def overlap_summary(deduplicated: list[dict], raw_total: int) -> dict:
    """RQ11: how much scanners overlap. Pairwise agreement is measured, not
    treated as independent confirmation."""
    multi = [d for d in deduplicated if d["scanner_count"] > 1]
    pair_counts: dict = {}
    for d in deduplicated:
        scanners = [s for s in (d["scanners"] or "").split(";") if s]
        for a, b in combinations(sorted(scanners), 2):
            pair_counts[f"{a}+{b}"] = pair_counts.get(f"{a}+{b}", 0) + 1
    from collections import Counter
    return {
        "raw_findings": raw_total,
        "deduplicated_findings": len(deduplicated),
        "collapsed": raw_total - len(deduplicated),
        "multi_scanner_findings": len(multi),
        "multi_scanner_rate": round(len(multi) / len(deduplicated), 4) if deduplicated else None,
        "by_scanner_pair": dict(sorted(pair_counts.items())),
        "by_category": dict(Counter(d["category"] for d in deduplicated)),
    }


# =========================================================================== #
# WRITER
# =========================================================================== #
def write_deduplicated(records: list[dict], json_path: Path, csv_path: Path) -> None:
    common.atomic_write_json(json_path, records)
    common.ensure_dir(csv_path.parent)
    tmp = csv_path.with_suffix(".csv.tmp")
    with tmp.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=DEDUP_FIELDS, extrasaction="ignore")
        w.writeheader()
        for r in records:
            w.writerow(r)
    os.replace(tmp, csv_path)


def main(argv: Optional[list[str]] = None) -> int:
    argparse.ArgumentParser(description="Deduplicate findings across scanners (Phase 32).").parse_args(argv)
    cfg = common.load_study_config()
    classified = STUDY_ROOT / cfg["paths"]["results_redacted"] / "findings-classified.json"
    out_dir = STUDY_ROOT / cfg["paths"]["results_deduplicated"]
    if not classified.exists():
        print("ERROR: classified findings not found. Run classify_findings.py first.", file=sys.stderr)
        return 2

    findings = common.read_json(classified)
    deduped = deduplicate(findings)
    summary = overlap_summary(deduped, len(findings))
    write_deduplicated(deduped, out_dir / "findings.json", out_dir / "findings.csv")
    common.atomic_write_json(out_dir / "overlap-summary.json", summary)

    print(f"Deduplicated {len(findings)} -> {len(deduped)} findings -> {out_dir / 'findings.csv'}")
    print(f"  multi-scanner (RQ11): {summary['multi_scanner_findings']} "
          f"({summary['multi_scanner_rate']}); pairs: {summary['by_scanner_pair']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
