#!/usr/bin/env python3
"""
create_validation_sample.py — Phase 33 manual-validation sample.

Draws a reproducible, stratified sample of deduplicated findings for single-
reviewer manual validation (true/false positive labelling later). Stratified by
(category, normalized_severity) with a fixed seed. The sample is PRIVATE (it
carries repository identity + file/line) -> data/processed/.

Pure `sample_findings` split from I/O; unit-tested offline.
"""

from __future__ import annotations

import argparse
import csv
import os
import random
import sys
from pathlib import Path
from typing import Optional

try:
    from . import _common as common  # type: ignore
except Exception:  # pragma: no cover
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _common as common  # type: ignore

STUDY_ROOT = common.STUDY_ROOT
SAMPLE_FIELDS = ["validation_id", "repository_full_name", "anonymous_id", "category",
                 "detection_reliability", "normalized_severity", "scanners", "file",
                 "line", "package", "rule_id", "title", "validation_label"]


# =========================================================================== #
# PURE
# =========================================================================== #
def sample_findings(findings: list[dict], per_stratum: int, seed: int) -> list[dict]:
    """Stratified reproducible sample: up to `per_stratum` findings per
    (category, severity) stratum. Every stratum is represented if non-empty."""
    rng = random.Random(seed)
    strata: dict = {}
    for f in sorted(findings, key=lambda r: r.get("dedup_id") or ""):
        key = (f.get("category"), f.get("normalized_severity"))
        strata.setdefault(key, []).append(f)
    out: list[dict] = []
    for key in sorted(strata, key=lambda k: tuple(str(x) for x in k)):
        items = list(strata[key])
        rng.shuffle(items)
        for f in items[:per_stratum]:
            out.append({
                "validation_id": f.get("dedup_id"),
                "repository_full_name": f.get("repository_full_name"),
                "anonymous_id": f.get("anonymous_id"),
                "category": f.get("category"),
                "detection_reliability": f.get("detection_reliability"),
                "normalized_severity": f.get("normalized_severity"),
                "scanners": f.get("scanners"),
                "file": f.get("file"), "line": f.get("line"),
                "package": f.get("package"), "rule_id": f.get("rule_id"),
                "title": f.get("title"),
                "validation_label": "PENDING",     # reviewer sets TRUE_POSITIVE / FALSE_POSITIVE
            })
    return out


# =========================================================================== #
# main
# =========================================================================== #
def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Create a manual-validation sample (Phase 33).")
    p.add_argument("--per-stratum", type=int, default=5)
    args = p.parse_args(argv)

    cfg = common.load_study_config()
    seed = int(cfg.get("reproducibility", {}).get("random_seed", 20260711))
    deduped = STUDY_ROOT / cfg["paths"]["results_deduplicated"] / "findings.json"
    out = STUDY_ROOT / cfg["paths"]["processed"] / "validation-sample.csv"
    if not deduped.exists():
        print("ERROR: deduplicated findings not found. Run deduplicate_findings.py first.", file=sys.stderr)
        return 2

    sample = sample_findings(common.read_json(deduped), args.per_stratum, seed)
    common.ensure_dir(out.parent)
    tmp = out.with_suffix(".csv.tmp")
    with tmp.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=SAMPLE_FIELDS, extrasaction="ignore")
        w.writeheader()
        for r in sample:
            w.writerow(r)
    os.replace(tmp, out)
    print(f"Validation sample: {len(sample)} findings (seed={seed}) -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
