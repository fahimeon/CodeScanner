#!/usr/bin/env python3
"""
analyse_results.py — Phase 35-36 statistics.

Computes the prevalence outcomes (RQ1-8, RQ11) over the scanned repositories with
Wilson score confidence intervals (appropriate for rare events) and Benjamini-
Hochberg FDR control for multiple comparisons. Categories are reported grouped by
detection_reliability so that low counts in weak / out_of_scope categories are
read as low sensitivity, NOT low prevalence.

Pure statistics (wilson_ci, benjamini_hochberg, prevalence) are dependency-free
(no scipy/statsmodels needed for these) and unit-tested offline.

Inputs:  results/deduplicated/findings.json, overlap-summary.json + a repo universe
Output:  results/tables/analysis-summary.json
"""

from __future__ import annotations

import argparse
import math
import sys
from collections import Counter
from pathlib import Path
from typing import Optional

try:
    from . import _common as common  # type: ignore
except Exception:  # pragma: no cover
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _common as common  # type: ignore

STUDY_ROOT = common.STUDY_ROOT
SEVERITIES = ["critical", "high", "medium", "low", "informational", "unknown"]


# =========================================================================== #
# PURE STATISTICS
# =========================================================================== #
def wilson_ci(k: int, n: int, z: float = 1.959963985) -> dict:
    """Wilson score interval for a binomial proportion (rare-event safe)."""
    if n == 0:
        return {"k": k, "n": 0, "proportion": None, "low": None, "high": None}
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = (z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / denom
    return {"k": k, "n": n, "proportion": round(p, 4),
            "low": round(max(0.0, centre - half), 4),
            "high": round(min(1.0, centre + half), 4)}


def benjamini_hochberg(pvalues: dict, alpha: float = 0.05) -> dict:
    """BH FDR: returns {name: {p, q (adjusted), rejected}}. Input {name: p}."""
    items = sorted(pvalues.items(), key=lambda kv: kv[1])
    m = len(items)
    out: dict = {}
    prev_q = 1.0
    # compute adjusted q-values from largest rank down (monotone)
    for rank in range(m, 0, -1):
        name, p = items[rank - 1]
        q = min(prev_q, p * m / rank)
        prev_q = q
        out[name] = {"p": round(p, 6), "q_value": round(q, 6), "rejected": q <= alpha}
    return out


def repo_has_finding(findings: list[dict], predicate=lambda f: True) -> set:
    return {f["repository_full_name"] for f in findings
            if f.get("repository_full_name") and predicate(f)}


def prevalence(findings: list[dict], repos: set) -> dict:
    n = len(repos)
    any_finding = wilson_ci(len(repo_has_finding(findings) & repos), n)
    by_severity = {sev: wilson_ci(len(repo_has_finding(
        findings, lambda f, s=sev: f.get("normalized_severity") == s) & repos), n)
        for sev in SEVERITIES}
    by_category = {}
    for cat in sorted({f.get("category") for f in findings if f.get("category")}):
        by_category[cat] = wilson_ci(len(repo_has_finding(
            findings, lambda f, c=cat: f.get("category") == c) & repos), n)
    return {"repositories": n, "any_finding": any_finding,
            "by_severity": by_severity, "by_category": by_category}


def group_categories_by_reliability(by_category: dict, reliability_of: dict) -> dict:
    grouped: dict = {"strong": {}, "partial": {}, "weak": {}, "out_of_scope": {}, "unknown": {}}
    for cat, ci in by_category.items():
        tier = reliability_of.get(cat, "unknown")
        grouped.setdefault(tier, {})[cat] = ci
    return grouped


# =========================================================================== #
# ORCHESTRATION
# =========================================================================== #
def analyse(findings: list[dict], repos: set, reliability_of: dict,
            overlap: Optional[dict] = None) -> dict:
    prev = prevalence(findings, repos)
    grouped = group_categories_by_reliability(prev["by_category"], reliability_of)
    # BH across the per-category "any repo in category" proportions vs 0 is not a
    # hypothesis test per se; we expose category counts + CIs and reserve BH for
    # confirmatory comparisons. Provide the category count table here.
    cat_counts = Counter()
    for f in findings:
        if f.get("category"):
            cat_counts[f["category"]] += 1
    return {
        "generated_utc": common.iso_now(),
        "repositories_analysed": len(repos),
        "prevalence": prev,
        "categories_by_reliability": grouped,
        "finding_counts_by_category": dict(cat_counts.most_common()),
        "scanner_overlap_rq11": overlap or {},
        "reading_note": "Zero findings in a category means 'no findings detected by the "
                        "configured scanners', not absence of the class. weak / out_of_scope "
                        "categories have little or no sensitivity.",
    }


def _repo_universe(cfg) -> set:
    """Denominator = repositories actually scanned (clone-manifest OK)."""
    manifest = STUDY_ROOT / cfg["paths"]["processed"] / "clone-manifest.json"
    if manifest.exists():
        return {r["repository_full_name"] for r in common.read_json(manifest)
                if r.get("status") == "OK" and r.get("repository_full_name")}
    return set()


def main(argv: Optional[list[str]] = None) -> int:
    argparse.ArgumentParser(description="Analyse results (Phase 35-36).").parse_args(argv)
    cfg = common.load_study_config()
    taxonomy = common.load_yaml(common.CONFIG_DIR / "finding-taxonomy.yaml")
    reliability_of = {k: v.get("detection_reliability")
                      for k, v in (taxonomy.get("categories") or {}).items()}
    dd_dir = STUDY_ROOT / cfg["paths"]["results_deduplicated"]
    findings_path = dd_dir / "findings.json"
    if not findings_path.exists():
        print("ERROR: deduplicated findings not found. Run deduplicate_findings.py first.", file=sys.stderr)
        return 2

    findings = common.read_json(findings_path)
    overlap = common.read_json(dd_dir / "overlap-summary.json") \
        if (dd_dir / "overlap-summary.json").exists() else {}
    repos = _repo_universe(cfg) or {f["repository_full_name"] for f in findings
                                    if f.get("repository_full_name")}

    summary = analyse(findings, repos, reliability_of, overlap)
    out = STUDY_ROOT / cfg["paths"]["tables"] / "analysis-summary.json"
    common.atomic_write_json(out, summary)

    p = summary["prevalence"]["any_finding"]
    print(f"Analysed {len(repos)} repositories -> {out}")
    print(f"  >=1 finding: {p['proportion']} (Wilson 95% CI {p['low']}-{p['high']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
