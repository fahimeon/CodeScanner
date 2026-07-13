#!/usr/bin/env python3
"""
generate_reports.py — Phase 40 reports + anonymised public dataset (Phase 38).

Builds the markdown results report from results/tables/analysis-summary.json and,
with --public-only, emits the anonymised public aggregates (no identities). All
wording uses "no findings detected by the configured scanners" — never "secure".

Pure `build_report_markdown` + `build_public_dataset` split from I/O; unit-tested.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional

try:
    from . import _common as common  # type: ignore
except Exception:  # pragma: no cover
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _common as common  # type: ignore

STUDY_ROOT = common.STUDY_ROOT
_DISCLAIMER = ("Zero findings for a repository or category means **no findings were "
               "detected by the configured scanners** at their pinned versions and "
               "rulesets — NOT that the repository is secure or free of that class. "
               "`weak` / `out_of_scope` categories have little or no sensitivity.")


# =========================================================================== #
# PURE
# =========================================================================== #
def _ci(ci: dict) -> str:
    if not ci or ci.get("proportion") is None:
        return "n/a"
    return f"{ci['proportion']:.1%} (95% CI {ci['low']:.1%}–{ci['high']:.1%}; {ci['k']}/{ci['n']})"


def build_report_markdown(analysis: dict) -> str:
    prev = analysis.get("prevalence", {})
    lines = [
        "# Results — Security findings in deployed, Claude Code-attributed web apps",
        "",
        f"_Generated {analysis.get('generated_utc')}. "
        f"Repositories analysed: {analysis.get('repositories_analysed')}._",
        "",
        "> **Detection-scope caveat.** " + _DISCLAIMER,
        "",
        "## Headline prevalence",
        f"- **Repositories with ≥1 finding:** {_ci(prev.get('any_finding', {}))}",
        "",
        "### By normalized severity (repositories with ≥1 finding at that severity)",
        "| Severity | Prevalence |", "|---|---|",
    ]
    for sev, ci in (prev.get("by_severity") or {}).items():
        lines.append(f"| {sev} | {_ci(ci)} |")

    lines += ["", "### By category, grouped by detection reliability",
              "Low counts in `weak` / `out_of_scope` tiers reflect low detection "
              "sensitivity, not low prevalence."]
    for tier in ("strong", "partial", "weak", "out_of_scope", "unknown"):
        cats = (analysis.get("categories_by_reliability") or {}).get(tier) or {}
        if not cats:
            continue
        lines += ["", f"**{tier}**", "", "| Category | Prevalence |", "|---|---|"]
        for cat, ci in sorted(cats.items(), key=lambda kv: -(kv[1].get("proportion") or 0)):
            lines.append(f"| {cat} | {_ci(ci)} |")

    overlap = analysis.get("scanner_overlap_rq11") or {}
    lines += ["", "## Scanner overlap (RQ11)",
              f"- Deduplicated findings: {overlap.get('deduplicated_findings', 'n/a')}",
              f"- Found by >1 scanner: {overlap.get('multi_scanner_findings', 'n/a')} "
              f"(rate {overlap.get('multi_scanner_rate', 'n/a')})",
              "- Overlap is **measured, not** treated as independent confirmation.", ""]
    return "\n".join(lines)


def build_public_dataset(analysis: dict) -> dict:
    """Anonymised aggregates only — no repository identities, URLs, or IDs."""
    prev = analysis.get("prevalence", {})
    return {
        "generated_utc": common.iso_now(),
        "repositories_analysed": analysis.get("repositories_analysed"),
        "any_finding": prev.get("any_finding"),
        "by_severity": prev.get("by_severity"),
        "by_category": prev.get("by_category"),
        "categories_by_reliability": analysis.get("categories_by_reliability"),
        "scanner_overlap_rq11": {k: v for k, v in (analysis.get("scanner_overlap_rq11") or {}).items()
                                 if k != "by_repository"},
        "detection_scope_note": _DISCLAIMER.replace("**", ""),
    }


# =========================================================================== #
# main
# =========================================================================== #
def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Generate reports (Phase 40).")
    p.add_argument("--public-only", action="store_true", help="emit only the anonymised public dataset")
    args = p.parse_args(argv)

    cfg = common.load_study_config()
    analysis_path = STUDY_ROOT / cfg["paths"]["tables"] / "analysis-summary.json"
    if not analysis_path.exists():
        print("ERROR: analysis-summary.json not found. Run analyse_results.py first.", file=sys.stderr)
        return 2
    analysis = common.read_json(analysis_path)

    public = build_public_dataset(analysis)
    common.atomic_write_json(STUDY_ROOT / cfg["paths"]["public"] / "public-findings-summary.json", public)
    if args.public_only:
        print(f"Public dataset -> {cfg['paths']['public']}/public-findings-summary.json")
        return 0

    report_md = build_report_markdown(analysis)
    out = STUDY_ROOT / cfg["paths"]["reports"] / "results-report.md"
    common.atomic_write_text(out, report_md)
    print(f"Report -> {out} (+ anonymised public dataset).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
