#!/usr/bin/env python3
"""
generate_figures.py — Phase 37 figures.

Renders the headline figures from results/tables/analysis-summary.json:
prevalence by category (grouped by detection_reliability), severity distribution,
and scanner overlap. Pure chart-data preparation is split from rendering; the
matplotlib rendering uses the headless Agg backend and is skipped (with a clear
message) if matplotlib is unavailable, so the data prep stays unit-testable
offline without a plotting dependency.

Output: results/figures/*.png (+ figure-data.json)
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
SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational", "unknown"]


# =========================================================================== #
# PURE — chart data preparation
# =========================================================================== #
def category_prevalence_data(analysis: dict) -> list[dict]:
    """(category, proportion, low, high, reliability) sorted by proportion desc."""
    by_cat = analysis.get("prevalence", {}).get("by_category", {})
    reliability = {}
    for tier, cats in analysis.get("categories_by_reliability", {}).items():
        for c in cats:
            reliability[c] = tier
    rows = []
    for cat, ci in by_cat.items():
        rows.append({"category": cat, "proportion": ci.get("proportion") or 0.0,
                     "low": ci.get("low"), "high": ci.get("high"),
                     "reliability": reliability.get(cat, "unknown")})
    return sorted(rows, key=lambda r: r["proportion"], reverse=True)


def severity_distribution_data(analysis: dict) -> list[dict]:
    by_sev = analysis.get("prevalence", {}).get("by_severity", {})
    return [{"severity": s, "proportion": (by_sev.get(s, {}) or {}).get("proportion") or 0.0}
            for s in SEVERITY_ORDER]


def overlap_pair_data(analysis: dict) -> list[dict]:
    pairs = analysis.get("scanner_overlap_rq11", {}).get("by_scanner_pair", {})
    return sorted(({"pair": k, "count": v} for k, v in pairs.items()),
                  key=lambda r: r["count"], reverse=True)


def build_figure_data(analysis: dict) -> dict:
    return {
        "category_prevalence": category_prevalence_data(analysis),
        "severity_distribution": severity_distribution_data(analysis),
        "scanner_overlap": overlap_pair_data(analysis),
    }


# =========================================================================== #
# RENDERING (optional matplotlib)
# =========================================================================== #
def render(figure_data: dict, out_dir: Path) -> list[str]:  # pragma: no cover
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception:
        print("matplotlib not available; wrote figure-data.json only.", file=sys.stderr)
        return []
    common.ensure_dir(out_dir)
    written = []

    cats = figure_data["category_prevalence"][:20]
    if cats:
        fig, ax = plt.subplots(figsize=(9, max(3, 0.35 * len(cats))))
        ax.barh([c["category"] for c in cats][::-1], [c["proportion"] for c in cats][::-1])
        ax.set_xlabel("proportion of repositories (detected by configured scanners)")
        ax.set_title("Finding prevalence by category")
        fig.tight_layout()
        p = out_dir / "prevalence-by-category.png"
        fig.savefig(p, dpi=120)
        plt.close(fig)
        written.append(str(p))

    sev = figure_data["severity_distribution"]
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.bar([s["severity"] for s in sev], [s["proportion"] for s in sev])
    ax.set_ylabel("proportion of repositories")
    ax.set_title("Repositories with >=1 finding at each normalized severity")
    fig.tight_layout()
    p = out_dir / "severity-distribution.png"
    fig.savefig(p, dpi=120)
    plt.close(fig)
    written.append(str(p))
    return written


def main(argv: Optional[list[str]] = None) -> int:
    argparse.ArgumentParser(description="Generate figures (Phase 37).").parse_args(argv)
    cfg = common.load_study_config()
    analysis_path = STUDY_ROOT / cfg["paths"]["tables"] / "analysis-summary.json"
    out_dir = STUDY_ROOT / cfg["paths"]["figures"]
    if not analysis_path.exists():
        print("ERROR: analysis-summary.json not found. Run analyse_results.py first.", file=sys.stderr)
        return 2

    figure_data = build_figure_data(common.read_json(analysis_path))
    common.atomic_write_json(out_dir / "figure-data.json", figure_data)
    written = render(figure_data, out_dir)
    print(f"Figure data -> {out_dir / 'figure-data.json'}; rendered {len(written)} PNG(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
