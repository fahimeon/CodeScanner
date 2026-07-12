#!/usr/bin/env python3
"""
calculate_claude_contribution.py — Phase 6 involvement metric (RQ9, EXPLORATORY).

Turns the per-repo attribution counts from verify_claude_attribution.py into the
study's Claude-"involvement" variable: attributed share of non-merge commits,
attributed share of relevant source-line changes, and a coarse involvement band
(study-config.yaml `involvement.bands`).

IMPORTANT (study terminology): this variable is a proxy for attribution
RETENTION, not actual Claude usage intensity. Any downstream correlation is
EXPLORATORY and cannot compare Claude-vs-non-Claude usage levels.

Pure and offline: it consumes the attribution-verification table written by the
previous step (no git, no network). Unit-tested in tests/test_verify_claude_attribution.py.

Outputs:
  data/interim/claude-contribution.{json,csv}
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

CONTRIBUTION_FIELDS = [
    "repository_full_name",
    "status",
    "attributed_non_merge_commits",
    "total_non_merge_commits",
    "attributed_commit_share",
    "substantive_attributed_commits",
    "attributed_source_lines",
    "total_source_lines",
    "attributed_source_line_share",
    "involvement_band",
]


# =========================================================================== #
# PURE FUNCTIONS
# =========================================================================== #
def involvement_band(substantive_attributed: int, commit_share: float,
                     bands_cfg: dict) -> str:
    """Map (substantive attributed commits, attributed commit share) to a band.
    'none' when there is no substantive attributed commit."""
    low = bands_cfg.get("low", {})
    med = bands_cfg.get("medium", {})
    high = bands_cfg.get("high", {})

    high_min = high.get("min_substantive", 20)
    high_share = high.get("or_min_share", 0.25)
    if substantive_attributed >= high_min or commit_share >= high_share:
        return "high"
    if med.get("min_substantive", 5) <= substantive_attributed <= med.get("max_substantive", 19):
        return "medium"
    if low.get("min_substantive", 1) <= substantive_attributed <= low.get("max_substantive", 4):
        return "low"
    return "none"


def _ratio(numer, denom) -> Optional[float]:
    if not denom:
        return 0.0 if numer in (0, None) else None
    return round((numer or 0) / denom, 4)


def compute_involvement(row: dict, bands_cfg: dict) -> dict:
    """Build one involvement record from an attribution-verification row."""
    status = row.get("status")
    full = row.get("repository_full_name")
    if status != "OK":
        return {
            "repository_full_name": full,
            "status": status,
            "attributed_non_merge_commits": None,
            "total_non_merge_commits": None,
            "attributed_commit_share": None,
            "substantive_attributed_commits": None,
            "attributed_source_lines": None,
            "total_source_lines": None,
            "attributed_source_line_share": None,
            "involvement_band": "none",
        }

    substantive = int(row.get("substantive_attributed_commits") or 0)
    commit_share = float(row.get("attributed_commit_share") or 0.0)
    attr_lines = row.get("attributed_source_lines") or 0
    total_lines = row.get("total_source_lines") or 0
    return {
        "repository_full_name": full,
        "status": status,
        "attributed_non_merge_commits": row.get("attributed_non_merge_commits"),
        "total_non_merge_commits": row.get("total_non_merge_commits"),
        "attributed_commit_share": commit_share,
        "substantive_attributed_commits": substantive,
        "attributed_source_lines": attr_lines,
        "total_source_lines": total_lines,
        "attributed_source_line_share": _ratio(attr_lines, total_lines),
        "involvement_band": involvement_band(substantive, commit_share, bands_cfg),
    }


def build_contribution(rows: list[dict], bands_cfg: dict) -> list[dict]:
    return [compute_involvement(r, bands_cfg) for r in rows]


# =========================================================================== #
# WRITER
# =========================================================================== #
def write_contribution(records: list[dict], json_path: Path, csv_path: Path) -> None:
    common.atomic_write_json(json_path, records)
    common.ensure_dir(Path(csv_path).parent)
    tmp = Path(csv_path).with_suffix(".csv.tmp")
    with tmp.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CONTRIBUTION_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for rec in records:
            writer.writerow(rec)
    os.replace(tmp, csv_path)


# =========================================================================== #
# main
# =========================================================================== #
def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Compute Claude involvement metric (Phase 6, exploratory).")
    parser.add_argument("--control", action="store_true")
    args = parser.parse_args(argv)

    cfg = common.load_study_config()
    bands_cfg = cfg.get("involvement", {}).get("bands", {})

    interim = STUDY_ROOT / cfg["paths"]["interim"]
    if args.control:
        in_json = interim / "control" / "attribution-verification.json"
        out_json = interim / "control" / "claude-contribution.json"
        out_csv = interim / "control" / "claude-contribution.csv"
    else:
        in_json = interim / "attribution-verification.json"
        out_json = interim / "claude-contribution.json"
        out_csv = interim / "claude-contribution.csv"

    if not in_json.exists():
        print(f"ERROR: attribution table not found: {in_json}", file=sys.stderr)
        print("       Run 'verify_claude_attribution.py' first.", file=sys.stderr)
        return 2

    rows = common.read_json(in_json)
    records = build_contribution(rows, bands_cfg)
    write_contribution(records, out_json, out_csv)

    from collections import Counter
    bands = Counter(r["involvement_band"] for r in records)
    print(f"Involvement computed for {len(records)} repositories -> {out_csv}")
    print(f"  involvement bands: {dict(bands)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
