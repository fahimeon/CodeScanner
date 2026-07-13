#!/usr/bin/env python3
"""
screen_candidates.py — Phase 5/17 eligibility screening.

Joins the enrichment tables (metadata + attribution + classification + LOC) and
applies the study's hard requirements (inclusion-rules.yaml) and exclusion codes
(exclusion-rules.yaml) to decide REPOSITORY-SIDE eligibility. The deployment gate
(Phases 9-13) is applied later and partitions eligible repos into the deployed /
repository-only tracks — it is NOT decided here.

Rules of engagement (never violated here):
  * Record ALL applicable exclusion codes, not just the first.
  * Intentionally-vulnerable / security-lab / tutorial repos are FLAGGED for
    MANUAL_REVIEW, not auto-excluded (per exclusion-rules decisions).
  * Exclusion records are never deleted.
  * Eligibility is never weakened to hit a target N.

Pure decision logic (screen_repo / build_funnel) is split from I/O and unit-tested.

Outputs:
  data/processed/screening-results.{json,csv}
  data/processed/excluded-candidates.csv         (append-only record, never deleted)
  data/processed/eligibility-funnel.json         (CONSORT-style stage counts)
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
JS_TS = {"JavaScript", "TypeScript"}

# CONSORT funnel stages (ordered) -> the exclusion codes that fail each stage.
# A repo "reaches" a stage iff it has none of the codes from that stage or any
# earlier one (and its inputs are complete). Cumulative attrition.
FUNNEL_STAGES = [
    ("not_fork_archived_empty",
     ["EX_ARCHIVED", "EX_FORK", "EX_EMPTY_REPOSITORY", "EX_NO_DEFAULT_BRANCH"]),
    ("js_ts_with_package_json", ["EX_NO_PACKAGE_JSON", "EX_NOT_JS_TS"]),
    ("web_app", ["EX_NOT_WEB_APP", "EX_LIBRARY_ONLY"]),
    ("loc_in_range", ["EX_INSUFFICIENT_LOC", "EX_EXCESSIVE_LOC"]),
    ("substantial_attribution",
     ["EX_WEAK_ATTRIBUTION", "EX_UNREACHABLE_CLAUDE_COMMIT", "EX_CONTROL_ATTRIBUTION_SIGNAL"]),
    ("not_duplicate", ["EX_DUPLICATE"]),
]

SCREENING_FIELDS = [
    "repository_full_name",
    "repository_eligible",
    "data_incomplete",
    "exclusion_codes",
    "manual_review_flags",
    "primary_language",
    "is_web_app",
    "application_type",
    "framework",
    "relevant_source_loc",
    "size_bucket",
    "substantial_attribution",
]
_LIST_FIELDS = {"data_incomplete", "exclusion_codes", "manual_review_flags"}


# =========================================================================== #
# PURE DECISION LOGIC
# =========================================================================== #
def _order_by_precedence(codes: list[str], precedence: list[str]) -> list[str]:
    rank = {c: i for i, c in enumerate(precedence)}
    return sorted(set(codes), key=lambda c: rank.get(c, len(precedence)))


def screen_repo(full_name: str, meta: Optional[dict], cls: Optional[dict],
                loc: Optional[dict], attr: Optional[dict], cfg: dict,
                precedence: list[str], duplicate: Optional[dict] = None,
                control: bool = False) -> dict:
    """Apply hard requirements + exclusion codes to one repository."""
    incomplete: list[str] = []
    if not meta or meta.get("fetch_status") != "OK":
        incomplete.append("metadata")
    if not cls or cls.get("status") != "OK":
        incomplete.append("classification")
    if not loc or loc.get("status") != "OK":
        incomplete.append("loc")
    if not control and (not attr or attr.get("status") != "OK"):
        incomplete.append("attribution")

    meta, cls, loc, attr = meta or {}, cls or {}, loc or {}, attr or {}
    src = cfg.get("source_loc", {})
    min_loc, max_loc = src.get("min", 500), src.get("max", 100000)

    codes: list[str] = []
    flags: list[str] = []

    # --- repository status ---
    if meta.get("is_archived"):
        codes.append("EX_ARCHIVED")
    if meta.get("is_fork"):
        codes.append("EX_FORK")
    if attr.get("status") == "NO_COMMITS" or meta.get("size_kb") == 0:
        codes.append("EX_EMPTY_REPOSITORY")
    if meta.get("has_default_branch") is False:
        codes.append("EX_NO_DEFAULT_BRANCH")

    # --- language / package.json ---
    if not cls.get("has_package_json"):
        codes.append("EX_NO_PACKAGE_JSON")
    # STRICT JS/TS (audit #11): require MEASURED JS/TS presence, not just a web app
    # with a package.json. Accept if primary language is JS/TS, OR enough JS/TS
    # source files, OR enough measured JS/TS LOC (tokei breakdown).
    hr = cfg.get("_inclusion_hard_requirements", {})
    min_files = hr.get("min_js_ts_source_files", 3)
    min_js_ts_loc = hr.get("min_js_ts_loc", 100)
    lang = meta.get("primary_language")
    breakdown = loc.get("language_breakdown") or {}
    js_ts_loc = (breakdown.get("TypeScript", 0) + breakdown.get("JavaScript", 0)
                 + breakdown.get("TSX", 0) + breakdown.get("JSX", 0))
    js_ts_files = cls.get("js_ts_file_count") or 0
    language_ok = ((lang in JS_TS) or js_ts_files >= min_files or js_ts_loc >= min_js_ts_loc)
    if not language_ok:
        codes.append("EX_NOT_JS_TS")

    # --- web application ---
    if cls.get("status") == "OK" and not cls.get("is_web_app"):
        codes.append("EX_NOT_WEB_APP")
    if cls.get("is_library_or_cli") and not cls.get("is_web_app"):
        codes.append("EX_LIBRARY_ONLY")

    # --- relevant source LOC ---
    relevant = loc.get("relevant_source_loc")
    if isinstance(relevant, int):
        if relevant < min_loc:
            codes.append("EX_INSUFFICIENT_LOC")
        elif relevant > max_loc:
            codes.append("EX_EXCESSIVE_LOC")

    # --- manual-review families (flagged, NOT auto-excluded) ---
    for fr in cls.get("flagged_reasons", []) or []:
        if fr == "intentionally_vulnerable_or_security_lab":
            flags.append("MANUAL_REVIEW_SECURITY_LAB")
        elif fr == "tutorial_or_example":
            flags.append("MANUAL_REVIEW_TUTORIAL")

    # --- attribution (cohort-specific) ---
    if not control:
        if attr.get("status") == "OK":
            if attr.get("qualifies"):
                if not attr.get("reachable_qualifying_commit"):
                    codes.append("EX_UNREACHABLE_CLAUDE_COMMIT")
            elif attr.get("any_attribution_signal_found") and \
                    (attr.get("attributed_non_merge_commits") or 0) > 0:
                # Has attributed commits, but they are not SUBSTANTIVE (audit #11).
                codes.append("EX_NON_SUBSTANTIVE_CLAUDE_CHANGE")
            else:
                # No detectable Claude attribution meeting substantiality.
                codes.append("EX_WEAK_ATTRIBUTION")
    else:
        # Controls must have ZERO detectable attribution signals.
        if attr.get("any_attribution_signal_found"):
            codes.append("EX_CONTROL_ATTRIBUTION_SIGNAL")

    # --- duplicate/template (non-representative member of a duplicate cluster) ---
    if (duplicate or {}).get("is_duplicate"):
        codes.append("EX_DUPLICATE")

    codes = _order_by_precedence(codes, precedence)
    eligible = (not incomplete) and (not codes)

    return {
        "repository_full_name": full_name,
        "repository_eligible": eligible,
        "data_incomplete": incomplete,
        "exclusion_codes": codes,
        "manual_review_flags": sorted(set(flags)),
        "primary_language": meta.get("primary_language"),
        "is_web_app": cls.get("is_web_app"),
        "application_type": cls.get("application_type"),
        "framework": cls.get("framework"),
        "relevant_source_loc": loc.get("relevant_source_loc"),
        "size_bucket": loc.get("size_bucket"),
        "substantial_attribution": (None if control else attr.get("qualifies")),
    }


def build_funnel(records: list[dict]) -> dict:
    """CONSORT-style cumulative stage counts from screening records."""
    n = len(records)
    complete = [r for r in records if not r.get("data_incomplete")]
    funnel = {"candidates": n, "data_complete": len(complete)}
    failed_so_far: set[str] = set()
    survivors = list(complete)
    for stage_name, stage_codes in FUNNEL_STAGES:
        failed_so_far.update(stage_codes)
        survivors = [r for r in survivors
                     if not (set(r.get("exclusion_codes", [])) & failed_so_far)]
        funnel[f"reached_{stage_name}"] = len(survivors)
    funnel["repository_eligible"] = sum(1 for r in records if r.get("repository_eligible"))
    funnel["flagged_manual_review"] = sum(1 for r in records if r.get("manual_review_flags"))
    return funnel


# =========================================================================== #
# WRITERS
# =========================================================================== #
def _csv_row(rec: dict) -> dict:
    row = dict(rec)
    for field in _LIST_FIELDS:
        val = row.get(field)
        if isinstance(val, list):
            row[field] = ";".join(str(v) for v in val)
    return row


def write_screening(records: list[dict], json_path: Path, csv_path: Path) -> None:
    common.atomic_write_json(json_path, records)
    common.ensure_dir(Path(csv_path).parent)
    tmp = Path(csv_path).with_suffix(".csv.tmp")
    with tmp.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=SCREENING_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for rec in records:
            writer.writerow(_csv_row(rec))
    os.replace(tmp, csv_path)


def write_excluded(records: list[dict], csv_path: Path) -> None:
    """Excluded-candidates record (repos with >=1 code or incomplete data)."""
    common.ensure_dir(Path(csv_path).parent)
    excluded = [r for r in records
                if r.get("exclusion_codes") or r.get("data_incomplete")]
    tmp = Path(csv_path).with_suffix(".csv.tmp")
    with tmp.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["repository_full_name", "exclusion_codes", "data_incomplete"])
        for r in excluded:
            writer.writerow([r["repository_full_name"],
                             ";".join(r.get("exclusion_codes", [])),
                             ";".join(r.get("data_incomplete", []))])
    os.replace(tmp, csv_path)


# =========================================================================== #
# ORCHESTRATION
# =========================================================================== #
def _index(path: Path, key: str = "repository_full_name") -> dict[str, dict]:
    if not path.exists():
        return {}
    return {r[key]: r for r in common.read_json(path)
            if isinstance(r, dict) and r.get(key)}


def screen_all(candidates: list[dict], metadata: dict, classification: dict,
               loc: dict, attribution: dict, cfg: dict, precedence: list[str],
               duplicates: Optional[dict] = None, control: bool = False) -> list[dict]:
    duplicates = duplicates or {}
    rows: list[dict] = []
    seen: set[str] = set()
    for cand in candidates:
        full = cand.get("repository_full_name")
        if not full or full in seen:
            continue
        seen.add(full)
        rows.append(screen_repo(full, metadata.get(full), classification.get(full),
                                loc.get(full), attribution.get(full), cfg,
                                precedence, duplicate=duplicates.get(full), control=control))
    return rows


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Screen candidates for eligibility (Phase 5/17).")
    parser.add_argument("--control", action="store_true")
    args = parser.parse_args(argv)

    cfg = common.load_study_config()
    exclusion = common.load_yaml(common.CONFIG_DIR / "exclusion-rules.yaml")
    inclusion = common.load_yaml(common.CONFIG_DIR / "inclusion-rules.yaml")
    cfg["_inclusion_hard_requirements"] = inclusion.get("hard_requirements", {})
    precedence = exclusion.get("precedence", [])
    interim = STUDY_ROOT / cfg["paths"]["interim"]
    processed = STUDY_ROOT / cfg["paths"]["processed"]

    cand_key = "repo_full_name" if args.control else "repository_full_name"
    candidates_path = (interim / "control" / "control-candidate-repositories.json") if args.control \
        else (interim / "claude-candidate-repositories.json")

    if not candidates_path.exists():
        print(f"ERROR: candidate table not found: {candidates_path}", file=sys.stderr)
        return 2

    base = interim / "control" if args.control else interim
    metadata = _index(base / "repository-metadata.json")
    classification = _index(base / "project-classification.json")
    loc = _index(base / "source-loc.json")
    attribution = _index(base / "attribution-verification.json")
    duplicates = _index(base / "duplicate-flags.json")   # Phase 16 (optional; absent => no EX_DUPLICATE)

    raw_candidates = common.read_json(candidates_path)
    candidates = [{"repository_full_name": c.get(cand_key) or c.get("repository_full_name")}
                  for c in raw_candidates]
    candidates = [c for c in candidates if c["repository_full_name"]]

    rows = screen_all(candidates, metadata, classification, loc, attribution,
                      cfg, precedence, duplicates=duplicates, control=args.control)
    funnel = build_funnel(rows)

    out_dir = processed / "control" if args.control else processed
    write_screening(rows, out_dir / "screening-results.json", out_dir / "screening-results.csv")
    write_excluded(rows, out_dir / "excluded-candidates.csv")
    common.atomic_write_json(out_dir / "eligibility-funnel.json", funnel)

    print(f"Screened {len(rows)} candidates -> {out_dir / 'screening-results.csv'}")
    print(f"  eligible (repository-side): {funnel['repository_eligible']}; "
          f"flagged for manual review: {funnel['flagged_manual_review']}")
    print(f"  funnel: {funnel}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
