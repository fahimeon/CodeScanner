#!/usr/bin/env python3
"""
merge_candidates.py — Phase 3 merge + deduplicate.

Loads the immutable raw gh-search dumps produced by collect_candidates.py,
deduplicates first by commit SHA then aggregates to one record per repository,
and writes the candidate tables.

Unit of analysis is the REPOSITORY. All logic here is pure/offline and unit
tested with synthetic raw dumps (tests/test_merge_candidates.py); no network.

Outputs (treated):
  data/interim/claude-candidate-repositories.json
  data/interim/claude-candidate-repositories.csv
Outputs (--control):
  data/interim/control/control-candidate-repositories.{json,csv}
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path
from typing import Iterable, Optional

try:
    from . import _common as common  # type: ignore
    from . import collect_candidates as collect  # type: ignore
except Exception:  # pragma: no cover
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _common as common  # type: ignore
    import collect_candidates as collect  # type: ignore

STUDY_ROOT = common.STUDY_ROOT

CANDIDATE_FIELDS = [
    "repository_full_name",
    "repository_url",
    "matching_commit_sha",
    "matching_commit_url",
    "matching_commit_date",
    "matching_attribution",
    "matching_commit_message",
    "number_of_claude_attributed_commits",
    "first_claude_commit_date",
    "last_claude_commit_date",
]


# =========================================================================== #
# PURE FUNCTIONS
# =========================================================================== #
def load_raw_commit_records(raw_dir: Path) -> list[dict]:
    """Parse every *.json dump in raw_dir into normalized commit records."""
    records: list[dict] = []
    for path in sorted(Path(raw_dir).glob("*.json")):
        text = path.read_text(encoding="utf-8")
        records.extend(collect.parse_commit_search_output(text))
    return records


def dedup_commits(records: Iterable[dict]) -> dict[str, dict]:
    """
    Deduplicate commit records by SHA. When the same SHA appears in multiple
    slices/signals, keep one record and UNION the detected attribution signals.
    """
    by_sha: dict[str, dict] = {}
    for rec in records:
        sha = rec.get("sha")
        if not sha:
            continue
        signals = set(collect.detect_signals(rec.get("commit_message")))
        if sha not in by_sha:
            merged = dict(rec)
            merged["_signals"] = signals
            by_sha[sha] = merged
        else:
            by_sha[sha]["_signals"] |= signals
            # keep earliest known commit_date if the existing one is missing
            if not by_sha[sha].get("commit_date") and rec.get("commit_date"):
                by_sha[sha]["commit_date"] = rec["commit_date"]
    return by_sha


def _min_date(dates: Iterable[Optional[str]]) -> Optional[str]:
    vals = sorted(d for d in dates if d)
    return vals[0] if vals else None


def _max_date(dates: Iterable[Optional[str]]) -> Optional[str]:
    vals = sorted(d for d in dates if d)
    return vals[-1] if vals else None


def aggregate_by_repo(deduped: dict[str, dict]) -> list[dict]:
    """
    Group deduplicated commits by repository and build one candidate record per
    repo. The representative matching commit is the earliest attributed commit.
    """
    repos: dict[str, list[dict]] = {}
    for rec in deduped.values():
        repos.setdefault(rec["repo_full_name"], []).append(rec)

    candidates: list[dict] = []
    for full_name, commits in sorted(repos.items()):
        dates = [c.get("commit_date") for c in commits]
        # representative = earliest by date (fall back to first if dates missing)
        dated = [c for c in commits if c.get("commit_date")]
        representative = (
            min(dated, key=lambda c: c["commit_date"]) if dated else commits[0]
        )
        signals: set[str] = set()
        for c in commits:
            signals |= set(c.get("_signals") or [])
        candidates.append({
            "repository_full_name": full_name,
            "repository_url": representative.get("repo_url"),
            "matching_commit_sha": representative.get("sha"),
            "matching_commit_url": representative.get("commit_url"),
            "matching_commit_date": representative.get("commit_date"),
            "matching_attribution": ",".join(sorted(signals)),
            "matching_commit_message": _trim(representative.get("commit_message")),
            "number_of_claude_attributed_commits": len(commits),
            "first_claude_commit_date": _min_date(dates),
            "last_claude_commit_date": _max_date(dates),
        })
    return candidates


def _trim(msg: Optional[str], limit: int = 500) -> str:
    """First line of the message, length-capped (avoid dumping large bodies)."""
    if not msg:
        return ""
    first = msg.splitlines()[0].strip()
    return first[:limit]


def build_candidates(raw_dir: Path) -> list[dict]:
    records = load_raw_commit_records(raw_dir)
    deduped = dedup_commits(records)
    return aggregate_by_repo(deduped)


# --------------------------------------------------------------------------- #
# Control cohort (repo-search dumps)
# --------------------------------------------------------------------------- #
def load_raw_repo_records(raw_dir: Path) -> list[dict]:
    records: list[dict] = []
    for path in sorted(Path(raw_dir).glob("*.json")):
        text = path.read_text(encoding="utf-8")
        records.extend(collect.parse_repo_search_output(text))
    return records


def dedup_control_repos(records: Iterable[dict]) -> list[dict]:
    """Deduplicate control repos by full name (keep first seen)."""
    seen: dict[str, dict] = {}
    for rec in records:
        name = rec.get("repo_full_name")
        if name and name not in seen:
            seen[name] = rec
    return list(seen.values())


# --------------------------------------------------------------------------- #
# Writers
# --------------------------------------------------------------------------- #
def write_candidates(candidates: list[dict], json_path: Path, csv_path: Path,
                     fields: list[str] = CANDIDATE_FIELDS) -> None:
    common.atomic_write_json(json_path, candidates)
    common.ensure_dir(Path(csv_path).parent)
    tmp = Path(csv_path).with_suffix(".csv.tmp")
    with tmp.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in candidates:
            writer.writerow(row)
    import os
    os.replace(tmp, csv_path)


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Merge + deduplicate candidate search dumps.")
    parser.add_argument("--control", action="store_true")
    args = parser.parse_args(argv)

    cfg = common.load_study_config()
    interim = STUDY_ROOT / cfg["paths"]["interim"]

    if args.control:
        raw_dir = STUDY_ROOT / cfg["paths"]["raw_search_control"]
        out_json = interim / "control" / "control-candidate-repositories.json"
        out_csv = interim / "control" / "control-candidate-repositories.csv"
        repos = dedup_control_repos(load_raw_repo_records(raw_dir))
        fields = ["repo_full_name", "repo_url", "created_at", "pushed_at",
                  "primary_language", "is_fork", "is_archived", "stars", "license"]
        write_candidates(repos, out_json, out_csv, fields=fields)
        print(f"Control candidates: {len(repos)} unique repositories -> {out_csv}")
        _report_saturated_leaves(interim / "control" / "search-slice-tree.json")
        return 0

    raw_dir = STUDY_ROOT / cfg["paths"]["raw_search"]
    out_json = interim / "claude-candidate-repositories.json"
    out_csv = interim / "claude-candidate-repositories.csv"
    candidates = build_candidates(raw_dir)
    write_candidates(candidates, out_json, out_csv)
    print(f"Treated candidates: {len(candidates)} unique repositories -> {out_csv}")
    _report_saturated_leaves(interim / "search-slice-tree.json")
    return 0


def _report_saturated_leaves(tree_path: Path) -> None:
    """Surface SATURATED_LEAF slices (capped single-day windows) from the slice
    tree so the merged pool's truncation/bias risk is not silently ignored."""
    if not tree_path.exists():
        return
    try:
        tree = common.read_json(tree_path)
    except Exception:
        return
    n = collect.count_saturated_leaves(tree)
    if n:
        print(f"WARNING: {n} SATURATED_LEAF slice(s) in {tree_path.name}: those single-day "
              f"windows hit the result cap and are likely truncated; the candidate pool for "
              f"those days may be biased. Report this in the funnel/limitations.")


if __name__ == "__main__":
    raise SystemExit(main())
