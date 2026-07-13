#!/usr/bin/env python3
"""
select_sample.py — Phase 18 sample selection + control matching.

Draws the study samples from the FROZEN eligible population (Phase 17):
  * deployed track: up to target_n, stratified by (size_bucket, framework),
  * repository_only track: up to target_n from repo-eligible repos that failed
    only the deployment gate,
with a fixed seed, a per-owner cap (diversity guard), and anonymous IDs. Then
matches each treated unit 1:1 to a non-Claude control (exact on size stratum +
framework where possible, else relaxed / nearest-age), reporting the achieved
match rate. Selection happens BEFORE any scan and is NEVER changed by scan
results; if a track is short of target it is REPORTED, never back-filled by
weakening criteria.

Pure sampling/matching logic split from I/O; unit-tested offline (deterministic).

Outputs:
  data/processed/selected-500-repositories.csv     (deployed track; SELECTED marker)
  data/processed/selected-repository-only.csv
  data/processed/control-matches.csv
  data/processed/selection-report.json
"""

from __future__ import annotations

import argparse
import csv
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
STRATA_KEYS = ("size_bucket", "framework")


# =========================================================================== #
# PURE FUNCTIONS
# =========================================================================== #
def _owner(full: str) -> str:
    return full.split("/", 1)[0]


def _allocate_quotas(strata: dict, target: int) -> dict:
    total = sum(len(v) for v in strata.values())
    if total == 0:
        return {}
    quotas = {k: int(target * len(v) / total) for k, v in strata.items()}
    remainder = target - sum(quotas.values())
    # Give the remainder to the largest strata first (deterministic tie-break).
    for k in sorted(strata, key=lambda k: (-len(strata[k]), str(k))):
        if remainder <= 0:
            break
        quotas[k] += 1
        remainder -= 1
    return quotas


def stratified_sample(pool: list[dict], target_n: int, seed: int,
                      max_per_owner: int, strata_keys=STRATA_KEYS) -> list[dict]:
    """Deterministic stratified sample respecting a per-owner cap. Returns up to
    target_n records (fewer if the cap/pool size makes target infeasible)."""
    rng = random.Random(seed)
    strata: dict = {}
    for r in sorted(pool, key=lambda r: r["repository_full_name"]):
        key = tuple(r.get(s) for s in strata_keys)
        strata.setdefault(key, []).append(r)
    for k in strata:
        rng.shuffle(strata[k])

    total = sum(len(v) for v in strata.values())
    if total == 0:
        return []
    target = min(target_n, total)
    quotas = _allocate_quotas(strata, target)

    selected: list[dict] = []
    owner_count: dict[str, int] = {}
    leftovers: list[dict] = []

    for key, items in strata.items():
        picked = 0
        for r in items:
            owner = _owner(r["repository_full_name"])
            if picked >= quotas.get(key, 0) or owner_count.get(owner, 0) >= max_per_owner:
                leftovers.append(r)
                continue
            selected.append(dict(r))
            owner_count[owner] = owner_count.get(owner, 0) + 1
            picked += 1

    # Top up toward target from leftovers (still honoring the per-owner cap).
    for r in leftovers:
        if len(selected) >= target:
            break
        owner = _owner(r["repository_full_name"])
        if owner_count.get(owner, 0) >= max_per_owner:
            continue
        selected.append(dict(r))
        owner_count[owner] = owner_count.get(owner, 0) + 1

    # Per-stratum inclusion probability (selected / stratum size) on each record.
    from collections import Counter
    stratum_size = {k: len(v) for k, v in strata.items()}
    chosen = Counter(tuple(r.get(s) for s in strata_keys) for r in selected)
    for r in selected:
        k = tuple(r.get(s) for s in strata_keys)
        r["selection_probability"] = (round(chosen[k] / stratum_size[k], 4)
                                      if stratum_size.get(k) else None)
    return selected


def assign_anonymous_ids(records: list[dict], prefix: str, width: int) -> list[dict]:
    out = []
    for i, r in enumerate(sorted(records, key=lambda r: r["repository_full_name"]), start=1):
        row = dict(r)
        row["anonymous_id"] = f"{prefix}-{str(i).zfill(width)}"
        out.append(row)
    return out


def match_controls(treated: list[dict], control_pool: list[dict], seed: int,
                   strata_keys=STRATA_KEYS) -> list[dict]:
    """1:1 nearest-neighbour control matching. Exact (size+framework) first, then
    relaxed (size only / framework only), then nearest repo-age; else unmatched."""
    rng = random.Random(seed)
    controls = sorted(control_pool, key=lambda r: r["repository_full_name"])
    rng.shuffle(controls)
    used: set[str] = set()

    def _available():
        return [c for c in controls if c["repository_full_name"] not in used]

    matches: list[dict] = []
    for t in sorted(treated, key=lambda r: r["repository_full_name"]):
        tkey = tuple(t.get(s) for s in strata_keys)
        chosen, quality = None, "unmatched"
        avail = _available()
        for c in avail:
            if tuple(c.get(s) for s in strata_keys) == tkey:
                chosen, quality = c, "exact"
                break
        if not chosen:
            for c in avail:
                if c.get("size_bucket") == t.get("size_bucket"):
                    chosen, quality = c, "size_only"
                    break
        if not chosen:
            for c in avail:
                if c.get("framework") == t.get("framework"):
                    chosen, quality = c, "framework_only"
                    break
        if not chosen and avail:
            ta = t.get("repo_age_months") or 0
            chosen = min(avail, key=lambda c: abs((c.get("repo_age_months") or 0) - ta))
            quality = "nearest_age"
        if chosen:
            used.add(chosen["repository_full_name"])
        matches.append({
            "treated_repository": t["repository_full_name"],
            "treated_id": t.get("anonymous_id"),
            "control_repository": chosen["repository_full_name"] if chosen else None,
            "match_quality": quality,
        })
    return matches


def selection_report(deployed: list[dict], repo_only: list[dict],
                     matches: list[dict], targets: dict) -> dict:
    from collections import Counter
    matched = sum(1 for m in matches if m["control_repository"])
    return {
        "generated_utc": common.iso_now(),
        "deployed": {"target": targets.get("deployed"), "selected": len(deployed),
                     "shortfall": max(0, (targets.get("deployed") or 0) - len(deployed)),
                     "by_size_bucket": dict(Counter(r.get("size_bucket") for r in deployed))},
        "repository_only": {"target": targets.get("repository_only"),
                            "selected": len(repo_only),
                            "shortfall": max(0, (targets.get("repository_only") or 0) - len(repo_only))},
        "control_matching": {"treated_to_match": len(matches), "matched": matched,
                             "match_rate": round(matched / len(matches), 4) if matches else None,
                             "by_quality": dict(Counter(m["match_quality"] for m in matches))},
    }


# =========================================================================== #
# WRITERS
# =========================================================================== #
def _write_csv(path: Path, records: list[dict], fields: list[str]) -> None:
    import os
    common.ensure_dir(path.parent)
    tmp = path.with_suffix(".csv.tmp")
    with tmp.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for rec in records:
            writer.writerow(rec)
    os.replace(tmp, path)


SELECTED_FIELDS = ["anonymous_id", "repository_full_name", "owner", "repository_url",
                   "frozen_commit_sha", "metadata_snapshot_hash", "configuration_hash",
                   "track", "size_bucket", "framework", "application_type",
                   "involvement_band", "deployment_provider", "deployment_evidence_level",
                   "relevant_source_loc", "repo_age_months",
                   "selection_seed", "selection_timestamp", "selection_probability"]
MATCH_FIELDS = ["treated_id", "treated_repository", "control_repository", "match_quality"]


# =========================================================================== #
# ORCHESTRATION
# =========================================================================== #
def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Select samples + match controls (Phase 18).")
    parser.parse_args(argv)

    cfg = common.load_study_config()
    seed = int(cfg.get("reproducibility", {}).get("random_seed", 20260711))
    tracks = cfg.get("tracks", {})
    anon = cfg.get("anonymization", {})
    max_per_owner = int(cfg.get("sampling", {}).get("max_repos_per_owner", 2))
    processed = STUDY_ROOT / cfg["paths"]["processed"]

    frozen = processed / "eligible-population-checksum.txt"
    population_path = processed / "eligible-population.json"
    if not frozen.exists() or not population_path.exists():
        print("REFUSING TO SELECT: population not frozen. Run 'make freeze' first.",
              file=sys.stderr)
        return 2

    population = common.read_json(population_path)
    deployed_pool = [r for r in population if r.get("track") == "deployed"]
    repo_only_pool = [r for r in population
                      if r.get("repository_eligible") and r.get("track") == "repository_only"]

    deployed_target = int(tracks.get("deployed", {}).get("target_n", 500))
    repo_only_target = int(tracks.get("repository_only", {}).get("target_n", 500))

    width = int(anon.get("id_width", 4))
    # Globally-unique prefixes across tracks (audit #12): deployed vs repository-only.
    deployed = assign_anonymous_ids(
        stratified_sample(deployed_pool, deployed_target, seed, max_per_owner),
        anon.get("treated_id_prefix", "CLR"), width)
    repo_only = assign_anonymous_ids(
        stratified_sample(repo_only_pool, repo_only_target, seed + 1, max_per_owner),
        anon.get("repository_only_id_prefix", "CLO"), width)

    # Stamp run-level selection provenance onto each selected record.
    selection_ts = common.iso_now()
    for rec in deployed + repo_only:
        rec["selection_seed"] = seed
        rec["selection_timestamp"] = selection_ts

    # Control pool from the control-cohort frozen population, if present.
    control_pop_path = processed / "control" / "eligible-population.json"
    control_pool = common.read_json(control_pop_path) if control_pop_path.exists() else []
    control_pool = [r for r in control_pool if r.get("repository_eligible")]
    matches = match_controls(deployed, control_pool, seed)

    _write_csv(processed / "selected-500-repositories.csv", deployed, SELECTED_FIELDS)
    _write_csv(processed / "selected-repository-only.csv", repo_only, SELECTED_FIELDS)
    _write_csv(processed / "control-matches.csv", matches, MATCH_FIELDS)
    report = selection_report(deployed, repo_only, matches,
                              {"deployed": deployed_target, "repository_only": repo_only_target})
    common.atomic_write_json(processed / "selection-report.json", report)

    print(f"Selected deployed: {len(deployed)}/{deployed_target}; "
          f"repository_only: {len(repo_only)}/{repo_only_target}.")
    if not control_pool:
        print("  NOTE: no control population found (run the control pipeline + 'make freeze' "
              "with --control); control matching skipped.")
    else:
        print(f"  control match rate: {report['control_matching']['match_rate']} "
              f"({report['control_matching']['by_quality']})")
    if report["deployed"]["shortfall"]:
        print(f"  DEPLOYED SHORTFALL: {report['deployed']['shortfall']} short of target "
              f"— reported, NOT back-filled (criteria never weakened).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
