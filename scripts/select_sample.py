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
    from . import freeze_population as fp  # type: ignore
except Exception:  # pragma: no cover
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _common as common  # type: ignore
    import freeze_population as fp  # type: ignore

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


DEFAULT_EXACT_COVARIATES = ("size_bucket", "framework", "application_type", "deployment_provider")


def compute_smd(treated_vals: list, control_vals: list) -> Optional[float]:
    """Standardised mean difference between two numeric groups (covariate balance)."""
    tv = [float(v) for v in treated_vals if isinstance(v, (int, float))]
    cv = [float(v) for v in control_vals if isinstance(v, (int, float))]
    if not tv or not cv:
        return None
    mt, mc = sum(tv) / len(tv), sum(cv) / len(cv)
    var_t = sum((x - mt) ** 2 for x in tv) / len(tv)
    var_c = sum((x - mc) ** 2 for x in cv) / len(cv)
    pooled = ((var_t + var_c) / 2) ** 0.5
    return round((mt - mc) / pooled, 4) if pooled else (0.0 if mt == mc else None)


def match_controls(treated: list[dict], control_pool: list[dict], seed: int,
                   *, exact_covariates=DEFAULT_EXACT_COVARIATES, age_caliper_months: float = 6.0,
                   require_control_deployment: bool = True) -> list[dict]:
    """1:1 matching with a PREDECLARED caliper: a control must match EVERY exact
    covariate, be within the repo-age caliper, and (for the deployed cohort) have
    a verified deployment. Nearest age within the caliper wins. No silent relaxing
    beyond the protocol: if nothing qualifies, the treated unit is unmatched with a
    reason. Records distance + match quality."""
    rng = random.Random(seed)
    controls = sorted(control_pool, key=lambda r: r["repository_full_name"])
    rng.shuffle(controls)
    used: set[str] = set()

    matches: list[dict] = []
    for t in sorted(treated, key=lambda r: r["repository_full_name"]):
        ta = t.get("repo_age_months")
        candidates = []
        strata_pool = 0
        for c in controls:
            if c["repository_full_name"] in used:
                continue
            if require_control_deployment and not (c.get("deployed_eligible")
                                                   or c.get("track") == "deployed"):
                continue
            if any(c.get(k) != t.get(k) for k in exact_covariates):
                continue
            strata_pool += 1
            ca = c.get("repo_age_months")
            if ta is None or ca is None:
                dist = None
            else:
                dist = abs(ca - ta)
                if dist > age_caliper_months:
                    continue
            candidates.append((c, dist))

        chosen, distance, quality, reason = None, None, "unmatched", None
        if candidates:
            chosen, distance = min(candidates, key=lambda cd: (cd[1] is None, cd[1] or 0.0))
            quality = "exact_strata_within_caliper"
            used.add(chosen["repository_full_name"])
        else:
            reason = ("no_control_in_strata" if strata_pool == 0
                      else "no_control_within_age_caliper")
        matches.append({
            "treated_repository": t["repository_full_name"],
            "treated_id": t.get("anonymous_id"),
            "control_repository": chosen["repository_full_name"] if chosen else None,
            "match_quality": quality,
            "distance_age_months": distance,
            "unmatched_reason": reason,
        })
    return matches


def balance_report(treated: list[dict], control_pool: list[dict], matches: list[dict],
                   covariates=("repo_age_months", "relevant_source_loc")) -> dict:
    """Pre-match (all treated vs all controls) and post-match (matched pairs) SMD."""
    ctrl_by_name = {c["repository_full_name"]: c for c in control_pool}
    t_by_name = {t["repository_full_name"]: t for t in treated}
    matched = [(t_by_name[m["treated_repository"]], ctrl_by_name[m["control_repository"]])
               for m in matches if m.get("control_repository") in ctrl_by_name
               and m["treated_repository"] in t_by_name]
    out = {}
    for cov in covariates:
        pre = compute_smd([t.get(cov) for t in treated], [c.get(cov) for c in control_pool])
        post = compute_smd([t.get(cov) for t, _ in matched], [c.get(cov) for _, c in matched])
        out[cov] = {"smd_pre_match": pre, "smd_post_match": post}
    return out


def selection_report(deployed: list[dict], repo_only: list[dict],
                     matches: list[dict], targets: dict, balance: Optional[dict] = None) -> dict:
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
        "control_matching": {
            "treated_to_match": len(matches), "matched": matched,
            "match_rate": round(matched / len(matches), 4) if matches else None,
            "by_quality": dict(Counter(m["match_quality"] for m in matches)),
            "unmatched_reasons": dict(Counter(m.get("unmatched_reason") for m in matches
                                              if m.get("unmatched_reason"))),
        },
        "covariate_balance": balance or {},
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
MATCH_FIELDS = ["treated_id", "treated_repository", "control_repository", "match_quality",
                "distance_age_months", "unmatched_reason"]
# PUBLIC table: anonymous id + design covariates ONLY — no identities (audit #12).
PUBLIC_FIELDS = ["anonymous_id", "track", "size_bucket", "framework", "application_type",
                 "involvement_band", "deployment_provider", "deployment_evidence_level",
                 "relevant_source_loc", "repo_age_months", "selection_probability"]


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

    # CS-009: verify the frozen checksum is still VALID (population unedited since
    # freeze), not merely that the marker file exists.
    ok, detail = fp.verify_population_integrity(
        population_path, processed / "eligible-population-checksum.json")
    if not ok:
        print(f"REFUSING TO SELECT: frozen population integrity check failed ({detail}). "
              f"Re-run 'make freeze'.", file=sys.stderr)
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
    m_cfg = cfg.get("control_cohort", {}).get("matching", {})
    caliper = float(m_cfg.get("age_caliper_months", 6))
    exact_cov = tuple(m_cfg.get("exact_covariates", DEFAULT_EXACT_COVARIATES))
    matches = match_controls(deployed, control_pool, seed, exact_covariates=exact_cov,
                             age_caliper_months=caliper,
                             require_control_deployment=bool(
                                 m_cfg.get("require_control_deployment_for_deployed", True)))
    balance = balance_report(deployed, control_pool, matches,
                             tuple(m_cfg.get("balance_covariates", ("repo_age_months",
                                                                    "relevant_source_loc"))))

    report = selection_report(deployed, repo_only, matches,
                              {"deployed": deployed_target, "repository_only": repo_only_target},
                              balance)

    # TARGET POLICY (audit #12): exact_or_refuse aborts on shortfall without
    # writing the SELECTED marker; up_to_target proceeds and reports the shortfall.
    policy = cfg.get("sampling", {}).get("target_policy", "up_to_target")
    if policy == "exact_or_refuse" and (report["deployed"]["shortfall"]
                                        or report["repository_only"]["shortfall"]):
        print(f"REFUSING TO SELECT (exact_or_refuse): deployed "
              f"{len(deployed)}/{deployed_target}, repository_only "
              f"{len(repo_only)}/{repo_only_target}. Criteria are never weakened; "
              f"switch sampling.target_policy to 'up_to_target' to accept a shortfall.",
              file=sys.stderr)
        common.atomic_write_json(processed / "selection-report.json", report)
        return 2

    _write_csv(processed / "selected-500-repositories.csv", deployed, SELECTED_FIELDS)
    _write_csv(processed / "selected-repository-only.csv", repo_only, SELECTED_FIELDS)
    _write_csv(processed / "control-matches.csv", matches, MATCH_FIELDS)
    # PUBLIC tables: covariates + anonymous ids only (no identities).
    public_dir = STUDY_ROOT / cfg["paths"]["public"]
    _write_csv(public_dir / "selected-deployed-public.csv", deployed, PUBLIC_FIELDS)
    _write_csv(public_dir / "selected-repository-only-public.csv", repo_only, PUBLIC_FIELDS)
    common.atomic_write_json(processed / "selection-report.json", report)

    print(f"Selected deployed: {len(deployed)}/{deployed_target}; "
          f"repository_only: {len(repo_only)}/{repo_only_target} (policy={policy}).")
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
