#!/usr/bin/env python3
"""
freeze_population.py — Phase 17 freeze the eligible population.

Joins every enrichment + decision table into one covariate row per
repository-side-eligible repository, then FREEZES the population by writing it
with a SHA-256 checksum. Selection (Phase 18) and scanning (Phase 20+) refuse to
run unless this frozen artifact exists — the population is fixed BEFORE any
sample is drawn or any scanner runs, and is NEVER re-derived from scan results.

Pure join + checksum logic split from I/O; unit-tested offline.

Outputs:
  data/processed/eligible-population.{json,csv}
  data/processed/eligible-population-checksum.txt     (the FROZEN marker)
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Optional

try:
    from . import _common as common  # type: ignore
except Exception:  # pragma: no cover
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _common as common  # type: ignore

STUDY_ROOT = common.STUDY_ROOT

POPULATION_FIELDS = [
    "repository_full_name",
    "owner",
    "repository_url",
    "frozen_commit_sha",
    "metadata_snapshot_hash",
    "configuration_hash",
    "repository_eligible",
    "deployed_eligible",
    "track",
    "size_bucket",
    "relevant_source_loc",
    "framework",
    "application_type",
    "involvement_band",
    "substantial_attribution",
    "deployment_provider",
    "deployment_evidence_level",
    "deployment_status",
    "repo_age_months",
    "last_push_age_days",
    "github_actions_present",
    "docker_present",
]


# =========================================================================== #
# PURE FUNCTIONS
# =========================================================================== #
def metadata_snapshot_hash(meta: dict) -> str:
    """Deterministic hash of the exact metadata record frozen for this repo."""
    return common.sha256_hex(json.dumps(meta or {}, sort_keys=True, ensure_ascii=False))


def config_bundle_hash() -> str:
    """Hash of ALL config files, so a frozen record is tied to the exact config."""
    return common.config_bundle_hash()


def build_population_record(full: str, screen: dict, track: dict, meta: dict,
                            cls: dict, loc: dict, contrib: dict,
                            provider: Optional[str], config_hash: str = "") -> dict:
    screen, track = screen or {}, track or {}
    meta, cls, loc, contrib = meta or {}, cls or {}, loc or {}, contrib or {}
    return {
        "repository_full_name": full,
        "owner": full.split("/", 1)[0],
        "repository_url": meta.get("repository_url") or f"https://github.com/{full}",
        "frozen_commit_sha": meta.get("default_branch_head_sha"),
        "metadata_snapshot_hash": metadata_snapshot_hash(meta),
        "configuration_hash": config_hash,
        "repository_eligible": bool(screen.get("repository_eligible")),
        "deployed_eligible": bool(track.get("final_deployment_eligible")),
        "track": track.get("track", "excluded"),
        "size_bucket": loc.get("size_bucket"),
        "relevant_source_loc": loc.get("relevant_source_loc"),
        "framework": cls.get("framework"),
        "application_type": cls.get("application_type"),
        "involvement_band": contrib.get("involvement_band"),
        "substantial_attribution": screen.get("substantial_attribution"),
        "deployment_provider": provider,
        "deployment_evidence_level": track.get("best_evidence_level"),
        "deployment_status": track.get("deployment_status"),
        "repo_age_months": meta.get("repo_age_months"),
        "last_push_age_days": meta.get("last_push_age_days"),
        "github_actions_present": cls.get("github_actions_present"),
        "docker_present": cls.get("docker_present"),
    }


def canonical_checksum(records: list[dict]) -> str:
    """Deterministic SHA-256 of the population (order- and key-independent)."""
    ordered = sorted(records, key=lambda r: r["repository_full_name"])
    blob = json.dumps(ordered, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return common.sha256_hex(blob)


def verify_population_integrity(population_path: Path,
                                checksum_json_path: Path) -> tuple[bool, str]:
    """CS-009: recompute the population checksum and COMPARE it to the frozen
    manifest value, instead of only checking that the marker file exists. Returns
    (ok, detail). ok is False if either file is missing/unreadable or the recomputed
    SHA-256 differs from the recorded one (i.e. the population was edited post-freeze)."""
    if not population_path.exists():
        return False, "population_missing"
    if not checksum_json_path.exists():
        return False, "checksum_manifest_missing"
    try:
        manifest = common.read_json(checksum_json_path)
        records = common.read_json(population_path)
    except Exception as exc:
        return False, f"unreadable:{type(exc).__name__}"
    recorded = manifest.get("population_sha256")
    recomputed = canonical_checksum(records)
    if not recorded:
        return False, "no_recorded_hash"
    if recorded != recomputed:
        return False, f"checksum_mismatch recorded={recorded[:12]}.. recomputed={recomputed[:12]}.."
    return True, recomputed


def build_checksum_manifest(records: list[dict], seed: int) -> dict:
    from collections import Counter
    deployed = [r for r in records if r["track"] == "deployed"]
    repo_only = [r for r in records if r["repository_eligible"]]
    return {
        "frozen_utc": common.iso_now(),
        "random_seed": seed,
        "checksum_algorithm": "sha256",
        "population_sha256": canonical_checksum(records),
        "deployed_population_sha256": canonical_checksum(deployed),
        "counts": {
            "eligible_total": len(records),
            "deployed_eligible": len(deployed),
            "repository_only_eligible": len(repo_only),
            "by_size_bucket": dict(Counter(r.get("size_bucket") for r in records)),
            "by_framework": dict(Counter(r.get("framework") for r in records)),
        },
    }


# =========================================================================== #
# WRITERS
# =========================================================================== #
def write_population(records: list[dict], json_path: Path, csv_path: Path) -> None:
    ordered = sorted(records, key=lambda r: r["repository_full_name"])
    common.atomic_write_json(json_path, ordered)
    common.ensure_dir(csv_path.parent)
    import os
    tmp = csv_path.with_suffix(".csv.tmp")
    with tmp.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=POPULATION_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for rec in ordered:
            writer.writerow(rec)
    os.replace(tmp, csv_path)


def write_checksum(manifest: dict, checksum_path: Path) -> None:
    common.atomic_write_json(checksum_path.with_suffix(".json"), manifest)
    # A plain-text marker (what the Makefile guard tests for).
    lines = [
        f"population_sha256={manifest['population_sha256']}",
        f"deployed_population_sha256={manifest['deployed_population_sha256']}",
        f"frozen_utc={manifest['frozen_utc']}",
        f"random_seed={manifest['random_seed']}",
        f"eligible_total={manifest['counts']['eligible_total']}",
        f"deployed_eligible={manifest['counts']['deployed_eligible']}",
    ]
    common.atomic_write_text(checksum_path, "\n".join(lines) + "\n")


# =========================================================================== #
# ORCHESTRATION
# =========================================================================== #
def freeze(candidates: list[dict], screening: dict, track: dict, metadata: dict,
           classification: dict, loc: dict, contribution: dict,
           providers: dict, seed: int) -> tuple[list[dict], dict]:
    """Build population records for repository-side-eligible repos, then freeze."""
    config_hash = config_bundle_hash()
    records: list[dict] = []
    seen: set[str] = set()
    for cand in candidates:
        full = cand.get("repository_full_name")
        if not full or full in seen:
            continue
        seen.add(full)
        screen = screening.get(full) or {}
        if not screen.get("repository_eligible"):
            continue                              # frozen population = eligible only
        records.append(build_population_record(
            full, screen, track.get(full), metadata.get(full),
            classification.get(full), loc.get(full), contribution.get(full),
            providers.get(full), config_hash))
    manifest = build_checksum_manifest(records, seed)
    manifest["configuration_hash"] = config_hash
    return records, manifest


# =========================================================================== #
# main
# =========================================================================== #
def _index(path: Path, key: str = "repository_full_name") -> dict[str, dict]:
    if not path.exists():
        return {}
    data = common.read_json(path)
    if isinstance(data, dict):
        data = data.get("records", [])
    return {r[key]: r for r in data if isinstance(r, dict) and r.get(key)}


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Freeze the eligible population (Phase 17).")
    parser.add_argument("--control", action="store_true")
    args = parser.parse_args(argv)

    cfg = common.load_study_config()
    seed = int(cfg.get("reproducibility", {}).get("random_seed", 20260711))
    interim = STUDY_ROOT / cfg["paths"]["interim"]
    processed = STUDY_ROOT / cfg["paths"]["processed"]
    private = STUDY_ROOT / cfg["paths"]["private"]
    bi = interim / "control" if args.control else interim
    bp = processed / "control" if args.control else processed
    bpriv = private / "control" if args.control else private
    key = "repo_full_name" if args.control else "repository_full_name"

    candidates_path = bi / ("control-candidate-repositories.json" if args.control
                            else "claude-candidate-repositories.json")
    screening_path = bp / "screening-results.json"
    if not candidates_path.exists() or not screening_path.exists():
        print("ERROR: need candidate + screening tables. Run 'make screen' first.", file=sys.stderr)
        return 2

    raw_candidates = common.read_json(candidates_path)
    candidates = [{"repository_full_name": c.get(key) or c.get("repository_full_name")}
                  for c in raw_candidates]
    candidates = [c for c in candidates if c["repository_full_name"]]

    screening = _index(screening_path)
    track = _index(bp / "track-assignment.json")
    metadata = _index(bi / "repository-metadata.json")
    classification = _index(bi / "project-classification.json")
    loc = _index(bi / "source-loc.json")
    contribution = _index(bi / "claude-contribution.json")
    # Provider tag (safe covariate) from the private discovery table.
    discovery = _index(bpriv / "deployment-discovery.json")
    providers = {k: v.get("primary_provider") for k, v in discovery.items()}

    records, manifest = freeze(candidates, screening, track, metadata, classification,
                               loc, contribution, providers, seed)

    # Two-check deployment policy (audit #8): a DEPLOYED-track repo must pass BOTH
    # the screening (first) and pre-freeze (second) checks. The second check is
    # independent (its own cache). A deployed repo lacking a passing two-check is
    # downgraded to repository_only (deployment gate not satisfied twice).
    try:
        from . import verify_deployments as vdep  # type: ignore
    except Exception:  # pragma: no cover
        import verify_deployments as vdep  # type: ignore
    first = _index(bpriv / "deployment-verification-first.json")
    second = _index(bpriv / "deployment-verification-second.json")
    downgraded = 0
    for r in records:
        if r.get("track") == "deployed":
            full = r["repository_full_name"]
            if not vdep.two_check_passed(first.get(full), second.get(full)):
                r["track"] = "repository_only"
                r["deployed_eligible"] = False
                r["two_check_downgraded"] = True
                downgraded += 1
    if downgraded:
        print(f"  two-check policy: {downgraded} deployed repo(s) downgraded to "
              f"repository_only (did not pass both deployment checks).")

    # Manual-review gate (audit #10): refuse to freeze while any eligible repo is
    # still PENDING; drop human-EXCLUDEd repos.
    try:
        from . import resolve_manual_review as mrv  # type: ignore
    except Exception:  # pragma: no cover
        import resolve_manual_review as mrv  # type: ignore
    decisions = mrv.read_decisions(bp / "manual-review-decisions.csv")
    records, pending = mrv.apply_decisions(records, decisions)
    if pending:
        print("REFUSING TO FREEZE: unresolved manual-review (PENDING) cases:", file=sys.stderr)
        for full in pending[:50]:
            print(f"  {full}", file=sys.stderr)
        print("Resolve each to INCLUDE/EXCLUDE in manual-review-decisions.csv "
              "(run 'make resolve-review'), then re-freeze.", file=sys.stderr)
        return 2
    manifest = build_checksum_manifest(records, seed)
    manifest["configuration_hash"] = config_bundle_hash()

    write_population(records, bp / "eligible-population.json", bp / "eligible-population.csv")
    write_checksum(manifest, bp / "eligible-population-checksum.txt")

    print(f"Frozen eligible population: {manifest['counts']['eligible_total']} repositories "
          f"(deployed-eligible: {manifest['counts']['deployed_eligible']}).")
    print(f"  population sha256: {manifest['population_sha256'][:16]}… -> {bp / 'eligible-population-checksum.txt'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
