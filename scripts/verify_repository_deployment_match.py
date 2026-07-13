#!/usr/bin/env python3
"""
verify_repository_deployment_match.py — Phase 11-13 correspondence + track split.

Decides whether a reachable deployment CORRESPONDS to its repository (using only
non-invasive signals captured in Phase 11-13 availability: a link back to the
repo on the page, the project name appearing on the page, or GitHub deployment
metadata for Level A), and assigns each repository to a TRACK:

  deployed          repository-side eligible AND a corresponding, reachable
                    deployment at evidence level A/B/C
  repository_only   repository-side eligible but fails the deployment gate
  excluded          not repository-side eligible

The deployment-commit relationship is UNKNOWN for most providers (they do not
expose the deployed SHA) — reported honestly, never guessed.

Pure `finalize_match` split from I/O; unit-tested offline.

Outputs:
  data/private/deployment-eligibility.{json,csv}   (per-repo, has status)
  data/processed/track-assignment.{json,csv}       (URL-free track + funnel)
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
INCLUSION_LEVELS = {"A", "B", "C"}

MATCH_FIELDS = [
    "repository_full_name",
    "repository_side_eligible",
    "best_evidence_level",
    "deployment_status",
    "availability_eligible",
    "correspondence_signals",
    "corresponds",
    "final_deployment_eligible",
    "deployment_commit_relationship",
    "track",
]
_LIST_FIELDS = {"correspondence_signals"}
TRACK_FIELDS = ["repository_full_name", "repository_side_eligible", "track",
                "best_evidence_level", "deployment_status", "final_deployment_eligible"]


# =========================================================================== #
# PURE LOGIC
# =========================================================================== #
def correspondence_signals(verify: dict) -> list[str]:
    signals: list[str] = []
    if verify.get("best_evidence_level") == "A":
        signals.append("github_deployment_metadata")
    if verify.get("repo_link_found"):
        signals.append("repository_link_on_deployed_page")
    if verify.get("name_in_page"):
        signals.append("matching_project_name")
    return signals


def compute_commit_relationship(deployed_sha, reference_sha, is_ancestor=None) -> str:
    """Relationship of the deployed commit to the repo's reference commit.

    Returns EXACT_COMMIT / DEPLOYED_COMMIT_IS_ANCESTOR / DEPLOYED_COMMIT_IS_DESCENDANT
    / DIFFERENT_BRANCH / UNKNOWN. Stays UNKNOWN when the deployed SHA is unavailable
    (the common case) or when no ancestry oracle is provided. `is_ancestor(a, b)`
    must return True iff commit a is an ancestor of commit b. NEVER guesses.
    """
    if not deployed_sha or not reference_sha:
        return "UNKNOWN"
    if deployed_sha == reference_sha:
        return "EXACT_COMMIT"
    if is_ancestor is None:
        return "UNKNOWN"                      # cannot decide without the git graph
    if is_ancestor(deployed_sha, reference_sha):
        return "DEPLOYED_COMMIT_IS_ANCESTOR"
    if is_ancestor(reference_sha, deployed_sha):
        return "DEPLOYED_COMMIT_IS_DESCENDANT"
    return "DIFFERENT_BRANCH"


def finalize_match(full_name: str, verify: Optional[dict], screen: Optional[dict],
                   reference_sha: Optional[str] = None, is_ancestor=None) -> dict:
    """Combine availability + correspondence + repository-side eligibility into a
    track. Never invents a deployment: missing verification => repository_only/excluded."""
    repo_eligible = bool((screen or {}).get("repository_eligible"))
    verify = verify or {}
    level = verify.get("best_evidence_level")
    avail_eligible = bool(verify.get("availability_eligible"))
    relationship = compute_commit_relationship(
        verify.get("deployment_sha"), reference_sha, is_ancestor)

    signals = correspondence_signals(verify)
    # minimum_signals_required = 1 (Level A implies metadata; B/C need >=1 extra,
    # which for B/C can only be a non-metadata signal since metadata is A-only).
    corresponds = len(signals) >= 1
    final_deployment_eligible = bool(
        avail_eligible and corresponds and (level in INCLUSION_LEVELS))

    if final_deployment_eligible and repo_eligible:
        track = "deployed"
    elif repo_eligible:
        track = "repository_only"
    else:
        track = "excluded"

    return {
        "repository_full_name": full_name,
        "repository_side_eligible": repo_eligible,
        "best_evidence_level": level,
        "deployment_status": verify.get("deployment_status"),
        "availability_eligible": avail_eligible,
        "correspondence_signals": signals,
        "corresponds": corresponds,
        "final_deployment_eligible": final_deployment_eligible,
        "deployment_commit_relationship": relationship,   # UNKNOWN unless a deployed SHA is known
        "track": track,
    }


def build_track_funnel(records: list[dict]) -> dict:
    from collections import Counter
    tracks = Counter(r["track"] for r in records)
    return {
        "total": len(records),
        "repository_side_eligible": sum(1 for r in records if r["repository_side_eligible"]),
        "deployed": tracks.get("deployed", 0),
        "repository_only": tracks.get("repository_only", 0),
        "excluded": tracks.get("excluded", 0),
        "corresponding_deployments": sum(1 for r in records if r["corresponds"]),
    }


# =========================================================================== #
# WRITERS
# =========================================================================== #
def _row(rec: dict) -> dict:
    row = dict(rec)
    for field in _LIST_FIELDS:
        if isinstance(row.get(field), list):
            row[field] = ";".join(row[field])
    return row


def _write_csv(path: Path, records: list[dict], fields: list[str]) -> None:
    common.ensure_dir(path.parent)
    tmp = path.with_suffix(".csv.tmp")
    with tmp.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for rec in records:
            writer.writerow(_row(rec))
    os.replace(tmp, path)


def write_match(records: list[dict], private_json: Path, private_csv: Path,
                track_json: Path, track_csv: Path) -> None:
    common.atomic_write_json(private_json, records)
    _write_csv(private_csv, records, MATCH_FIELDS)
    _write_csv(track_csv, records, TRACK_FIELDS)          # URL-free
    common.atomic_write_json(track_json, build_track_funnel(records))


# =========================================================================== #
# ORCHESTRATION
# =========================================================================== #
def match_all(verification: dict[str, dict], screening: dict[str, dict]) -> list[dict]:
    rows: list[dict] = []
    for full in sorted(set(verification) | set(screening)):
        rows.append(finalize_match(full, verification.get(full), screening.get(full)))
    return rows


def _index(path: Path, key: str = "repository_full_name") -> dict[str, dict]:
    if not path.exists():
        return {}
    return {r[key]: r for r in common.read_json(path)
            if isinstance(r, dict) and r.get(key)}


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Repository<->deployment match + track (Phase 11-13).")
    parser.add_argument("--control", action="store_true")
    args = parser.parse_args(argv)

    cfg = common.load_study_config()
    private = STUDY_ROOT / cfg["paths"]["private"]
    processed = STUDY_ROOT / cfg["paths"]["processed"]
    base_private = private / "control" if args.control else private
    base_processed = processed / "control" if args.control else processed

    verification_path = base_private / "deployment-verification.json"
    screening_path = base_processed / "screening-results.json"
    if not verification_path.exists() or not screening_path.exists():
        print("ERROR: need deployment-verification and screening-results. "
              "Run 'make verify-deployments' and 'make screen' first.", file=sys.stderr)
        return 2

    verification = _index(verification_path)
    screening = _index(screening_path)
    rows = match_all(verification, screening)

    write_match(rows,
                base_private / "deployment-eligibility.json",
                base_private / "deployment-eligibility.csv",
                base_processed / "track-assignment.json",
                base_processed / "track-assignment.csv")

    funnel = build_track_funnel(rows)
    print(f"Track assignment for {len(rows)} repositories -> {base_processed / 'track-assignment.csv'}")
    print(f"  deployed: {funnel['deployed']}; repository_only: {funnel['repository_only']}; "
          f"excluded: {funnel['excluded']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
