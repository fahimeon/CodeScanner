#!/usr/bin/env python3
"""
workflow_status.py — cross-platform "what is built vs planned".

`make status` is only available where GNU Make is installed (not the default
Windows/PowerShell environment). This script is the portable equivalent:

    python scripts/workflow_status.py

It lists every phase script in pipeline order, marks each [built] or [planned]
by checking scripts/, and prints a coverage count. This is the authoritative
source of truth for pipeline completeness; the Makefile's ALL_PHASE_SCRIPTS is
kept in sync with the list below.
"""

from __future__ import annotations

import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent

# (script filename, phase label). Order = pipeline order (README section 7).
PHASE_SCRIPTS = [
    ("check_environment.py", "Phase 1  environment + manifest"),
    ("collect_candidates.py", "Phase 2  candidate discovery (+ --control)"),
    ("merge_candidates.py", "Phase 3  merge + deduplicate"),
    ("fetch_repository_metadata.py", "Phase 4  repository metadata"),
    ("verify_claude_attribution.py", "Phase 6  attribution + substantiality + reachability"),
    ("calculate_claude_contribution.py", "Phase 6  involvement metric (exploratory)"),
    ("classify_projects.py", "Phase 7  project type / framework / tech indicators"),
    ("calculate_loc.py", "Phase 8  relevant source LOC"),
    ("discover_deployments.py", "Phase 9-10  deployment URL discovery"),
    ("verify_deployments.py", "Phase 11-13  non-invasive availability"),
    ("verify_repository_deployment_match.py", "Phase 11-13  repo <-> deployment match"),
    ("detect_duplicates.py", "Phase 16  duplicate / template clustering"),
    ("screen_candidates.py", "Phase 5/17  eligibility screening"),
    ("freeze_population.py", "Phase 17  freeze eligible population + checksums"),
    ("select_sample.py", "Phase 18  select 500 (+ control matching)"),
    ("prepare_scanners.py", "Phase 19  build scanner image, prefetch/pin DBs, record digest"),
    ("clone_selected_repositories.py", "Phase 19  safe clone of selected repos"),
    ("run_gitleaks.py", "Phase 20-28  secrets scan"),
    ("run_semgrep.py", "Phase 20-28  source-code scan"),
    ("run_trivy.py", "Phase 20-28  deps / misconfig / secret scan"),
    ("run_osv_scanner.py", "Phase 20-28  dependency advisories"),
    ("run_zizmor.py", "Phase 20-28  GitHub Actions audit"),
    ("normalize_results.py", "Phase 29-30  normalize scanner output"),
    ("redact_secrets.py", "Phase 29-30  redact secret values"),
    ("classify_findings.py", "Phase 29-30  taxonomy classification"),
    ("deduplicate_findings.py", "Phase 32  cross-scanner dedup"),
    ("create_validation_sample.py", "Phase 33  sample findings for manual validation"),
    ("analyse_results.py", "Phase 35-36  statistics"),
    ("generate_figures.py", "Phase 37  figures"),
    ("generate_reports.py", "Phase 40  reports (+ --public-only dataset)"),
    ("cleanup_repositories.py", "cleanup  remove cloned repositories"),
]


def statuses() -> list[tuple[str, str, bool]]:
    return [(name, label, (SCRIPTS_DIR / name).is_file())
            for name, label in PHASE_SCRIPTS]


def main() -> int:
    rows = statuses()
    built = sum(1 for _, _, ok in rows if ok)
    total = len(rows)
    print("Pipeline phase-script status (authoritative):")
    print("-" * 72)
    for name, label, ok in rows:
        mark = "[built]  " if ok else "[planned]"
        print(f"  {mark} {name:<38} {label}")
    print("-" * 72)
    print(f"  {built} / {total} phase scripts implemented")
    if built < total:
        planned = ", ".join(n for n, _, ok in rows if not ok)
        print(f"  planned (not yet implemented): {planned}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
