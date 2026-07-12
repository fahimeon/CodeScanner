"""Unit tests for merge_candidates.py — dedup + repo aggregation (offline)."""

import csv
from pathlib import Path

import merge_candidates as mc

FIXTURES = Path(__file__).resolve().parent / "fixtures"
RAW_SEARCH = FIXTURES / "raw_search"
RAW_REPO = FIXTURES / "raw_repo"


# --------------------------------------------------------------------------- #
# Loading + dedup
# --------------------------------------------------------------------------- #
def test_load_raw_commit_records_reads_all_files():
    recs = mc.load_raw_commit_records(RAW_SEARCH)
    # anthropic_email file: 3 valid; generated file: 2 -> 5 total (pre-dedup).
    assert len(recs) == 5


def test_dedup_commits_unions_signals_across_files():
    recs = mc.load_raw_commit_records(RAW_SEARCH)
    deduped = mc.dedup_commits(recs)
    # sha 1111... appears in BOTH files with different signals -> unioned.
    key = "1111111111111111111111111111111111111111"
    assert key in deduped
    assert deduped[key]["_signals"] == {"anthropic_email", "generated_claude_code"}
    # 5 raw records, one shared sha -> 4 unique commits.
    assert len(deduped) == 4


# --------------------------------------------------------------------------- #
# Aggregation to one record per repository
# --------------------------------------------------------------------------- #
def test_aggregate_by_repo_counts_and_dates_and_attribution():
    candidates = mc.build_candidates(RAW_SEARCH)
    by_repo = {c["repository_full_name"]: c for c in candidates}

    # Two repositories total: octo/alpha-app and hubber/beta-site.
    assert set(by_repo) == {"octo/alpha-app", "hubber/beta-site"}

    alpha = by_repo["octo/alpha-app"]
    # alpha has SHAs 1111, 2222, 4444 -> 3 attributed commits.
    assert alpha["number_of_claude_attributed_commits"] == 3
    # Attribution union across the repo's commits.
    assert alpha["matching_attribution"] == "anthropic_email,generated_claude_code"
    # Representative = earliest commit (4444 @ 2025-03-02).
    assert alpha["matching_commit_sha"] == "4444444444444444444444444444444444444444"
    assert alpha["matching_commit_date"] == "2025-03-02T08:00:00Z"
    # First/last span.
    assert alpha["first_claude_commit_date"] == "2025-03-02T08:00:00Z"
    assert alpha["last_claude_commit_date"] == "2025-03-12T09:30:00Z"

    beta = by_repo["hubber/beta-site"]
    assert beta["number_of_claude_attributed_commits"] == 1
    assert beta["repository_url"] == "https://github.com/hubber/beta-site"


def test_message_is_trimmed_to_first_line():
    candidates = mc.build_candidates(RAW_SEARCH)
    for c in candidates:
        assert "\n" not in c["matching_commit_message"]


# --------------------------------------------------------------------------- #
# Control cohort dedup
# --------------------------------------------------------------------------- #
def test_control_repo_dedup():
    repos = mc.dedup_control_repos(mc.load_raw_repo_records(RAW_REPO))
    names = sorted(r["repo_full_name"] for r in repos)
    # acme/ts-store appears twice in the fixture -> deduped to one.
    assert names == ["acme/ts-store", "widgets/dash"]


# --------------------------------------------------------------------------- #
# End-to-end write (CSV + JSON), atomic
# --------------------------------------------------------------------------- #
def test_write_candidates_roundtrip(tmp_path):
    candidates = mc.build_candidates(RAW_SEARCH)
    out_json = tmp_path / "cand.json"
    out_csv = tmp_path / "cand.csv"
    mc.write_candidates(candidates, out_json, out_csv)

    assert out_json.exists() and out_csv.exists()
    # No leftover temp files.
    assert not list(tmp_path.glob("*.tmp"))
    # CSV header matches the canonical field list.
    with out_csv.open(encoding="utf-8") as fh:
        header = next(csv.reader(fh))
    assert header == mc.CANDIDATE_FIELDS
