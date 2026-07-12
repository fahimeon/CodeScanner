"""Unit tests for select_sample.py — stratified sampling + control matching (offline)."""

import select_sample as ss


def _repo(name, size="small", fw="next", owner=None, age=12.0):
    return {"repository_full_name": name, "size_bucket": size, "framework": fw,
            "repo_age_months": age}


# --------------------------------------------------------------------------- #
# Stratified sampling
# --------------------------------------------------------------------------- #
def test_sample_is_deterministic_for_seed():
    pool = [_repo(f"o/r{i}", size=("small" if i % 2 else "large")) for i in range(30)]
    a = ss.stratified_sample(pool, 10, seed=20260711, max_per_owner=99)
    b = ss.stratified_sample(pool, 10, seed=20260711, max_per_owner=99)
    assert [r["repository_full_name"] for r in a] == [r["repository_full_name"] for r in b]
    assert len(a) == 10


def test_sample_respects_per_owner_cap():
    pool = [_repo(f"acme/r{i}") for i in range(10)]      # all same owner
    sel = ss.stratified_sample(pool, 10, seed=1, max_per_owner=2)
    assert len(sel) == 2                                  # capped at 2 per owner


def test_sample_covers_multiple_strata():
    pool = ([_repo(f"o/s{i}", size="small") for i in range(20)] +
            [_repo(f"o/l{i}", size="large") for i in range(20)])
    sel = ss.stratified_sample(pool, 20, seed=7, max_per_owner=99)
    buckets = {r["size_bucket"] for r in sel}
    assert buckets == {"small", "large"}                 # both strata represented
    assert len(sel) == 20


def test_sample_capped_by_pool_size():
    pool = [_repo(f"o{i}/r") for i in range(5)]
    sel = ss.stratified_sample(pool, 500, seed=1, max_per_owner=2)
    assert len(sel) == 5                                  # cannot exceed the pool


# --------------------------------------------------------------------------- #
# Anonymous IDs
# --------------------------------------------------------------------------- #
def test_assign_anonymous_ids():
    recs = [_repo("o/b"), _repo("o/a")]
    out = ss.assign_anonymous_ids(recs, "CLR", 4)
    by = {r["repository_full_name"]: r["anonymous_id"] for r in out}
    assert by["o/a"] == "CLR-0001" and by["o/b"] == "CLR-0002"   # sorted by name


# --------------------------------------------------------------------------- #
# Control matching
# --------------------------------------------------------------------------- #
def test_match_controls_exact_then_relaxed():
    treated = [_repo("t/a", size="small", fw="next"),
               _repo("t/b", size="large", fw="vite")]
    controls = [_repo("c/x", size="small", fw="next"),      # exact for t/a
                _repo("c/y", size="large", fw="astro", age=13)]  # size_only for t/b
    matches = ss.match_controls(treated, controls, seed=3)
    by = {m["treated_repository"]: m for m in matches}
    assert by["t/a"]["control_repository"] == "c/x" and by["t/a"]["match_quality"] == "exact"
    assert by["t/b"]["control_repository"] == "c/y" and by["t/b"]["match_quality"] == "size_only"


def test_match_controls_one_to_one_no_reuse():
    treated = [_repo("t/a", size="small", fw="next"), _repo("t/b", size="small", fw="next")]
    controls = [_repo("c/x", size="small", fw="next")]       # only one control
    matches = ss.match_controls(treated, controls, seed=1)
    used = [m["control_repository"] for m in matches if m["control_repository"]]
    assert used == ["c/x"]                                   # not reused
    assert any(m["match_quality"] == "unmatched" for m in matches)


def test_selection_report_counts_shortfall_and_match_rate():
    deployed = [_repo("o/a"), _repo("o/b")]
    matches = [{"treated_repository": "o/a", "control_repository": "c/1", "match_quality": "exact"},
               {"treated_repository": "o/b", "control_repository": None, "match_quality": "unmatched"}]
    rep = ss.selection_report(deployed, [], matches, {"deployed": 5, "repository_only": 0})
    assert rep["deployed"]["selected"] == 2 and rep["deployed"]["shortfall"] == 3
    assert rep["control_matching"]["matched"] == 1
    assert rep["control_matching"]["match_rate"] == 0.5
