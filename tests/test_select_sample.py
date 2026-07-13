"""Unit tests for select_sample.py — stratified sampling + control matching (offline)."""

import select_sample as ss


def _repo(name, size="small", fw="next", owner=None, age=12.0,
          app="fullstack_monolith", provider="vercel", deployed=True):
    return {"repository_full_name": name, "size_bucket": size, "framework": fw,
            "repo_age_months": age, "application_type": app, "deployment_provider": provider,
            "deployed_eligible": deployed, "relevant_source_loc": 3000}


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
def test_match_within_caliper_on_exact_covariates():
    treated = [_repo("t/a", age=12.0)]
    controls = [_repo("c/x", age=15.0),                      # within 6-month caliper
                _repo("c/far", age=40.0)]                    # outside caliper
    matches = ss.match_controls(treated, controls, seed=3, age_caliper_months=6.0)
    m = matches[0]
    assert m["control_repository"] == "c/x"
    assert m["match_quality"] == "exact_strata_within_caliper"
    assert m["distance_age_months"] == 3.0


def test_match_requires_control_deployment_for_deployed_cohort():
    treated = [_repo("t/a")]
    controls = [_repo("c/x", deployed=False)]                # control has no deployment
    matches = ss.match_controls(treated, controls, seed=1, require_control_deployment=True)
    assert matches[0]["control_repository"] is None
    assert matches[0]["unmatched_reason"] == "no_control_in_strata"


def test_match_respects_age_caliper():
    treated = [_repo("t/a", age=12.0)]
    controls = [_repo("c/x", age=30.0)]                      # 18 months > 6 caliper
    matches = ss.match_controls(treated, controls, seed=1, age_caliper_months=6.0)
    assert matches[0]["control_repository"] is None
    assert matches[0]["unmatched_reason"] == "no_control_within_age_caliper"


def test_match_no_reuse_and_no_silent_relaxation():
    treated = [_repo("t/a"), _repo("t/b")]
    controls = [_repo("c/x")]                                # only one qualifying control
    matches = ss.match_controls(treated, controls, seed=1)
    used = [m["control_repository"] for m in matches if m["control_repository"]]
    assert used == ["c/x"]                                   # not reused
    # A differing covariate is NOT silently relaxed.
    treated2 = [_repo("t/c", fw="next")]
    controls2 = [_repo("c/z", fw="astro")]                   # framework differs
    assert ss.match_controls(treated2, controls2, seed=1)[0]["control_repository"] is None


def test_compute_smd_and_balance_report():
    assert ss.compute_smd([10, 10, 10], [10, 10, 10]) == 0.0
    smd = ss.compute_smd([10, 12, 14], [4, 6, 8])
    assert smd is not None and smd > 0
    treated = [_repo("t/a", age=12.0), _repo("t/b", age=14.0)]
    controls = [_repo("c/x", age=13.0), _repo("c/y", age=50.0)]
    matches = ss.match_controls(treated, controls, seed=1, age_caliper_months=6.0)
    bal = ss.balance_report(treated, controls, matches, ("repo_age_months",))
    assert "repo_age_months" in bal
    assert "smd_pre_match" in bal["repo_age_months"] and "smd_post_match" in bal["repo_age_months"]


def test_selection_report_counts_shortfall_and_match_rate():
    deployed = [_repo("o/a"), _repo("o/b")]
    matches = [{"treated_repository": "o/a", "control_repository": "c/1", "match_quality": "exact"},
               {"treated_repository": "o/b", "control_repository": None, "match_quality": "unmatched"}]
    rep = ss.selection_report(deployed, [], matches, {"deployed": 5, "repository_only": 0})
    assert rep["deployed"]["selected"] == 2 and rep["deployed"]["shortfall"] == 3
    assert rep["control_matching"]["matched"] == 1
    assert rep["control_matching"]["match_rate"] == 0.5
