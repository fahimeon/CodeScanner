"""Unit tests for analyse_results.py + create_validation_sample.py (offline)."""

import analyse_results as ar
import create_validation_sample as cvs


# --------------------------------------------------------------------------- #
# Wilson CI
# --------------------------------------------------------------------------- #
def test_wilson_ci_basic_and_edges():
    r = ar.wilson_ci(0, 0)
    assert r["proportion"] is None
    z = ar.wilson_ci(0, 100)
    assert z["proportion"] == 0.0 and z["low"] == 0.0 and z["high"] > 0     # rare-event upper bound > 0
    half = ar.wilson_ci(50, 100)
    assert half["proportion"] == 0.5 and half["low"] < 0.5 < half["high"]
    full = ar.wilson_ci(10, 10)
    assert full["proportion"] == 1.0 and full["high"] == 1.0 and full["low"] < 1.0


# --------------------------------------------------------------------------- #
# Benjamini-Hochberg
# --------------------------------------------------------------------------- #
def test_benjamini_hochberg_monotone_and_rejection():
    out = ar.benjamini_hochberg({"a": 0.001, "b": 0.04, "c": 0.5, "d": 0.9}, alpha=0.05)
    assert out["a"]["rejected"] is True                    # very small p rejected
    assert out["d"]["rejected"] is False
    # q-values are monotone non-decreasing in p.
    order = sorted(out.items(), key=lambda kv: kv[1]["p"])
    qs = [v["q_value"] for _, v in order]
    assert qs == sorted(qs)


# --------------------------------------------------------------------------- #
# Prevalence + reliability grouping
# --------------------------------------------------------------------------- #
def test_prevalence_over_repo_universe():
    findings = [
        {"repository_full_name": "o/a", "category": "exposed_secrets", "normalized_severity": "high"},
        {"repository_full_name": "o/a", "category": "cross_site_scripting", "normalized_severity": "high"},
        {"repository_full_name": "o/b", "category": "exposed_secrets", "normalized_severity": "critical"},
    ]
    repos = {"o/a", "o/b", "o/c"}                          # o/c has zero findings
    prev = ar.prevalence(findings, repos)
    assert prev["repositories"] == 3
    assert prev["any_finding"]["k"] == 2 and prev["any_finding"]["n"] == 3
    assert prev["by_category"]["exposed_secrets"]["k"] == 2   # o/a + o/b
    assert prev["by_severity"]["critical"]["k"] == 1


def test_group_categories_by_reliability():
    by_cat = {"exposed_secrets": {"k": 1}, "cross_site_scripting": {"k": 1},
              "business_logic_flaw": {"k": 0}}
    rel = {"exposed_secrets": "strong", "cross_site_scripting": "partial",
           "business_logic_flaw": "out_of_scope"}
    g = ar.group_categories_by_reliability(by_cat, rel)
    assert "exposed_secrets" in g["strong"] and "cross_site_scripting" in g["partial"]
    assert "business_logic_flaw" in g["out_of_scope"]


def test_analyse_end_to_end():
    findings = [{"repository_full_name": "o/a", "category": "exposed_secrets",
                 "normalized_severity": "high"}]
    summary = ar.analyse(findings, {"o/a", "o/b"}, {"exposed_secrets": "strong"},
                         {"multi_scanner_findings": 0})
    assert summary["repositories_analysed"] == 2
    assert summary["prevalence"]["any_finding"]["proportion"] == 0.5
    assert "exposed_secrets" in summary["categories_by_reliability"]["strong"]


# --------------------------------------------------------------------------- #
# Validation sample
# --------------------------------------------------------------------------- #
def _f(fid, cat, sev):
    return {"dedup_id": fid, "category": cat, "normalized_severity": sev,
            "repository_full_name": "o/a"}


def test_validation_sample_is_stratified_and_deterministic():
    findings = ([_f(f"s{i}", "exposed_secrets", "high") for i in range(10)] +
                [_f(f"x{i}", "cross_site_scripting", "medium") for i in range(10)])
    a = cvs.sample_findings(findings, per_stratum=3, seed=20260711)
    b = cvs.sample_findings(findings, per_stratum=3, seed=20260711)
    assert [r["validation_id"] for r in a] == [r["validation_id"] for r in b]   # deterministic
    cats = {r["category"] for r in a}
    assert cats == {"exposed_secrets", "cross_site_scripting"}                  # both strata
    assert sum(1 for r in a if r["category"] == "exposed_secrets") == 3         # per-stratum cap
    assert all(r["validation_label"] == "PENDING" for r in a)
