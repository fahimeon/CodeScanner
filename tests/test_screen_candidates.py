"""Unit tests for screen_candidates.py — eligibility decisions + funnel (offline)."""

import screen_candidates as sc
import _common as common

CFG = common.load_study_config()
PRECEDENCE = common.load_yaml(common.CONFIG_DIR / "exclusion-rules.yaml")["precedence"]


def _meta(**kw):
    base = {"fetch_status": "OK", "is_fork": False, "is_archived": False,
            "has_default_branch": True, "primary_language": "TypeScript", "size_kb": 100}
    base.update(kw)
    return base


def _cls(**kw):
    base = {"status": "OK", "is_web_app": True, "has_package_json": True,
            "is_library_or_cli": False, "typescript_present": True,
            "application_type": "fullstack_monolith", "framework": "next",
            "flagged_reasons": []}
    base.update(kw)
    return base


def _loc(**kw):
    base = {"status": "OK", "relevant_source_loc": 3000, "size_bucket": "small"}
    base.update(kw)
    return base


def _attr(**kw):
    base = {"status": "OK", "qualifies": True, "reachable_qualifying_commit": True,
            "any_attribution_signal_found": True}
    base.update(kw)
    return base


def _screen(meta, cls, loc, attr, control=False, duplicate=None):
    return sc.screen_repo("o/r", meta, cls, loc, attr, CFG, PRECEDENCE,
                          duplicate=duplicate, control=control)


# --------------------------------------------------------------------------- #
# Happy path + individual exclusion codes
# --------------------------------------------------------------------------- #
def test_fully_eligible_treated_repo():
    r = _screen(_meta(), _cls(), _loc(), _attr())
    assert r["repository_eligible"] is True
    assert r["exclusion_codes"] == []
    assert r["data_incomplete"] == []


def test_fork_and_archived_flagged():
    r = _screen(_meta(is_fork=True, is_archived=True), _cls(), _loc(), _attr())
    assert "EX_FORK" in r["exclusion_codes"]
    assert "EX_ARCHIVED" in r["exclusion_codes"]
    assert r["repository_eligible"] is False


def test_not_web_app_and_library():
    r = _screen(_meta(), _cls(is_web_app=False, is_library_or_cli=True), _loc(), _attr())
    assert "EX_NOT_WEB_APP" in r["exclusion_codes"]
    assert "EX_LIBRARY_ONLY" in r["exclusion_codes"]


def test_loc_bounds():
    lo = _screen(_meta(), _cls(), _loc(relevant_source_loc=100), _attr())
    assert "EX_INSUFFICIENT_LOC" in lo["exclusion_codes"]
    hi = _screen(_meta(), _cls(), _loc(relevant_source_loc=200000), _attr())
    assert "EX_EXCESSIVE_LOC" in hi["exclusion_codes"]


def test_no_package_json_and_language():
    r = _screen(_meta(primary_language="Python"),
                _cls(has_package_json=False, typescript_present=False, is_web_app=False),
                _loc(), _attr())
    assert "EX_NO_PACKAGE_JSON" in r["exclusion_codes"]
    assert "EX_NOT_JS_TS" in r["exclusion_codes"]


def test_weak_attribution_excluded():
    r = _screen(_meta(), _cls(), _loc(), _attr(qualifies=False))
    assert "EX_WEAK_ATTRIBUTION" in r["exclusion_codes"]


def test_unreachable_attribution_excluded():
    r = _screen(_meta(), _cls(), _loc(),
                _attr(qualifies=True, reachable_qualifying_commit=False))
    assert "EX_UNREACHABLE_CLAUDE_COMMIT" in r["exclusion_codes"]


# --------------------------------------------------------------------------- #
# Manual-review flags are NOT auto-exclusions
# --------------------------------------------------------------------------- #
def test_security_lab_is_manual_review_not_exclusion():
    r = _screen(_meta(), _cls(flagged_reasons=["intentionally_vulnerable_or_security_lab"]),
                _loc(), _attr())
    assert "MANUAL_REVIEW_SECURITY_LAB" in r["manual_review_flags"]
    # Flag alone does not exclude or make ineligible.
    assert r["exclusion_codes"] == []
    assert r["repository_eligible"] is True


# --------------------------------------------------------------------------- #
# Control cohort: zero-attribution requirement, no attribution gate
# --------------------------------------------------------------------------- #
def test_duplicate_non_representative_excluded():
    r = _screen(_meta(), _cls(), _loc(), _attr(),
                duplicate={"is_duplicate": True, "duplicate_of": "o/original"})
    assert "EX_DUPLICATE" in r["exclusion_codes"]
    assert r["repository_eligible"] is False
    # The cluster representative (is_duplicate False) is NOT excluded.
    rep = _screen(_meta(), _cls(), _loc(), _attr(),
                  duplicate={"is_duplicate": False})
    assert "EX_DUPLICATE" not in rep["exclusion_codes"]
    assert rep["repository_eligible"] is True


def test_control_excluded_when_any_signal_present():
    r = _screen(_meta(), _cls(), _loc(),
                _attr(any_attribution_signal_found=True), control=True)
    assert "EX_CONTROL_ATTRIBUTION_SIGNAL" in r["exclusion_codes"]
    assert r["substantial_attribution"] is None      # not applicable to controls


def test_control_eligible_when_no_signal():
    r = _screen(_meta(), _cls(), _loc(),
                {"status": "OK", "any_attribution_signal_found": False}, control=True)
    assert r["repository_eligible"] is True
    assert r["exclusion_codes"] == []


# --------------------------------------------------------------------------- #
# Incomplete data blocks eligibility without inventing a code
# --------------------------------------------------------------------------- #
def test_incomplete_data_blocks_eligibility():
    r = _screen({"fetch_status": "NOT_FOUND"}, None, None, None)
    assert r["repository_eligible"] is False
    assert "metadata" in r["data_incomplete"]
    assert "classification" in r["data_incomplete"]


# --------------------------------------------------------------------------- #
# Funnel: cumulative attrition
# --------------------------------------------------------------------------- #
def test_build_funnel_cumulative():
    records = [
        _screen(_meta(), _cls(), _loc(), _attr()),                         # eligible
        _screen(_meta(is_fork=True), _cls(), _loc(), _attr()),             # fails stage 1
        _screen(_meta(), _cls(is_web_app=False), _loc(), _attr()),         # fails stage 3
        _screen(_meta(), _cls(), _loc(relevant_source_loc=10), _attr()),   # fails stage 4
        _screen(_meta(), _cls(), _loc(), _attr(qualifies=False)),          # fails stage 5
    ]
    f = sc.build_funnel(records)
    assert f["candidates"] == 5
    assert f["data_complete"] == 5
    assert f["reached_not_fork_archived_empty"] == 4       # fork dropped
    assert f["reached_js_ts_with_package_json"] == 4
    assert f["reached_web_app"] == 3                        # non-web-app dropped
    assert f["reached_loc_in_range"] == 2                   # low-LOC dropped
    assert f["reached_substantial_attribution"] == 1       # weak-attribution dropped
    assert f["repository_eligible"] == 1


# --------------------------------------------------------------------------- #
# End-to-end orchestrator + writers
# --------------------------------------------------------------------------- #
def test_screen_all_and_writers(tmp_path):
    candidates = [{"repository_full_name": "o/a"}, {"repository_full_name": "o/b"}]
    metadata = {"o/a": _meta(), "o/b": _meta(is_archived=True)}
    classification = {"o/a": _cls(), "o/b": _cls()}
    loc = {"o/a": _loc(), "o/b": _loc()}
    attribution = {"o/a": _attr(), "o/b": _attr()}
    rows = sc.screen_all(candidates, metadata, classification, loc, attribution,
                         CFG, PRECEDENCE)
    by = {r["repository_full_name"]: r for r in rows}
    assert by["o/a"]["repository_eligible"] is True
    assert by["o/b"]["repository_eligible"] is False

    sc.write_screening(rows, tmp_path / "s.json", tmp_path / "s.csv")
    sc.write_excluded(rows, tmp_path / "excluded.csv")
    import csv as _csv
    with (tmp_path / "s.csv").open(encoding="utf-8") as fh:
        header = next(_csv.reader(fh))
    assert header == sc.SCREENING_FIELDS
    excluded_text = (tmp_path / "excluded.csv").read_text(encoding="utf-8")
    assert "o/b" in excluded_text and "EX_ARCHIVED" in excluded_text
    assert not list(tmp_path.glob("*.tmp"))
