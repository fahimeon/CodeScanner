"""Unit tests for resolve_manual_review.py + the freeze manual-review gate (offline)."""

import resolve_manual_review as mrv


def test_review_flags_from_screening_and_deployment():
    screen = {"manual_review_flags": ["MANUAL_REVIEW_SECURITY_LAB"]}
    match = {"deployment_status": "PLACEHOLDER", "availability_eligible": True, "corresponds": False}
    flags = mrv.review_flags_for(screen, match)
    assert "MANUAL_REVIEW_SECURITY_LAB" in flags
    assert "MANUAL_REVIEW_DEPLOYMENT_AMBIGUOUS" in flags
    assert "MANUAL_REVIEW_DEPLOYMENT_MATCH_UNCONFIRMED" in flags
    # A clean repo has no flags.
    assert mrv.review_flags_for({"manual_review_flags": []}, {"deployment_status": "LIVE_CONFIRMED",
                                "availability_eligible": True, "corresponds": True}) == []


def test_build_review_items_only_flagged():
    screening = {"o/a": {"manual_review_flags": ["MANUAL_REVIEW_TUTORIAL"]},
                 "o/b": {"manual_review_flags": []}}
    items = mrv.build_review_items(screening, {})
    assert set(items) == {"o/a"}


def test_merge_preserves_prior_decisions_and_resets_on_flag_change():
    items = {"o/a": ["MANUAL_REVIEW_TUTORIAL"], "o/b": ["MANUAL_REVIEW_SECURITY_LAB"]}
    existing = {
        "o/a": {"flags": "MANUAL_REVIEW_TUTORIAL", "decision": "INCLUDE",
                "resolved_by": "reviewer", "note": "ok"},
        "o/b": {"flags": "OLD_FLAG", "decision": "INCLUDE"},   # flags changed -> reset
    }
    rows = {r["repository_full_name"]: r for r in mrv.merge_decisions(items, existing)}
    assert rows["o/a"]["decision"] == "INCLUDE"                # preserved
    assert rows["o/b"]["decision"] == "PENDING"               # reset (flags changed)


def test_apply_decisions_drops_exclude_and_flags_pending():
    records = [{"repository_full_name": "o/a"}, {"repository_full_name": "o/b"},
               {"repository_full_name": "o/c"}]
    decisions = {"o/a": {"decision": "INCLUDE"}, "o/b": {"decision": "EXCLUDE"},
                 "o/c": {"decision": "PENDING"}}
    kept, pending = mrv.apply_decisions(records, decisions)
    names = {r["repository_full_name"] for r in kept}
    assert names == {"o/a", "o/c"}          # EXCLUDE dropped
    assert pending == ["o/c"]               # PENDING surfaced


def test_decisions_roundtrip(tmp_path):
    rows = [{"repository_full_name": "o/a", "flags": "MANUAL_REVIEW_TUTORIAL",
             "decision": "PENDING", "resolved_by": "", "note": ""}]
    path = tmp_path / "manual-review-decisions.csv"
    mrv.write_decisions(rows, path)
    back = mrv.read_decisions(path)
    assert back["o/a"]["decision"] == "PENDING"
    assert not list(tmp_path.glob("*.tmp"))
