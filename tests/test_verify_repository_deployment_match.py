"""Unit tests for verify_repository_deployment_match.py — correspondence + tracks (offline)."""

import verify_repository_deployment_match as vm


def _verify(**kw):
    base = {"best_evidence_level": "B", "availability_eligible": True,
            "deployment_status": "LIVE_CONFIRMED", "repo_link_found": False,
            "name_in_page": False}
    base.update(kw)
    return base


# --------------------------------------------------------------------------- #
# Correspondence signals
# --------------------------------------------------------------------------- #
def test_correspondence_signals():
    assert vm.correspondence_signals(_verify(best_evidence_level="A")) == \
        ["github_deployment_metadata"]
    sig = vm.correspondence_signals(_verify(repo_link_found=True, name_in_page=True))
    assert set(sig) == {"repository_link_on_deployed_page", "matching_project_name"}


# --------------------------------------------------------------------------- #
# Track assignment
# --------------------------------------------------------------------------- #
def test_deployed_track_requires_eligible_avail_correspondence_level():
    # Level B, reachable, repo link on page, repo-side eligible -> deployed.
    r = vm.finalize_match("o/a", _verify(repo_link_found=True),
                          {"repository_eligible": True})
    assert r["corresponds"] is True
    assert r["final_deployment_eligible"] is True
    assert r["track"] == "deployed"


def test_level_A_metadata_alone_corresponds():
    r = vm.finalize_match("o/a", _verify(best_evidence_level="A"),
                          {"repository_eligible": True})
    assert r["track"] == "deployed"           # Level A implies metadata correspondence


def test_reachable_but_no_correspondence_falls_to_repo_only():
    # Level B reachable but nothing ties the page to the repo -> not deployed.
    r = vm.finalize_match("o/a", _verify(repo_link_found=False, name_in_page=False),
                          {"repository_eligible": True})
    assert r["corresponds"] is False
    assert r["final_deployment_eligible"] is False
    assert r["track"] == "repository_only"


def test_dead_deployment_is_repo_only_when_repo_eligible():
    r = vm.finalize_match("o/a",
                          _verify(deployment_status="DEAD_404", availability_eligible=False,
                                  repo_link_found=True),
                          {"repository_eligible": True})
    assert r["track"] == "repository_only"


def test_not_repo_eligible_is_excluded():
    r = vm.finalize_match("o/a", _verify(repo_link_found=True),
                          {"repository_eligible": False})
    assert r["track"] == "excluded"


def test_no_deployment_record_repo_only():
    r = vm.finalize_match("o/a", None, {"repository_eligible": True})
    assert r["track"] == "repository_only"
    assert r["final_deployment_eligible"] is False
    assert r["deployment_commit_relationship"] == "UNKNOWN"


# --------------------------------------------------------------------------- #
# Orchestrator + funnel + writers
# --------------------------------------------------------------------------- #
def test_match_all_and_funnel(tmp_path):
    verification = {
        "o/deployed": _verify(best_evidence_level="A"),
        "o/repoonly": _verify(repo_link_found=False, name_in_page=False),
    }
    screening = {
        "o/deployed": {"repository_eligible": True},
        "o/repoonly": {"repository_eligible": True},
        "o/excluded": {"repository_eligible": False},
    }
    rows = vm.match_all(verification, screening)
    by = {r["repository_full_name"]: r["track"] for r in rows}
    assert by == {"o/deployed": "deployed", "o/repoonly": "repository_only",
                  "o/excluded": "excluded"}
    funnel = vm.build_track_funnel(rows)
    assert funnel["deployed"] == 1 and funnel["repository_only"] == 1 and funnel["excluded"] == 1

    vm.write_match(rows, tmp_path / "e.json", tmp_path / "e.csv",
                   tmp_path / "t.json", tmp_path / "t.csv")
    import csv as _csv
    with (tmp_path / "t.csv").open(encoding="utf-8") as fh:
        header = next(_csv.reader(fh))
    assert header == vm.TRACK_FIELDS
    assert not list(tmp_path.glob("*.tmp"))
