"""Unit tests for freeze_population.py — join + deterministic checksum (offline)."""

import freeze_population as fp


def _screen(elig=True, **kw):
    base = {"repository_eligible": elig, "substantial_attribution": True}
    base.update(kw)
    return base


def test_build_population_record_joins_covariates():
    rec = fp.build_population_record(
        "octo/app",
        _screen(),
        {"track": "deployed", "final_deployment_eligible": True,
         "best_evidence_level": "A", "deployment_status": "LIVE_CONFIRMED"},
        {"repo_age_months": 12.5, "last_push_age_days": 40},
        {"framework": "next", "application_type": "fullstack_monolith",
         "github_actions_present": True, "docker_present": False},
        {"size_bucket": "medium", "relevant_source_loc": 8000},
        {"involvement_band": "high"},
        "vercel")
    assert rec["owner"] == "octo"
    assert rec["track"] == "deployed" and rec["deployed_eligible"] is True
    assert rec["framework"] == "next" and rec["size_bucket"] == "medium"
    assert rec["involvement_band"] == "high" and rec["deployment_provider"] == "vercel"
    assert rec["deployment_evidence_level"] == "A"


def test_population_record_carries_frozen_identity():
    meta = {"repository_url": "https://github.com/octo/app",
            "default_branch_head_sha": "abc123def456"}
    rec = fp.build_population_record("octo/app", {"repository_eligible": True}, {}, meta,
                                     {}, {}, {}, None, config_hash="CFGHASH")
    assert rec["repository_url"] == "https://github.com/octo/app"
    assert rec["frozen_commit_sha"] == "abc123def456"
    assert rec["configuration_hash"] == "CFGHASH"
    assert len(rec["metadata_snapshot_hash"]) == 64      # sha256 of the metadata record


def test_canonical_checksum_is_order_independent():
    a = {"repository_full_name": "o/a", "track": "deployed"}
    b = {"repository_full_name": "o/b", "track": "repository_only"}
    assert fp.canonical_checksum([a, b]) == fp.canonical_checksum([b, a])
    # Any change to the population changes the checksum.
    assert fp.canonical_checksum([a, b]) != fp.canonical_checksum([a])


def test_freeze_keeps_only_eligible_and_counts(tmp_path):
    candidates = [{"repository_full_name": n} for n in ("o/a", "o/b", "o/c")]
    screening = {"o/a": _screen(True), "o/b": _screen(False), "o/c": _screen(True)}
    track = {"o/a": {"track": "deployed", "final_deployment_eligible": True},
             "o/c": {"track": "repository_only", "final_deployment_eligible": False}}
    meta = {n: {} for n in ("o/a", "o/b", "o/c")}
    cls = {"o/a": {"framework": "next"}, "o/c": {"framework": "vite"}}
    loc = {"o/a": {"size_bucket": "small"}, "o/c": {"size_bucket": "large"}}
    contrib = {"o/a": {"involvement_band": "medium"}}
    records, manifest = fp.freeze(candidates, screening, track, meta, cls, loc,
                                  contrib, {"o/a": "vercel"}, seed=20260711)
    names = {r["repository_full_name"] for r in records}
    assert names == {"o/a", "o/c"}                       # o/b ineligible -> excluded
    assert manifest["counts"]["eligible_total"] == 2
    assert manifest["counts"]["deployed_eligible"] == 1
    assert manifest["random_seed"] == 20260711
    assert len(manifest["population_sha256"]) == 64


def test_write_population_and_checksum_marker(tmp_path):
    records, manifest = fp.freeze(
        [{"repository_full_name": "o/a"}], {"o/a": _screen(True)},
        {"o/a": {"track": "deployed", "final_deployment_eligible": True}},
        {"o/a": {}}, {"o/a": {}}, {"o/a": {}}, {"o/a": {}}, {}, 20260711)
    fp.write_population(records, tmp_path / "pop.json", tmp_path / "pop.csv")
    fp.write_checksum(manifest, tmp_path / "checksum.txt")
    assert (tmp_path / "checksum.txt").exists()
    marker = (tmp_path / "checksum.txt").read_text(encoding="utf-8")
    assert "population_sha256=" in marker and "deployed_eligible=1" in marker
    import csv as _csv
    with (tmp_path / "pop.csv").open(encoding="utf-8") as fh:
        assert next(_csv.reader(fh)) == fp.POPULATION_FIELDS
