"""Unit tests for the scan track: prepare_scanners, clone_selected_repositories,
and the shared scanner harness (all offline; docker/git behind injected runners)."""

import json
from pathlib import Path

import pytest

import prepare_scanners as ps
import clone_selected_repositories as cl
import _scanner_runner as sr
import _common as common


# =========================================================================== #
# prepare_scanners
# =========================================================================== #
def test_build_scanner_commands():
    assert ps.build_image_args("docker/Dockerfile.scanner", "img")[:2] == ["build", "-f"]
    assert "img" in ps.inspect_digest_args("img")
    assert ps.parse_digest("  sha256:abc  ") == "sha256:abc" and ps.parse_digest("") is None
    assert ps.build_trivy_download_args("/c")[:2] == ["fs", "--download-db-only"]
    assert "/c" in ps.build_trivy_download_args("/c")
    assert "/d" in ps.build_osv_download_args("/d")
    smoke = ps.build_smoke_args("gitleaks", "img")
    assert "--network" in smoke and "none" in smoke and "--entrypoint" in smoke


def _point_caches(monkeypatch, tmp_path, populate=True):
    for attr, name in [("SEMGREP_CACHE", "sg"), ("TRIVY_CACHE", "tv"), ("OSV_DB_DIR", "osv")]:
        d = tmp_path / name
        d.mkdir(exist_ok=True)
        if populate:
            (d / "pinned").write_text("data", encoding="utf-8")
        monkeypatch.setattr(ps, attr, d)


def test_prepare_ready_when_all_present(tmp_path, monkeypatch):
    _point_caches(monkeypatch, tmp_path, populate=True)

    def run_fn(cmd):
        joined = " ".join(str(c) for c in cmd)
        if "RepoDigests" in joined:
            return 0, "img@sha256:deadbeef\n", ""
        if "inspect" in cmd:
            return 0, "sha256:localid\n", ""
        return 0, "v1.0.0\n", ""            # build/export/download/smoke all succeed

    marker = ps.prepare("docker", "semgrep", "trivy", "osv-scanner", run_fn, build=True)
    assert marker["ready"] is True
    assert marker["image_digest"] == "img@sha256:deadbeef"
    assert marker["semgrep_ruleset_hash"] and len(marker["semgrep_ruleset_hash"]) == 64
    assert all(marker["smoke_tests"][s]["ok"] for s in ps.FIVE_SCANNERS)
    assert marker["configuration_hash"]


def test_prepare_fail_closed_when_rules_or_dbs_missing(tmp_path, monkeypatch):
    _point_caches(monkeypatch, tmp_path, populate=False)   # empty caches

    def run_fn(cmd):
        joined = " ".join(str(c) for c in cmd)
        if "RepoDigests" in joined:
            return 0, "img@sha256:dead\n", ""
        if "inspect" in cmd:
            return 0, "sha256:id\n", ""
        return 0, "", ""

    marker = ps.prepare("docker", None, None, None, run_fn, build=True)
    assert marker["ready"] is False           # fail-closed
    assert "semgrep_rules_cache_missing" in marker["problems"]
    assert "trivy_db_missing" in marker["problems"]
    assert "osv_db_missing" in marker["problems"]


def test_scanners_ready_state_transitions():
    m = {"ready": True, "configuration_hash": "CFG", "image_digest": "IMG"}
    assert ps.scanners_ready_state(m, "CFG", "IMG")[0] == "READY"
    assert ps.scanners_ready_state(m, "OTHER", "IMG")[0] == "STALE"     # config drift
    assert ps.scanners_ready_state(m, "CFG", "OTHERIMG")[0] == "STALE"  # image drift
    assert ps.scanners_ready_state(None, "CFG")[0] == "NOT_READY"
    assert ps.scanners_ready_state({"ready": False, "problems": ["x"]}, "CFG")[0] == "NOT_READY"


# =========================================================================== #
# clone_selected_repositories
# =========================================================================== #
def test_clone_guard_arg_building():
    args = cl.build_working_tree_clone_args("https://github.com/o/r", "/dest", "/hooks")
    joined = " ".join(args)
    assert "--filter=blob:none" in joined and "protocol.ext.allowed=never" in joined
    assert cl.build_checkout_args("abc123") == ["checkout", "--force", "abc123"]


def test_check_clone_guards():
    limits = {"max_repo_size_mb": 10, "max_file_count": 100, "max_single_file_mb": 5}
    ok, reasons = cl.check_clone_guards(1_000_000, 50, 1_000_000, limits)
    assert ok is True and reasons == []
    bad, reasons = cl.check_clone_guards(20 * 1024 * 1024, 200, 6 * 1024 * 1024, limits)
    assert bad is False
    assert any("repo_size" in r for r in reasons)
    assert any("file_count" in r for r in reasons)
    assert any("single_file" in r for r in reasons)


def test_build_clone_record_flags_oversize_as_ex_clone_failed():
    limits = {"max_repo_size_mb": 1, "max_file_count": 10, "max_single_file_mb": 1}
    result = {"status": "OK", "size_bytes": 5 * 1024 * 1024, "file_count": 3,
              "largest_file_bytes": 100, "checked_out_sha": "abc"}
    rec = cl.build_clone_record("o/r", "CLR-0001", result, limits)
    assert rec["status"] == "CLONE_ERROR" and rec["exclusion_code"] == "EX_CLONE_FAILED"


_LIMITS = {"max_repo_size_mb": 2048, "max_file_count": 200000, "max_single_file_mb": 50}


def test_clone_reads_frozen_sha_from_selected_sample(tmp_path):
    # Identity comes from the SELECTED sample, not interim metadata (audit P0 #5).
    def clone_fn(full, url, ref, dest):
        assert ref == "frozensha123" and url == "https://github.com/o/a"
        return {"status": "OK", "size_bytes": 1000, "file_count": 5,
                "largest_file_bytes": 500, "checked_out_sha": ref}

    selected = [{"repository_full_name": "o/a", "anonymous_id": "CLR-0001",
                 "repository_url": "https://github.com/o/a", "frozen_commit_sha": "frozensha123"}]
    records = cl.clone_all(selected, tmp_path / "sel", tmp_path / "log.jsonl", clone_fn, _LIMITS)
    assert records[0]["status"] == "OK" and records[0]["checked_out_sha"] == "frozensha123"


def test_clone_refuses_on_sha_mismatch(tmp_path):
    # Checkout landed on a different commit than the frozen SHA -> refuse.
    def clone_fn(full, url, ref, dest):
        return {"status": "OK", "size_bytes": 1000, "file_count": 5,
                "largest_file_bytes": 500, "checked_out_sha": "DIFFERENTsha456"}

    selected = [{"repository_full_name": "o/a", "repository_url": "https://github.com/o/a",
                 "frozen_commit_sha": "frozensha123"}]
    records = cl.clone_all(selected, tmp_path / "sel", tmp_path / "log.jsonl", clone_fn, _LIMITS)
    assert records[0]["status"] == "CLONE_ERROR"
    assert records[0]["exclusion_code"] == "EX_CLONE_FAILED"
    assert "sha_mismatch" in records[0]["reasons"]


def test_clone_refuses_missing_frozen_sha(tmp_path):
    selected = [{"repository_full_name": "o/a"}]      # no frozen_commit_sha
    called = {"n": 0}

    def clone_fn(full, url, ref, dest):
        called["n"] += 1
        return {"status": "OK"}

    records = cl.clone_all(selected, tmp_path / "sel", tmp_path / "log.jsonl", clone_fn, _LIMITS)
    assert records[0]["status"] == "CLONE_ERROR"
    assert "missing_frozen_commit_sha" in records[0]["reasons"]
    assert called["n"] == 0                           # never attempted the clone


# =========================================================================== #
# scanner harness
# =========================================================================== #
def test_docker_run_args_are_isolated():
    mounts = [("/host/repos", "/scan/repositories", "ro"),
              ("/host/results", "/scan/results/raw", "rw")]
    iso = {"user_uid": "10001:10001", "limits": {"pids": 512, "memory": "4g", "cpus": "2.0"}}
    args = sr.build_docker_run_args("gitleaks", "/scan/repositories/o__r",
                                    "/scan/results/raw/gitleaks/o__r.json", mounts,
                                    "img", iso)
    joined = " ".join(args)
    assert "--network none" in joined
    assert "--read-only" in joined
    assert "--cap-drop ALL" in joined
    assert "no-new-privileges:true" in joined
    assert args[-3:] == ["gitleaks", "/scan/repositories/o__r",
                         "/scan/results/raw/gitleaks/o__r.json"]


def test_finding_count_parsers():
    assert sr.count_gitleaks(json.dumps([{"a": 1}, {"b": 2}])) == 2
    assert sr.count_gitleaks(json.dumps([])) == 0
    assert sr.count_gitleaks("not json") is None
    sarif = json.dumps({"runs": [{"results": [1, 2, 3]}, {"results": [4]}]})
    assert sr.count_semgrep(sarif) == 4
    trivy = json.dumps({"Results": [{"Vulnerabilities": [1, 2], "Secrets": [3]},
                                    {"Misconfigurations": [4]}]})
    assert sr.count_trivy(trivy) == 4
    osv = json.dumps({"results": [{"packages": [{"vulnerabilities": [1, 2]},
                                                {"vulnerabilities": [3]}]}]})
    assert sr.count_osv(osv) == 3


def test_classify_execution():
    assert sr.classify_execution(0, False, 5) == "SUCCESS_WITH_FINDINGS"
    assert sr.classify_execution(0, False, 0) == "NO_FINDINGS"
    assert sr.classify_execution(0, False, None) == "PARSER_ERROR"
    assert sr.classify_execution(2, False, None) == "SCANNER_ERROR"
    assert sr.classify_execution(0, True, None) == "TIMEOUT"


# --- scanner-specific exit-code semantics (audit P0 #2) --------------------- #
def test_exit_semantics_from_config():
    ok, findings = sr.exit_semantics_for("semgrep")
    assert 0 in ok and 1 in findings          # 1 = results found
    ok, findings = sr.exit_semantics_for("osv-scanner")
    assert 1 in findings
    ok, findings = sr.exit_semantics_for("gitleaks")
    assert findings == set()                  # entrypoint forces --exit-code 0


def test_findings_exit_code_is_success_not_error():
    ok, findings = sr.exit_semantics_for("semgrep")
    accepted = ok | findings
    # Semgrep exit 1 with findings parsed => SUCCESS_WITH_FINDINGS, NOT SCANNER_ERROR.
    assert sr.classify_execution(1, False, 3, accepted) == "SUCCESS_WITH_FINDINGS"
    # Exit 2 is a genuine error for semgrep.
    assert sr.classify_execution(2, False, None, accepted) == "SCANNER_ERROR"
    # OSV exit 1 = vulnerabilities found.
    ok2, f2 = sr.exit_semantics_for("osv-scanner")
    assert sr.classify_execution(1, False, 2, ok2 | f2) == "SUCCESS_WITH_FINDINGS"


@pytest.mark.parametrize("scanner,ext", [
    ("gitleaks", "json"), ("semgrep", "sarif"), ("trivy", "json"),
    ("osv-scanner", "json"), ("zizmor", "sarif"),
])
def test_positive_fixture_yields_success_with_findings(scanner, ext, tmp_path):
    """Each scanner's synthetic positive fixture: output parses, status is
    SUCCESS_WITH_FINDINGS, finding_count>0, and no real secret is present."""
    fixture = (Path(__file__).resolve().parent / "fixtures" / "scanner_output" /
               f"{scanner}.{ext}")
    fixture_text = fixture.read_text(encoding="utf-8")
    assert "REDACTED" in fixture_text or "Secret" not in fixture_text  # no real secret

    ok, findings = sr.exit_semantics_for(scanner)
    exit_code = (sorted(findings)[0] if findings else 0)   # simulate the scanner's exit
    output_host = tmp_path / "raw" / scanner / f"o__r.{ext}"

    def run_fn(cmd):
        output_host.parent.mkdir(parents=True, exist_ok=True)
        output_host.write_text(fixture_text, encoding="utf-8")
        return exit_code, "", ""

    rec = sr.run_one(scanner, "o/r", "CLR-0001", "sha1",
                     f"/scan/repositories/o__r", output_host,
                     f"/scan/results/raw/{scanner}/o__r.{ext}", [], "img",
                     {"limits": {}}, run_fn, accepted_exit_codes=(ok | findings))
    assert rec["status"] == "SUCCESS_WITH_FINDINGS", rec
    assert rec["finding_count"] and rec["finding_count"] > 0


def test_run_one_reads_container_output_and_records(tmp_path):
    output_host = tmp_path / "raw" / "gitleaks" / "o__r.json"

    def run_fn(cmd):
        # Simulate the container writing the scanner output file.
        output_host.parent.mkdir(parents=True, exist_ok=True)
        output_host.write_text(json.dumps([{"secret": "x"}, {"secret": "y"}]), encoding="utf-8")
        return 0, "", ""

    rec = sr.run_one("gitleaks", "o/r", "CLR-0001", "sha1",
                     "/scan/repositories/o__r", output_host,
                     "/scan/results/raw/gitleaks/o__r.json", [], "img",
                     {"user_uid": "10001:10001", "limits": {}}, run_fn)
    assert rec["status"] == "SUCCESS_WITH_FINDINGS"
    assert rec["finding_count"] == 2
    assert rec["scanner"] == "gitleaks" and rec["exit_code"] == 0


def test_run_one_scanner_error_is_not_zero_findings(tmp_path):
    def run_fn(cmd):
        return 3, "", "scanner crashed"       # no output file written

    rec = sr.run_one("trivy", "o/r", None, "sha", "/scan/repositories/o__r",
                     tmp_path / "missing.json", "/scan/results/raw/trivy/o__r.json",
                     [], "img", {"limits": {}}, run_fn)
    assert rec["status"] == "SCANNER_ERROR"
    assert rec["finding_count"] is None       # NOT zeroed on failure


# --- P0 #4: run context, complete records, validation, quarantine ----------- #
def test_build_run_context_from_marker():
    marker = {"pinned_scanner_versions": {"semgrep": "1.97.0", "gitleaks": "8.21.2"},
              "semgrep_ruleset_hash": "RH", "image_digest": "IMG", "configuration_hash": "CFG",
              "database_snapshots": {"trivy_db": {"snapshot_utc": "T"}, "osv_db": {"snapshot_utc": "O"}}}
    ctx = sr.build_run_context("semgrep", marker)
    assert ctx["scanner_version"] == "1.97.0" and ctx["ruleset_or_db_hash"] == "RH"
    assert ctx["image_digest"] == "IMG" and ctx["configuration_hash"] == "CFG"
    assert sr.build_run_context("gitleaks", marker)["ruleset_or_db_hash"] == ""
    assert sr.build_run_context("trivy", marker)["ruleset_or_db_hash"] == "T"


def test_run_one_records_complete_fields():
    ctx = {"scanner_version": "8.21.2", "ruleset_or_db_hash": "", "image_digest": "IMG",
           "configuration_hash": "CFG"}

    def run_fn(cmd):
        return 0, "", ""

    import tempfile
    with tempfile.TemporaryDirectory() as d:
        out = Path(d) / "o__r.json"
        out.write_text("[]", encoding="utf-8")
        rec = sr.run_one("gitleaks", "o/r", "CLR-0001", "sha1", "/scan/repositories/o__r",
                         out, "/scan/results/raw/gitleaks/o__r.json", [], "IMG",
                         {"limits": {}}, run_fn, run_context=ctx)
    for f in ("start_time", "end_time", "timeout_status", "scanner_version",
              "image_digest", "configuration_hash", "schema_valid", "files_analysed"):
        assert f in rec
    assert rec["scanner_version"] == "8.21.2" and rec["image_digest"] == "IMG"
    assert rec["schema_valid"] is True and rec["timeout_status"] == "OK"


def test_validate_existing_output(tmp_path):
    out = tmp_path / "o__r.json"
    out.write_text("[]", encoding="utf-8")            # valid (empty) gitleaks output
    side = tmp_path / "o__r.record.json"
    ctx = {"scanner_version": "8.21.2", "ruleset_or_db_hash": "", "image_digest": "IMG",
           "configuration_hash": "CFG"}
    rec = {"repository_full_name": "o/r", "commit_sha": "sha1", "scanner": "gitleaks",
           "scanner_version": "8.21.2", "ruleset_or_db_hash": "", "image_digest": "IMG",
           "configuration_hash": "CFG"}
    side.write_text(json.dumps(rec), encoding="utf-8")

    assert sr.validate_existing_output(out, side, "gitleaks", "o/r", "sha1", ctx)[0] is True
    # frozen-SHA mismatch -> invalid
    ok, reasons = sr.validate_existing_output(out, side, "gitleaks", "o/r", "OTHER", ctx)
    assert ok is False and any("commit_sha" in r for r in reasons)
    # corrupt output -> schema invalid
    out.write_text("not json", encoding="utf-8")
    ok, reasons = sr.validate_existing_output(out, side, "gitleaks", "o/r", "sha1", ctx)
    assert ok is False and "output_schema_invalid" in reasons


def test_run_all_records_accumulate_resume_and_quarantine(tmp_path, monkeypatch):
    monkeypatch.setattr(sr, "STUDY_ROOT", tmp_path)
    (tmp_path / "repositories" / "selected" / "o__r").mkdir(parents=True)
    raw_dir = tmp_path / "results" / "raw" / "gitleaks"
    out_host = raw_dir / "o__r.json"
    marker = {"pinned_scanner_versions": {"gitleaks": "8.21.2"}, "image_digest": "IMG",
              "configuration_hash": common.config_bundle_hash()}
    manifest = [{"repository_full_name": "o/r", "status": "OK",
                 "anonymous_id": "CLR-0001", "checked_out_sha": "sha1"}]
    calls = {"n": 0}

    def run_fn(cmd):
        calls["n"] += 1
        out_host.parent.mkdir(parents=True, exist_ok=True)
        out_host.write_text('[{"RuleID":"x","Secret":"REDACTED"}]', encoding="utf-8")
        return 0, "", ""

    recs = sr.run_all("gitleaks", manifest, run_fn, ready_marker=marker)
    assert calls["n"] == 1 and recs[0]["finding_count"] == 1
    events = raw_dir / "execution-records.jsonl"
    assert (raw_dir / "o__r.record.json").exists() and events.exists()

    # Resume: a valid sidecar is reused; the scanner is NOT re-run.
    def boom(cmd):
        raise AssertionError("must not re-scan a valid cached output")
    recs2 = sr.run_all("gitleaks", manifest, boom, ready_marker=marker)
    assert recs2[0]["reused"] is True
    assert len(events.read_text(encoding="utf-8").strip().splitlines()) >= 2  # append-only

    # Stale identity (config drift) -> quarantine + re-scan (not skipped).
    stale = dict(marker); stale["configuration_hash"] = "OTHER_CFG_HASH"
    calls["n"] = 0
    sr.run_all("gitleaks", manifest, run_fn, ready_marker=stale)
    assert calls["n"] == 1
    assert list((raw_dir / "quarantine").glob("*"))
