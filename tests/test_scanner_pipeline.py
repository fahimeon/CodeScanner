"""Unit tests for the scan track: prepare_scanners, clone_selected_repositories,
and the shared scanner harness (all offline; docker/git behind injected runners)."""

import json
import subprocess
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


def test_prepare_fail_closed_when_build_fails_even_if_stale_image_exists(tmp_path, monkeypatch):
    """CS-015: a failed build must not reuse a stale :latest image and claim ready."""
    _point_caches(monkeypatch, tmp_path, populate=True)

    def run_fn(cmd):
        joined = " ".join(str(c) for c in cmd)
        if cmd[:2] == ["docker", "build"] or "Dockerfile.scanner" in joined:
            return 1, "", "build error: layer failed"      # BUILD FAILS
        if "RepoDigests" in joined:                          # a stale image still resolves
            return 0, "img@sha256:staaale\n", ""
        if "inspect" in cmd:
            return 0, "sha256:staleid\n", ""
        return 0, "v1.0.0\n", ""

    marker = ps.prepare("docker", "semgrep", "trivy", "osv-scanner", run_fn, build=True)
    assert marker["ready"] is False                          # never ready on failed build
    assert marker["image_digest"] is None and marker["image_id"] is None  # no stale reuse
    assert "scanner_image_not_built" in marker["problems"]


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


# --- P0 #6: Gitleaks history (separate mirror clone) ------------------------ #
def test_mirror_clone_args_and_history_guards():
    args = cl.build_mirror_clone_args("https://github.com/o/r", "/dest", "/hooks")
    joined = " ".join(args)
    assert "--mirror" in args and "protocol.ext.allowed=never" in joined
    limits = {"max_repo_size_mb": 10, "max_single_file_mb": 5}
    assert cl.check_history_guards(1_000_000, 1_000_000, limits) == (True, [])
    bad, reasons = cl.check_history_guards(20 * 1024 * 1024, 6 * 1024 * 1024, limits)
    assert bad is False and any("history_size" in r for r in reasons) and any("pack" in r for r in reasons)


def test_build_history_record_requires_frozen_commit():
    limits = {"max_repo_size_mb": 2048, "max_single_file_mb": 50}
    ok = cl.build_history_record("o/r", {"status": "OK", "git_size_bytes": 1000,
                                         "largest_pack_bytes": 100, "has_frozen_commit": True},
                                 "sha1", limits)
    assert ok["history_status"] == "OK"
    missing = cl.build_history_record("o/r", {"status": "OK", "git_size_bytes": 1000,
                                              "largest_pack_bytes": 100, "has_frozen_commit": False},
                                      "sha1", limits)
    assert missing["history_status"] == "HISTORY_CLONE_ERROR"
    assert "frozen_commit_absent_in_history" in missing["history_reasons"]


def test_gitleaks_history_fixture_parses_as_findings(tmp_path):
    fixture = (Path(__file__).resolve().parent / "fixtures" / "scanner_output" /
               "gitleaks-history.json")
    text = fixture.read_text(encoding="utf-8")
    assert "REDACTED" in text and "Commit" in text          # historical + redacted
    out = tmp_path / "raw" / "gitleaks-history" / "o__r.json"

    def run_fn(cmd):
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        return 0, "", ""

    rec = sr.run_one("gitleaks-history", "o/r", "CLR-0001", "sha1",
                     "/scan/repositories/o__r", out,
                     "/scan/results/raw/gitleaks-history/o__r.json", [], "img",
                     {"limits": {}}, run_fn, accepted_exit_codes={0})
    assert rec["status"] == "SUCCESS_WITH_FINDINGS" and rec["finding_count"] == 1


def test_clone_all_records_history_status(tmp_path):
    def clone_fn(full, url, ref, dest):
        return {"status": "OK", "size_bytes": 1000, "file_count": 5,
                "largest_file_bytes": 500, "checked_out_sha": ref}

    def history_fn(full, url, ref, dest):
        return {"status": "OK", "git_size_bytes": 2000, "largest_pack_bytes": 500,
                "has_frozen_commit": True}

    selected = [{"repository_full_name": "o/a", "repository_url": "https://github.com/o/a",
                 "frozen_commit_sha": "sha1"}]
    records = cl.clone_all(selected, tmp_path / "sel", tmp_path / "log.jsonl", clone_fn,
                           _LIMITS, history_clone_fn=history_fn, history_root=tmp_path / "hist")
    assert records[0]["status"] == "OK" and records[0]["history_status"] == "OK"


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
    sarif = json.dumps({"version": "2.1.0", "runs": [{"results": [1, 2, 3]}, {"results": [4]}]})
    assert sr.count_semgrep(sarif) == 4
    trivy = json.dumps({"Results": [{"Vulnerabilities": [1, 2], "Secrets": [3]},
                                    {"Misconfigurations": [4]}]})
    assert sr.count_trivy(trivy) == 4
    osv = json.dumps({"results": [{"packages": [{"vulnerabilities": [1, 2]},
                                                {"vulnerabilities": [3]}]}]})
    assert sr.count_osv(osv) == 3


# --- CS-012: valid JSON with the WRONG schema must be PARSER_ERROR, not zero -- #
def test_wrong_schema_json_is_parser_error_not_zero():
    err = json.dumps({"error": "rate limited", "code": 429})     # error-envelope JSON
    # None (=> PARSER_ERROR) for every scanner; a real empty scan (below) is 0.
    assert sr.count_gitleaks(err) is None                        # gitleaks report is an array
    assert sr.count_semgrep(err) is None                         # no version/runs
    assert sr.count_zizmor(err) is None
    assert sr.count_trivy(err) is None                           # no Results key
    assert sr.count_osv(err) is None                             # no results key
    # SARIF missing `version`, or `runs` not a list, is not a SARIF document.
    assert sr.count_semgrep(json.dumps({"runs": [{"results": []}]})) is None
    assert sr.count_semgrep(json.dumps({"version": "2.1.0", "runs": "nope"})) is None
    # A SARIF log from the WRONG tool is rejected on identity.
    other = json.dumps({"version": "2.1.0",
                        "runs": [{"tool": {"driver": {"name": "gitleaks"}}, "results": [1]}]})
    assert sr.count_semgrep(other) is None
    # Genuine empty scans still count as 0 (NO_FINDINGS), not PARSER_ERROR.
    assert sr.count_semgrep(json.dumps({"version": "2.1.0", "runs": []})) == 0
    assert sr.count_trivy(json.dumps({"SchemaVersion": 2, "Results": None})) == 0
    assert sr.count_osv(json.dumps({"results": []})) == 0


def test_run_one_wrong_schema_output_records_parser_error(tmp_path):
    """A scanner that exits 0 but writes wrong-schema JSON -> PARSER_ERROR record."""
    out = tmp_path / "raw" / "trivy" / "o__r.json"

    def run_fn(cmd):
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps({"error": "db missing"}), encoding="utf-8")
        return 0, "", ""

    rec = sr.run_one("trivy", "o/r", "CLR-0001", "sha1", "/scan/repositories/o__r",
                     out, "/scan/results/raw/trivy/o__r.json", [], "img",
                     {"limits": {}}, run_fn)
    assert rec["status"] == "PARSER_ERROR" and rec["finding_count"] is None
    assert rec["schema_valid"] is False


def test_classify_execution():
    assert sr.classify_execution(0, False, 5) == "SUCCESS_WITH_FINDINGS"
    assert sr.classify_execution(0, False, 0) == "NO_FINDINGS"
    assert sr.classify_execution(0, False, None) == "PARSER_ERROR"
    assert sr.classify_execution(2, False, None) == "SCANNER_ERROR"
    assert sr.classify_execution(0, True, None) == "TIMEOUT"


# --- CS-007: batch outcome -> process exit code (findings never fail a run) --- #
def test_run_exit_policy():
    policy = {"fail_if_attempted_zero": True, "fail_if_successful_zero": True,
              "max_scanner_error_rate": 0.02, "max_timeout_rate": 0.05}

    def recs(**counts):
        out = []
        for status, k in counts.items():
            out += [{"status": status.upper()}] * k
        return out

    # Nothing attempted -> systemic (4).
    assert sr.run_exit_policy([], policy)[0] == 4
    # Everything failed -> systemic (4).
    assert sr.run_exit_policy(recs(scanner_error=5), policy)[0] == 4
    # A clean run, including findings, is exit 0 (findings never fail a run).
    assert sr.run_exit_policy(recs(success_with_findings=50, no_findings=50), policy)[0] == 0
    # One error in 100 = 1% <= 2% threshold -> still 0.
    assert sr.run_exit_policy(recs(no_findings=99, scanner_error=1), policy)[0] == 0
    # 5 errors in 100 = 5% > 2% -> degraded (3), not systemic.
    assert sr.run_exit_policy(recs(no_findings=95, scanner_error=5), policy)[0] == 3
    # 10 timeouts in 100 = 10% > 5% -> degraded (3).
    assert sr.run_exit_policy(recs(no_findings=90, timeout=10), policy)[0] == 3
    # NOT_APPLICABLE counts as a successful conclusion, not a failure.
    assert sr.run_exit_policy(recs(not_applicable=100), policy)[0] == 0


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


# --- CS-003: a scanner timeout must record TIMEOUT and NOT abort the batch --- #
def test_run_one_timeout_expired_becomes_timeout_record(tmp_path):
    """A raw subprocess.TimeoutExpired (NOT a subclass of built-in TimeoutError)
    must still be recorded as TIMEOUT, and the timed-out container force-removed."""
    killed = []

    def run_fn(cmd):
        raise subprocess.TimeoutExpired(cmd, 1200)

    rec = sr.run_one("semgrep", "o/r", "CLR-0001", "sha1", "/scan/repositories/o__r",
                     tmp_path / "out.sarif", "/scan/results/raw/semgrep/o__r.sarif",
                     [], "img", {"limits": {}}, run_fn,
                     container_name="cds-semgrep-o__r", kill_fn=killed.append)
    assert rec["status"] == "TIMEOUT" and rec["timeout_status"] == "TIMEOUT"
    assert rec["exit_code"] == 124 and rec["finding_count"] is None   # never zeroed
    assert killed == ["cds-semgrep-o__r"]                             # container cleaned up


def test_run_all_continues_to_next_repo_after_timeout(tmp_path, monkeypatch):
    """The first repository times out; the batch must continue and scan the second."""
    monkeypatch.setattr(sr, "STUDY_ROOT", tmp_path)
    for name in ("o__a", "o__b"):
        (tmp_path / "repositories" / "selected" / name).mkdir(parents=True)
    raw_dir = tmp_path / "results" / "raw" / "gitleaks"
    marker = {"pinned_scanner_versions": {"gitleaks": "8.21.2"}, "image_digest": "IMG",
              "configuration_hash": common.config_bundle_hash()}
    manifest = [{"repository_full_name": "o/a", "status": "OK",
                 "anonymous_id": "CLR-0001", "checked_out_sha": "sha1"},
                {"repository_full_name": "o/b", "status": "OK",
                 "anonymous_id": "CLR-0002", "checked_out_sha": "sha2"}]
    killed = []

    def run_fn(cmd):
        if "o__a" in " ".join(cmd):
            raise subprocess.TimeoutExpired(cmd, 1200)     # first repo times out
        out = raw_dir / "o__b.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text('[{"RuleID":"x","Secret":"REDACTED"}]', encoding="utf-8")
        return 0, "", ""

    recs = sr.run_all("gitleaks", manifest, run_fn, ready_marker=marker,
                      kill_fn=killed.append)
    by_repo = {r["repository_full_name"]: r for r in recs}
    assert by_repo["o/a"]["status"] == "TIMEOUT"           # first recorded, not raised
    assert by_repo["o/b"]["status"] == "SUCCESS_WITH_FINDINGS"   # batch continued
    assert killed == ["cds-gitleaks-o__a"]


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


def test_zizmor_not_applicable_without_workflows(tmp_path, monkeypatch):
    """CS-017: a repo with no .github/workflows -> NOT_APPLICABLE, no container run."""
    monkeypatch.setattr(sr, "STUDY_ROOT", tmp_path)
    repo = tmp_path / "repositories" / "selected" / "o__r"
    repo.mkdir(parents=True)               # NO .github/workflows
    marker = {"pinned_scanner_versions": {"zizmor": "1.0.0"}, "image_digest": "IMG",
              "configuration_hash": common.config_bundle_hash()}
    manifest = [{"repository_full_name": "o/r", "status": "OK",
                 "anonymous_id": "CLR-0001", "checked_out_sha": "sha1"}]

    def boom(cmd):
        raise AssertionError("zizmor must not run a container when not applicable")

    recs = sr.run_all("zizmor", manifest, boom, ready_marker=marker)
    assert recs[0]["status"] == "NOT_APPLICABLE"
    assert recs[0]["finding_count"] is None and recs[0]["applicable_file_count"] == 0
    assert recs[0]["error_message"] == "no_github_workflows"

    # With a workflow present, zizmor DOES run.
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / ".github" / "workflows" / "ci.yml").write_text("on: push", encoding="utf-8")
    raw = tmp_path / "results" / "raw" / "zizmor" / "o__r.sarif"

    def run_fn(cmd):
        raw.parent.mkdir(parents=True, exist_ok=True)
        raw.write_text(json.dumps({"version": "2.1.0", "runs": []}), encoding="utf-8")
        return 0, "", ""

    recs2 = sr.run_all("zizmor", manifest, run_fn, ready_marker=marker)
    assert recs2[0]["status"] == "NO_FINDINGS"


def test_count_workflow_files(tmp_path):
    assert sr.count_workflow_files(tmp_path) == 0
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text("on: push", encoding="utf-8")
    (wf / "release.yaml").write_text("on: tag", encoding="utf-8")
    (wf / "notes.md").write_text("ignore me", encoding="utf-8")
    assert sr.count_workflow_files(tmp_path) == 2


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
