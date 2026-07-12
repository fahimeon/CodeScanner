"""Unit tests for the scan track: prepare_scanners, clone_selected_repositories,
and the shared scanner harness (all offline; docker/git behind injected runners)."""

import json
from pathlib import Path

import prepare_scanners as ps
import clone_selected_repositories as cl
import _scanner_runner as sr


# =========================================================================== #
# prepare_scanners
# =========================================================================== #
def test_build_image_and_inspect_args():
    assert ps.build_image_args("docker/Dockerfile.scanner", "img")[:2] == ["build", "-f"]
    assert "img" in ps.inspect_digest_args("img")
    assert ps.parse_digest("  sha256:abc  ") == "sha256:abc"
    assert ps.parse_digest("") is None


def test_prepare_sequence_records_steps_and_digest(tmp_path):
    calls = []

    def run_fn(cmd):
        calls.append(cmd)
        if "inspect" in cmd and "{{index .RepoDigests 0}}" in cmd:
            return 0, "myimage@sha256:deadbeef\n", ""
        if "inspect" in cmd:
            return 0, "sha256:localid\n", ""
        return 0, "", ""

    manifest = ps.prepare("docker", "trivy", run_fn, build=True, cache_root=tmp_path)
    assert manifest["image_prepared"] is True
    assert manifest["image_digest"] == "myimage@sha256:deadbeef"
    names = [s["name"] for s in manifest["steps"]]
    assert "build_scanner_image" in names and "prefetch_trivy_db" in names
    assert manifest["pinned_scanner_versions"].get("gitleaks")   # from Dockerfile


def test_prepare_reports_unprepared_when_no_digest(tmp_path):
    def run_fn(cmd):
        return 1, "", "boom"        # everything fails
    manifest = ps.prepare("docker", None, run_fn, build=True, cache_root=tmp_path)
    assert manifest["image_prepared"] is False


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


def test_clone_all_uses_metadata_sha_and_records(tmp_path):
    def clone_fn(full, url, ref, dest):
        assert ref == "frozensha123"           # from metadata default_branch_head_sha
        return {"status": "OK", "size_bytes": 1000, "file_count": 5,
                "largest_file_bytes": 500, "checked_out_sha": ref}

    selected = [{"repository_full_name": "o/a", "anonymous_id": "CLR-0001"}]
    metadata = {"o/a": {"repository_url": "https://github.com/o/a",
                        "default_branch_head_sha": "frozensha123"}}
    limits = {"max_repo_size_mb": 2048, "max_file_count": 200000, "max_single_file_mb": 50}
    records = cl.clone_all(selected, metadata, tmp_path / "sel", tmp_path / "log.jsonl",
                           clone_fn, limits)
    assert records[0]["status"] == "OK"
    assert records[0]["checked_out_sha"] == "frozensha123"


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
