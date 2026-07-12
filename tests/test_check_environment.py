"""Unit tests for check_environment.py — readiness logic + scanner pinning (offline)."""

import check_environment as ce


# --------------------------------------------------------------------------- #
# Exit-code decision (collection gate vs strict-scan)
# --------------------------------------------------------------------------- #
def test_exit_code_for_collection_gate():
    ready_collect_only = {"collection_ready": True, "scanning_ready": False}
    assert ce.exit_code_for(ready_collect_only) == 0
    # --strict-scan additionally requires scanning readiness.
    assert ce.exit_code_for(ready_collect_only, strict_scan=True) == 1

    not_ready = {"collection_ready": False, "scanning_ready": False}
    assert ce.exit_code_for(not_ready) == 1
    assert ce.exit_code_for(not_ready, no_strict=True) == 0        # forced success

    all_ready = {"collection_ready": True, "scanning_ready": True}
    assert ce.exit_code_for(all_ready, strict_scan=True) == 0


# --------------------------------------------------------------------------- #
# Scanner pin parsing + host reconciliation
# --------------------------------------------------------------------------- #
def test_parse_scanner_pins_reads_dockerfile():
    pins = ce.parse_scanner_pins()   # reads the real docker/Dockerfile.scanner
    assert pins.get("gitleaks") == "8.21.2"
    assert pins.get("trivy") == "0.58.0"
    assert pins.get("semgrep") == "1.97.0"


def test_reconcile_flags_host_pin_drift():
    tools = {
        "gitleaks": {"present": True, "version": "8.30.1"},   # != pinned 8.21.2
        "trivy": {"present": True, "version": "Version: 0.58.0"},  # == pinned
        "semgrep": {"present": False, "version": None},       # absent -> matches None
    }
    pins = {"gitleaks": "8.21.2", "trivy": "0.58.0", "semgrep": "1.97.0"}
    recon = ce.reconcile_scanner_versions(tools, pins)
    assert "gitleaks" in recon["host_pin_drift"]
    assert "trivy" not in recon["host_pin_drift"]
    assert "semgrep" not in recon["host_pin_drift"]   # host absent -> not counted as drift
    assert recon["drift_detected"] is True


# --------------------------------------------------------------------------- #
# Scanning readiness requires a built+pinned image
# --------------------------------------------------------------------------- #
def _manifest(scanner_digest):
    return {
        "tools": {name: {"present": True} for name in
                  ("docker", "git", "gh", "gitleaks", "trivy", "osv-scanner", "zizmor")}
                 | {"semgrep": {"present": False}},
        "python": {"meets_minimum_3_11": True},
        "github_auth": {"authenticated": True},
        "loc_counter": {"satisfied": True},
        "container_image_digests": {"claude-study-scanner:latest": scanner_digest},
        "scanner_version_reconciliation": {"host_pin_drift": []},
    }


def test_scanning_not_ready_without_built_image():
    r = ce.evaluate_readiness(_manifest(scanner_digest=None))
    assert r["collection_ready"] is True
    assert r["scanning_ready"] is False
    assert r["scanner_image_built"] is False
    assert any("not built" in p for p in r["scanning_problems"])


def test_scanning_ready_once_image_built():
    r = ce.evaluate_readiness(_manifest(scanner_digest="sha256:abc123"))
    assert r["scanning_ready"] is True
    assert r["scanner_image_built"] is True
