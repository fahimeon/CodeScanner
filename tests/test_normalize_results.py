"""Unit tests for normalize_results.py — per-scanner parsers + severity (offline)."""

import json
from pathlib import Path

import normalize_results as nr
import _common as common

SEV = common.load_yaml(common.CONFIG_DIR / "severity-mapping.yaml")
FIX = Path(__file__).resolve().parent / "fixtures" / "scanner_output"
CTX = {"repository_full_name": "octo/app", "anonymous_id": "CLR-0001", "commit_sha": "sha1"}


def _read(name):
    return (FIX / name).read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# Severity normalization
# --------------------------------------------------------------------------- #
def test_normalize_severity_and_cvss():
    assert nr.normalize_severity("semgrep", "error", SEV) == "high"
    assert nr.normalize_severity("trivy", "CRITICAL", SEV) == "critical"
    assert nr.normalize_severity("gitleaks", None, SEV) == "high"          # _default
    assert nr.normalize_severity("osv-scanner", None, SEV, cvss_score=9.5) == "critical"
    assert nr.normalize_severity("osv-scanner", None, SEV, cvss_score=5.0) == "medium"
    assert nr.normalize_severity("semgrep", "nonsense", SEV) == "unknown"


def test_finding_id_is_stable_and_distinct():
    a = nr.finding_id(CTX, "gitleaks", "working_tree", "r1", "f.ts", 1)
    b = nr.finding_id(CTX, "gitleaks", "working_tree", "r1", "f.ts", 1)
    c = nr.finding_id(CTX, "gitleaks", "working_tree", "r1", "f.ts", 2)
    assert a == b and a != c and len(a) == 64


# --------------------------------------------------------------------------- #
# Per-scanner parsers (against the synthetic positive fixtures)
# --------------------------------------------------------------------------- #
def test_parse_gitleaks_working_and_history():
    wt = nr.parse_gitleaks(_read("gitleaks.json"), CTX, SEV, source="working_tree")
    assert len(wt) == 1 and wt[0]["scanner"] == "gitleaks" and wt[0]["source"] == "working_tree"
    assert wt[0]["normalized_severity"] == "high"
    hist = nr.parse_gitleaks(_read("gitleaks-history.json"), CTX, SEV, source="history")
    assert hist[0]["scanner"] == "gitleaks-history" and hist[0]["source"] == "history"


def test_parse_semgrep_sarif():
    fs = nr.parse_semgrep(_read("semgrep.sarif"), CTX, SEV)
    assert len(fs) == 1
    f = fs[0]
    assert f["scanner"] == "semgrep" and f["native_severity"] == "error"
    assert f["normalized_severity"] == "high" and f["file"] == "src/routes/user.ts"
    assert f["line"] == 42


def test_parse_trivy_vulnerabilities():
    fs = nr.parse_trivy(_read("trivy.json"), CTX, SEV)
    assert len(fs) == 1 and fs[0]["rule_id"] == "CVE-2020-8203"
    assert fs[0]["package"] == "lodash" and fs[0]["normalized_severity"] == "high"


def test_parse_osv_vulnerabilities():
    fs = nr.parse_osv(_read("osv-scanner.json"), CTX, SEV)
    assert len(fs) == 1 and fs[0]["rule_id"] == "GHSA-p6mc-m468-83gw"
    assert fs[0]["package"] == "lodash"


def test_parse_zizmor_sarif():
    fs = nr.parse_zizmor(_read("zizmor.sarif"), CTX, SEV)
    assert len(fs) == 1 and fs[0]["scanner"] == "zizmor"
    assert fs[0]["normalized_severity"] == "high"        # SARIF error -> high


def test_normalize_scanner_output_dispatch():
    fs = nr.normalize_scanner_output("gitleaks-history", _read("gitleaks-history.json"), CTX, SEV)
    assert fs[0]["source"] == "history"


def test_parsers_handle_garbage():
    for p in (nr.parse_gitleaks, nr.parse_semgrep, nr.parse_trivy, nr.parse_osv, nr.parse_zizmor):
        assert p("not json", CTX, SEV) == []
        assert p("", CTX, SEV) == []


# --------------------------------------------------------------------------- #
# Orchestrator + writer
# --------------------------------------------------------------------------- #
def test_normalize_all_reads_sidecars_and_writes(tmp_path):
    raw = tmp_path / "raw"
    # Two scanners, one repo each, with sidecar records providing repo/commit ids.
    for scanner, fixture, ext in [("gitleaks", "gitleaks.json", "json"),
                                  ("semgrep", "semgrep.sarif", "sarif")]:
        d = raw / scanner
        d.mkdir(parents=True)
        (d / f"octo__app.{ext}").write_text(_read(fixture), encoding="utf-8")
        (d / "octo__app.record.json").write_text(json.dumps(
            {"repository_full_name": "octo/app", "anonymous_id": "CLR-0001",
             "commit_sha": "sha1"}), encoding="utf-8")

    findings = nr.normalize_all(["gitleaks", "semgrep"], raw, SEV)
    assert len(findings) == 2
    assert all(f["repository_full_name"] == "octo/app" and f["commit_sha"] == "sha1"
               for f in findings)

    nr.write_findings(findings, tmp_path / "f.json", tmp_path / "f.csv")
    import csv as _csv
    with (tmp_path / "f.csv").open(encoding="utf-8") as fh:
        assert next(_csv.reader(fh)) == nr.FINDING_FIELDS
    assert not list(tmp_path.glob("*.tmp"))
