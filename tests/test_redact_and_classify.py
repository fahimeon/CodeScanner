"""Unit tests for redact_secrets.py + classify_findings.py (offline; fake secrets)."""

import redact_secrets as rs
import classify_findings as cf
import _common as common

TAX = common.load_yaml(common.CONFIG_DIR / "finding-taxonomy.yaml")


# --------------------------------------------------------------------------- #
# Redaction of findings (audit #19)
# --------------------------------------------------------------------------- #
def test_redact_findings_masks_and_counts():
    findings = [
        {"rule_id": "generic", "title": "leaked AKIAABCDEFGHIJKLMNOP here", "file": "a.ts"},
        {"rule_id": "clean", "title": "possible XSS", "file": "b.ts"},
    ]
    out, leaked = rs.redact_findings(findings)
    assert leaked == 1
    assert "AKIA" not in out[0]["title"] and "REDACTED" in out[0]["title"]
    assert out[1]["title"] == "possible XSS"


# --------------------------------------------------------------------------- #
# Taxonomy classification
# --------------------------------------------------------------------------- #
def test_classify_by_scanner_defaults():
    gl = cf.classify_finding({"scanner": "gitleaks", "rule_id": "generic-api-key"}, TAX)
    assert gl["category"] == "exposed_secrets" and gl["detection_reliability"] == "strong"
    osv = cf.classify_finding({"scanner": "osv-scanner", "rule_id": "GHSA-xxxx", "title": "vuln"}, TAX)
    assert osv["category"] == "vulnerable_dependencies"
    ziz = cf.classify_finding({"scanner": "zizmor", "rule_id": "artipacked", "title": "risk"}, TAX)
    assert ziz["category"] == "github_actions_risk"


def test_classify_semgrep_by_keyword():
    xss = cf.classify_finding({"scanner": "semgrep", "rule_id": "js.audit.xss.direct-write",
                               "title": "Detected XSS"}, TAX)
    assert xss["category"] == "cross_site_scripting" and xss["detection_reliability"] == "partial"
    sqli = cf.classify_finding({"scanner": "semgrep", "rule_id": "js.sqli.raw-query",
                                "title": "SQL injection"}, TAX)
    assert sqli["category"] == "sql_injection"
    crypto = cf.classify_finding({"scanner": "semgrep", "rule_id": "weak-crypto-md5",
                                  "title": "weak hash"}, TAX)
    assert crypto["category"] == "weak_cryptography" and crypto["detection_reliability"] == "strong"


def test_classify_trivy_misconfig_vs_dependency():
    dep = cf.classify_finding({"scanner": "trivy", "rule_id": "CVE-2020-8203",
                               "file": "package-lock.json", "package": "lodash"}, TAX)
    assert dep["category"] == "vulnerable_dependencies"
    docker = cf.classify_finding({"scanner": "trivy", "rule_id": "DS002",
                                  "file": "Dockerfile", "title": "root user"}, TAX)
    assert docker["category"] == "docker_misconfiguration"


def test_classify_unknown_semgrep_gets_partial_not_guessed_cwe():
    f = cf.classify_finding({"scanner": "semgrep", "rule_id": "some.obscure.rule",
                             "title": "unclear"}, TAX)
    assert f["category"] == "unknown" and f["detection_reliability"] == "partial"
    assert f["cwe"] is None                         # never a guessed CWE


def test_classify_attaches_cwe_from_taxonomy():
    f = cf.classify_finding({"scanner": "gitleaks", "rule_id": "aws"}, TAX)
    assert f["cwe"] and "CWE-798" in f["cwe"]        # from taxonomy category
