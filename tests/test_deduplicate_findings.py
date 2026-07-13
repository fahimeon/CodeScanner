"""Unit tests for deduplicate_findings.py — cross-scanner dedup + overlap (offline)."""

import deduplicate_findings as dd


def _dep(repo, scanner, adv, pkg="lodash", sev="high"):
    return {"repository_full_name": repo, "scanner": scanner, "category": "vulnerable_dependencies",
            "rule_id": adv, "package": pkg, "normalized_severity": sev, "detection_reliability": "strong"}


def _code(repo, scanner, cat, file, line, sev="high", source="working_tree"):
    return {"repository_full_name": repo, "scanner": scanner, "category": cat, "file": file,
            "line": line, "normalized_severity": sev, "source": source,
            "detection_reliability": "partial"}


def test_dependency_overlap_collapses_across_scanners():
    findings = [_dep("o/a", "trivy", "CVE-2020-8203"),
                _dep("o/a", "osv-scanner", "cve-2020-8203")]   # same advisory, case-insensitive
    out = dd.deduplicate(findings)
    assert len(out) == 1
    assert out[0]["scanner_count"] == 2 and out[0]["duplicate_count"] == 2
    assert set(out[0]["scanners"].split(";")) == {"trivy", "osv-scanner"}


def test_distinct_advisories_not_merged():
    findings = [_dep("o/a", "trivy", "CVE-1"), _dep("o/a", "osv-scanner", "CVE-2")]
    assert len(dd.deduplicate(findings)) == 2


def test_code_findings_merge_on_file_line_category():
    findings = [_code("o/a", "semgrep", "exposed_secrets", "cfg.ts", 3),
                _code("o/a", "trivy", "exposed_secrets", "cfg.ts", 3)]
    out = dd.deduplicate(findings)
    assert len(out) == 1 and out[0]["scanner_count"] == 2


def test_secrets_working_tree_vs_history_kept_separate():
    findings = [_code("o/a", "gitleaks", "exposed_secrets", "x.ts", 1, source="working_tree"),
                _code("o/a", "gitleaks-history", "exposed_secrets", "x.ts", 1, source="history")]
    out = dd.deduplicate(findings)
    assert len(out) == 2                          # different source -> not merged


def test_representative_keeps_highest_severity():
    findings = [_dep("o/a", "trivy", "CVE-9", sev="low"),
                _dep("o/a", "osv-scanner", "CVE-9", sev="critical")]
    out = dd.deduplicate(findings)
    assert out[0]["normalized_severity"] == "critical"


def test_overlap_summary_measures_pairs_and_rate():
    findings = [_dep("o/a", "trivy", "CVE-1"), _dep("o/a", "osv-scanner", "CVE-1"),
                _code("o/b", "semgrep", "cross_site_scripting", "a.ts", 5)]
    deduped = dd.deduplicate(findings)
    s = dd.overlap_summary(deduped, raw_total=len(findings))
    assert s["raw_findings"] == 3 and s["deduplicated_findings"] == 2
    assert s["collapsed"] == 1 and s["multi_scanner_findings"] == 1
    assert s["by_scanner_pair"].get("osv-scanner+trivy") == 1


def test_write_deduplicated_header(tmp_path):
    out = dd.deduplicate([_dep("o/a", "trivy", "CVE-1")])
    dd.write_deduplicated(out, tmp_path / "d.json", tmp_path / "d.csv")
    import csv
    with (tmp_path / "d.csv").open(encoding="utf-8") as fh:
        assert next(csv.reader(fh)) == dd.DEDUP_FIELDS
    assert not list(tmp_path.glob("*.tmp"))
