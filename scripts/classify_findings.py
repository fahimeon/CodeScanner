#!/usr/bin/env python3
"""
classify_findings.py — Phase 29-30 map findings to the taxonomy.

Assigns each normalized/redacted finding a canonical category from
finding-taxonomy.yaml, attaching that category's detection_reliability and CWE.
Mapping is rule-based (scanner + rule_id/title keywords) and conservative: an
unmatched finding gets category "unknown" with the scanner's default reliability
(never a guessed CWE). Reliability travels with every finding so downstream
analysis can separate strong/partial from weak/out_of_scope categories.

Pure `classify_finding` split from I/O; unit-tested offline.

Input:  results/redacted/findings.json
Output: results/redacted/findings-classified.json (+ .csv)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional

try:
    from . import _common as common  # type: ignore
    from . import normalize_results as nr  # type: ignore
except Exception:  # pragma: no cover
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _common as common  # type: ignore
    import normalize_results as nr  # type: ignore

STUDY_ROOT = common.STUDY_ROOT

# Semgrep/zizmor keyword -> taxonomy category (first match wins; ordered).
KEYWORD_CATEGORY = [
    ("xss", "cross_site_scripting"), ("cross-site-scripting", "cross_site_scripting"),
    ("sqli", "sql_injection"), ("sql-injection", "sql_injection"), ("sql_injection", "sql_injection"),
    ("command-injection", "command_injection"), ("command_injection", "command_injection"),
    ("os-command", "command_injection"),
    ("path-traversal", "path_traversal"), ("path_traversal", "path_traversal"),
    ("ssrf", "server_side_request_forgery"), ("server-side-request", "server_side_request_forgery"),
    ("open-redirect", "open_redirect"), ("open_redirect", "open_redirect"),
    ("deserial", "insecure_deserialization"),
    ("prototype-pollution", "prototype_pollution"), ("prototype_pollution", "prototype_pollution"),
    ("code-injection", "code_injection"), ("eval", "code_injection"),
    ("template-injection", "server_side_template_injection"),
    ("nosql", "nosql_injection"), ("xxe", "xxe"), ("redos", "redos"),
    ("csrf", "csrf"), ("cookie", "insecure_cookies"), ("cors", "insecure_cors"),
    ("crypto", "weak_cryptography"), ("cipher", "weak_cryptography"), ("hash", "weak_cryptography"),
    ("session", "insecure_session_config"), ("jwt", "authentication_weakness"),
    ("hardcoded", "hardcoded_credentials"), ("secret", "exposed_secrets"),
    ("permission", "excessive_workflow_permissions"), ("unpinned", "unpinned_workflow_dependencies"),
    ("template_injection", "server_side_template_injection"),
]

# Scanner -> (default category, default reliability when unmatched)
SCANNER_DEFAULT = {
    "gitleaks": ("exposed_secrets", "strong"),
    "gitleaks-history": ("exposed_secrets", "strong"),
    "osv-scanner": ("vulnerable_dependencies", "strong"),
    "trivy": ("vulnerable_dependencies", "strong"),   # refined below for misconfig
    "semgrep": ("unknown", "partial"),
    "zizmor": ("github_actions_risk", "partial"),
}


# =========================================================================== #
# PURE
# =========================================================================== #
def _keyword_category(text: str) -> Optional[str]:
    low = (text or "").lower()
    for kw, cat in KEYWORD_CATEGORY:
        if kw in low:
            return cat
    return None


def classify_finding(finding: dict, taxonomy: dict) -> dict:
    scanner = finding.get("scanner")
    rule = str(finding.get("rule_id") or "")
    title = str(finding.get("title") or "")
    hay = f"{rule} {title} {finding.get('file') or ''}"
    cats = taxonomy.get("categories", {})

    category = _keyword_category(hay)
    if not category:
        if scanner == "trivy":
            fileref = (finding.get("file") or "").lower()
            if "dockerfile" in fileref or "docker-compose" in fileref:
                category = "docker_misconfiguration"
            elif rule.upper().startswith(("CVE-", "GHSA-")):
                category = "vulnerable_dependencies"
            else:
                category = "infrastructure_misconfiguration" if rule and not rule[0].isdigit() \
                    else "vulnerable_dependencies"
        else:
            category = SCANNER_DEFAULT.get(scanner, ("unknown", "unknown"))[0]

    cat_meta = cats.get(category, {})
    reliability = cat_meta.get("detection_reliability") or \
        SCANNER_DEFAULT.get(scanner, ("unknown", "unknown"))[1]
    out = dict(finding)
    out["category"] = category
    out["detection_reliability"] = reliability
    out["cwe"] = out.get("cwe") or (";".join(cat_meta["cwe"]) if isinstance(cat_meta.get("cwe"), list) else None)
    out["owasp"] = cat_meta.get("owasp")
    return out


def classify_all(findings: list[dict], taxonomy: dict) -> list[dict]:
    return [classify_finding(f, taxonomy) for f in findings]


CLASSIFIED_FIELDS = nr.FINDING_FIELDS + ["category", "detection_reliability", "owasp"]


# =========================================================================== #
# main
# =========================================================================== #
def main(argv: Optional[list[str]] = None) -> int:
    argparse.ArgumentParser(description="Classify findings into the taxonomy (Phase 29-30).").parse_args(argv)
    cfg = common.load_study_config()
    taxonomy = common.load_yaml(common.CONFIG_DIR / "finding-taxonomy.yaml")
    redacted = STUDY_ROOT / cfg["paths"]["results_redacted"] / "findings.json"
    out_dir = STUDY_ROOT / cfg["paths"]["results_redacted"]
    if not redacted.exists():
        print("ERROR: redacted findings not found. Run redact_secrets.py first.", file=sys.stderr)
        return 2

    classified = classify_all(common.read_json(redacted), taxonomy)
    _write(classified, out_dir / "findings-classified.json", out_dir / "findings-classified.csv")

    from collections import Counter
    by_cat = Counter(f["category"] for f in classified)
    by_rel = Counter(f["detection_reliability"] for f in classified)
    print(f"Classified {len(classified)} findings -> {out_dir / 'findings-classified.csv'}")
    print(f"  by reliability: {dict(by_rel)}")
    print(f"  top categories: {dict(by_cat.most_common(8))}")
    return 0


def _write(records: list[dict], json_path: Path, csv_path: Path) -> None:
    import csv
    import os
    common.atomic_write_json(json_path, records)
    common.ensure_dir(csv_path.parent)
    tmp = csv_path.with_suffix(".csv.tmp")
    with tmp.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=CLASSIFIED_FIELDS, extrasaction="ignore")
        w.writeheader()
        for r in records:
            w.writerow(r)
    os.replace(tmp, csv_path)


if __name__ == "__main__":
    raise SystemExit(main())
