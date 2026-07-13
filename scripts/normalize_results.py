#!/usr/bin/env python3
"""
normalize_results.py — Phase 29-30 normalize raw scanner output.

Parses each scanner's raw output (gitleaks/trivy/osv JSON, semgrep/zizmor SARIF)
into ONE unified finding schema, preserving BOTH the native and normalized
severity (severity-mapping.yaml). Cross-scanner severities are NOT assumed
equivalent; unavailable severity -> "unknown". No repository code is executed.

Pure per-scanner parsers + severity normalization are split from I/O and
unit-tested offline against the synthetic scanner-output fixtures.

Outputs: results/normalized/findings.{json,csv}
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from pathlib import Path
from typing import Optional

try:
    from . import _common as common  # type: ignore
    from . import verify_claude_attribution as vca  # type: ignore
except Exception:  # pragma: no cover
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _common as common  # type: ignore
    import verify_claude_attribution as vca  # type: ignore

STUDY_ROOT = common.STUDY_ROOT

# scanner name -> severity-mapping.yaml key
_SEV_KEY = {"gitleaks": "gitleaks", "gitleaks-history": "gitleaks", "semgrep": "semgrep",
            "trivy": "trivy", "osv-scanner": "osv_scanner", "zizmor": "zizmor"}

FINDING_FIELDS = [
    "finding_id", "repository_full_name", "anonymous_id", "scanner", "source",
    "rule_id", "title", "file", "line", "package",
    "native_severity", "normalized_severity", "confidence", "cwe", "commit_sha",
]


# =========================================================================== #
# PURE — severity normalization
# =========================================================================== #
def cvss_band(score: Optional[float], bands: dict) -> str:
    if score is None:
        return "unknown"
    for name, b in bands.items():
        if b.get("min", 0) <= score <= b.get("max", 10):
            return name
    return "unknown"


def normalize_severity(scanner: str, native, sev_cfg: dict,
                       cvss_score: Optional[float] = None) -> str:
    m = sev_cfg.get("mappings", {}).get(_SEV_KEY.get(scanner, scanner), {})
    if native is not None:
        v = m.get(str(native).lower())
        if v:
            return v
    if cvss_score is not None:
        return cvss_band(cvss_score, sev_cfg.get("cvss_to_normalized", {}))
    return m.get("_default", sev_cfg.get("policy", {}).get("default_when_unavailable", "unknown"))


def finding_id(ctx: dict, scanner: str, source: str, rule_id, file, line, package="") -> str:
    key = "|".join(str(x) for x in [ctx.get("repository_full_name"), scanner, source,
                                    rule_id, file, line, package])
    return common.sha256_hex(key)


def _finding(ctx: dict, scanner: str, source: str, *, rule_id=None, title=None,
             file=None, line=None, package=None, native_severity=None,
             normalized_severity="unknown", confidence="unknown", cwe=None) -> dict:
    return {
        "finding_id": finding_id(ctx, scanner, source, rule_id, file, line, package or ""),
        "repository_full_name": ctx.get("repository_full_name"),
        "anonymous_id": ctx.get("anonymous_id"),
        "scanner": scanner,
        "source": source,
        "rule_id": rule_id,
        "title": (title or "")[:300],
        "file": file,
        "line": line,
        "package": package,
        "native_severity": native_severity,
        "normalized_severity": normalized_severity,
        "confidence": confidence,
        "cwe": ";".join(cwe) if isinstance(cwe, list) else cwe,
        "commit_sha": ctx.get("commit_sha"),
    }


# =========================================================================== #
# PURE — per-scanner parsers  (text, ctx, sev_cfg) -> [finding]
# =========================================================================== #
def _load(text):
    try:
        return json.loads(text) if text and text.strip() else None
    except Exception:
        return None


def parse_gitleaks(text, ctx, sev_cfg, source="working_tree") -> list[dict]:
    obj = _load(text)
    if not isinstance(obj, list):
        return []
    out = []
    for f in obj:
        if not isinstance(f, dict):
            continue
        out.append(_finding(ctx, "gitleaks" if source == "working_tree" else "gitleaks-history",
                            source, rule_id=f.get("RuleID"),
                            title=f.get("Description") or f.get("RuleID"),
                            file=f.get("File"), line=f.get("StartLine"),
                            native_severity=None,
                            normalized_severity=normalize_severity("gitleaks", None, sev_cfg)))
    return out


def _sarif_results(text):
    obj = _load(text)
    if not isinstance(obj, dict):
        return []
    res = []
    for run in obj.get("runs") or []:
        for r in run.get("results") or []:
            res.append(r)
    return res


def _sarif_loc(r):
    for loc in r.get("locations") or []:
        pl = loc.get("physicalLocation", {})
        uri = pl.get("artifactLocation", {}).get("uri")
        line = pl.get("region", {}).get("startLine")
        return uri, line
    return None, None


def parse_semgrep(text, ctx, sev_cfg, source="working_tree") -> list[dict]:
    out = []
    for r in _sarif_results(text):
        uri, line = _sarif_loc(r)
        level = r.get("level")
        out.append(_finding(ctx, "semgrep", source, rule_id=r.get("ruleId"),
                            title=(r.get("message") or {}).get("text"), file=uri, line=line,
                            native_severity=level,
                            normalized_severity=normalize_severity("semgrep", level, sev_cfg)))
    return out


def parse_zizmor(text, ctx, sev_cfg, source="working_tree") -> list[dict]:
    out = []
    for r in _sarif_results(text):
        uri, line = _sarif_loc(r)
        level = r.get("level")
        # SARIF level (error/warning/note) mapped like semgrep if zizmor emits severity text.
        native = {"error": "high", "warning": "medium", "note": "low"}.get(level, level)
        out.append(_finding(ctx, "zizmor", source, rule_id=r.get("ruleId"),
                            title=(r.get("message") or {}).get("text"), file=uri, line=line,
                            native_severity=native,
                            normalized_severity=normalize_severity("zizmor", native, sev_cfg)))
    return out


def parse_trivy(text, ctx, sev_cfg, source="working_tree") -> list[dict]:
    obj = _load(text)
    if not isinstance(obj, dict):
        return []
    out = []
    for res in obj.get("Results") or []:
        target = res.get("Target")
        for v in res.get("Vulnerabilities") or []:
            sev = v.get("Severity")
            out.append(_finding(ctx, "trivy", source, rule_id=v.get("VulnerabilityID"),
                                title=v.get("Title") or v.get("VulnerabilityID"), file=target,
                                package=v.get("PkgName"), native_severity=sev,
                                normalized_severity=normalize_severity("trivy", sev, sev_cfg)))
        for mc in res.get("Misconfigurations") or []:
            sev = mc.get("Severity")
            out.append(_finding(ctx, "trivy", source, rule_id=mc.get("ID"),
                                title=mc.get("Title") or mc.get("ID"), file=target,
                                native_severity=sev,
                                normalized_severity=normalize_severity("trivy", sev, sev_cfg)))
        for s in res.get("Secrets") or []:
            sev = s.get("Severity")
            out.append(_finding(ctx, "trivy", source, rule_id=s.get("RuleID"),
                                title=s.get("Title") or s.get("RuleID"), file=target,
                                native_severity=sev,
                                normalized_severity=normalize_severity("trivy", sev, sev_cfg)))
    return out


def _osv_cvss_score(vuln: dict) -> Optional[float]:
    for sev in vuln.get("severity") or []:
        score = sev.get("score")
        if isinstance(score, (int, float)):
            return float(score)
    return None


def parse_osv(text, ctx, sev_cfg, source="working_tree") -> list[dict]:
    obj = _load(text)
    if not isinstance(obj, dict):
        return []
    out = []
    for res in obj.get("results") or []:
        target = (res.get("source") or {}).get("path")
        for pkg in res.get("packages") or []:
            name = (pkg.get("package") or {}).get("name")
            for v in pkg.get("vulnerabilities") or []:
                dbsev = ((v.get("database_specific") or {}).get("severity"))
                score = _osv_cvss_score(v)
                out.append(_finding(ctx, "osv-scanner", source, rule_id=v.get("id"),
                                    title=v.get("summary") or v.get("id"), file=target,
                                    package=name, native_severity=dbsev or (score and f"cvss:{score}"),
                                    normalized_severity=normalize_severity("osv-scanner", dbsev,
                                                                           sev_cfg, cvss_score=score)))
    return out


PARSERS = {"gitleaks": parse_gitleaks, "gitleaks-history": parse_gitleaks,
           "semgrep": parse_semgrep, "trivy": parse_trivy,
           "osv-scanner": parse_osv, "zizmor": parse_zizmor}


def normalize_scanner_output(scanner: str, text: str, ctx: dict, sev_cfg: dict) -> list[dict]:
    source = "history" if scanner == "gitleaks-history" else "working_tree"
    parser = PARSERS[scanner]
    if scanner in ("gitleaks", "gitleaks-history"):
        return parser(text, ctx, sev_cfg, source=source)
    return parser(text, ctx, sev_cfg, source=source)


# =========================================================================== #
# WRITER
# =========================================================================== #
def write_findings(findings: list[dict], json_path: Path, csv_path: Path) -> None:
    common.atomic_write_json(json_path, findings)
    common.ensure_dir(csv_path.parent)
    tmp = csv_path.with_suffix(".csv.tmp")
    with tmp.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=FINDING_FIELDS, extrasaction="ignore")
        w.writeheader()
        for f in findings:
            w.writerow(f)
    os.replace(tmp, csv_path)


# =========================================================================== #
# ORCHESTRATION
# =========================================================================== #
def normalize_all(scanners: list[str], results_raw: Path, sev_cfg: dict) -> list[dict]:
    """Read each scanner's per-repo raw output + sidecar and normalize."""
    findings: list[dict] = []
    for scanner in scanners:
        sdir = results_raw / scanner
        if not sdir.is_dir():
            continue
        for raw_file in sorted(sdir.glob("*.json")) + sorted(sdir.glob("*.sarif")):
            if raw_file.name.endswith(".record.json") or raw_file.name.startswith("execution-records"):
                continue
            sidecar = sdir / (raw_file.stem + ".record.json")
            rec = common.read_json(sidecar) if sidecar.exists() else {}
            ctx = {"repository_full_name": rec.get("repository_full_name"),
                   "anonymous_id": rec.get("anonymous_id"),
                   "commit_sha": rec.get("commit_sha")}
            text = raw_file.read_text(encoding="utf-8", errors="replace")
            findings.extend(normalize_scanner_output(scanner, text, ctx, sev_cfg))
    return findings


def main(argv: Optional[list[str]] = None) -> int:
    argparse.ArgumentParser(description="Normalize scanner output (Phase 29-30).").parse_args(argv)
    cfg = common.load_study_config()
    sev_cfg = common.load_yaml(common.CONFIG_DIR / "severity-mapping.yaml")
    results_raw = STUDY_ROOT / cfg["paths"]["results_raw"]
    out_dir = STUDY_ROOT / cfg["paths"]["results_normalized"]

    scanners = list(PARSERS.keys())
    findings = normalize_all(scanners, results_raw, sev_cfg)
    write_findings(findings, out_dir / "findings.json", out_dir / "findings.csv")

    from collections import Counter
    by_sev = Counter(f["normalized_severity"] for f in findings)
    print(f"Normalized {len(findings)} findings -> {out_dir / 'findings.csv'}")
    print(f"  by normalized severity: {dict(by_sev)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
