#!/usr/bin/env python3
"""
tests/test_taxonomy_and_config.py

Consistency tests for the finding taxonomy and scanner configuration. These
guard the Checkpoint-1.5 corrections:

  * every taxonomy category declares a valid detection_reliability;
  * every non-strong category explains its coverage_limitation;
  * the newly added vulnerability categories exist;
  * access-control / logic / runtime classes are marked out_of_scope;
  * Trivy is NOT credited for information_exposure or github_actions_risk;
  * the Trivy --scanners list is identical across config, entrypoint, and
    excludes license scanning;
  * CodeQL is an optional enhanced track, not part of the primary five;
  * groupings reference only defined categories and cover them all.

Runs under pytest AND standalone:  python tests/test_taxonomy_and_config.py
Uses PyYAML only (no network, no real secrets).
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
TAXONOMY = ROOT / "config" / "finding-taxonomy.yaml"
SCANNER_CFG = ROOT / "config" / "scanner-config.yaml"
ENTRYPOINT = ROOT / "docker" / "scanner-entrypoint.sh"

VALID_RELIABILITY = {"strong", "partial", "weak", "out_of_scope"}
REQUIRE_LIMITATION = {"partial", "weak", "out_of_scope"}

# Categories that had to be added in this revision.
REQUIRED_NEW_CATEGORIES = {
    "csrf",
    "prototype_pollution",
    "nosql_injection",
    "code_injection",
    "server_side_template_injection",
    "xxe",
    "redos",
    "race_condition_toctou",
}

# Classes that must remain explicitly not-measurable (out_of_scope).
REQUIRED_OUT_OF_SCOPE = {
    "authorization_weakness",
    "idor_bola",
    "business_logic_flaw",
    "missing_rate_limiting",
    "multi_tenant_isolation",
    "race_condition_toctou",
    "runtime_deployment_risk",
}

PRIMARY_PIPELINE = ["gitleaks", "semgrep", "trivy", "osv_scanner", "zizmor"]
EXPECTED_TRIVY_SCANNERS = ["vuln", "misconfig", "secret"]


def _load(path: Path) -> dict:
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


# --------------------------------------------------------------------------- #
# Taxonomy tests
# --------------------------------------------------------------------------- #
def test_every_category_has_valid_reliability():
    cats = _load(TAXONOMY)["categories"]
    bad = {
        name: c.get("detection_reliability")
        for name, c in cats.items()
        if c.get("detection_reliability") not in VALID_RELIABILITY
    }
    assert not bad, f"categories with missing/invalid detection_reliability: {bad}"


def test_non_strong_categories_have_coverage_limitation():
    cats = _load(TAXONOMY)["categories"]
    missing = [
        name
        for name, c in cats.items()
        if c.get("detection_reliability") in REQUIRE_LIMITATION
        and not str(c.get("coverage_limitation", "")).strip()
    ]
    assert not missing, f"non-strong categories missing coverage_limitation: {missing}"


def test_new_categories_exist():
    cats = _load(TAXONOMY)["categories"]
    missing = REQUIRED_NEW_CATEGORIES - set(cats)
    assert not missing, f"required new categories absent: {missing}"


def test_required_categories_are_out_of_scope():
    cats = _load(TAXONOMY)["categories"]
    wrong = {
        name: cats.get(name, {}).get("detection_reliability")
        for name in REQUIRED_OUT_OF_SCOPE
        if cats.get(name, {}).get("detection_reliability") != "out_of_scope"
    }
    assert not wrong, f"categories that must be out_of_scope but are not: {wrong}"


def test_trivy_not_credited_for_infoexposure_or_gha():
    cats = _load(TAXONOMY)["categories"]
    for name in ("information_exposure", "github_actions_risk"):
        scanners = cats[name].get("typical_scanners", [])
        assert "trivy" not in scanners, (
            f"{name} still credits trivy: {scanners}"
        )


def test_groupings_reference_defined_categories_and_cover_them():
    tax = _load(TAXONOMY)
    cats = set(tax["categories"])
    groupings = tax["groupings"]
    referenced = set()
    for members in groupings.values():
        for m in members:
            assert m in cats, f"grouping references unknown category: {m}"
            referenced.add(m)
    orphans = cats - referenced
    assert not orphans, f"categories not present in any grouping: {orphans}"


def test_not_reliably_measurable_matches_out_of_scope_set():
    tax = _load(TAXONOMY)
    cats = tax["categories"]
    out_of_scope = {
        n for n, c in cats.items()
        if c.get("detection_reliability") == "out_of_scope"
    }
    grouped = set(tax["groupings"]["not_reliably_measurable"])
    assert grouped == out_of_scope, (
        f"not_reliably_measurable grouping {grouped} != out_of_scope set {out_of_scope}"
    )


def test_reliability_semantics_documented():
    tax = _load(TAXONOMY)
    defs = tax.get("detection_reliability_definitions", {})
    assert VALID_RELIABILITY <= set(defs), "missing reliability tier definitions"
    assert str(tax.get("zero_findings_interpretation", "")).strip(), (
        "zero_findings_interpretation must be documented"
    )


# --------------------------------------------------------------------------- #
# Scanner-config / entrypoint consistency tests
# --------------------------------------------------------------------------- #
def test_trivy_scanners_exclude_license_in_config():
    cfg = _load(SCANNER_CFG)
    trivy = cfg["scanners"]["trivy"]["scanners"]
    assert trivy == EXPECTED_TRIVY_SCANNERS, f"unexpected trivy scanners: {trivy}"
    assert "license" not in trivy, "license scanning must not be enabled"


def test_entrypoint_trivy_scanners_match_config():
    cfg = _load(SCANNER_CFG)
    config_scanners = cfg["scanners"]["trivy"]["scanners"]
    # Skip comment lines so prose like "# The --scanners list below" is ignored;
    # match only the executable command line.
    code_lines = [
        ln for ln in ENTRYPOINT.read_text(encoding="utf-8").splitlines()
        if not ln.strip().startswith("#")
    ]
    m = re.search(r"--scanners\s+([a-z0-9,]+)", "\n".join(code_lines))
    assert m, "could not find trivy --scanners in entrypoint"
    entrypoint_scanners = m.group(1).split(",")
    assert entrypoint_scanners == config_scanners, (
        f"entrypoint {entrypoint_scanners} != config {config_scanners}"
    )


def test_trivy_github_actions_disabled():
    cfg = _load(SCANNER_CFG)
    assert cfg["scanners"]["trivy"]["scan"]["github_actions"] is False, (
        "Trivy must not claim GitHub Actions coverage (zizmor owns that)"
    )


def test_codeql_is_optional_enhanced_not_primary():
    cfg = _load(SCANNER_CFG)
    codeql = cfg["scanners"]["codeql"]
    assert codeql["enabled"] is False, "CodeQL must not be enabled in the primary run"
    assert codeql.get("track") == "enhanced_analysis"
    pipeline = cfg["pipeline"]
    assert pipeline["primary"] == PRIMARY_PIPELINE, (
        f"primary pipeline changed: {pipeline['primary']}"
    )
    assert "codeql" not in pipeline["primary"], "CodeQL must not be in primary pipeline"
    assert "codeql" in pipeline["enhanced_optional"]
    assert pipeline["enhanced_results"]["never_merge_into_primary"] is True


# --------------------------------------------------------------------------- #
# Standalone runner
# --------------------------------------------------------------------------- #
def _all_tests():
    return [obj for name, obj in sorted(globals().items()) if name.startswith("test_")]


def main() -> int:
    passed = failed = 0
    for fn in _all_tests():
        try:
            fn()
            print(f"  PASS  {fn.__name__}")
            passed += 1
        except AssertionError as exc:
            print(f"  FAIL  {fn.__name__}: {exc}")
            failed += 1
        except Exception as exc:  # pragma: no cover
            print(f"  ERROR {fn.__name__}: {type(exc).__name__}: {exc}")
            failed += 1
    print("-" * 60)
    print(f"{passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
