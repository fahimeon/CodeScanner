"""Unit tests for generate_figures / generate_reports / cleanup_repositories (offline)."""

import generate_figures as gf
import generate_reports as gr
import cleanup_repositories as cr


ANALYSIS = {
    "generated_utc": "2026-07-13T00:00:00Z",
    "repositories_analysed": 4,
    "prevalence": {
        "any_finding": {"k": 3, "n": 4, "proportion": 0.75, "low": 0.30, "high": 0.95},
        "by_severity": {"critical": {"k": 1, "n": 4, "proportion": 0.25, "low": 0.05, "high": 0.7},
                        "high": {"k": 2, "n": 4, "proportion": 0.5, "low": 0.15, "high": 0.85}},
        "by_category": {"exposed_secrets": {"k": 2, "n": 4, "proportion": 0.5, "low": 0.1, "high": 0.9},
                        "cross_site_scripting": {"k": 1, "n": 4, "proportion": 0.25, "low": 0.05, "high": 0.7}},
    },
    "categories_by_reliability": {
        "strong": {"exposed_secrets": {"proportion": 0.5, "low": 0.1, "high": 0.9, "k": 2, "n": 4}},
        "partial": {"cross_site_scripting": {"proportion": 0.25, "low": 0.05, "high": 0.7, "k": 1, "n": 4}},
    },
    "scanner_overlap_rq11": {"deduplicated_findings": 5, "multi_scanner_findings": 2,
                             "multi_scanner_rate": 0.4, "by_scanner_pair": {"osv-scanner+trivy": 2}},
}


# --------------------------------------------------------------------------- #
# Figures (pure data prep)
# --------------------------------------------------------------------------- #
def test_figure_data_sorted_and_complete():
    data = gf.build_figure_data(ANALYSIS)
    cats = data["category_prevalence"]
    assert cats[0]["category"] == "exposed_secrets"          # highest prevalence first
    assert cats[0]["reliability"] == "strong"
    sev = {s["severity"]: s["proportion"] for s in data["severity_distribution"]}
    assert sev["critical"] == 0.25 and sev["low"] == 0.0     # all severities present
    assert data["scanner_overlap"][0]["pair"] == "osv-scanner+trivy"


# --------------------------------------------------------------------------- #
# Reports
# --------------------------------------------------------------------------- #
def test_report_markdown_uses_scanner_scope_language():
    md = gr.build_report_markdown(ANALYSIS)
    low = md.lower()
    assert "no findings were detected by the configured scanners" in low
    # "secure" only ever appears inside the caveat's negation ("... NOT ... secure ...").
    assert "not that the repository is secure" in low
    assert "75.0%" in md and "Scanner overlap (RQ11)" in md


def test_public_dataset_has_no_identities():
    pub = gr.build_public_dataset(ANALYSIS)
    blob = str(pub)
    assert "repository_full_name" not in blob and "http" not in blob
    assert pub["repositories_analysed"] == 4
    assert pub["any_finding"]["proportion"] == 0.75


# --------------------------------------------------------------------------- #
# Cleanup safety
# --------------------------------------------------------------------------- #
def test_safe_remove_refuses_outside_root(tmp_path):
    root = tmp_path / "repositories"
    (root / "selected").mkdir(parents=True)
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    removed, reason = cr.safe_remove(outside, root)
    assert removed is False and reason == "refused_outside_or_root"
    # Refuses to delete the root itself.
    assert cr.safe_remove(root, root)[0] is False


def test_cleanup_removes_clone_subdirs(tmp_path):
    root = tmp_path / "repositories"
    for sub in ("selected", "history", "candidates"):
        (root / sub / "o__a").mkdir(parents=True)
    results = cr.cleanup(root)
    assert all(r["removed"] for r in results)
    assert not (root / "selected").exists() and not (root / "history").exists()
