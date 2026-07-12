"""Unit tests for discover_deployments.py — discovery logic + orchestrator (offline)."""

import json

import discover_deployments as dd
import _common as common

DCFG = common.load_yaml(common.CONFIG_DIR / "deployment-rules.yaml")
PROVIDERS = DCFG["providers"]
LABELS = DCFG["readme_live_link_labels"]


# --------------------------------------------------------------------------- #
# URL extraction + provider tagging
# --------------------------------------------------------------------------- #
def test_extract_urls_strips_trailing_punctuation():
    urls = dd.extract_urls("see https://a.example.com/path, and (https://b.example.com).")
    assert "https://a.example.com/path" in urls
    assert "https://b.example.com" in urls


def test_classify_provider():
    assert dd.classify_provider("https://app.vercel.app", PROVIDERS) == "vercel"
    assert dd.classify_provider("https://x.netlify.app/y", PROVIDERS) == "netlify"
    assert dd.classify_provider("https://user.github.io/repo", PROVIDERS) == "github_pages"
    assert dd.classify_provider("https://myapp.com", PROVIDERS) == "custom_or_unknown"


# --------------------------------------------------------------------------- #
# README labelled live links
# --------------------------------------------------------------------------- #
def test_parse_readme_live_links_markdown_and_bare():
    md = ("# Project\n"
          "[Live Demo](https://demo.example.com)\n"
          "[docs](https://docs.example.com)\n"           # unlabelled -> ignored
          "Production: https://prod.example.com\n")
    links = dd.parse_readme_live_links(md, LABELS)
    assert "https://demo.example.com" in links
    assert "https://prod.example.com" in links
    assert "https://docs.example.com" not in links


# --------------------------------------------------------------------------- #
# Candidate de-dup keeps highest evidence
# --------------------------------------------------------------------------- #
def test_dedup_candidates_keeps_highest_evidence():
    cands = [
        {"url": "https://app.x", "source": "hosting_config_files", "evidence_level": "D", "provider": "x"},
        {"url": "https://app.x", "source": "repository_homepage_field", "evidence_level": "B", "provider": "x"},
    ]
    out = dd.dedup_candidates(cands)
    assert len(out) == 1 and out[0]["evidence_level"] == "B"


# --------------------------------------------------------------------------- #
# Full per-repo discovery + evidence-level precedence
# --------------------------------------------------------------------------- #
def test_discover_for_repo_all_sources_and_best_level():
    meta = {"homepage": "https://home.example.com",
            "description": "docs at https://desc.example.com"}
    contents = {"README.md": "[Live Demo](https://demo.example.com)",
                "CNAME": "app.mydomain.com\n"}
    gh_data = {
        "deployments": [{"environment": "production",
                         "statuses": [{"state": "success",
                                       "environment_url": "https://app.vercel.app"}]}],
        "pages": {"html_url": "https://user.github.io/repo"},
    }
    rec = dd.discover_for_repo("octo/site", meta, [], contents, gh_data, PROVIDERS, LABELS)
    assert rec["status"] == "OK"
    assert rec["has_deployment_url"] is True
    assert rec["best_evidence_level"] == "A"                     # production env URL wins
    assert rec["primary_deployment_url"] == "https://app.vercel.app"
    assert rec["primary_provider"] == "vercel"
    urls = {c["url"]: c for c in rec["deployment_candidates"]}
    assert urls["https://home.example.com"]["evidence_level"] == "B"
    assert urls["https://demo.example.com"]["evidence_level"] == "C"
    assert urls["https://desc.example.com"]["evidence_level"] == "D"
    assert "https://app.mydomain.com" in urls                    # from CNAME


def test_discover_for_repo_no_evidence():
    rec = dd.discover_for_repo("octo/none", {}, [], {}, {}, PROVIDERS, LABELS)
    assert rec["has_deployment_url"] is False
    assert rec["best_evidence_level"] is None
    assert rec["candidate_count"] == 0


# --------------------------------------------------------------------------- #
# Orchestrator: gating, caching, read errors, and private URL output
# --------------------------------------------------------------------------- #
def test_discover_all_gates_caches_and_errors(tmp_path):
    def reader(full, branch, url):
        return ["README.md"], {"README.md": "[Live App](https://app.example.com)"}

    def gh_fn(full):
        return {"deployments": [], "pages": {}}

    candidates = [{"repository_full_name": "o/a"}, {"repository_full_name": "o/gone"}]
    metadata = {
        "o/a": {"repository_full_name": "o/a", "fetch_status": "OK",
                "default_branch": "main", "homepage": "https://home.a"},
        "o/gone": {"repository_full_name": "o/gone", "fetch_status": "NOT_FOUND"},
    }
    raw_dir = tmp_path / "dep"
    log = tmp_path / "log.jsonl"
    rows = dd.discover_all(candidates, metadata, raw_dir, log, reader, gh_fn, PROVIDERS, LABELS)
    by = {r["repository_full_name"]: r for r in rows}
    assert by["o/a"]["status"] == "OK" and by["o/a"]["has_deployment_url"] is True
    assert by["o/gone"]["status"] == "UNAVAILABLE"
    assert (raw_dir / "o__a.json").exists()

    def boom(full, branch, url):
        raise AssertionError("must not re-read a cached repo")
    rows2 = dd.discover_all(candidates, metadata, raw_dir, log, boom, gh_fn, PROVIDERS, LABELS)
    assert {r["repository_full_name"]: r["status"] for r in rows2}["o/a"] == "OK"


def test_discover_all_records_read_error(tmp_path):
    def failing(full, branch, url):
        raise RuntimeError("clone failed")
    candidates = [{"repository_full_name": "o/a"}]
    metadata = {"o/a": {"repository_full_name": "o/a", "fetch_status": "OK", "default_branch": "main"}}
    rows = dd.discover_all(candidates, metadata, tmp_path / "dep", tmp_path / "log.jsonl",
                           failing, lambda f: {}, PROVIDERS, LABELS)
    assert rows[0]["status"] == "READ_ERROR"


def test_write_discovery_splits_private_and_summary(tmp_path):
    rec = dd.discover_for_repo("o/a", {"homepage": "https://home.a"}, [], {}, {}, PROVIDERS, LABELS)
    priv_json = tmp_path / "d.json"
    priv_csv = tmp_path / "d.csv"
    summary = tmp_path / "summary.csv"
    dd.write_discovery([rec], priv_json, priv_csv, summary)
    import csv as _csv
    # Summary must NOT contain the URL.
    summary_text = summary.read_text(encoding="utf-8")
    assert "https://home.a" not in summary_text
    with summary.open(encoding="utf-8") as fh:
        assert next(_csv.reader(fh)) == dd.SUMMARY_FIELDS
    # Private CSV carries the URL (candidates serialized as JSON).
    assert "https://home.a" in priv_csv.read_text(encoding="utf-8")
    assert not list(tmp_path.glob("*.tmp"))
