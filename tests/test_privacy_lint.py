"""Unit tests for privacy_lint.py — CS-013 public-output identity guard (offline)."""

import privacy_lint as pl


def test_clean_text_has_no_leaks():
    assert pl.find_identity_leaks("Prevalence was 42% across CLD-0007 and CLR-0123.") == []


def test_detects_github_urls_and_remotes():
    leaks = pl.find_identity_leaks("see https://github.com/octocat/Hello-World and git@github.com:foo/bar")
    kinds = {l.split(":", 1)[0] for l in leaks}
    assert "github_url" in kinds and "git_remote" in kinds


def test_detects_repo_slug_but_not_anonymous_id():
    leaks = pl.find_identity_leaks("path repositories/octocat__Hello-World/index.js for CLD-0001")
    assert any(l.startswith("repo_slug:octocat__Hello-World") for l in leaks)
    # An anonymous ID must never be flagged as identity, even mid-sentence.
    assert not any("CLD-0001" in l for l in pl.find_identity_leaks("CLD-0001"))


def test_detects_and_masks_raw_secret_tokens():
    leaks = pl.find_identity_leaks("token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
    assert any(l.startswith("secret_token:ghp_") and "***" in l for l in leaks)
    # The full secret is never echoed back by the linter.
    assert all("MNOPQRSTUV" not in l for l in leaks)


def test_scan_tree_flags_leaky_file_and_skips_gitkeep(tmp_path):
    (tmp_path / ".gitkeep").write_text("", encoding="utf-8")
    (tmp_path / "clean.md").write_text("Aggregate: 3/4 repos, CTR-0002.", encoding="utf-8")
    (tmp_path / "leak.md").write_text("owner is https://github.com/acme/webapp", encoding="utf-8")
    findings = pl.scan_tree(tmp_path)
    rels = {p.split("/")[-1].split("\\")[-1] for p in findings}
    assert "leak.md" in rels and "clean.md" not in rels and ".gitkeep" not in rels
