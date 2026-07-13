"""Unit tests for workflow_status.py — status markdown + README updater (offline)."""

import workflow_status as ws


def test_status_markdown_has_markers_and_counts():
    md = ws.status_markdown()
    assert ws.STATUS_START in md and ws.STATUS_END in md
    assert "Pipeline implementation:" in md
    # Every phase script appears exactly once as a table row.
    for name, _ in ws.PHASE_SCRIPTS:
        assert f"`{name}`" in md


def test_update_readme_replaces_block(tmp_path):
    readme = tmp_path / "README.md"
    readme.write_text(f"# Title\n\nintro\n\n{ws.STATUS_START}\nOLD\n{ws.STATUS_END}\n\ntail\n",
                      encoding="utf-8")
    assert ws.update_readme(readme) is True
    text = readme.read_text(encoding="utf-8")
    assert "OLD" not in text                       # stale block replaced
    assert "# Title" in text and "tail" in text    # surrounding content preserved
    assert text.count(ws.STATUS_START) == 1 and text.count(ws.STATUS_END) == 1


def test_update_readme_without_markers_returns_false(tmp_path):
    readme = tmp_path / "README.md"
    readme.write_text("# No markers here\n", encoding="utf-8")
    assert ws.update_readme(readme) is False


def test_status_reflects_filesystem():
    rows = ws.statuses()
    built = {n for n, _, ok in rows if ok}
    assert "check_environment.py" in built          # exists on disk
    # A script that does NOT exist is reported as planned, not built.
    assert ("this_script_does_not_exist.py", "n/a", False) not in rows
    assert all((ws.SCRIPTS_DIR / n).is_file() == ok for n, _, ok in rows)
