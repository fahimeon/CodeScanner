"""Unit tests for Phase 6 — attribution verification + involvement (offline).

All git output is synthesized with the module's own field/record separators, so
these tests never invoke git or the network.
"""

from pathlib import Path

import verify_claude_attribution as vca
import calculate_claude_contribution as ccc
import _common as common

US = vca.FIELD_SEP
RS = vca.REC_SEP

RULES = common.load_yaml(common.CONFIG_DIR / "inclusion-rules.yaml")["substantial_attribution_rules"]
MIN_SUB = 10
MATCHER = vca.load_exclude_matcher()
BANDS = common.load_study_config()["involvement"]["bands"]

TRAILER = "Co-Authored-By: Claude <noreply@anthropic.com>"


# --------------------------------------------------------------------------- #
# Synthetic git-output builders (mirror the real --format strings)
# --------------------------------------------------------------------------- #
def _meta(commits) -> str:
    # commits newest-first: dict(sha, date, parents(str), message)
    return "".join(
        f"{c['sha']}{US}{c['date']}{US}{c['parents']}{US}{c['message']}{RS}"
        for c in commits
    )


def _numstat(commits) -> str:
    blocks = []
    for c in commits:
        lines = [f"{RS}{c['sha']}"]
        for add, dl, path in c["numstat"]:
            lines.append(f"{add}\t{dl}\t{path}")
        blocks.append("\n".join(lines))
    return "\n".join(blocks)


def _attributed(subject):
    return f"{subject}\n\n{TRAILER}"


# --------------------------------------------------------------------------- #
# Path exclusion + source detection
# --------------------------------------------------------------------------- #
def test_is_excluded_path():
    assert vca.is_excluded_path("node_modules/react/index.js", MATCHER)
    assert vca.is_excluded_path("packages/app/node_modules/x.js", MATCHER)  # nested
    assert vca.is_excluded_path("dist/bundle.js", MATCHER)
    assert vca.is_excluded_path("package-lock.json", MATCHER)
    assert vca.is_excluded_path("src/app.min.js", MATCHER)
    assert vca.is_excluded_path("logo.png", MATCHER)
    assert not vca.is_excluded_path("src/app.ts", MATCHER)


def test_is_source_file():
    assert vca.is_source_file("src/app.ts", MATCHER)
    assert vca.is_source_file("components/Button.tsx", MATCHER)
    assert vca.is_source_file("styles/main.scss", MATCHER)
    assert not vca.is_source_file("README.md", MATCHER)        # docs, not source
    assert not vca.is_source_file("package.json", MATCHER)     # config, not source
    assert not vca.is_source_file("node_modules/x.ts", MATCHER)  # excluded tree
    assert not vca.is_source_file("logo.png", MATCHER)


# --------------------------------------------------------------------------- #
# Attribution signal on a commit
# --------------------------------------------------------------------------- #
def test_commit_is_attributed():
    assert vca.commit_is_attributed(_attributed("feat: add page"))
    assert vca.commit_is_attributed("Generated with Claude Code")
    assert not vca.commit_is_attributed("Claude-Session: abc")   # supporting only
    assert not vca.commit_is_attributed("ordinary commit")
    assert not vca.commit_is_attributed(None)


def test_commit_has_any_signal_includes_supporting():
    # Supporting-only session marker: NOT attributed, but IS an attribution signal.
    assert vca.commit_has_any_signal("chore\n\nClaude-Session: abc") is True
    assert vca.commit_is_attributed("chore\n\nClaude-Session: abc") is False
    assert vca.commit_has_any_signal(_attributed("f")) is True
    assert vca.commit_has_any_signal("ordinary commit") is False


# --------------------------------------------------------------------------- #
# Arg builders
# --------------------------------------------------------------------------- #
def test_build_clone_args_is_safe():
    args = vca.build_clone_args("https://github.com/o/r", "/tmp/dest", "/tmp/hooks", "main")
    joined = " ".join(args)
    assert "--no-checkout" in args          # no working tree materialized
    assert "protocol.ext.allowed=never" in joined
    assert "core.symlinks=false" in joined
    assert "core.hooksPath=/tmp/hooks" in joined
    assert "--single-branch" in args and "--no-tags" in args
    assert args[-2:] == ["https://github.com/o/r", "/tmp/dest"]


def test_build_log_args():
    # Merges are captured (for total_commits) and excluded in code, so the log
    # commands must NOT pass --no-merges.
    meta = vca.build_log_meta_args()
    assert meta[:2] == ["log", "HEAD"]
    assert "--no-merges" not in meta
    numstat = vca.build_log_numstat_args()
    assert "--numstat" in numstat
    assert "--no-merges" not in numstat


# --------------------------------------------------------------------------- #
# Numstat parsing: excluded paths, binaries, renames
# --------------------------------------------------------------------------- #
def test_line_counting_excludes_nonsource_binary_and_vendored():
    commits = [{
        "sha": "a" * 40, "date": "2025-03-01T00:00:00Z", "parents": "",
        "message": _attributed("init"),
        "numstat": [
            (10, 0, "src/x.ts"),            # counted
            (1000, 0, "node_modules/y.js"), # excluded tree
            (50, 0, "README.md"),           # docs, not source
            ("-", "-", "logo.png"),         # binary
        ],
    }]
    recs = vca.build_commit_records(vca.parse_log_meta(_meta(commits)),
                                    vca.parse_log_numstat(_numstat(commits)),
                                    MATCHER, MIN_SUB)
    assert len(recs) == 1
    assert recs[0]["relevant_added"] == 10
    assert recs[0]["relevant_changed"] == 10
    assert recs[0]["substantive"] is True
    assert recs[0]["attributed"] is True


def test_numstat_rename_takes_destination_path():
    assert vca._numstat_path("src/old.ts => src/new.ts") == "src/new.ts"
    assert vca._numstat_path("src/{old => new}.ts").endswith("new.ts")


# --------------------------------------------------------------------------- #
# Rule evaluation A-D
# --------------------------------------------------------------------------- #
def _analyze(commits, name="o/r"):
    return vca.analyze_history(name, _meta(commits), _numstat(commits),
                               MATCHER, RULES, MIN_SUB)


def test_rule_A_and_C_three_substantive_attributed():
    commits = [
        {"sha": "1" * 40, "date": "2025-03-10T00:00:00Z", "parents": "0" * 40,
         "message": _attributed("f1"), "numstat": [(20, 0, "src/a.ts")]},
        {"sha": "2" * 40, "date": "2025-03-05T00:00:00Z", "parents": "3" * 40,
         "message": _attributed("f2"), "numstat": [(15, 5, "src/b.ts")]},
        {"sha": "3" * 40, "date": "2025-03-01T00:00:00Z", "parents": "",
         "message": _attributed("f3 init"), "numstat": [(30, 0, "src/c.ts")]},
        {"sha": "4" * 40, "date": "2025-03-08T00:00:00Z", "parents": "1" * 40,
         "message": "chore: docs", "numstat": [(50, 0, "README.md")]},
    ]
    a = _analyze(commits)
    assert a["status"] == "OK"
    assert a["qualifies"] is True
    assert set(a["qualifying_rules"]) == {"A", "C"}
    assert a["substantive_attributed_commits"] == 3
    assert a["attributed_non_merge_commits"] == 3
    assert a["total_non_merge_commits"] == 4
    assert a["attributed_commit_share"] == 0.75
    assert a["reachable_qualifying_commit"] is True


def test_single_attributed_commit_does_not_qualify():
    commits = [
        {"sha": "1" * 40, "date": "2025-03-03T00:00:00Z", "parents": "2" * 40,
         "message": _attributed("only one"), "numstat": [(20, 0, "src/a.ts")]},
        {"sha": "2" * 40, "date": "2025-03-02T00:00:00Z", "parents": "3" * 40,
         "message": "plain", "numstat": [(10, 0, "src/b.ts")]},
        {"sha": "3" * 40, "date": "2025-03-01T00:00:00Z", "parents": "",
         "message": "root plain", "numstat": [(10, 0, "src/c.ts")]},
    ]
    a = _analyze(commits)
    assert a["qualifies"] is False
    assert a["qualifying_rules"] == []
    assert a["reachable_qualifying_commit"] is False


def test_rule_B_and_D_big_initial_attributed_commit():
    commits = [
        {"sha": "1" * 40, "date": "2025-03-05T00:00:00Z", "parents": "2" * 40,
         "message": "plain follow-up", "numstat": [(10, 0, "src/x.ts")]},
        {"sha": "2" * 40, "date": "2025-03-01T00:00:00Z", "parents": "",
         "message": _attributed("initial implementation"),
         "numstat": [(600, 0, "src/app.ts")]},
    ]
    a = _analyze(commits)
    assert a["qualifies"] is True
    assert set(a["qualifying_rules"]) == {"B", "D"}   # 600 >= 500 in one attributed commit + attributed root


def test_no_commits_status():
    a = vca.analyze_history("o/empty", "", "", MATCHER, RULES, MIN_SUB)
    assert a["status"] == "NO_COMMITS"
    assert a["qualifies"] is False
    assert a["total_commits"] == 0
    assert a["any_attribution_signal_found"] is False


def test_merge_commits_counted_but_excluded_from_denominators():
    commits = [
        {"sha": "m" * 40, "date": "2025-03-10T00:00:00Z",
         "parents": f"{'1' * 40} {'2' * 40}", "message": "Merge branch", "numstat": []},
        {"sha": "1" * 40, "date": "2025-03-05T00:00:00Z", "parents": "3" * 40,
         "message": _attributed("f1"), "numstat": [(20, 0, "src/a.ts")]},
        {"sha": "3" * 40, "date": "2025-03-01T00:00:00Z", "parents": "",
         "message": "root plain", "numstat": [(10, 0, "src/b.ts")]},
    ]
    a = _analyze(commits)
    assert a["total_commits"] == 3
    assert a["merge_commits"] == 1
    assert a["total_non_merge_commits"] == 2
    assert a["attributed_non_merge_commits"] == 1


def test_records_added_deleted_files_dates_and_initial_impl():
    commits = [
        {"sha": "1" * 40, "date": "2025-03-10T00:00:00Z", "parents": "2" * 40,
         "message": _attributed("feat"),
         "numstat": [(30, 10, "src/a.ts"), (5, 0, "src/b.ts")]},
        {"sha": "2" * 40, "date": "2025-03-01T00:00:00Z", "parents": "",
         "message": _attributed("init"), "numstat": [(600, 0, "src/app.ts")]},
    ]
    a = _analyze(commits)
    assert a["attributed_source_lines_added"] == 635      # 30+5+600
    assert a["attributed_source_lines_deleted"] == 10
    assert a["attributed_source_lines"] == 645
    assert a["attributed_files_changed"] == 3             # a.ts, b.ts, app.ts
    assert a["first_attributed_commit_date"] == "2025-03-01T00:00:00Z"
    assert a["last_attributed_commit_date"] == "2025-03-10T00:00:00Z"
    assert a["initial_implementation_attributed"] is True


def test_any_attribution_signal_found_with_supporting_only():
    # A repo whose ONLY signal is supporting (Claude-Session:) does NOT qualify,
    # but the any-signal flag is True — this is what excludes it from the control cohort.
    commits = [
        {"sha": "1" * 40, "date": "2025-03-02T00:00:00Z", "parents": "2" * 40,
         "message": "chore\n\nClaude-Session: abc", "numstat": [(10, 0, "src/a.ts")]},
        {"sha": "2" * 40, "date": "2025-03-01T00:00:00Z", "parents": "",
         "message": "init", "numstat": [(20, 0, "src/b.ts")]},
    ]
    a = _analyze(commits)
    assert a["attributed_non_merge_commits"] == 0
    assert a["qualifies"] is False
    assert a["any_attribution_signal_found"] is True


def test_is_within_guard(tmp_path):
    root = tmp_path / "clones"
    root.mkdir()
    assert vca._is_within(root, root / "octo__repo")
    assert vca._is_within(root, root)
    assert not vca._is_within(root, tmp_path)              # parent
    assert not vca._is_within(root, root.parent / "evil")  # sibling


# --------------------------------------------------------------------------- #
# Orchestrator: metadata gating, caching/resume, error handling
# --------------------------------------------------------------------------- #
def _ok_history(commits):
    def _fn(full, branch, url):
        return _meta(commits), _numstat(commits)
    return _fn


def test_verify_all_gates_on_metadata_and_caches(tmp_path):
    commits = [
        {"sha": "1" * 40, "date": "2025-03-03T00:00:00Z", "parents": "",
         "message": _attributed("init"), "numstat": [(600, 0, "src/app.ts")]},
    ]
    calls = {"n": 0}

    def counting_history(full, branch, url):
        calls["n"] += 1
        return _meta(commits), _numstat(commits)

    candidates = [
        {"repository_full_name": "octo/live"},
        {"repository_full_name": "octo/gone"},      # metadata NOT_FOUND -> UNAVAILABLE
        {"repository_full_name": "octo/missing"},   # absent from metadata -> UNAVAILABLE
    ]
    metadata = {
        "octo/live": {"repository_full_name": "octo/live", "fetch_status": "OK",
                      "default_branch": "main", "repository_url": "https://github.com/octo/live"},
        "octo/gone": {"repository_full_name": "octo/gone", "fetch_status": "NOT_FOUND"},
    }
    raw_dir = tmp_path / "raw"
    analysis_dir = tmp_path / "analysis"
    log = tmp_path / "log.jsonl"

    rows = vca.verify_all(candidates, metadata, raw_dir, analysis_dir, log,
                          counting_history, RULES, MATCHER, MIN_SUB)
    by = {r["repository_full_name"]: r for r in rows}
    assert by["octo/live"]["status"] == "OK" and by["octo/live"]["qualifies"] is True
    assert by["octo/gone"]["status"] == "UNAVAILABLE"
    assert by["octo/missing"]["status"] == "UNAVAILABLE"
    # Only the reachable repo was cloned.
    assert calls["n"] == 1
    assert (raw_dir / "octo__live.meta.txt").exists()
    assert (analysis_dir / "octo__live.json").exists()

    # Re-run resumes from cached raw output; no second clone.
    vca.verify_all(candidates, metadata, raw_dir, analysis_dir, log,
                   counting_history, RULES, MATCHER, MIN_SUB)
    assert calls["n"] == 1


def test_verify_all_records_clone_error(tmp_path):
    def failing_history(full, branch, url):
        raise RuntimeError("clone failed")

    candidates = [{"repository_full_name": "octo/live"}]
    metadata = {"octo/live": {"repository_full_name": "octo/live",
                              "fetch_status": "OK", "default_branch": "main"}}
    rows = vca.verify_all(candidates, metadata, tmp_path / "raw", tmp_path / "an",
                          tmp_path / "log.jsonl", failing_history, RULES, MATCHER, MIN_SUB)
    assert rows[0]["status"] == "CLONE_ERROR"
    assert rows[0]["qualifies"] is False


def test_write_aggregate_header(tmp_path):
    rows = [{"repository_full_name": "o/r", "status": "OK", "qualifies": True,
             "qualifying_rules": "A;C"}]
    out_json = tmp_path / "agg.json"
    out_csv = tmp_path / "agg.csv"
    vca.write_aggregate(rows, out_json, out_csv)
    import csv as _csv
    with out_csv.open(encoding="utf-8") as fh:
        header = next(_csv.reader(fh))
    assert header == vca.ATTRIBUTION_FIELDS
    assert not list(tmp_path.glob("*.tmp"))


# --------------------------------------------------------------------------- #
# Involvement metric (calculate_claude_contribution)
# --------------------------------------------------------------------------- #
def test_involvement_band_thresholds():
    assert ccc.involvement_band(0, 0.0, BANDS) == "none"
    assert ccc.involvement_band(1, 0.05, BANDS) == "low"
    assert ccc.involvement_band(4, 0.05, BANDS) == "low"
    assert ccc.involvement_band(5, 0.05, BANDS) == "medium"
    assert ccc.involvement_band(19, 0.05, BANDS) == "medium"
    assert ccc.involvement_band(20, 0.05, BANDS) == "high"
    assert ccc.involvement_band(3, 0.30, BANDS) == "high"   # share override


def test_compute_involvement_ok_and_line_share():
    row = {"repository_full_name": "o/r", "status": "OK",
           "attributed_non_merge_commits": 6, "total_non_merge_commits": 40,
           "substantive_attributed_commits": 6, "attributed_commit_share": 0.15,
           "attributed_source_lines": 300, "total_source_lines": 1200}
    rec = ccc.compute_involvement(row, BANDS)
    assert rec["involvement_band"] == "medium"
    assert rec["attributed_source_line_share"] == 0.25


def test_compute_involvement_non_ok_is_none_band():
    for status in ("UNAVAILABLE", "CLONE_ERROR", "NO_COMMITS"):
        rec = ccc.compute_involvement({"repository_full_name": "o/r", "status": status}, BANDS)
        assert rec["involvement_band"] == "none"
        assert rec["attributed_commit_share"] is None


def test_build_contribution_writer_roundtrip(tmp_path):
    rows = [
        {"repository_full_name": "o/a", "status": "OK",
         "attributed_non_merge_commits": 3, "total_non_merge_commits": 4,
         "substantive_attributed_commits": 3, "attributed_commit_share": 0.75,
         "attributed_source_lines": 65, "total_source_lines": 65},
    ]
    records = ccc.build_contribution(rows, BANDS)
    out_json = tmp_path / "c.json"
    out_csv = tmp_path / "c.csv"
    ccc.write_contribution(records, out_json, out_csv)
    import csv as _csv
    with out_csv.open(encoding="utf-8") as fh:
        header = next(_csv.reader(fh))
    assert header == ccc.CONTRIBUTION_FIELDS
    assert records[0]["involvement_band"] == "high"   # share 0.75 >= 0.25
