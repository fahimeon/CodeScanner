"""Unit tests for collect_candidates.py — pure logic + orchestrator (offline)."""

import json
from datetime import date
from pathlib import Path

import collect_candidates as cc


# --------------------------------------------------------------------------- #
# Date-window generation
# --------------------------------------------------------------------------- #
def test_month_windows_boundaries():
    wins = cc.month_windows(date(2025, 2, 24), date(2026, 6, 30))
    # First window starts on the study start date, mid-February.
    assert wins[0] == (date(2025, 2, 24), date(2025, 2, 28))
    # A full interior month is covered end-to-end.
    assert (date(2025, 3, 1), date(2025, 3, 31)) in wins
    # Last window ends on the study end date, mid-June.
    assert wins[-1] == (date(2026, 6, 1), date(2026, 6, 30))
    # Windows are contiguous with no gaps.
    for (s1, e1), (s2, e2) in zip(wins, wins[1:]):
        assert (e1.toordinal() + 1) == s2.toordinal()


def test_month_windows_empty_when_reversed():
    assert cc.month_windows(date(2026, 1, 1), date(2025, 1, 1)) == []


def test_probe_plan_picks_first_window_and_strong_signal():
    wins = cc.month_windows(date(2025, 2, 24), date(2026, 6, 30))
    label, query, win = cc.probe_plan(wins)
    assert label == "anthropic_email"
    assert query == cc.SIGNAL_QUERIES["anthropic_email"]
    assert win == (date(2025, 2, 24), date(2025, 2, 28))  # small, mid-Feb first window


def test_split_window_halves_are_contiguous_and_strictly_smaller():
    win = (date(2025, 3, 1), date(2025, 3, 31))
    parts = cc.split_window(win)
    assert len(parts) == 2
    (s1, e1), (s2, e2) = parts
    assert s1 == win[0] and e2 == win[1]
    assert e1.toordinal() + 1 == s2.toordinal()  # contiguous, no overlap
    assert (e1 - s1).days < (win[1] - win[0]).days  # strictly smaller


def test_split_window_single_day_is_unsplittable():
    win = (date(2025, 3, 1), date(2025, 3, 1))
    assert cc.split_window(win) == [win]


# --------------------------------------------------------------------------- #
# Query building
# --------------------------------------------------------------------------- #
def test_build_commit_search_args():
    args = cc.build_commit_search_args('"noreply@anthropic.com"',
                                       date(2025, 3, 1), date(2025, 3, 31), 1000)
    assert args[:3] == ["search", "commits", '"noreply@anthropic.com"']
    assert "--author-date" in args
    assert "2025-03-01..2025-03-31" in args
    assert "--limit" in args and "1000" in args
    assert "--json" in args


def test_build_repo_search_args_has_public_nonfork_nonarchived():
    args = cc.build_repo_search_args("TypeScript", date(2025, 3, 1), date(2025, 3, 31), 1000)
    joined = " ".join(args)
    assert "fork:false" in joined
    assert "archived:false" in joined
    assert "pushed:2025-03-01..2025-03-31" in joined
    assert "--language" in args and "TypeScript" in args
    assert "--visibility" in args and "public" in args
    assert "stars:" not in joined  # no star restriction unless a bucket is given


def test_build_repo_search_args_adds_star_bucket():
    args = cc.build_repo_search_args("JavaScript", date(2025, 3, 1), date(2025, 3, 31), 1000,
                                     stars="5..24")
    joined = " ".join(args)
    assert "stars:5..24" in joined
    assert "fork:false" in joined and "archived:false" in joined


def test_star_bucket_slug_is_filename_safe():
    assert cc.star_bucket_slug("0") == "0"
    assert cc.star_bucket_slug("5..24") == "5-24"
    assert cc.star_bucket_slug(">=2500") == "gte2500"
    assert cc.star_bucket_slug(None) == "any"
    # Slug feeds a filename; it must contain no path/range separators.
    for b in ("0", "1..4", ">=2500", "100..499"):
        slug = cc.star_bucket_slug(b)
        assert "/" not in slug and ".." not in slug and ">" not in slug


# --------------------------------------------------------------------------- #
# Output parsing
# --------------------------------------------------------------------------- #
def test_parse_commit_search_output_from_fixture(fixtures_dir=None):
    fx = Path(__file__).resolve().parent / "fixtures" / "raw_search" / \
        "anthropic_email-2025-03-01_2025-03-31.json"
    recs = cc.parse_commit_search_output(fx.read_text(encoding="utf-8"))
    # 4 raw entries, one has null sha -> skipped -> 3 valid.
    assert len(recs) == 3
    by_sha = {r["sha"]: r for r in recs}
    assert by_sha["1111111111111111111111111111111111111111"]["repo_full_name"] == "octo/alpha-app"
    # owner+name fallback (no fullName field) resolves correctly.
    assert by_sha["3333333333333333333333333333333333333333"]["repo_full_name"] == "hubber/beta-site"
    # committer date used when author date absent.
    assert by_sha["3333333333333333333333333333333333333333"]["commit_date"] == "2025-03-20T14:00:00Z"


def test_parse_commit_search_output_handles_garbage():
    assert cc.parse_commit_search_output("") == []
    assert cc.parse_commit_search_output("not json") == []
    assert cc.parse_commit_search_output("{}") == []


def test_parse_repo_search_output_from_fixture():
    fx = Path(__file__).resolve().parent / "fixtures" / "raw_repo" / \
        "control_typescript-2025-03-01_2025-03-31.json"
    recs = cc.parse_repo_search_output(fx.read_text(encoding="utf-8"))
    assert len(recs) == 3  # includes the duplicate row (dedup happens in merge)
    r = recs[0]
    assert r["repo_full_name"] == "acme/ts-store"
    assert r["primary_language"] == "TypeScript"
    assert r["is_fork"] is False
    assert r["license"] == "mit"


# --------------------------------------------------------------------------- #
# Signal detection
# --------------------------------------------------------------------------- #
def test_detect_signals():
    assert cc.detect_signals("x\nCo-Authored-By: Claude <noreply@anthropic.com>") == ["anthropic_email"]
    assert cc.detect_signals("Generated with Claude Code") == ["generated_claude_code"]
    assert cc.detect_signals("Claude-Session: abc") == ["claude_session"]
    both = cc.detect_signals("Generated with Claude Code\nCo-Authored-By: Claude <noreply@anthropic.com>")
    assert both == ["anthropic_email", "generated_claude_code"]
    assert cc.detect_signals("ordinary commit") == []
    assert cc.detect_signals(None) == []


# --------------------------------------------------------------------------- #
# Orchestrator: adaptive sub-slicing + immutable saving + resumption
# (uses an injected fake search function — NO gh, NO network)
# --------------------------------------------------------------------------- #
def _fake_records(n, day="2025-03-05"):
    return [
        {
            "sha": f"{i:040x}",
            "url": f"https://github.com/o/r/commit/{i:040x}",
            "repository": {"fullName": "o/r", "url": "https://github.com/o/r"},
            "commit": {"message": "x noreply@anthropic.com", "author": {"date": f"{day}T00:00:00Z"}},
        }
        for i in range(n)
    ]


def test_orchestrator_subslices_on_saturation(tmp_path):
    calls = {"n": 0}

    def fake_search(query, start, end):
        calls["n"] += 1
        # Saturate any multi-day window; return few for single-day windows.
        n = 5 if start == end else 950
        recs = _fake_records(n)
        return json.dumps(recs), recs

    out_dir = tmp_path / "raw"
    log = tmp_path / "log.jsonl"
    # One 5-day window that will saturate and recurse down to single days.
    windows = [(date(2025, 3, 1), date(2025, 3, 5))]
    tree = cc.collect_signal("anthropic_email", "q", windows, out_dir, log,
                             fake_search, threshold=950, subslice=True)

    files = sorted(p.name for p in out_dir.glob("*.json"))
    # Parent slice saved, plus recursive children down to single days.
    assert "anthropic_email-2025-03-01_2025-03-05.json" in files
    assert "anthropic_email-2025-03-01_2025-03-01.json" in files  # a single-day leaf
    assert log.exists()
    # Recursion terminates (no infinite loop on single-day saturation).
    assert calls["n"] < 50
    # Tree records the subdivision.
    assert tree[0]["children"], "expected sub-slices recorded in the tree"


def test_orchestrator_resumes_from_cache(tmp_path):
    calls = {"n": 0}

    def fake_search(query, start, end):
        calls["n"] += 1
        recs = _fake_records(3)
        return json.dumps(recs), recs

    out_dir = tmp_path / "raw"
    log = tmp_path / "log.jsonl"
    windows = [(date(2025, 3, 1), date(2025, 3, 31))]

    cc.collect_signal("anthropic_email", "q", windows, out_dir, log,
                      fake_search, threshold=950, subslice=True)
    first = calls["n"]
    # Second run should hit the cache and not call the search function again.
    cc.collect_signal("anthropic_email", "q", windows, out_dir, log,
                      fake_search, threshold=950, subslice=True)
    assert calls["n"] == first  # no refetch


def test_orchestrator_flags_saturated_single_day_leaf(tmp_path):
    def fake_search(query, start, end):
        recs = _fake_records(950)               # always saturates, even single day
        return json.dumps(recs), recs

    windows = [(date(2025, 3, 1), date(2025, 3, 1))]   # unsplittable single day
    tree = cc.collect_signal("anthropic_email", "q", windows, tmp_path / "raw",
                             tmp_path / "log.jsonl", fake_search, threshold=950, subslice=True)
    assert tree[0]["status"] == "SATURATED_LEAF"
    assert tree[0]["saturated_leaf"] is True
    assert cc.count_saturated_leaves(tree) == 1
    assert "SATURATED_LEAF" in (tmp_path / "log.jsonl").read_text(encoding="utf-8")


def test_count_saturated_leaves_walks_full_tree():
    tree = {
        "label_a": [{"status": "OK", "children": [{"status": "SATURATED_LEAF", "children": []}]}],
        "label_b": [{"saturated_leaf": True, "children": []}],
    }
    assert cc.count_saturated_leaves(tree) == 2


def test_parse_retry_after_and_http_status():
    assert cc.parse_retry_after("Retry-After: 30") == 30
    assert cc.parse_retry_after("secondary rate limit. Please wait 45 seconds") == 45
    assert cc.parse_retry_after("no timing info here") is None
    assert cc.parse_http_status("gh: API rate limit exceeded (HTTP 403)") == 403
    assert cc.parse_http_status("nope") is None


def test_orchestrator_logs_audit_meta_on_success(tmp_path):
    def fake_search(query, start, end):
        recs = _fake_records(3)
        return json.dumps(recs), recs, {
            "attempts": 2, "exit_code": 0, "http_status": 200,
            "retry_after": None, "status": "OK"}

    windows = [(date(2025, 3, 1), date(2025, 3, 31))]
    cc.collect_signal("x", "q", windows, tmp_path / "raw", tmp_path / "log.jsonl",
                      fake_search, threshold=950, subslice=False)
    rec = json.loads((tmp_path / "log.jsonl").read_text(encoding="utf-8").splitlines()[0])
    assert rec["attempts"] == 2 and rec["exit_code"] == 0 and rec["http_status"] == 200


def test_orchestrator_logs_audit_meta_on_error(tmp_path):
    def failing_search(query, start, end):
        raise cc.GhSearchError("boom", transient=False,
                               meta={"attempts": 3, "exit_code": 22,
                                     "http_status": 403, "retry_after": 60})

    windows = [(date(2025, 3, 1), date(2025, 3, 31))]
    cc.collect_signal("x", "q", windows, tmp_path / "raw", tmp_path / "log.jsonl",
                      failing_search, threshold=950, subslice=False)
    rec = json.loads((tmp_path / "log.jsonl").read_text(encoding="utf-8").splitlines()[0])
    assert rec["status"] == "ERROR"
    assert rec["exit_code"] == 22 and rec["http_status"] == 403
    assert rec["retry_after"] == 60 and rec["attempts"] == 3


def test_orchestrator_records_error_without_zeroing(tmp_path):
    def failing_search(query, start, end):
        raise RuntimeError("simulated gh failure")

    out_dir = tmp_path / "raw"
    log = tmp_path / "log.jsonl"
    windows = [(date(2025, 3, 1), date(2025, 3, 31))]
    tree = cc.collect_signal("anthropic_email", "q", windows, out_dir, log,
                             failing_search, threshold=950, subslice=True)
    # No output file written on error; status recorded as ERROR in the log/tree.
    assert not list(out_dir.glob("*.json"))
    assert tree[0]["status"] == "ERROR"
    log_lines = log.read_text(encoding="utf-8").strip().splitlines()
    assert any('"status": "ERROR"' in ln for ln in log_lines)
