"""Unit tests for fetch_repository_metadata.py — normalization + orchestrator (offline)."""

import json
from datetime import date
from pathlib import Path

import fetch_repository_metadata as fm

FIXTURES = Path(__file__).resolve().parent / "fixtures"
REPO_API = FIXTURES / "repo_api"
REF = date(2026, 7, 1)   # fixed reference date for deterministic derivations


# --------------------------------------------------------------------------- #
# Filename safety + arg building
# --------------------------------------------------------------------------- #
def test_safe_repo_filename_sanitizes_slash():
    assert fm.safe_repo_filename("octo/alpha-app") == "octo__alpha-app.json"
    # No path separators survive, even with odd characters.
    weird = fm.safe_repo_filename("a b/c:d")
    assert "/" not in weird and "\\" not in weird and ":" not in weird


def test_build_repo_api_args():
    args = fm.build_repo_api_args("octo/alpha-app")
    assert args[0] == "api"
    assert args[1] == "repos/octo/alpha-app"
    assert "-H" in args


def test_build_languages_and_head_args():
    assert fm.build_languages_api_args("octo/alpha-app")[1] == "repos/octo/alpha-app/languages"
    head = fm.build_head_commit_api_args("octo/alpha-app", "main")
    assert head[1] == "repos/octo/alpha-app/commits?sha=main&per_page=1"


def test_languages_list_orders_by_bytes_desc():
    assert fm._languages_list({"TypeScript": 900, "CSS": 100, "JavaScript": 500}) == \
        ["TypeScript", "JavaScript", "CSS"]
    assert fm._languages_list({}) == []
    assert fm._languages_list(None) == []


# --------------------------------------------------------------------------- #
# Date math
# --------------------------------------------------------------------------- #
def test_days_between_and_months_between():
    assert fm.days_between("2026-05-20T12:30:00Z", REF) == 42
    assert fm.months_between("2025-01-15T10:00:00Z", REF) == round(532 / 30.4375, 1)
    # Missing / malformed inputs yield None, never an exception.
    assert fm.days_between(None, REF) is None
    assert fm.months_between("", REF) is None
    assert fm.days_between("not-a-date", REF) is None


# --------------------------------------------------------------------------- #
# Normalization: OK object
# --------------------------------------------------------------------------- #
def test_parse_repo_metadata_ok_from_fixture():
    text = (REPO_API / "octo__alpha-app.json").read_text(encoding="utf-8")
    rec = fm.parse_repo_metadata(text, "octo/alpha-app", reference_date=REF)

    assert rec["fetch_status"] == "OK"
    assert rec["repository_full_name"] == "octo/alpha-app"
    assert rec["repository_url"] == "https://github.com/octo/alpha-app"
    assert rec["is_fork"] is False
    assert rec["is_archived"] is False
    assert rec["is_disabled"] is False
    assert rec["is_private"] is False
    assert rec["has_default_branch"] is True
    assert rec["default_branch"] == "main"
    assert rec["primary_language"] == "TypeScript"
    assert rec["size_kb"] == 8421
    assert rec["stargazers_count"] == 42
    assert rec["license_spdx"] == "MIT"
    assert rec["topics"] == ["nextjs", "typescript", "web-app"]
    assert rec["homepage"] == "https://alpha-app.example.com"
    assert rec["visibility"] == "public"
    # A bare repo object carries no HEAD sha or language distribution.
    assert rec["default_branch_head_sha"] is None
    assert rec["languages"] == []
    # Derived covariates against the fixed reference date.
    assert rec["last_push_age_days"] == 42
    assert rec["repo_age_months"] == round(532 / 30.4375, 1)


def test_parse_repo_metadata_composite_head_and_languages():
    import json as _json
    repo = _json.loads((REPO_API / "octo__alpha-app.json").read_text(encoding="utf-8"))
    composite = {
        "repo": repo,
        "languages": {"TypeScript": 9000, "CSS": 1000},
        "head": [{"sha": "deadbeef" * 5, "commit": {"committer": {"date": "2026-05-20T12:30:00Z"}}}],
    }
    rec = fm.parse_repo_metadata(composite, "octo/alpha-app", reference_date=REF)
    assert rec["fetch_status"] == "OK"
    assert rec["default_branch_head_sha"] == "deadbeef" * 5
    assert rec["languages"] == ["TypeScript", "CSS"]
    assert rec["language_distribution"] == {"TypeScript": 9000, "CSS": 1000}
    assert rec["visibility"] == "public"


def test_parse_repo_metadata_without_reference_leaves_derived_none():
    text = (REPO_API / "octo__alpha-app.json").read_text(encoding="utf-8")
    rec = fm.parse_repo_metadata(text, "octo/alpha-app")
    assert rec["fetch_status"] == "OK"
    assert rec["repo_age_months"] is None
    assert rec["last_push_age_days"] is None


def test_parse_repo_metadata_missing_license_and_topics():
    obj = {"id": 1, "full_name": "o/r", "default_branch": "main", "language": "JavaScript"}
    rec = fm.parse_repo_metadata(obj, "o/r", reference_date=REF)
    assert rec["fetch_status"] == "OK"
    assert rec["license_spdx"] is None
    assert rec["topics"] == []
    assert rec["homepage"] is None


# --------------------------------------------------------------------------- #
# Normalization: NOT_FOUND + garbage
# --------------------------------------------------------------------------- #
def test_parse_repo_metadata_not_found_from_fixture():
    text = (REPO_API / "deleted__gone.json").read_text(encoding="utf-8")
    rec = fm.parse_repo_metadata(text, "deleted/gone", reference_date=REF)
    assert rec["fetch_status"] == "NOT_FOUND"
    assert rec["repository_full_name"] == "deleted/gone"


def test_parse_repo_metadata_garbage_is_error():
    assert fm.parse_repo_metadata("", "o/r")["fetch_status"] == "ERROR"
    assert fm.parse_repo_metadata("not json", "o/r")["fetch_status"] == "ERROR"
    assert fm.parse_repo_metadata("[]", "o/r")["fetch_status"] == "ERROR"


# --------------------------------------------------------------------------- #
# Orchestrator: immutable caching, logging, no-drop, resumption
# (injected fake fetch — NO gh, NO network)
# --------------------------------------------------------------------------- #
def _ok_body(full, lang="TypeScript"):
    # Composite (current schema) so the resumption cache is treated as current.
    return json.dumps({
        "repo": {
            "id": abs(hash(full)) % 10_000,
            "full_name": full,
            "html_url": f"https://github.com/{full}",
            "fork": False, "archived": False, "disabled": False, "private": False,
            "default_branch": "main", "language": lang, "size": 1000,
            "stargazers_count": 1, "forks_count": 0, "open_issues_count": 0,
            "topics": [], "license": None, "homepage": None,
            "created_at": "2025-03-01T00:00:00Z",
            "pushed_at": "2026-06-01T00:00:00Z",
            "updated_at": "2026-06-02T00:00:00Z",
        },
        "languages": {lang: 1000},
        "head": [{"sha": "f" * 40}],
    })


def test_orchestrator_fetches_caches_and_records_all(tmp_path):
    calls = {"n": 0}

    def fake_fetch(full):
        calls["n"] += 1
        if full == "deleted/gone":
            body = '{"message": "Not Found"}'
            return body, json.loads(body)
        text = _ok_body(full)
        return text, json.loads(text)

    candidates = [
        {"repository_full_name": "octo/alpha-app"},
        {"repository_full_name": "hubber/beta-site"},
        {"repository_full_name": "deleted/gone"},
    ]
    raw_dir = tmp_path / "raw"
    log = tmp_path / "log.jsonl"

    records = fm.fetch_repository_metadata(candidates, raw_dir, log, fake_fetch, REF)

    # Every candidate produces a record; the 404 is carried, not dropped.
    assert len(records) == 3
    by_name = {r["repository_full_name"]: r for r in records}
    assert by_name["octo/alpha-app"]["fetch_status"] == "OK"
    assert by_name["deleted/gone"]["fetch_status"] == "NOT_FOUND"
    # Raw dumps written immutably, one per repo, no temp leftovers.
    assert (raw_dir / "octo__alpha-app.json").exists()
    assert (raw_dir / "deleted__gone.json").exists()
    assert not list(raw_dir.glob("*.tmp"))
    # Audit log has one line per fetched repo.
    assert len(log.read_text(encoding="utf-8").strip().splitlines()) == 3


def test_cache_is_current_detection():
    assert fm._cache_is_current({"repo": {"id": 1}}) is True         # composite
    assert fm._cache_is_current({"message": "Not Found"}) is True    # terminal body
    assert fm._cache_is_current({"id": 1, "full_name": "o/r"}) is False  # bare (stale)
    assert fm._cache_is_current("garbage") is False


def test_orchestrator_refetches_stale_bare_cache(tmp_path):
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    # A pre-composite bare repo object left by an older run.
    stale = {"id": 1, "full_name": "octo/alpha-app", "default_branch": "main", "language": "TS"}
    (raw_dir / "octo__alpha-app.json").write_text(json.dumps(stale), encoding="utf-8")

    calls = {"n": 0}

    def fetch(full):
        calls["n"] += 1
        comp = {"repo": {"id": 1, "full_name": full, "default_branch": "main", "fork": False},
                "languages": {"TypeScript": 100}, "head": [{"sha": "abc123"}]}
        return json.dumps(comp), comp

    recs = fm.fetch_repository_metadata(
        [{"repository_full_name": "octo/alpha-app"}], raw_dir, tmp_path / "log.jsonl", fetch, REF)
    assert calls["n"] == 1                                   # refetched despite cache present
    assert recs[0]["default_branch_head_sha"] == "abc123"    # now has composite fields
    assert recs[0]["languages"] == ["TypeScript"]


def test_orchestrator_keeps_current_composite_cache(tmp_path):
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    comp = {"repo": {"id": 1, "full_name": "octo/alpha-app", "default_branch": "main", "fork": False},
            "languages": {"TypeScript": 100}, "head": [{"sha": "abc123"}]}
    (raw_dir / "octo__alpha-app.json").write_text(json.dumps(comp), encoding="utf-8")

    def fetch(full):
        raise AssertionError("must not refetch a current composite cache")

    recs = fm.fetch_repository_metadata(
        [{"repository_full_name": "octo/alpha-app"}], raw_dir, tmp_path / "log.jsonl", fetch, REF)
    assert recs[0]["_source"] == "CACHED"
    assert recs[0]["default_branch_head_sha"] == "abc123"


def test_orchestrator_resumes_from_cache(tmp_path):
    calls = {"n": 0}

    def fake_fetch(full):
        calls["n"] += 1
        text = _ok_body(full)
        return text, json.loads(text)

    candidates = [{"repository_full_name": "octo/alpha-app"}]
    raw_dir = tmp_path / "raw"
    log = tmp_path / "log.jsonl"

    fm.fetch_repository_metadata(candidates, raw_dir, log, fake_fetch, REF)
    first = calls["n"]
    recs = fm.fetch_repository_metadata(candidates, raw_dir, log, fake_fetch, REF)
    assert calls["n"] == first          # served from cache, no refetch
    assert recs[0]["_source"] == "CACHED"
    assert recs[0]["fetch_status"] == "OK"


def test_orchestrator_dedups_repeated_candidate(tmp_path):
    def fake_fetch(full):
        text = _ok_body(full)
        return text, json.loads(text)

    candidates = [
        {"repository_full_name": "octo/alpha-app"},
        {"repository_full_name": "octo/alpha-app"},   # duplicate row
    ]
    records = fm.fetch_repository_metadata(
        candidates, tmp_path / "raw", tmp_path / "log.jsonl", fake_fetch, REF)
    assert len(records) == 1


def test_orchestrator_records_error_without_raising(tmp_path):
    def failing_fetch(full):
        raise RuntimeError("simulated gh failure")

    candidates = [{"repository_full_name": "octo/alpha-app"}]
    raw_dir = tmp_path / "raw"
    log = tmp_path / "log.jsonl"
    records = fm.fetch_repository_metadata(candidates, raw_dir, log, failing_fetch, REF)
    assert records[0]["fetch_status"] == "ERROR"
    # No raw file on error; the failure is logged, not swallowed silently.
    assert not list(raw_dir.glob("*.json"))
    assert '"fetch_status": "ERROR"' in log.read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# Writers: CSV/JSON roundtrip, list-field flattening, header
# --------------------------------------------------------------------------- #
def test_write_metadata_roundtrip_and_topics_flattened(tmp_path):
    text = (REPO_API / "octo__alpha-app.json").read_text(encoding="utf-8")
    rec = fm.parse_repo_metadata(text, "octo/alpha-app", reference_date=REF)
    out_json = tmp_path / "meta.json"
    out_csv = tmp_path / "meta.csv"
    fm.write_metadata([rec], out_json, out_csv)

    assert out_json.exists() and out_csv.exists()
    assert not list(tmp_path.glob("*.tmp"))

    import csv as _csv
    with out_csv.open(encoding="utf-8") as fh:
        rows = list(_csv.reader(fh))
    assert rows[0] == fm.METADATA_FIELDS
    topics_idx = fm.METADATA_FIELDS.index("topics")
    assert rows[1][topics_idx] == "nextjs;typescript;web-app"
    # JSON keeps topics as a real list.
    assert json.loads(out_json.read_text(encoding="utf-8"))[0]["topics"] == \
        ["nextjs", "typescript", "web-app"]


def test_write_metadata_includes_language_distribution(tmp_path):
    rec = fm.parse_repo_metadata(
        {"repo": {"id": 1, "full_name": "o/r", "default_branch": "main", "fork": False},
         "languages": {"TypeScript": 900, "CSS": 100}, "head": [{"sha": "x"}]},
        "o/r", reference_date=REF)
    out_json = tmp_path / "m.json"
    out_csv = tmp_path / "m.csv"
    fm.write_metadata([rec], out_json, out_csv)

    import csv as _csv
    with out_csv.open(encoding="utf-8") as fh:
        rows = list(_csv.reader(fh))
    assert "language_distribution" in rows[0]                 # column not dropped
    idx = rows[0].index("language_distribution")
    assert json.loads(rows[1][idx]) == {"TypeScript": 900, "CSS": 100}
    # JSON keeps it as a native dict.
    assert json.loads(out_json.read_text(encoding="utf-8"))[0]["language_distribution"] == \
        {"TypeScript": 900, "CSS": 100}
