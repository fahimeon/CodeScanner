"""Unit tests for calculate_loc.py — tokei parsing, LOC/bucketing, orchestrator (offline)."""

import json

import calculate_loc as cl
import _common as common

CFG = common.load_study_config()


# --------------------------------------------------------------------------- #
# tokei JSON parsing (both shapes) + relevant-source selection
# --------------------------------------------------------------------------- #
def _tokei(langs: dict) -> str:
    # tokei-like: {lang: {"code": n, ...}} plus a Total that must be ignored.
    obj = {lang: {"code": code, "comments": 0, "blanks": 0} for lang, code in langs.items()}
    obj["Total"] = {"code": sum(langs.values())}
    return json.dumps(obj)


def test_parse_tokei_json_flat_and_nested():
    flat = _tokei({"TypeScript": 100, "CSS": 20})
    assert cl.parse_tokei_json(flat) == {"TypeScript": 100, "CSS": 20}
    nested = json.dumps({"languages": {"Rust": {"code": 50}, "Total": {"code": 50}}})
    assert cl.parse_tokei_json(nested) == {"Rust": 50}
    assert cl.parse_tokei_json("not json") == {}


def test_relevant_source_excludes_docs_and_data():
    by_lang = {"TypeScript": 1000, "CSS": 200, "Markdown": 500, "JSON": 300,
               "YAML": 40, "Dockerfile": 15}
    # Only TypeScript + CSS count as relevant source.
    assert cl.relevant_source_loc(by_lang) == 1200
    assert cl.source_breakdown(by_lang) == {"TypeScript": 1000, "CSS": 200}


# --------------------------------------------------------------------------- #
# Size bucketing against real study-config strata
# --------------------------------------------------------------------------- #
def test_size_bucket_thresholds():
    strata = CFG["size_strata"]
    lo, hi = CFG["source_loc"]["min"], CFG["source_loc"]["max"]
    assert cl.size_bucket(100, strata, lo, hi) == "below_min"       # < 500
    assert cl.size_bucket(500, strata, lo, hi) == "small"           # 500..4999
    assert cl.size_bucket(4999, strata, lo, hi) == "small"
    assert cl.size_bucket(5000, strata, lo, hi) == "medium"         # 5000..19999
    assert cl.size_bucket(20000, strata, lo, hi) == "large"         # 20000..100000
    assert cl.size_bucket(100000, strata, lo, hi) == "large"
    assert cl.size_bucket(100001, strata, lo, hi) == "above_max"


def test_build_loc_record():
    rec = cl.build_loc_record("o/r", _tokei({"TypeScript": 6000, "Markdown": 900}), CFG)
    assert rec["status"] == "OK"
    assert rec["relevant_source_loc"] == 6000
    assert rec["size_bucket"] == "medium"
    assert rec["language_breakdown"] == {"TypeScript": 6000}
    assert rec["total_code_loc"] == 6900


# --------------------------------------------------------------------------- #
# Writer: dict field serialized to CSV
# --------------------------------------------------------------------------- #
def test_write_loc_serializes_breakdown(tmp_path):
    rec = cl.build_loc_record("o/r", _tokei({"TypeScript": 800}), CFG)
    out_json = tmp_path / "loc.json"
    out_csv = tmp_path / "loc.csv"
    cl.write_loc([rec], out_json, out_csv)
    import csv as _csv
    with out_csv.open(encoding="utf-8") as fh:
        rows = list(_csv.reader(fh))
    assert rows[0] == cl.LOC_FIELDS
    idx = rows[0].index("language_breakdown")
    assert json.loads(rows[1][idx]) == {"TypeScript": 800}
    assert not list(tmp_path.glob("*.tmp"))


# --------------------------------------------------------------------------- #
# Orchestrator: metadata gating, caching, LOC errors
# --------------------------------------------------------------------------- #
def test_calculate_all_gates_caches_and_errors(tmp_path):
    def loc_fn(full, branch, url):
        return _tokei({"TypeScript": 900})

    candidates = [
        {"repository_full_name": "octo/app"},
        {"repository_full_name": "octo/gone"},   # metadata not OK -> UNAVAILABLE
    ]
    metadata = {
        "octo/app": {"repository_full_name": "octo/app", "fetch_status": "OK",
                     "default_branch": "main", "repository_url": "https://github.com/octo/app"},
        "octo/gone": {"repository_full_name": "octo/gone", "fetch_status": "NOT_FOUND"},
    }
    raw_dir = tmp_path / "loc"
    log = tmp_path / "log.jsonl"
    rows = cl.calculate_all(candidates, metadata, raw_dir, log, loc_fn, CFG)
    by = {r["repository_full_name"]: r for r in rows}
    assert by["octo/app"]["status"] == "OK" and by["octo/app"]["relevant_source_loc"] == 900
    assert by["octo/gone"]["status"] == "UNAVAILABLE"
    assert (raw_dir / "octo__app.json").exists()

    # Cached second run re-derives from raw tokei JSON without calling loc_fn.
    def boom(full, branch, url):
        raise AssertionError("must not recompute a cached repo")
    rows2 = cl.calculate_all(candidates, metadata, raw_dir, log, boom, CFG)
    assert {r["repository_full_name"]: r["status"] for r in rows2}["octo/app"] == "OK"


def test_calculate_all_records_loc_error(tmp_path):
    def failing(full, branch, url):
        raise RuntimeError("tokei failed")
    candidates = [{"repository_full_name": "octo/app"}]
    metadata = {"octo/app": {"repository_full_name": "octo/app",
                             "fetch_status": "OK", "default_branch": "main"}}
    rows = cl.calculate_all(candidates, metadata, tmp_path / "loc",
                            tmp_path / "log.jsonl", failing, CFG)
    assert rows[0]["status"] == "LOC_ERROR"
