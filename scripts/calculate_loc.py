#!/usr/bin/env python3
"""
calculate_loc.py — Phase 8 relevant source-LOC.

Computes each repository's RELEVANT source lines of code (the eligibility gate is
500–100k) with tokei, over the repository tree obtained via `git archive` (NO
working-tree checkout of the live clone, NO code execution). Doc/data languages
(Markdown, JSON, YAML, …) and the excluded-paths trees are not counted as source;
lock/minified/vendor paths are excluded via config/excluded-paths.txt.

Design mirrors the earlier phases: a pure tokei-JSON parser + size-bucketing,
split from an injectable `loc_fn`, unit-tested offline with synthetic tokei JSON.

Outputs:
  data/interim/loc/{owner__repo}.json      (raw tokei JSON, per repo)
  data/interim/source-loc.{json,csv}       (aggregate)
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Callable, Optional

try:
    from . import _common as common  # type: ignore
    from . import verify_claude_attribution as vca  # type: ignore
except Exception:  # pragma: no cover
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _common as common  # type: ignore
    import verify_claude_attribution as vca  # type: ignore

STUDY_ROOT = common.STUDY_ROOT

# Languages tokei may report that are NOT counted as relevant application source
# (docs, config/data, markup-of-content). Code/style/template languages ARE counted.
NON_SOURCE_LANGUAGES = {
    "Markdown", "Text", "Plain Text", "JSON", "JSON5", "YAML", "TOML", "INI",
    "XML", "SVG", "CSV", "TSV", "Org", "reStructuredText", "AsciiDoc",
    "Dockerfile", "Makefile", "Batch", "Autoconf", "License", "BASH", "Shell",
    "Module-Definition", "Gitignore",
}

LOC_FIELDS = [
    "repository_full_name",
    "status",                    # OK | UNAVAILABLE | LOC_ERROR
    "relevant_source_loc",
    "total_code_loc",
    "size_bucket",               # below_min | small | medium | large | above_max
    "loc_tool",
    "language_breakdown",        # {lang: code} JSON (source languages only)
]
_DICT_FIELDS = {"language_breakdown"}


# =========================================================================== #
# PURE FUNCTIONS
# =========================================================================== #
def parse_tokei_json(text_or_obj) -> dict[str, int]:
    """Parse tokei --output json into {language: code_lines}. Robust to the
    `{lang: {...}}` and `{"languages": {lang: {...}}}` shapes; skips 'Total'."""
    if isinstance(text_or_obj, (str, bytes)):
        try:
            obj = json.loads(text_or_obj)
        except Exception:
            return {}
    else:
        obj = text_or_obj
    if not isinstance(obj, dict):
        return {}
    languages = obj.get("languages") if isinstance(obj.get("languages"), dict) else obj
    out: dict[str, int] = {}
    for lang, stats in languages.items():
        if lang == "Total" or not isinstance(stats, dict):
            continue
        code = stats.get("code")
        if isinstance(code, (int, float)):
            out[lang] = int(code)
    return out


def relevant_source_loc(by_language: dict[str, int],
                        non_source: set[str] = NON_SOURCE_LANGUAGES) -> int:
    return sum(code for lang, code in by_language.items() if lang not in non_source)


def source_breakdown(by_language: dict[str, int],
                     non_source: set[str] = NON_SOURCE_LANGUAGES) -> dict[str, int]:
    return {lang: code for lang, code in by_language.items()
            if lang not in non_source and code > 0}


def size_bucket(loc: int, strata: dict, min_loc: int, max_loc: int) -> str:
    """Map a relevant-LOC count to a size stratum (below_min/small/medium/large/above_max)."""
    if loc < min_loc:
        return "below_min"
    if loc > max_loc:
        return "above_max"
    for name in ("small", "medium", "large"):
        band = strata.get(name)
        if band and band.get("min", 0) <= loc <= band.get("max", 10 ** 12):
            return name
    return "small" if loc >= min_loc else "below_min"


def build_loc_record(full_name: str, tokei_text, cfg: dict, tool: str = "tokei") -> dict:
    by_language = parse_tokei_json(tokei_text)
    relevant = relevant_source_loc(by_language)
    total = sum(by_language.values())
    strata = cfg.get("size_strata", {})
    src = cfg.get("source_loc", {})
    bucket = size_bucket(relevant, strata, src.get("min", 500), src.get("max", 100000))
    return {
        "repository_full_name": full_name,
        "status": "OK",
        "relevant_source_loc": relevant,
        "total_code_loc": total,
        "size_bucket": bucket,
        "loc_tool": tool,
        "language_breakdown": source_breakdown(by_language),
    }


# =========================================================================== #
# WRITERS
# =========================================================================== #
def _csv_row(rec: dict) -> dict:
    row = dict(rec)
    for field in _DICT_FIELDS:
        val = row.get(field)
        if isinstance(val, dict):
            row[field] = json.dumps(val, separators=(",", ":"), ensure_ascii=False)
    return row


def write_loc(records: list[dict], json_path: Path, csv_path: Path) -> None:
    common.atomic_write_json(json_path, records)
    common.ensure_dir(Path(csv_path).parent)
    tmp = Path(csv_path).with_suffix(".csv.tmp")
    with tmp.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=LOC_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for rec in records:
            writer.writerow(_csv_row(rec))
    os.replace(tmp, csv_path)


# =========================================================================== #
# ORCHESTRATION (I/O; tokei injected as loc_fn for testability)
# =========================================================================== #
# loc_fn signature: (full_name, default_branch, url) -> tokei_json_text
LocFn = Callable[[str, Optional[str], str], str]


def calculate_all(candidates: list[dict], metadata_by_name: dict[str, dict],
                  raw_dir: Path, log_path: Path, loc_fn: LocFn, cfg: dict) -> list[dict]:
    common.ensure_dir(raw_dir)
    rows: list[dict] = []
    seen: set[str] = set()

    for cand in candidates:
        full = cand.get("repository_full_name")
        if not full or full in seen:
            continue
        seen.add(full)

        meta = metadata_by_name.get(full)
        if not meta or meta.get("fetch_status") != "OK":
            rows.append({"repository_full_name": full, "status": "UNAVAILABLE"})
            _log(log_path, full, "UNAVAILABLE", None)
            continue

        raw_file = raw_dir / f"{vca._safe_name(full)}.json"
        if common.is_valid_json_file(raw_file):
            rec = build_loc_record(full, common.read_json(raw_file), cfg)
            rows.append(rec)
            continue

        try:
            tokei_text = loc_fn(full, meta.get("default_branch"),
                                meta.get("repository_url") or f"https://github.com/{full}")
            common.atomic_write_text(raw_file, tokei_text)
            rec = build_loc_record(full, tokei_text, cfg)
        except Exception as exc:
            rec = {"repository_full_name": full, "status": "LOC_ERROR"}
            _log(log_path, full, "LOC_ERROR", f"{type(exc).__name__}: {exc}")
            rows.append(rec)
            continue

        rows.append(rec)
        _log(log_path, full, "OK", None, loc=rec.get("relevant_source_loc"))

    return rows


def _log(log_path: Path, full: str, status: str, error: Optional[str], loc=None) -> None:
    common.append_jsonl(log_path, {
        "ts": common.iso_now(), "repository_full_name": full,
        "status": status, "relevant_source_loc": loc, "error": error,
    })


# --------------------------------------------------------------------------- #
# Real tokei-backed loc function (git archive -> extract -> tokei; no execution)
# --------------------------------------------------------------------------- #
def load_exclude_globs() -> list[str]:
    """Directory/file patterns from excluded-paths.txt as tokei --exclude globs."""
    text = (common.CONFIG_DIR / "excluded-paths.txt").read_text(encoding="utf-8")
    globs: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        globs.append(line.rstrip("/"))
    return globs


def make_tokei_loc_fn(git_path: str, tokei_path: str, clone_root: Path,
                      clone_timeout: int = 300) -> LocFn:
    common.ensure_dir(clone_root)
    hooks_dir = clone_root / ".empty-hooks"
    common.ensure_dir(hooks_dir)
    env = vca._git_env()
    exclude_globs = load_exclude_globs()

    def _run(args, timeout, cwd=None):
        import subprocess
        return subprocess.run(args, capture_output=True, text=True, encoding="utf-8", errors="replace",
                              timeout=timeout, check=False, env=env, cwd=cwd)

    def _fn(full_name: str, default_branch: Optional[str], url: str) -> str:
        dest = clone_root / vca._safe_name(full_name)
        if not vca._is_within(clone_root, dest):
            raise RuntimeError(f"refusing to operate outside clone root: {dest}")
        if not (dest / ".git").exists() and not (dest / "HEAD").exists():
            args = vca.build_clone_args(url, str(dest), str(hooks_dir), default_branch)
            proc = _run([git_path, *args], clone_timeout)
            if proc.returncode != 0:
                raise RuntimeError(f"clone failed: {proc.stderr.strip()[:200]}")
        with tempfile.TemporaryDirectory(prefix="loc_") as tmp:
            tar_path = Path(tmp) / "tree.tar"
            arch = _run([git_path, "-C", str(dest), "archive",
                         "-o", str(tar_path), "HEAD"], 180)
            if arch.returncode != 0:
                raise RuntimeError(f"git archive failed: {arch.stderr.strip()[:200]}")
            extract_dir = Path(tmp) / "tree"
            extract_dir.mkdir()
            with tarfile.open(tar_path) as tf:
                # Python 3.12 'data' filter blocks path traversal / unsafe members.
                try:
                    tf.extractall(extract_dir, filter="data")
                except TypeError:  # pragma: no cover - older Python
                    tf.extractall(extract_dir)
            args = [tokei_path, "--output", "json"]
            for g in exclude_globs:
                args += ["--exclude", g]
            args += [str(extract_dir)]
            tk = _run(args, 300)
            if tk.returncode != 0 or not tk.stdout.strip():
                raise RuntimeError(f"tokei failed: {tk.stderr.strip()[:200]}")
            return tk.stdout

    return _fn


# =========================================================================== #
# main
# =========================================================================== #
def _load_metadata_index(path: Path) -> dict[str, dict]:
    if not path.exists():
        return {}
    return {r["repository_full_name"]: r for r in common.read_json(path)
            if isinstance(r, dict) and r.get("repository_full_name")}


def main(argv: Optional[list[str]] = None) -> int:
    import shutil
    parser = argparse.ArgumentParser(description="Compute relevant source LOC (Phase 8).")
    parser.add_argument("--control", action="store_true")
    args = parser.parse_args(argv)

    cfg = common.load_study_config()
    interim = STUDY_ROOT / cfg["paths"]["interim"]
    if args.control:
        candidates_path = interim / "control" / "control-candidate-repositories.json"
        metadata_path = interim / "control" / "repository-metadata.json"
        raw_dir = interim / "control" / "loc"
        out_json = interim / "control" / "source-loc.json"
        out_csv = interim / "control" / "source-loc.csv"
        log_path = STUDY_ROOT / cfg["paths"]["logs"] / "calculate_loc_control.jsonl"
        key = "repo_full_name"
    else:
        candidates_path = interim / "claude-candidate-repositories.json"
        metadata_path = interim / "repository-metadata.json"
        raw_dir = interim / "loc"
        out_json = interim / "source-loc.json"
        out_csv = interim / "source-loc.csv"
        log_path = STUDY_ROOT / cfg["paths"]["logs"] / "calculate_loc.jsonl"
        key = "repository_full_name"

    if not candidates_path.exists() or not metadata_path.exists():
        print("ERROR: need candidate + metadata tables. Run 'make merge' and 'make metadata' first.",
              file=sys.stderr)
        return 2

    raw_candidates = common.read_json(candidates_path)
    candidates = [{"repository_full_name": c.get(key) or c.get("repository_full_name")}
                  for c in raw_candidates]
    candidates = [c for c in candidates if c["repository_full_name"]]
    metadata_by_name = _load_metadata_index(metadata_path)

    git = vca.find_git()
    tokei = shutil.which("tokei")
    if git is None or tokei is None:
        print("ERROR: git and tokei are both required on PATH.", file=sys.stderr)
        return 2
    scanner_cfg = common.load_yaml(common.CONFIG_DIR / "scanner-config.yaml")
    clone_timeout = int(scanner_cfg.get("clone", {}).get("limits", {})
                        .get("clone_timeout_seconds", 300))
    clone_root = STUDY_ROOT / cfg["paths"]["candidates_clone"] / "history"
    loc_fn = make_tokei_loc_fn(git, tokei, clone_root, clone_timeout)

    rows = calculate_all(candidates, metadata_by_name, raw_dir, log_path, loc_fn, cfg)
    write_loc(rows, out_json, out_csv)

    from collections import Counter
    buckets = Counter(r.get("size_bucket") for r in rows if r.get("status") == "OK")
    print(f"Computed LOC for {len(rows)} repositories -> {out_csv}")
    print(f"  size buckets: {dict(buckets)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
