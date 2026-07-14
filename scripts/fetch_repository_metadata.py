#!/usr/bin/env python3
"""
fetch_repository_metadata.py — Phase 4 repository metadata.

For every merged candidate repository (Phase 3 output), fetch the GitHub REST
repository object (`GET /repos/{owner}/{repo}`) via authenticated `gh api` and
normalize it into the fields the eligibility funnel and covariate model need:
fork/archived/disabled flags, default branch, primary language, size, dates
(→ repo age, last-push age), stars, license, topics, homepage.

This is enrichment ONLY. It clones nothing, contacts no deployment, and runs no
scanner. A repository that 404s (deleted / renamed / made private since the
immutable search dump) is recorded with fetch_status=NOT_FOUND and carried
forward — never silently dropped.

Design mirrors collect_candidates.py:
  * ALL pure logic (arg building, JSON normalization, date math, table writing)
    is separated from the gh-calling orchestration and unit-tested offline with
    synthetic fixtures (tests/test_fetch_repository_metadata.py).
  * The orchestrator takes an injectable `fetch_fn`, so resumption / logging /
    error handling are tested WITHOUT invoking gh or the network.
  * Raw API JSON is saved verbatim and immutably (one file per repo); reruns
    resume by re-parsing cached files instead of refetching.
  * Requests are paced under the REST core limit with exponential backoff on
    403/429/secondary-rate-limit responses.

Usage:
  python scripts/fetch_repository_metadata.py                 # treated cohort
  python scripts/fetch_repository_metadata.py --control       # control cohort
  python scripts/fetch_repository_metadata.py --reference-date 2026-07-01
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import date, timezone, datetime
from pathlib import Path
from typing import Callable, Optional

try:
    from . import _common as common  # type: ignore
except Exception:  # pragma: no cover
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _common as common  # type: ignore

STUDY_ROOT = common.STUDY_ROOT

# REST core limit is 5000 req/hr authenticated (~83/min). Pace well under it and
# lean on backoff for the secondary abuse limit.
REST_RATE_MIN_INTERVAL_S = 0.75
DAYS_PER_MONTH = 30.4375  # average Gregorian month, for age-in-months covariate

# Canonical output columns (order = CSV header). List-valued fields are joined
# with ';' for the CSV; the JSON keeps them as lists.
METADATA_FIELDS = [
    "repository_full_name",
    "repository_url",
    "fetch_status",          # OK | NOT_FOUND | ERROR
    "is_private",
    "visibility",
    "is_fork",
    "is_archived",
    "is_disabled",
    "has_default_branch",
    "default_branch",
    "default_branch_head_sha",
    "primary_language",
    "languages",
    "language_distribution",
    "size_kb",
    "stargazers_count",
    "forks_count",
    "open_issues_count",
    "license_spdx",
    "topics",
    "homepage",
    "description",
    "created_at",
    "pushed_at",
    "updated_at",
    "repo_age_months",
    "last_push_age_days",
    "fetched_at",
]
_LIST_FIELDS = {"topics", "languages"}
_DICT_FIELDS = {"language_distribution"}   # serialized as compact JSON in CSV


# =========================================================================== #
# PURE FUNCTIONS (unit-tested; no I/O, no network)
# =========================================================================== #
def safe_repo_filename(full_name: str) -> str:
    """`owner/repo` -> `owner__repo.json`, safe on every filesystem."""
    stem = full_name.replace("/", "__")
    stem = "".join(c if (c.isalnum() or c in "._-") else "_" for c in stem)
    return f"{stem}.json"


def build_repo_api_args(full_name: str) -> list[str]:
    """argv (excluding the gh executable) for `gh api repos/{owner}/{repo}`."""
    return ["api", f"repos/{full_name}", "-H", "Accept: application/vnd.github+json"]


def build_languages_api_args(full_name: str) -> list[str]:
    """argv for the language byte-distribution: `gh api repos/{owner}/{repo}/languages`."""
    return ["api", f"repos/{full_name}/languages", "-H", "Accept: application/vnd.github+json"]


def build_head_commit_api_args(full_name: str, branch: str) -> list[str]:
    """argv for the default-branch HEAD commit (compact list form, no file diffs)."""
    return ["api", f"repos/{full_name}/commits?sha={branch}&per_page=1",
            "-H", "Accept: application/vnd.github+json"]


def _split_composite(obj: dict):
    """Accept either a bare repo object or a composite
    {repo, languages, head} record, returning (repo_obj, languages, head)."""
    if isinstance(obj, dict) and isinstance(obj.get("repo"), dict):
        return obj["repo"], obj.get("languages"), obj.get("head")
    return obj, None, None


def _cache_is_current(raw_obj) -> bool:
    """
    True if a cached raw record matches the CURRENT (composite) schema, or is a
    terminal error/not-found body. A BARE repo object (has 'id', lacks 'repo')
    predates the composite schema — it has no languages/HEAD-sha — so it is
    treated as stale and refetched, migrating the cache forward.
    """
    if not isinstance(raw_obj, dict):
        return False
    if "repo" in raw_obj:                       # composite (current schema)
        return True
    if "id" not in raw_obj and "message" in raw_obj:  # terminal error / not-found body
        return True
    return False


def _languages_list(languages: Optional[dict]) -> list[str]:
    """Language names ordered by bytes descending (from the /languages map)."""
    if not isinstance(languages, dict) or not languages:
        return []
    return [name for name, _ in sorted(
        languages.items(), key=lambda kv: (-(kv[1] or 0), kv[0]))]


def _as_obj(text_or_obj) -> Optional[dict]:
    if isinstance(text_or_obj, dict):
        return text_or_obj
    if not isinstance(text_or_obj, str) or not text_or_obj.strip():
        return None
    try:
        obj = json.loads(text_or_obj)
    except Exception:
        return None
    return obj if isinstance(obj, dict) else None


def _parse_date(iso_ts: Optional[str]) -> Optional[date]:
    """Date part of an ISO-8601 timestamp ('2026-05-20T12:30:00Z' -> date)."""
    if not iso_ts or not isinstance(iso_ts, str) or len(iso_ts) < 10:
        return None
    try:
        return date.fromisoformat(iso_ts[:10])
    except ValueError:
        return None


def days_between(earlier_iso: Optional[str], reference: date) -> Optional[int]:
    d = _parse_date(earlier_iso)
    return (reference - d).days if d else None


def months_between(earlier_iso: Optional[str], reference: date) -> Optional[float]:
    d = _parse_date(earlier_iso)
    return round((reference - d).days / DAYS_PER_MONTH, 1) if d else None


def parse_repo_metadata(
    text_or_obj,
    full_name: Optional[str] = None,
    reference_date: Optional[date] = None,
) -> dict:
    """
    Normalize a GitHub REST repository object into the study's metadata record.

    Recognizes the three terminal shapes:
      * a real repo object (has 'id')            -> fetch_status=OK
      * a "Not Found" error body                 -> fetch_status=NOT_FOUND
      * anything else / unparseable              -> fetch_status=ERROR
    Derived date fields are filled only when `reference_date` is supplied.
    """
    obj = _as_obj(text_or_obj)
    if obj is None:
        return {"repository_full_name": full_name, "fetch_status": "ERROR"}

    repo_obj, languages, head = _split_composite(obj)
    if not isinstance(repo_obj, dict) or "id" not in repo_obj:
        msg = str((repo_obj or {}).get("message") or "")
        status = "NOT_FOUND" if "not found" in msg.lower() else "ERROR"
        return {
            "repository_full_name": (repo_obj or {}).get("full_name") or full_name,
            "fetch_status": status,
        }

    resolved_name = repo_obj.get("full_name") or full_name
    lic = repo_obj.get("license")
    lic_spdx = None
    if isinstance(lic, dict):
        lic_spdx = lic.get("spdx_id") or lic.get("key")
    default_branch = repo_obj.get("default_branch") or ""
    topics = repo_obj.get("topics") or []
    if not isinstance(topics, list):
        topics = []
    # HEAD sha comes from the composite; the commits endpoint returns a list.
    head_sha = None
    if isinstance(head, dict):
        head_sha = head.get("sha")
    elif isinstance(head, list) and head and isinstance(head[0], dict):
        head_sha = head[0].get("sha")

    obj = repo_obj  # remaining field reads pull from the repo object
    rec = {
        "repository_full_name": resolved_name,
        "repository_url": obj.get("html_url") or (
            f"https://github.com/{resolved_name}" if resolved_name else None
        ),
        "fetch_status": "OK",
        "is_private": bool(obj.get("private")),
        "visibility": obj.get("visibility"),
        "is_fork": bool(obj.get("fork")),
        "is_archived": bool(obj.get("archived")),
        "is_disabled": bool(obj.get("disabled")),
        "has_default_branch": bool(default_branch),
        "default_branch": default_branch or None,
        "default_branch_head_sha": head_sha,
        "primary_language": obj.get("language"),
        "languages": _languages_list(languages),
        "language_distribution": languages if isinstance(languages, dict) else {},
        "size_kb": obj.get("size"),
        "stargazers_count": obj.get("stargazers_count"),
        "forks_count": obj.get("forks_count"),
        "open_issues_count": obj.get("open_issues_count"),
        "license_spdx": lic_spdx,
        "topics": topics,
        "homepage": (obj.get("homepage") or None),
        "description": obj.get("description"),
        "created_at": obj.get("created_at"),
        "pushed_at": obj.get("pushed_at"),
        "updated_at": obj.get("updated_at"),
        "repo_age_months": None,
        "last_push_age_days": None,
        "fetched_at": common.iso_now(),
    }
    if reference_date is not None:
        rec["repo_age_months"] = months_between(rec["created_at"], reference_date)
        rec["last_push_age_days"] = days_between(rec["pushed_at"], reference_date)
    return rec


def load_candidates(path: Path) -> list[dict]:
    """Load the Phase 3 candidate table (JSON list of repo records)."""
    data = common.read_json(path)
    return data if isinstance(data, list) else []


# =========================================================================== #
# WRITERS
# =========================================================================== #
def _csv_row(rec: dict) -> dict:
    row = dict(rec)
    for field in _LIST_FIELDS:
        val = row.get(field)
        if isinstance(val, list):
            row[field] = ";".join(str(v) for v in val)
    for field in _DICT_FIELDS:
        val = row.get(field)
        if isinstance(val, dict):
            # Compact JSON so the byte-distribution survives in the CSV.
            row[field] = json.dumps(val, separators=(",", ":"), ensure_ascii=False)
    return row


def write_metadata(records: list[dict], json_path: Path, csv_path: Path,
                   fields: list[str] = METADATA_FIELDS) -> None:
    common.atomic_write_json(json_path, records)
    common.ensure_dir(Path(csv_path).parent)
    tmp = Path(csv_path).with_suffix(".csv.tmp")
    with tmp.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for rec in records:
            writer.writerow(_csv_row(rec))
    os.replace(tmp, csv_path)


# =========================================================================== #
# ORCHESTRATION (I/O; gh injected as fetch_fn for testability)
# =========================================================================== #
# fetch_fn signature: (full_name) -> (raw_text, raw_json_obj_or_None)
FetchFn = Callable[[str], tuple[str, Optional[dict]]]


def fetch_repository_metadata(
    candidates: list[dict],
    raw_dir: Path,
    log_path: Path,
    fetch_fn: FetchFn,
    reference_date: date,
) -> list[dict]:
    """
    Fetch (or resume from cache) metadata for every candidate. Saves each raw
    API response immutably, logs each request, and returns normalized records
    in candidate order. Never drops a repository: failures/404s are recorded.
    """
    common.ensure_dir(raw_dir)
    records: list[dict] = []
    seen: set[str] = set()

    for cand in candidates:
        full = cand.get("repository_full_name")
        if not full or full in seen:
            continue
        seen.add(full)
        raw_file = raw_dir / safe_repo_filename(full)

        if common.is_valid_json_file(raw_file):
            raw_obj = common.read_json(raw_file)
            if _cache_is_current(raw_obj):
                rec = parse_repo_metadata(raw_obj, full, reference_date)
                rec["_source"] = "CACHED"
                records.append(rec)
                continue
            # Stale pre-composite cache (bare repo object): fall through and
            # refetch, overwriting the file with the current composite schema.

        error = None
        try:
            raw_text, raw_obj = fetch_fn(full)
            common.atomic_write_text(raw_file, raw_text)
            rec = parse_repo_metadata(raw_obj, full, reference_date)
        except Exception as exc:  # transient/hard gh failure — recorded, never zeroed
            rec = {"repository_full_name": full, "fetch_status": "ERROR"}
            error = f"{type(exc).__name__}: {exc}"

        rec["_source"] = "FETCHED"
        records.append(rec)
        common.append_jsonl(log_path, {
            "ts": common.iso_now(),
            "repository_full_name": full,
            "fetch_status": rec.get("fetch_status"),
            "error": error,
            "file": raw_file.name,
        })

    return records


# --------------------------------------------------------------------------- #
# Real gh-backed fetch function (paced + retried)
# --------------------------------------------------------------------------- #
_last_call_ts = 0.0


def _pace() -> None:
    global _last_call_ts
    now = time.monotonic()
    wait = REST_RATE_MIN_INTERVAL_S - (now - _last_call_ts)
    if wait > 0:
        time.sleep(wait)
    _last_call_ts = time.monotonic()


def find_gh() -> Optional[str]:
    gh = shutil.which("gh")
    if gh:
        return gh
    win_default = Path(r"C:\Program Files\GitHub CLI\gh.exe")
    return str(win_default) if win_default.exists() else None


def gh_is_authenticated(gh_path: str) -> bool:
    try:
        proc = subprocess.run(
            [gh_path, "auth", "status"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30, check=False,
        )
        return proc.returncode == 0 and "Logged in to" in (proc.stdout + proc.stderr)
    except Exception:
        return False


def make_gh_metadata_fn(gh_path: str) -> FetchFn:
    """
    Build a real fetch function bound to gh. A 404 is a legitimate terminal
    state (repo deleted/renamed/privatized) and is returned, not raised; only
    transient/rate-limit failures raise (and are retried with backoff).
    """
    try:
        from tenacity import (retry, stop_after_attempt, wait_exponential,
                              retry_if_exception_type)
        retry_deco = retry(
            reraise=True,
            stop=stop_after_attempt(5),
            wait=wait_exponential(multiplier=2, min=2, max=60),
            retry=retry_if_exception_type(RuntimeError),
        )
    except Exception:  # pragma: no cover - tenacity available at runtime
        def retry_deco(fn):
            return fn

    def _api(args: list[str]) -> subprocess.CompletedProcess:
        _pace()
        return subprocess.run([gh_path, *args], capture_output=True, text=True, encoding="utf-8", errors="replace",
                              timeout=60, check=False)

    @retry_deco
    def _call(full_name: str) -> tuple[str, Optional[dict]]:
        proc = _api(build_repo_api_args(full_name))
        if proc.returncode != 0:
            stderr = (proc.stderr or "").lower()
            if "not found" in stderr or "404" in stderr:
                body = proc.stdout if proc.stdout.strip() else '{"message": "Not Found"}'
                return body, _as_obj(body) or {"message": "Not Found"}
            if any(k in stderr for k in ("rate limit", "403", "429", "secondary", "timeout")):
                raise RuntimeError(f"transient gh failure: {proc.stderr.strip()[:200]}")
            raise RuntimeError(f"gh api failed ({proc.returncode}): {proc.stderr.strip()[:200]}")

        repo_obj = _as_obj(proc.stdout)
        # Language byte-distribution (best-effort; a failure leaves it empty and
        # does not sink the whole record — the core repo object already succeeded).
        lproc = _api(build_languages_api_args(full_name))
        languages = _as_obj(lproc.stdout) if lproc.returncode == 0 else {}
        # Default-branch HEAD sha (best-effort). The commits endpoint returns a
        # JSON ARRAY, so parse directly rather than via _as_obj (dict-only).
        head = None
        branch = (repo_obj or {}).get("default_branch")
        if branch:
            hproc = _api(build_head_commit_api_args(full_name, branch))
            if hproc.returncode == 0:
                try:
                    head = json.loads(hproc.stdout) if hproc.stdout.strip() else None
                except Exception:
                    head = None
        composite = {"repo": repo_obj, "languages": languages or {}, "head": head}
        return json.dumps(composite), composite

    return _call


# =========================================================================== #
# main
# =========================================================================== #
def _default_reference_date() -> date:
    return datetime.now(timezone.utc).date()


def _summarize(records: list[dict]) -> dict:
    from collections import Counter
    return dict(Counter(r.get("fetch_status") for r in records))


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Fetch GitHub repository metadata (Phase 4).")
    parser.add_argument("--control", action="store_true",
                        help="enrich the control cohort instead of the treated cohort")
    parser.add_argument("--reference-date", default=None,
                        help="YYYY-MM-DD anchor for age/last-push derivations (default: today UTC)")
    args = parser.parse_args(argv)

    cfg = common.load_study_config()
    reference_date = (
        date.fromisoformat(args.reference_date) if args.reference_date
        else _default_reference_date()
    )

    interim = STUDY_ROOT / cfg["paths"]["interim"]
    if args.control:
        candidates_path = interim / "control" / "control-candidate-repositories.json"
        raw_dir = STUDY_ROOT / cfg["paths"]["raw_search_control"] / "repo-metadata"
        out_json = interim / "control" / "repository-metadata.json"
        out_csv = interim / "control" / "repository-metadata.csv"
        log_path = STUDY_ROOT / cfg["paths"]["logs"] / "fetch_repository_metadata_control.jsonl"
        candidate_key = "repo_full_name"
    else:
        candidates_path = interim / "claude-candidate-repositories.json"
        raw_dir = STUDY_ROOT / cfg["paths"]["raw_search"] / "repo-metadata"
        out_json = interim / "repository-metadata.json"
        out_csv = interim / "repository-metadata.csv"
        log_path = STUDY_ROOT / cfg["paths"]["logs"] / "fetch_repository_metadata.jsonl"
        candidate_key = "repository_full_name"

    if not candidates_path.exists():
        print(f"ERROR: candidate table not found: {candidates_path}", file=sys.stderr)
        print("       Run 'make collect' then 'make merge' first.", file=sys.stderr)
        return 2

    raw_candidates = load_candidates(candidates_path)
    # Normalize the join key so both cohorts feed the same orchestrator.
    candidates = [
        {"repository_full_name": c.get(candidate_key) or c.get("repository_full_name")}
        for c in raw_candidates
    ]
    candidates = [c for c in candidates if c["repository_full_name"]]

    gh = find_gh()
    if gh is None:
        print("ERROR: gh (GitHub CLI) not found. Install it and re-run.", file=sys.stderr)
        return 2
    if not gh_is_authenticated(gh):
        print("ERROR: GitHub CLI is not authenticated. Run: gh auth login", file=sys.stderr)
        return 3

    fetch_fn = make_gh_metadata_fn(gh)
    records = fetch_repository_metadata(candidates, raw_dir, log_path, fetch_fn, reference_date)
    # Strip the internal _source marker before persisting.
    for r in records:
        r.pop("_source", None)
    write_metadata(records, out_json, out_csv)

    summary = _summarize(records)
    print(f"Metadata fetched for {len(records)} repositories "
          f"(reference_date={reference_date.isoformat()}) -> {out_csv}")
    print(f"  status breakdown: {summary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
