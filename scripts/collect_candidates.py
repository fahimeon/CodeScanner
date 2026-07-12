#!/usr/bin/env python3
"""
collect_candidates.py — Phase 2 candidate discovery.

Searches public GitHub commit history for Claude Code attribution signals
(treated cohort) or discovers non-attributed JS/TS web-app repositories
(control cohort, --control), using authenticated GitHub CLI.

Design:
  * ALL pure logic (date slicing, query building, output parsing, signal
    detection) is separated from the gh-calling orchestration and is unit-tested
    offline with synthetic data (tests/test_collect_candidates.py).
  * The orchestrator accepts an injectable `search_fn`, so the adaptive-slicing
    and file-saving behaviour can be tested WITHOUT invoking gh or the network.
  * Raw gh output is saved verbatim and immutably (never overwritten); reruns
    resume by skipping slices whose valid output file already exists.
  * Requests are paced to the search rate limit (~30/min) with exponential
    backoff on 403/429/secondary-rate-limit responses.

This module makes NO network calls at import time. `main()` requires an
authenticated `gh`; without it, real collection is refused with a clear message.

Usage:
  python scripts/collect_candidates.py            # treated (commit search)
  python scripts/collect_candidates.py --control  # control (repo search)
  python scripts/collect_candidates.py --dry-run  # plan slices, no gh calls
"""

from __future__ import annotations

import argparse
import calendar
import re
import shutil
import subprocess
import sys
import time
from datetime import date, timedelta
from pathlib import Path
from typing import Callable, Optional

# Support import both as a module (tests) and as a script.
try:
    from . import _common as common  # type: ignore
except Exception:  # pragma: no cover
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _common as common  # type: ignore

STUDY_ROOT = common.STUDY_ROOT

# --------------------------------------------------------------------------- #
# Attribution signals: stable label -> (gh query string, message substring)
# --------------------------------------------------------------------------- #
SIGNAL_QUERIES = {
    "anthropic_email": '"noreply@anthropic.com"',
    "generated_claude_code": '"Generated with Claude Code"',
    "claude_session": '"Claude-Session:"',
}
SIGNAL_SUBSTRINGS = {
    "anthropic_email": "noreply@anthropic.com",
    "generated_claude_code": "Generated with Claude Code",
    "claude_session": "Claude-Session:",
}
SIGNAL_CONFIDENCE = {
    "anthropic_email": "high",
    "generated_claude_code": "high",
    "claude_session": "supporting",
}

SEARCH_RATE_MIN_INTERVAL_S = 2.1        # ~28/min, under the ~30/min search limit
GH_COMMIT_JSON_FIELDS = "sha,repository,commit,parents,author,committer,url"
GH_REPO_JSON_FIELDS = (
    "fullName,url,createdAt,pushedAt,primaryLanguage,isFork,isArchived,"
    "stargazersCount,description,license"
)


# =========================================================================== #
# PURE FUNCTIONS (unit-tested; no I/O, no network)
# =========================================================================== #
def iso(d: date) -> str:
    return d.isoformat()


def parse_iso_date(s: str) -> date:
    return date.fromisoformat(s)


def month_windows(start: date, end: date) -> list[tuple[date, date]]:
    """
    Calendar-month windows covering [start, end] inclusive. The first window
    begins at `start` (which may be mid-month, e.g. 2025-02-24) and the last
    ends at `end` (which may be mid-month, e.g. 2026-06-30).
    """
    if start > end:
        return []
    windows: list[tuple[date, date]] = []
    cur = start
    while cur <= end:
        last_dom = calendar.monthrange(cur.year, cur.month)[1]
        month_end = date(cur.year, cur.month, last_dom)
        win_end = min(month_end, end)
        windows.append((cur, win_end))
        # advance to first day of next month
        if cur.month == 12:
            cur = date(cur.year + 1, 1, 1)
        else:
            cur = date(cur.year, cur.month + 1, 1)
    return windows


def split_window(win: tuple[date, date]) -> list[tuple[date, date]]:
    """
    Split a (start, end) window into two contiguous halves with no gap/overlap.
    A single-day window cannot be split and is returned unchanged (the caller
    must not recurse on it — see _collect_window's saturation guard).
    """
    start, end = win
    if start >= end:
        return [win]
    span_days = (end - start).days
    mid = start + timedelta(days=span_days // 2)
    if mid >= end:            # ensure strict progress for 2-day windows
        mid = start
    return [(start, mid), (mid + timedelta(days=1), end)]


def build_commit_search_args(query: str, start: date, end: date, limit: int) -> list[str]:
    """argv (excluding the gh executable) for a commit search over a date slice."""
    return [
        "search", "commits", query,
        "--author-date", f"{iso(start)}..{iso(end)}",
        "--limit", str(limit),
        "--json", GH_COMMIT_JSON_FIELDS,
    ]


def build_repo_search_args(language: str, start: date, end: date, limit: int,
                           stars: Optional[str] = None) -> list[str]:
    """
    argv for a control-cohort repository search: non-fork, non-archived, pushed
    within the slice, in the given language, optionally restricted to a STAR
    bucket (e.g. "5..24", ">=2500"). Star bucketing partitions each slice to
    avoid the 1000-result cap + popularity skew. Attribution filtering happens
    later (Phase 6) against git history.
    """
    qualifiers = f"fork:false archived:false pushed:{iso(start)}..{iso(end)}"
    if stars:
        qualifiers += f" stars:{stars}"
    return [
        "search", "repos", qualifiers,
        "--language", language,
        "--limit", str(limit),
        "--visibility", "public",
        "--json", GH_REPO_JSON_FIELDS,
    ]


def star_bucket_slug(bucket: Optional[str]) -> str:
    """Filename-safe slug for a star bucket ('>=2500' -> 'gte2500', '5..24' -> '5-24')."""
    if not bucket:
        return "any"
    return (bucket.replace("..", "-").replace(">=", "gte").replace("<=", "lte")
            .replace(">", "gt").replace("<", "lt"))


def _repo_full_name(repo: dict) -> Optional[str]:
    if not isinstance(repo, dict):
        return None
    full = repo.get("fullName") or repo.get("full_name")
    if full:
        return full
    owner = (repo.get("owner") or {}).get("login")
    name = repo.get("name")
    if owner and name:
        return f"{owner}/{name}"
    return None


def parse_commit_search_output(text: str) -> list[dict]:
    """
    Parse gh `search commits --json ...` output into normalized commit records.
    Defensive against field-name variants and missing fields. Records without a
    sha or resolvable repository are skipped.
    """
    import json
    try:
        raw = json.loads(text) if text.strip() else []
    except Exception:
        return []
    out: list[dict] = []
    for rec in raw if isinstance(raw, list) else []:
        sha = rec.get("sha") or rec.get("oid")
        repo = rec.get("repository") or {}
        full = _repo_full_name(repo)
        if not sha or not full:
            continue
        repo_url = repo.get("url") or f"https://github.com/{full}"
        commit = rec.get("commit") or {}
        message = commit.get("message") or ""
        cdate = (
            (commit.get("author") or {}).get("date")
            or (commit.get("committer") or {}).get("date")
            or (rec.get("author") or {}).get("date")
            or (rec.get("committer") or {}).get("date")
        )
        curl = rec.get("url") or f"{repo_url}/commit/{sha}"
        out.append({
            "sha": sha,
            "repo_full_name": full,
            "repo_url": repo_url,
            "commit_message": message,
            "commit_date": cdate,
            "commit_url": curl,
        })
    return out


def parse_repo_search_output(text: str) -> list[dict]:
    """Parse gh `search repos --json ...` output into normalized repo records."""
    import json
    try:
        raw = json.loads(text) if text.strip() else []
    except Exception:
        return []
    out: list[dict] = []
    for rec in raw if isinstance(raw, list) else []:
        full = _repo_full_name(rec)
        if not full:
            continue
        lang = rec.get("primaryLanguage")
        lang_name = lang.get("name") if isinstance(lang, dict) else lang
        lic = rec.get("license")
        lic_key = lic.get("key") if isinstance(lic, dict) else lic
        out.append({
            "repo_full_name": full,
            "repo_url": rec.get("url") or f"https://github.com/{full}",
            "created_at": rec.get("createdAt"),
            "pushed_at": rec.get("pushedAt"),
            "primary_language": lang_name,
            "is_fork": bool(rec.get("isFork")),
            "is_archived": bool(rec.get("isArchived")),
            "stars": rec.get("stargazersCount"),
            "description": rec.get("description"),
            "license": lic_key,
        })
    return out


def detect_signals(message: Optional[str]) -> list[str]:
    """Return the sorted attribution-signal labels present in a commit message."""
    msg = message or ""
    return sorted(
        label for label, sub in SIGNAL_SUBSTRINGS.items() if sub in msg
    )


def slice_filename(label: str, start: date, end: date) -> str:
    return f"{label}-{iso(start)}_{iso(end)}.json"


PROBE_SIGNAL = "anthropic_email"


def probe_plan(windows: list[tuple[date, date]]) -> tuple[str, str, tuple[date, date]]:
    """
    Pick a single, small slice for the pre-flight probe: the strongest signal
    over the first (short, mid-February) monthly window. One API call, used to
    confirm the live gh JSON shape and query behaviour before the full sweep.
    """
    if not windows:
        raise ValueError("no windows to probe")
    return PROBE_SIGNAL, SIGNAL_QUERIES[PROBE_SIGNAL], windows[0]


# =========================================================================== #
# ORCHESTRATION (I/O; gh injected as search_fn for testability)
# =========================================================================== #
# search_fn signature: (query_or_language, start, end) -> (raw_text, records)
# The real gh-backed fn also returns a 3rd element (audit meta dict); the
# orchestrator accepts either arity so injected fakes may return a 2-tuple.
SearchFn = Callable[[str, date, date], tuple]


def _collect_window(
    label: str,
    query: str,
    win: tuple[date, date],
    out_dir: Path,
    log_path: Path,
    search_fn: SearchFn,
    threshold: int,
    subslice: bool,
    tree_node: dict,
) -> None:
    """
    Fetch one slice, save raw output immutably, log the request, and — if the
    slice saturated the result cap and is not a single day — recurse into finer
    sub-slices to recover truncated results (deduplicated later in merge).
    """
    start, end = win
    out_file = out_dir / slice_filename(label, start, end)
    tree_node.update({
        "label": label, "start": iso(start), "end": iso(end),
        "file": out_file.name, "children": [],
    })

    # Resumption: skip slices already fetched and valid.
    if common.is_valid_json_file(out_file):
        cached = common.read_json(out_file)
        count = len(cached) if isinstance(cached, list) else 0
        tree_node["count"] = count
        tree_node["status"] = "CACHED"
    else:
        meta: dict = {}
        try:
            result = search_fn(query, start, end)
            # search_fn may return (raw, records) or (raw, records, meta).
            raw_text, records = result[0], result[1]
            if len(result) > 2 and isinstance(result[2], dict):
                meta = result[2]
            common.atomic_write_text(out_file, raw_text)
            count = len(records)
            status = "OK"
            error = None
        except Exception as exc:  # network/gh failure recorded, never silently zeroed
            count = 0
            status = "ERROR"
            error = f"{type(exc).__name__}: {exc}"
            meta = getattr(exc, "meta", {}) or {}
        tree_node["count"] = count
        tree_node["status"] = status
        common.append_jsonl(log_path, {
            "ts": common.iso_now(), "label": label, "query": query,
            "start": iso(start), "end": iso(end), "count": count,
            "status": status, "error": error, "file": out_file.name,
            # Audit fields for rate-limit / failed-request reconstruction.
            "attempts": meta.get("attempts"),
            "exit_code": meta.get("exit_code"),
            "http_status": meta.get("http_status"),
            "retry_after": meta.get("retry_after"),
        })
        if status == "ERROR":
            return

    saturated = tree_node["count"] >= threshold
    can_recurse = subslice and saturated and start != end
    if can_recurse:
        for sub in split_window(win):
            child: dict = {}
            tree_node["children"].append(child)
            _collect_window(label, query, sub, out_dir, log_path,
                            search_fn, threshold, subslice, child)
    elif saturated:
        # Saturated but NOT further divisible (single day, or subslicing off):
        # the plan's "every leaf below threshold" guarantee is violated here, so
        # this slice is likely truncated/biased. Flag it loudly for merge/screening.
        tree_node["status"] = "SATURATED_LEAF"
        tree_node["saturated_leaf"] = True
        common.append_jsonl(log_path, {
            "ts": common.iso_now(), "label": label, "query": query,
            "start": iso(start), "end": iso(end), "count": tree_node["count"],
            "status": "SATURATED_LEAF", "error": None, "file": out_file.name,
        })


def count_saturated_leaves(tree) -> int:
    """Count SATURATED_LEAF nodes anywhere in a slice tree (node dict, list of
    nodes, or the full {label: [nodes]} mapping)."""
    total = 0
    if isinstance(tree, dict):
        if tree.get("saturated_leaf") or tree.get("status") == "SATURATED_LEAF":
            total += 1
        for key, value in tree.items():
            if isinstance(value, (list, dict)):
                total += count_saturated_leaves(value)
    elif isinstance(tree, list):
        for item in tree:
            total += count_saturated_leaves(item)
    return total


def collect_signal(
    label: str,
    query: str,
    windows: list[tuple[date, date]],
    out_dir: Path,
    log_path: Path,
    search_fn: SearchFn,
    threshold: int,
    subslice: bool = True,
) -> list[dict]:
    """Collect all monthly windows for one signal; return the slice tree."""
    common.ensure_dir(out_dir)
    tree: list[dict] = []
    for win in windows:
        node: dict = {}
        tree.append(node)
        _collect_window(label, query, win, out_dir, log_path,
                        search_fn, threshold, subslice, node)
    return tree


# --------------------------------------------------------------------------- #
# Real gh-backed search function (paced + retried)
# --------------------------------------------------------------------------- #
_last_call_ts = 0.0


def _pace() -> None:
    global _last_call_ts
    now = time.monotonic()
    wait = SEARCH_RATE_MIN_INTERVAL_S - (now - _last_call_ts)
    if wait > 0:
        time.sleep(wait)
    _last_call_ts = time.monotonic()


def find_gh() -> Optional[str]:
    """Locate the gh executable on PATH or at the default Windows install path."""
    gh = shutil.which("gh")
    if gh:
        return gh
    win_default = Path(r"C:\Program Files\GitHub CLI\gh.exe")
    return str(win_default) if win_default.exists() else None


def gh_is_authenticated(gh_path: str) -> bool:
    """True if `gh auth status` succeeds. Never captures or stores tokens."""
    try:
        proc = subprocess.run(
            [gh_path, "auth", "status"],
            capture_output=True, text=True, timeout=30, check=False,
        )
        return proc.returncode == 0 and "Logged in to" in (proc.stdout + proc.stderr)
    except Exception:
        return False


class GhSearchError(RuntimeError):
    """A gh search failure carrying audit metadata (exit code, HTTP status,
    Retry-After) and whether it is transient (retryable)."""

    def __init__(self, message: str, *, transient: bool = False, meta: Optional[dict] = None):
        super().__init__(message)
        self.transient = transient
        self.meta = meta or {}


def parse_retry_after(text: Optional[str]) -> Optional[int]:
    """Best-effort Retry-After (seconds) from gh stderr / GitHub rate-limit text."""
    if not text:
        return None
    m = re.search(r"retry[- ]after[:\s]+(\d+)", text, re.IGNORECASE)
    if m:
        return int(m.group(1))
    m = re.search(r"wait\s+(?:for\s+)?(\d+)\s+seconds", text, re.IGNORECASE)  # secondary-limit msg
    return int(m.group(1)) if m else None


def parse_http_status(text: Optional[str]) -> Optional[int]:
    """Best-effort HTTP status code from gh stderr (e.g. 'HTTP 403')."""
    if not text:
        return None
    m = re.search(r"HTTP\s+(\d{3})", text)
    return int(m.group(1)) if m else None


def make_gh_search_fn(gh_path: str, kind: str, limit: int, language: str = "",
                      stars: Optional[str] = None) -> SearchFn:
    """
    Build a real search function bound to gh. `kind` in {"commits","repos"}.
    For repo search, an optional `stars` bucket restricts the query.

    Returns (raw_text, records, meta) on success and raises GhSearchError (with
    .meta) on terminal failure, so the orchestrator can log retry count, exit
    code, HTTP status and Retry-After for every request. Only TRANSIENT failures
    (rate-limit / timeout) are retried with exponential backoff.
    """
    try:
        from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception
        retry_deco = retry(
            reraise=True,
            stop=stop_after_attempt(5),
            wait=wait_exponential(multiplier=2, min=2, max=60),
            retry=retry_if_exception(lambda exc: getattr(exc, "transient", False)),
        )
    except Exception:  # pragma: no cover - tenacity always available at runtime
        def retry_deco(fn):
            return fn

    @retry_deco
    def _attempt(query_or_lang: str, start: date, end: date) -> tuple[str, list[dict]]:
        _pace()
        if kind == "commits":
            args = build_commit_search_args(query_or_lang, start, end, limit)
            parser = parse_commit_search_output
        else:
            args = build_repo_search_args(language, start, end, limit, stars)
            parser = parse_repo_search_output
        proc = subprocess.run(
            [gh_path, *args], capture_output=True, text=True,
            timeout=180, check=False,
        )
        if proc.returncode != 0:
            stderr = proc.stderr or ""
            low = stderr.lower()
            transient = any(k in low for k in ("rate limit", "403", "429", "secondary", "timeout"))
            raise GhSearchError(
                f"{'transient ' if transient else ''}gh failure "
                f"({proc.returncode}): {stderr.strip()[:200]}",
                transient=transient,
                meta={"exit_code": proc.returncode,
                      "http_status": parse_http_status(stderr),
                      "retry_after": parse_retry_after(stderr)},
            )
        return proc.stdout, parser(proc.stdout)

    def _attempts() -> int:
        return getattr(_attempt, "statistics", {}).get("attempt_number", 1)

    def _call(query_or_lang: str, start: date, end: date) -> tuple[str, list[dict], dict]:
        try:
            raw, records = _attempt(query_or_lang, start, end)
        except GhSearchError as exc:
            exc.meta = {**(exc.meta or {}), "attempts": _attempts(), "status": "ERROR"}
            raise
        return raw, records, {
            "attempts": _attempts(), "exit_code": 0,
            "http_status": 200, "retry_after": None, "status": "OK",
        }

    return _call


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
def _plan_windows(cfg: dict) -> list[tuple[date, date]]:
    sw = cfg["search_window"]
    return month_windows(parse_iso_date(sw["start_date"]), parse_iso_date(sw["end_date"]))


def _report_probe(label: str, win: tuple[date, date], records: list[dict], path: Path) -> None:
    """Human-readable pre-flight report validating the live gh JSON shape."""
    print(f"PROBE {label} {iso(win[0])}..{iso(win[1])}: {len(records)} records")
    print(f"  saved raw -> {path}")
    if not records:
        print("  NOTE: 0 records. Verify query quoting, auth, or that the slice has commits.")
        return
    for field in ("sha", "repo_full_name", "repo_url", "commit_message", "commit_date", "commit_url"):
        present = sum(1 for r in records if r.get(field))
        flag = "OK" if present == len(records) else "!!"
        print(f"  [{flag}] field {field:<16}: {present}/{len(records)} populated")
    from collections import Counter
    sig = Counter()
    for r in records:
        for s in detect_signals(r.get("commit_message")):
            sig[s] += 1
    print("  detected signals   :", dict(sig))
    sample = sorted({r["repo_full_name"] for r in records})[:5]
    print("  sample repositories:", ", ".join(sample))


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Discover Claude-attributed (or control) candidates.")
    parser.add_argument("--control", action="store_true",
                        help="discover non-attributed JS/TS web-app repos (control cohort)")
    parser.add_argument("--dry-run", action="store_true",
                        help="print the planned slice windows and exit (no gh calls)")
    parser.add_argument("--probe", action="store_true",
                        help="run a single small slice to validate the live gh JSON shape (1 API call)")
    parser.add_argument("--limit", type=int, default=1000)
    args = parser.parse_args(argv)

    cfg = common.load_study_config()
    windows = _plan_windows(cfg)
    threshold = int(cfg["search_window"].get("saturation_threshold", 950))
    subslice = bool(cfg["search_window"].get("adaptive_subslicing", True))

    if args.dry_run:
        print(f"Planned monthly windows: {len(windows)}")
        for s, e in windows:
            print(f"  {iso(s)} .. {iso(e)}")
        print(f"saturation_threshold={threshold} adaptive_subslicing={subslice}")
        return 0

    gh = find_gh()
    if gh is None:
        print("ERROR: gh (GitHub CLI) not found. Install it and re-run.", file=sys.stderr)
        return 2
    if not gh_is_authenticated(gh):
        print("ERROR: GitHub CLI is not authenticated.", file=sys.stderr)
        print("       Run:  gh auth login    (this is an interactive step)", file=sys.stderr)
        return 3

    if args.probe:
        label, query, win = probe_plan(windows)
        fn = make_gh_search_fn(gh, "commits", args.limit)
        raw, records = fn(query, win[0], win[1])[:2]
        probe_path = (STUDY_ROOT / cfg["paths"]["interim"] / "probe"
                      / slice_filename(f"probe_{label}", win[0], win[1]))
        common.atomic_write_text(probe_path, raw)
        _report_probe(label, win, records, probe_path)
        return 0

    if args.control:
        out_dir = STUDY_ROOT / cfg["paths"]["raw_search_control"]
        log_path = STUDY_ROOT / cfg["paths"]["logs"] / "collect_candidates_control.jsonl"
        tree_out = STUDY_ROOT / cfg["paths"]["interim"] / "control" / "search-slice-tree.json"
        cd = cfg.get("control_discovery", {})
        languages = cd.get("languages", ["TypeScript", "JavaScript"])
        # A missing/empty star_buckets falls back to a single unbucketed pass.
        star_buckets = cd.get("star_buckets") or [None]
        full_tree = {}
        for lang in languages:
            for bucket in star_buckets:
                fn = make_gh_search_fn(gh, "repos", args.limit, language=lang, stars=bucket)
                label = f"control_{lang.lower()}_stars_{star_bucket_slug(bucket)}"
                full_tree[label] = collect_signal(
                    label, lang, windows, out_dir, log_path,
                    fn, threshold, subslice,
                )
        common.atomic_write_json(tree_out, full_tree)
        print(f"Control discovery complete: {len(languages)} languages x "
              f"{len(star_buckets)} star buckets. Slice tree -> {tree_out}")
        _warn_saturated_leaves(full_tree, threshold)
        return 0

    out_dir = STUDY_ROOT / cfg["paths"]["raw_search"]
    log_path = STUDY_ROOT / cfg["paths"]["logs"] / "collect_candidates.jsonl"
    tree_out = STUDY_ROOT / cfg["paths"]["interim"] / "search-slice-tree.json"
    full_tree = {}
    for label, query in SIGNAL_QUERIES.items():
        fn = make_gh_search_fn(gh, "commits", args.limit)
        full_tree[label] = collect_signal(
            label, query, windows, out_dir, log_path, fn, threshold, subslice,
        )
    common.atomic_write_json(tree_out, full_tree)
    print(f"Treated discovery complete. Slice tree -> {tree_out}")
    _warn_saturated_leaves(full_tree, threshold)
    return 0


def _warn_saturated_leaves(tree, threshold: int) -> None:
    n = count_saturated_leaves(tree)
    if n:
        print(f"WARNING: {n} single-day slice(s) remain SATURATED (>= {threshold} results) "
              f"and could not be subdivided further; those days are likely TRUNCATED and "
              f"the candidate pool may be biased. See the slice tree / log (status=SATURATED_LEAF).")


if __name__ == "__main__":
    raise SystemExit(main())
