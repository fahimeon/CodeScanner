#!/usr/bin/env python3
"""
verify_claude_attribution.py — Phase 6 attribution verification.

For each candidate repository, read its git HISTORY (never its working code) and
decide whether it meets the study's *substantial* Claude Code-attribution bar
(inclusion-rules.yaml `substantial_attribution_rules` A-D), computing the exact
attributed-commit counts that the capped/​indexed Phase-2 search only lower-bounds.

Reachability is inherent: history is enumerated from the default-branch HEAD
(`git log HEAD --no-merges`), so every attributed commit found is, by
construction, an ancestor of HEAD — the reachability requirement is satisfied
without a separate `merge-base` call, and side-branch/​rebased-away commits are
correctly excluded.

SAFETY (see scanner-config.yaml `clone`): the repo is cloned with `--no-checkout`
so NO working-tree files are ever materialized (nothing to execute or build),
with hooks/symlinks/ext-protocol/LFS smudge disabled and terminal prompts off.
Only `git clone` + `git log` run. No repository code is executed.

Design mirrors the earlier phases:
  * ALL pure logic (path exclusion, source-file test, git-output parsing, rule
    evaluation) is separated from the git-calling orchestration and unit-tested
    offline with synthetic `git log` output (tests/test_verify_claude_attribution.py).
  * The orchestrator takes an injectable `history_fn`, so resumption / logging /
    error handling are tested WITHOUT git or the network.
  * Raw `git log` output is saved verbatim + immutably (per repo); reruns resume
    by re-parsing the cached raw output instead of re-cloning.

Outputs:
  data/raw/git-history/{owner__repo}.meta.txt      (immutable raw)
  data/raw/git-history/{owner__repo}.numstat.txt   (immutable raw)
  data/interim/attribution/{owner__repo}.json      (per-repo analysis, recomputable)
  data/interim/attribution-verification.{json,csv} (aggregate)
"""

from __future__ import annotations

import argparse
import csv
import os
import shutil
import subprocess
import sys
from fnmatch import fnmatch
from pathlib import Path
from typing import Callable, Optional

try:
    from . import _common as common  # type: ignore
    from . import collect_candidates as collect  # type: ignore
except Exception:  # pragma: no cover
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _common as common  # type: ignore
    import collect_candidates as collect  # type: ignore

STUDY_ROOT = common.STUDY_ROOT

# Field / record separators used in the git --format strings (chosen because
# they never occur in commit messages or paths).
FIELD_SEP = "\x1f"
REC_SEP = "\x1e"

# Extensions counted as "application source" for the substantiveness proxy.
# This is deliberately a code/template/style allowlist: data/config (json/yaml),
# docs (md) and lockfiles are NOT counted here (exact relevant-LOC is Phase 8's
# job via tokei). Kept conservative and documented so counts are reproducible.
SOURCE_EXTENSIONS = {
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".cts", ".mts",
    ".vue", ".svelte", ".astro",
    ".css", ".scss", ".sass", ".less", ".styl",
    ".html", ".htm", ".ejs", ".hbs", ".pug", ".handlebars",
    ".graphql", ".gql", ".prisma", ".sql",
}

ATTRIBUTION_FIELDS = [
    "repository_full_name",
    "status",                        # OK | UNAVAILABLE | CLONE_ERROR | NO_COMMITS
    "qualifies",
    "qualifying_rules",
    "total_commits",                 # incl. merges
    "merge_commits",
    "total_non_merge_commits",
    "attributed_non_merge_commits",
    "substantive_attributed_commits",
    "attributed_commit_share",
    "attributed_source_lines_added",
    "attributed_source_lines_deleted",
    "attributed_source_lines",       # added + deleted (kept for continuity)
    "total_source_lines",
    "attributed_files_changed",      # distinct source files across attributed commits
    "first_attributed_commit_date",
    "last_attributed_commit_date",
    "initial_implementation_attributed",
    "any_attribution_signal_found",  # ANY signal incl. supporting (control exclusion)
    "reachable_qualifying_commit",
]


# =========================================================================== #
# PURE FUNCTIONS — path exclusion / source detection
# =========================================================================== #
class ExcludeMatcher:
    """Compiled excluded-paths.txt: directory subtrees, globs, and plain files."""

    def __init__(self, dir_patterns, glob_patterns, file_patterns):
        self.dir_patterns = list(dir_patterns)
        self.glob_patterns = list(glob_patterns)
        self.file_patterns = list(file_patterns)


def parse_excluded_paths(text: str) -> ExcludeMatcher:
    dirs, globs, files = [], [], []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.endswith("/"):
            dirs.append(line.rstrip("/"))
        elif "*" in line or "?" in line:
            globs.append(line)
        else:
            files.append(line)
    return ExcludeMatcher(dirs, globs, files)


def load_exclude_matcher() -> ExcludeMatcher:
    text = (common.CONFIG_DIR / "excluded-paths.txt").read_text(encoding="utf-8")
    return parse_excluded_paths(text)


def is_excluded_path(path: str, m: ExcludeMatcher) -> bool:
    p = path.replace("\\", "/").lstrip("./")
    anchored = "/" + p
    for d in m.dir_patterns:
        if p == d or p.startswith(d + "/") or (("/" + d + "/") in anchored):
            return True
    base = p.rsplit("/", 1)[-1]
    for f in m.file_patterns:
        if base == f or p == f:
            return True
    for g in m.glob_patterns:
        if fnmatch(base, g) or fnmatch(p, g):
            return True
    return False


def is_source_file(path: str, m: ExcludeMatcher) -> bool:
    if is_excluded_path(path, m):
        return False
    base = path.replace("\\", "/").rsplit("/", 1)[-1]
    return os.path.splitext(base)[1].lower() in SOURCE_EXTENSIONS


# =========================================================================== #
# PURE FUNCTIONS — attribution signal on a commit
# =========================================================================== #
def commit_is_attributed(message: Optional[str]) -> bool:
    """True iff a HIGH-confidence signal (email trailer or the fixed phrase) is
    present. `Claude-Session:` is supporting-only and never sufficient alone."""
    return any(
        collect.SIGNAL_CONFIDENCE.get(s) == "high"
        for s in collect.detect_signals(message)
    )


def commit_has_any_signal(message: Optional[str]) -> bool:
    """True if ANY attribution signal is present, including supporting-only
    (`Claude-Session:`). Used for STRICT control-cohort exclusion: a control repo
    must have zero attribution signals, not merely fail the substantiality rules."""
    return bool(collect.detect_signals(message))


# =========================================================================== #
# PURE FUNCTIONS — git output parsing
# =========================================================================== #
def build_clone_args(url: str, dest: str, hooks_dir: str,
                     branch: Optional[str] = None) -> list[str]:
    """
    Safe, history-only clone: full blobs (needed for numstat) but NO working-tree
    checkout, with the hardening switches from scanner-config.yaml `git_safety`.
    """
    args = [
        "-c", "protocol.ext.allowed=never",
        "-c", "core.symlinks=false",
        "-c", f"core.hooksPath={hooks_dir}",
        "clone", "--no-checkout", "--no-tags", "--single-branch",
    ]
    if branch:
        args += ["--branch", branch]
    args += [url, dest]
    return args


def build_log_meta_args() -> list[str]:
    # ALL commits (merges included) so total_commits is honest; merge commits are
    # flagged (>1 parent) and excluded from rule denominators in code.
    fmt = f"%H{FIELD_SEP}%aI{FIELD_SEP}%P{FIELD_SEP}%B{REC_SEP}"
    return ["log", "HEAD", f"--format={fmt}"]


def build_log_numstat_args() -> list[str]:
    # Merge commits emit no numstat lines by default -> they contribute 0 lines.
    return ["log", "HEAD", "--numstat", f"--format={REC_SEP}%H"]


def parse_log_meta(text: str) -> dict[str, dict]:
    """Parse the metadata log into {sha: {sha, date, parents, message}}."""
    out: dict[str, dict] = {}
    for rec in text.split(REC_SEP):
        rec = rec.strip("\n")
        if not rec.strip():
            continue
        parts = rec.split(FIELD_SEP)
        if len(parts) < 4:
            continue
        sha, cdate, parents, message = parts[0], parts[1], parts[2], parts[3]
        sha = sha.strip()
        if not sha:
            continue
        out[sha] = {
            "sha": sha,
            "date": cdate.strip() or None,
            "parents": parents.strip().split() if parents.strip() else [],
            "message": message,
        }
    return out


def _numstat_path(raw_path: str) -> str:
    """Resolve a numstat path, taking the destination side of any rename."""
    p = raw_path.strip()
    if "=>" in p:
        p = p.split("=>")[-1]
        p = p.replace("{", "").replace("}", "").strip()
    return p


def parse_log_numstat(text: str) -> dict[str, list[tuple]]:
    """Parse the numstat log into {sha: [(added, deleted, path), ...]}.

    Binary files (numstat '-') contribute (None, None, path) and are ignored by
    the line-counting caller.
    """
    out: dict[str, list[tuple]] = {}
    for chunk in text.split(REC_SEP):
        lines = [ln for ln in chunk.split("\n") if ln.strip()]
        if not lines:
            continue
        sha = lines[0].strip()
        files: list[tuple] = []
        for ln in lines[1:]:
            cols = ln.split("\t")
            if len(cols) < 3:
                continue
            add_s, del_s, path = cols[0], cols[1], "\t".join(cols[2:])
            added = None if add_s == "-" else _safe_int(add_s)
            deleted = None if del_s == "-" else _safe_int(del_s)
            files.append((added, deleted, _numstat_path(path)))
        out[sha] = files
    return out


def _safe_int(s: str) -> Optional[int]:
    try:
        return int(s)
    except ValueError:
        return None


def build_commit_records(meta: dict, numstat: dict, m: ExcludeMatcher,
                         min_substantive_lines: int) -> list[dict]:
    """Merge metadata + numstat into per-commit records with relevant-source
    line deltas and substantiveness/attribution flags. Order preserves the log
    (newest first)."""
    records: list[dict] = []
    for sha, md in meta.items():
        rel_add = rel_del = 0
        source_files: list[str] = []
        for added, deleted, path in numstat.get(sha, []):
            if added is None and deleted is None:
                continue  # binary
            if not is_source_file(path, m):
                continue
            rel_add += added or 0
            rel_del += deleted or 0
            source_files.append(path)
        rel_changed = rel_add + rel_del
        parents = md.get("parents") or []
        message = md.get("message")
        records.append({
            "sha": sha,
            "date": md.get("date"),
            "is_root": len(parents) == 0,
            "is_merge": len(parents) > 1,
            "attributed": commit_is_attributed(message),
            "any_signal": commit_has_any_signal(message),
            "relevant_added": rel_add,
            "relevant_deleted": rel_del,
            "relevant_changed": rel_changed,
            "source_files": source_files,
            "substantive": rel_changed >= min_substantive_lines,
        })
    return records


def _initial_impl_commit(records: list[dict]) -> Optional[dict]:
    """The repository's initial-implementation commit: prefer a root commit
    (no parents); otherwise the earliest by date. Used for rule D."""
    roots = [r for r in records if r.get("is_root")]
    pool = roots or records
    dated = [r for r in pool if r.get("date")]
    if dated:
        return min(dated, key=lambda r: r["date"])
    return pool[-1] if pool else None  # log is newest-first -> last is oldest


def apply_attribution_rules(records: list[dict], rules_cfg: dict) -> dict:
    """Evaluate substantial-attribution rules A-D. Merge commits are excluded
    from all rule denominators; `total_commits` still reports them."""
    total_commits = len(records)
    non_merge = [r for r in records if not r.get("is_merge")]
    total_non_merge = len(non_merge)
    attributed = [r for r in non_merge if r["attributed"]]
    substantive_attributed = [r for r in attributed if r["substantive"]]
    share = (len(attributed) / total_non_merge) if total_non_merge else 0.0

    a = rules_cfg.get("rule_A", {}).get("min_substantive_commits", 3)
    b = rules_cfg.get("rule_B", {}).get("min_relevant_lines_in_one_commit", 500)
    c_sub = rules_cfg.get("rule_C", {}).get("min_substantive_commits", 2)
    c_share = rules_cfg.get("rule_C", {}).get("min_attributed_share_of_non_merge", 0.10)
    d_lines = rules_cfg.get("rule_D", {}).get("initial_impl_min_relevant_lines", 500)

    initial = _initial_impl_commit(non_merge)
    initial_attributed = bool(initial and initial["attributed"])

    qualifying: list[str] = []
    if len(substantive_attributed) >= a:
        qualifying.append("A")
    if any(r["relevant_changed"] >= b for r in attributed):
        qualifying.append("B")
    if len(substantive_attributed) >= c_sub and share >= c_share:
        qualifying.append("C")
    if initial_attributed and initial["relevant_added"] >= d_lines:
        qualifying.append("D")

    attributed_added = sum(r["relevant_added"] for r in attributed)
    attributed_deleted = sum(r["relevant_deleted"] for r in attributed)
    attributed_files: set[str] = set()
    for r in attributed:
        attributed_files.update(r.get("source_files") or [])
    attr_dates = sorted(r["date"] for r in attributed if r.get("date"))
    total_source_lines = sum(r["relevant_changed"] for r in non_merge)
    qualifies = bool(qualifying)
    return {
        "qualifies": qualifies,
        "qualifying_rules": qualifying,
        "total_commits": total_commits,
        "merge_commits": total_commits - total_non_merge,
        "total_non_merge_commits": total_non_merge,
        "attributed_non_merge_commits": len(attributed),
        "substantive_attributed_commits": len(substantive_attributed),
        "attributed_commit_share": round(share, 4),
        "attributed_source_lines_added": attributed_added,
        "attributed_source_lines_deleted": attributed_deleted,
        "attributed_source_lines": attributed_added + attributed_deleted,
        "total_source_lines": total_source_lines,
        "attributed_files_changed": len(attributed_files),
        "first_attributed_commit_date": attr_dates[0] if attr_dates else None,
        "last_attributed_commit_date": attr_dates[-1] if attr_dates else None,
        "initial_implementation_attributed": initial_attributed,
        "any_attribution_signal_found": any(r.get("any_signal") for r in records),
        # HEAD-enumerated history => any attributed commit is reachable; a
        # qualifying repo therefore always has >=1 reachable qualifying commit.
        "reachable_qualifying_commit": qualifies and len(attributed) >= 1,
    }


def analyze_history(full_name: str, meta_text: str, numstat_text: str,
                    m: ExcludeMatcher, rules_cfg: dict,
                    min_substantive_lines: int) -> dict:
    """Full per-repo analysis: parse raw git output, build records, apply rules."""
    meta = parse_log_meta(meta_text)
    numstat = parse_log_numstat(numstat_text)
    records = build_commit_records(meta, numstat, m, min_substantive_lines)
    if not records:
        return {"repository_full_name": full_name, "status": "NO_COMMITS",
                "qualifies": False, "qualifying_rules": [],
                "total_commits": 0, "merge_commits": 0,
                "total_non_merge_commits": 0, "attributed_non_merge_commits": 0,
                "substantive_attributed_commits": 0, "attributed_commit_share": 0.0,
                "attributed_source_lines_added": 0, "attributed_source_lines_deleted": 0,
                "attributed_source_lines": 0, "total_source_lines": 0,
                "attributed_files_changed": 0,
                "first_attributed_commit_date": None, "last_attributed_commit_date": None,
                "initial_implementation_attributed": False,
                "any_attribution_signal_found": False,
                "reachable_qualifying_commit": False, "commits": []}
    result = apply_attribution_rules(records, rules_cfg)
    result["repository_full_name"] = full_name
    result["status"] = "OK"
    result["commits"] = [
        {"sha": r["sha"], "date": r["date"], "is_merge": r["is_merge"],
         "attributed": r["attributed"], "any_signal": r["any_signal"],
         "substantive": r["substantive"], "relevant_added": r["relevant_added"],
         "relevant_deleted": r["relevant_deleted"], "relevant_changed": r["relevant_changed"]}
        for r in records
    ]
    return result


def _aggregate_row(analysis: dict) -> dict:
    row = {k: analysis.get(k) for k in ATTRIBUTION_FIELDS}
    rules = analysis.get("qualifying_rules") or []
    row["qualifying_rules"] = ";".join(rules)
    return row


# =========================================================================== #
# ORCHESTRATION (I/O; git injected as history_fn for testability)
# =========================================================================== #
# history_fn signature: (full_name, default_branch, url) -> (meta_text, numstat_text)
HistoryFn = Callable[[str, Optional[str], str], tuple[str, str]]


def verify_all(
    candidates: list[dict],
    metadata_by_name: dict[str, dict],
    raw_dir: Path,
    analysis_dir: Path,
    log_path: Path,
    history_fn: HistoryFn,
    rules_cfg: dict,
    matcher: ExcludeMatcher,
    min_substantive_lines: int,
) -> list[dict]:
    """Verify every candidate; save raw git output immutably, cache per-repo
    analysis, and return one aggregate row per repo. Never drops a repo."""
    common.ensure_dir(raw_dir)
    common.ensure_dir(analysis_dir)
    rows: list[dict] = []
    seen: set[str] = set()

    for cand in candidates:
        full = cand.get("repository_full_name")
        if not full or full in seen:
            continue
        seen.add(full)

        meta = metadata_by_name.get(full)
        if not meta or meta.get("fetch_status") != "OK":
            analysis = {"repository_full_name": full, "status": "UNAVAILABLE",
                        "qualifies": False, "qualifying_rules": []}
            rows.append(_aggregate_row(analysis))
            _log(log_path, full, "UNAVAILABLE", None)
            continue

        safe = _safe_name(full)
        meta_file = raw_dir / f"{safe}.meta.txt"
        numstat_file = raw_dir / f"{safe}.numstat.txt"
        analysis_file = analysis_dir / f"{safe}.json"

        # Resume: re-parse cached raw output instead of re-cloning.
        if meta_file.exists() and numstat_file.exists():
            meta_text = meta_file.read_text(encoding="utf-8")
            numstat_text = numstat_file.read_text(encoding="utf-8")
            error = None
        else:
            try:
                meta_text, numstat_text = history_fn(
                    full, meta.get("default_branch"), meta.get("repository_url")
                    or f"https://github.com/{full}")
                common.atomic_write_text(meta_file, meta_text)
                common.atomic_write_text(numstat_file, numstat_text)
                error = None
            except Exception as exc:
                analysis = {"repository_full_name": full, "status": "CLONE_ERROR",
                            "qualifies": False, "qualifying_rules": []}
                rows.append(_aggregate_row(analysis))
                _log(log_path, full, "CLONE_ERROR", f"{type(exc).__name__}: {exc}")
                continue

        analysis = analyze_history(full, meta_text, numstat_text, matcher,
                                   rules_cfg, min_substantive_lines)
        common.atomic_write_json(analysis_file, analysis)
        rows.append(_aggregate_row(analysis))
        _log(log_path, full, analysis["status"], error,
             qualifies=analysis.get("qualifies"))

    return rows


def _log(log_path: Path, full: str, status: str, error: Optional[str],
         qualifies=None) -> None:
    common.append_jsonl(log_path, {
        "ts": common.iso_now(), "repository_full_name": full,
        "status": status, "qualifies": qualifies, "error": error,
    })


def _safe_name(full_name: str) -> str:
    stem = full_name.replace("/", "__")
    return "".join(c if (c.isalnum() or c in "._-") else "_" for c in stem)


def _is_within(root: Path, path: Path) -> bool:
    """True iff `path` resolves to `root` itself or a descendant of it."""
    root_r = root.resolve()
    path_r = path.resolve()
    return path_r == root_r or root_r in path_r.parents


def write_aggregate(rows: list[dict], json_path: Path, csv_path: Path) -> None:
    common.atomic_write_json(json_path, rows)
    common.ensure_dir(Path(csv_path).parent)
    tmp = Path(csv_path).with_suffix(".csv.tmp")
    with tmp.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=ATTRIBUTION_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    os.replace(tmp, csv_path)


# --------------------------------------------------------------------------- #
# Real git-backed history function (safe clone + logs)
# --------------------------------------------------------------------------- #
def find_git() -> Optional[str]:
    return shutil.which("git")


def _git_env() -> dict:
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"     # never prompt for credentials
    env["GIT_LFS_SKIP_SMUDGE"] = "1"     # do not fetch LFS content
    env["GIT_ALLOW_PROTOCOL"] = "https"  # https only
    return env


def make_git_history_fn(git_path: str, clone_root: Path,
                        clone_timeout: int = 300) -> HistoryFn:
    """Real history fetcher: safe `--no-checkout` clone (cached) + two `git log`
    passes. Raises on clone/log failure so the orchestrator records CLONE_ERROR."""
    common.ensure_dir(clone_root)
    hooks_dir = clone_root / ".empty-hooks"
    common.ensure_dir(hooks_dir)
    env = _git_env()

    def _run(args: list[str], timeout: int) -> subprocess.CompletedProcess:
        return subprocess.run([git_path, *args], capture_output=True, text=True,
                              timeout=timeout, check=False, env=env)

    def _fn(full_name: str, default_branch: Optional[str], url: str) -> tuple[str, str]:
        dest = clone_root / _safe_name(full_name)
        # Never rmtree outside the clone root (defends against a crafted repo
        # name escaping via .. or separators despite _safe_name sanitization).
        if not _is_within(clone_root, dest):
            raise RuntimeError(f"refusing to operate outside clone root: {dest}")
        if not (dest / "HEAD").exists() and not (dest / ".git").exists():
            if dest.exists():
                shutil.rmtree(dest, ignore_errors=True)
            clone_args = build_clone_args(url, str(dest), str(hooks_dir), default_branch)
            proc = _run(clone_args, clone_timeout)
            if proc.returncode != 0:
                raise RuntimeError(f"clone failed: {proc.stderr.strip()[:200]}")
        meta = _run(["-C", str(dest), *build_log_meta_args()], 120)
        if meta.returncode != 0:
            raise RuntimeError(f"git log meta failed: {meta.stderr.strip()[:200]}")
        numstat = _run(["-C", str(dest), *build_log_numstat_args()], 120)
        if numstat.returncode != 0:
            raise RuntimeError(f"git log numstat failed: {numstat.stderr.strip()[:200]}")
        return meta.stdout, numstat.stdout

    return _fn


# =========================================================================== #
# main
# =========================================================================== #
def _load_metadata_index(path: Path) -> dict[str, dict]:
    if not path.exists():
        return {}
    data = common.read_json(path)
    return {r["repository_full_name"]: r for r in data
            if isinstance(r, dict) and r.get("repository_full_name")}


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Verify substantial Claude attribution (Phase 6).")
    parser.add_argument("--control", action="store_true")
    args = parser.parse_args(argv)

    cfg = common.load_study_config()
    inclusion = common.load_yaml(common.CONFIG_DIR / "inclusion-rules.yaml")
    rules_cfg = inclusion.get("substantial_attribution_rules", {})
    min_sub = inclusion.get("substantive_commit", {}).get("min_source_lines_changed", 10)
    matcher = load_exclude_matcher()

    interim = STUDY_ROOT / cfg["paths"]["interim"]
    if args.control:
        candidates_path = interim / "control" / "control-candidate-repositories.json"
        metadata_path = interim / "control" / "repository-metadata.json"
        raw_dir = STUDY_ROOT / cfg["paths"]["results_raw"] / "git-history-control"
        analysis_dir = interim / "control" / "attribution"
        out_json = interim / "control" / "attribution-verification.json"
        out_csv = interim / "control" / "attribution-verification.csv"
        log_path = STUDY_ROOT / cfg["paths"]["logs"] / "verify_attribution_control.jsonl"
        key = "repo_full_name"
    else:
        candidates_path = interim / "claude-candidate-repositories.json"
        metadata_path = interim / "repository-metadata.json"
        raw_dir = STUDY_ROOT / "data" / "raw" / "git-history"
        analysis_dir = interim / "attribution"
        out_json = interim / "attribution-verification.json"
        out_csv = interim / "attribution-verification.csv"
        log_path = STUDY_ROOT / cfg["paths"]["logs"] / "verify_attribution.jsonl"
        key = "repository_full_name"

    if not candidates_path.exists():
        print(f"ERROR: candidate table not found: {candidates_path}", file=sys.stderr)
        print("       Run 'make merge' first.", file=sys.stderr)
        return 2
    if not metadata_path.exists():
        print(f"ERROR: metadata table not found: {metadata_path}", file=sys.stderr)
        print("       Run 'make metadata' first.", file=sys.stderr)
        return 2

    raw_candidates = common.read_json(candidates_path)
    candidates = [
        {"repository_full_name": c.get(key) or c.get("repository_full_name")}
        for c in raw_candidates
    ]
    candidates = [c for c in candidates if c["repository_full_name"]]
    metadata_by_name = _load_metadata_index(metadata_path)

    git = find_git()
    if git is None:
        print("ERROR: git not found on PATH.", file=sys.stderr)
        return 2

    clone_root = STUDY_ROOT / cfg["paths"]["candidates_clone"] / "history"
    # Clone limits live in scanner-config.yaml -> clone.limits, NOT study-config.
    scanner_cfg = common.load_yaml(common.CONFIG_DIR / "scanner-config.yaml")
    clone_timeout = int(
        scanner_cfg.get("clone", {}).get("limits", {}).get("clone_timeout_seconds", 300)
    )
    history_fn = make_git_history_fn(git, clone_root, clone_timeout)

    rows = verify_all(candidates, metadata_by_name, raw_dir, analysis_dir,
                      log_path, history_fn, rules_cfg, matcher, min_sub)
    write_aggregate(rows, out_json, out_csv)

    from collections import Counter
    status = Counter(r["status"] for r in rows)
    qualified = sum(1 for r in rows if r.get("qualifies"))
    print(f"Attribution verified for {len(rows)} repositories -> {out_csv}")
    print(f"  status: {dict(status)}")
    print(f"  substantial-attribution qualifying: {qualified}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
