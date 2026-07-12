#!/usr/bin/env python3
"""
detect_duplicates.py — Phase 16 duplicate / template clustering.

Finds exact and near-duplicate repositories (template scaffolds copied wholesale,
re-uploaded clones) by a STRUCTURAL fingerprint: the set of tracked file paths
plus the package.json name + dependency set. Repos whose path sets are highly
similar (Jaccard >= threshold) are clustered; within each cluster one
representative is kept and the rest are marked EX_DUPLICATE (consumed by
screen_candidates). Representative = most substantial Claude attribution, then
most stars, then oldest.

Design mirrors earlier phases: pure fingerprint/clustering logic split from an
injectable `fingerprint_fn` (git), unit-tested offline. Content is read from the
Phase 6 history clone via git (no checkout, no execution).

Outputs:
  data/interim/duplicate-clusters.json          (clusters + members)
  data/interim/duplicate-flags.{json,csv}        (per-repo duplicate decision)
"""

from __future__ import annotations

import argparse
import csv
import os
import sys
from pathlib import Path
from typing import Callable, Optional

try:
    from . import _common as common  # type: ignore
    from . import verify_claude_attribution as vca  # type: ignore
    from . import classify_projects as cp  # type: ignore
except Exception:  # pragma: no cover
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _common as common  # type: ignore
    import verify_claude_attribution as vca  # type: ignore
    import classify_projects as cp  # type: ignore

STUDY_ROOT = common.STUDY_ROOT
DEFAULT_JACCARD_THRESHOLD = 0.90
MIN_PATHS_FOR_CLUSTERING = 5     # tiny trees are not reliably "duplicate"

DUP_FIELDS = [
    "repository_full_name",
    "status",                    # OK | UNAVAILABLE | READ_ERROR
    "cluster_id",
    "cluster_size",
    "is_representative",
    "is_duplicate",
    "duplicate_of",
    "path_count",
]


# =========================================================================== #
# PURE FUNCTIONS
# =========================================================================== #
def repo_signature(files: list[str], pkg_text: Optional[str]) -> dict:
    """Structural fingerprint: normalized tracked-path set + package name + deps."""
    paths = frozenset(cp._norm(p) for p in files)
    pkg = cp.parse_package_json(pkg_text)
    name = (pkg or {}).get("name") if isinstance(pkg, dict) else None
    deps = frozenset(cp.all_dependencies(pkg))
    return {"paths": paths, "name": name, "deps": deps}


def jaccard(a: frozenset, b: frozenset) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


def _similar(sig_a: dict, sig_b: dict, threshold: float) -> bool:
    pa, pb = sig_a["paths"], sig_b["paths"]
    if len(pa) < MIN_PATHS_FOR_CLUSTERING or len(pb) < MIN_PATHS_FOR_CLUSTERING:
        return pa == pb and bool(pa)         # tiny trees only cluster if identical
    if jaccard(pa, pb) >= threshold:
        return True
    # Exact dependency + name match with substantial overlap also links.
    if sig_a["name"] and sig_a["name"] == sig_b["name"] and \
            sig_a["deps"] and sig_a["deps"] == sig_b["deps"] and jaccard(pa, pb) >= 0.6:
        return True
    return False


def cluster_signatures(signatures: dict[str, dict],
                       threshold: float = DEFAULT_JACCARD_THRESHOLD) -> list[list[str]]:
    """Union-find clustering over pairwise structural similarity. Returns groups
    (including singletons) as sorted lists of repository names."""
    names = sorted(signatures)
    parent = {n: n for n in names}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[max(ra, rb)] = min(ra, rb)

    for i, a in enumerate(names):
        for b in names[i + 1:]:
            if _similar(signatures[a], signatures[b], threshold):
                union(a, b)

    groups: dict[str, list[str]] = {}
    for n in names:
        groups.setdefault(find(n), []).append(n)
    return [sorted(g) for g in groups.values()]


def choose_representative(cluster: list[str], metadata: dict, attribution: dict) -> str:
    """Keep the most substantial member: attributed source lines, then stars, then oldest."""
    def key(full: str):
        attr = attribution.get(full, {})
        meta = metadata.get(full, {})
        attributed = attr.get("attributed_source_lines") or 0
        stars = meta.get("stargazers_count") or 0
        created = meta.get("created_at") or "9999"      # older (smaller) preferred
        return (attributed, stars, _neg_str(created), full)
    return max(cluster, key=key)


def _neg_str(s: str) -> tuple:
    # Sort helper: older created_at should rank higher, so invert lexical order.
    return tuple(-ord(c) for c in s)


def build_duplicate_records(clusters: list[list[str]], metadata: dict,
                            attribution: dict, signatures: dict) -> list[dict]:
    rows: list[dict] = []
    for cid, cluster in enumerate(sorted(clusters, key=lambda c: c[0])):
        rep = choose_representative(cluster, metadata, attribution) if len(cluster) > 1 \
            else cluster[0]
        for full in cluster:
            is_rep = (full == rep)
            rows.append({
                "repository_full_name": full,
                "status": "OK",
                "cluster_id": cid,
                "cluster_size": len(cluster),
                "is_representative": is_rep,
                "is_duplicate": (len(cluster) > 1 and not is_rep),
                "duplicate_of": (rep if (len(cluster) > 1 and not is_rep) else None),
                "path_count": len(signatures.get(full, {}).get("paths", ())),
            })
    return rows


# =========================================================================== #
# WRITERS
# =========================================================================== #
def write_duplicates(records: list[dict], clusters: list[list[str]],
                     clusters_json: Path, flags_json: Path, flags_csv: Path) -> None:
    common.atomic_write_json(clusters_json,
                             [{"cluster_id": i, "members": c}
                              for i, c in enumerate(sorted(clusters, key=lambda c: c[0]))])
    common.atomic_write_json(flags_json, records)
    common.ensure_dir(flags_csv.parent)
    tmp = flags_csv.with_suffix(".csv.tmp")
    with tmp.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=DUP_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for rec in records:
            writer.writerow(rec)
    os.replace(tmp, flags_csv)


# =========================================================================== #
# ORCHESTRATION
# =========================================================================== #
# fingerprint_fn: (full, default_branch, url) -> (files, package_json_text)
FingerprintFn = Callable[[str, Optional[str], str], tuple[list, Optional[str]]]


def detect_all(candidates: list[dict], metadata_by_name: dict[str, dict],
               attribution_by_name: dict[str, dict], raw_dir: Path, log_path: Path,
               fingerprint_fn: FingerprintFn, threshold: float) -> tuple[list[dict], list[list[str]]]:
    common.ensure_dir(raw_dir)
    signatures: dict[str, dict] = {}
    unavailable: list[dict] = []
    seen: set[str] = set()

    for cand in candidates:
        full = cand.get("repository_full_name")
        if not full or full in seen:
            continue
        seen.add(full)
        meta = metadata_by_name.get(full)
        if not meta or meta.get("fetch_status") != "OK":
            unavailable.append({"repository_full_name": full, "status": "UNAVAILABLE"})
            continue
        cache = raw_dir / f"{vca._safe_name(full)}.json"
        if common.is_valid_json_file(cache):
            cached = common.read_json(cache)
            signatures[full] = {"paths": frozenset(cached.get("paths", [])),
                                "name": cached.get("name"),
                                "deps": frozenset(cached.get("deps", []))}
            continue
        try:
            files, pkg_text = fingerprint_fn(
                full, meta.get("default_branch"),
                meta.get("repository_url") or f"https://github.com/{full}")
            sig = repo_signature(files, pkg_text)
        except Exception as exc:
            unavailable.append({"repository_full_name": full, "status": "READ_ERROR"})
            common.append_jsonl(log_path, {"ts": common.iso_now(),
                                           "repository_full_name": full,
                                           "status": "READ_ERROR", "error": f"{exc}"})
            continue
        common.atomic_write_json(cache, {"paths": sorted(sig["paths"]),
                                         "name": sig["name"], "deps": sorted(sig["deps"])})
        signatures[full] = sig

    clusters = cluster_signatures(signatures, threshold)
    rows = build_duplicate_records(clusters, metadata_by_name, attribution_by_name, signatures)
    rows.extend(unavailable)
    return rows, clusters


# --------------------------------------------------------------------------- #
# Real git-backed fingerprint reader
# --------------------------------------------------------------------------- #
def make_git_fingerprint_fn(git_path: str, clone_root: Path,
                            clone_timeout: int = 300) -> FingerprintFn:
    common.ensure_dir(clone_root)
    hooks_dir = clone_root / ".empty-hooks"
    common.ensure_dir(hooks_dir)
    env = vca._git_env()

    def _run(args, timeout):
        import subprocess
        return subprocess.run([git_path, *args], capture_output=True, text=True,
                              timeout=timeout, check=False, env=env)

    def _fn(full_name: str, default_branch: Optional[str], url: str):
        dest = clone_root / vca._safe_name(full_name)
        if not vca._is_within(clone_root, dest):
            raise RuntimeError(f"refusing to operate outside clone root: {dest}")
        if not (dest / ".git").exists() and not (dest / "HEAD").exists():
            args = vca.build_clone_args(url, str(dest), str(hooks_dir), default_branch)
            proc = _run(args, clone_timeout)
            if proc.returncode != 0:
                raise RuntimeError(f"clone failed: {proc.stderr.strip()[:200]}")
        ls = _run(["-C", str(dest), "ls-tree", "-r", "HEAD", "--name-only"], 120)
        if ls.returncode != 0:
            raise RuntimeError(f"git ls-tree failed: {ls.stderr.strip()[:200]}")
        files = [ln for ln in ls.stdout.splitlines() if ln.strip()]
        show = _run(["-C", str(dest), "show", "HEAD:package.json"], 60)
        pkg = show.stdout if show.returncode == 0 else None
        return files, pkg

    return _fn


# =========================================================================== #
# main
# =========================================================================== #
def _index(path: Path, key: str = "repository_full_name") -> dict[str, dict]:
    if not path.exists():
        return {}
    return {r[key]: r for r in common.read_json(path)
            if isinstance(r, dict) and r.get(key)}


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Detect duplicate/template repositories (Phase 16).")
    parser.add_argument("--control", action="store_true")
    parser.add_argument("--threshold", type=float, default=DEFAULT_JACCARD_THRESHOLD)
    args = parser.parse_args(argv)

    cfg = common.load_study_config()
    interim = STUDY_ROOT / cfg["paths"]["interim"]
    base = interim / "control" if args.control else interim
    key = "repo_full_name" if args.control else "repository_full_name"
    candidates_path = base / ("control-candidate-repositories.json" if args.control
                              else "claude-candidate-repositories.json")
    if not candidates_path.exists():
        print(f"ERROR: candidate table not found: {candidates_path}", file=sys.stderr)
        return 2

    metadata = _index(base / "repository-metadata.json")
    attribution = _index(base / "attribution-verification.json")
    raw_candidates = common.read_json(candidates_path)
    candidates = [{"repository_full_name": c.get(key) or c.get("repository_full_name")}
                  for c in raw_candidates]
    candidates = [c for c in candidates if c["repository_full_name"]]

    git = vca.find_git()
    if git is None:
        print("ERROR: git not found on PATH.", file=sys.stderr)
        return 2
    scanner_cfg = common.load_yaml(common.CONFIG_DIR / "scanner-config.yaml")
    clone_timeout = int(scanner_cfg.get("clone", {}).get("limits", {})
                        .get("clone_timeout_seconds", 300))
    clone_root = STUDY_ROOT / cfg["paths"]["candidates_clone"] / "history"
    fingerprint_fn = make_git_fingerprint_fn(git, clone_root, clone_timeout)
    raw_dir = base / "duplicate-fingerprints"
    log_path = STUDY_ROOT / cfg["paths"]["logs"] / (
        "detect_duplicates_control.jsonl" if args.control else "detect_duplicates.jsonl")

    rows, clusters = detect_all(candidates, metadata, attribution, raw_dir, log_path,
                                fingerprint_fn, args.threshold)
    write_duplicates(rows, clusters, base / "duplicate-clusters.json",
                     base / "duplicate-flags.json", base / "duplicate-flags.csv")

    dups = sum(1 for r in rows if r.get("is_duplicate"))
    multi = sum(1 for c in clusters if len(c) > 1)
    print(f"Duplicate detection over {len(rows)} repositories -> {base / 'duplicate-flags.csv'}")
    print(f"  {multi} multi-repo clusters; {dups} repos marked duplicate (EX_DUPLICATE).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
