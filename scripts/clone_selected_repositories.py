#!/usr/bin/env python3
"""
clone_selected_repositories.py — Phase 19 safe clone of the selected sample.

Clones each SELECTED repository at its FROZEN commit for scanning: a partial
(--filter=blob:none) clone, then a checkout of the frozen SHA, with every git
safety switch from scanner-config.yaml (hooks/symlinks/ext-protocol/LFS disabled,
no terminal prompt, no submodules) and clone-size/file-count/single-file guards.
Repository code is NEVER executed; install/build/test scripts are NEVER run.

Refuses to run unless the population is frozen and the sample selected. Reads the
frozen commit SHA + URL from Phase 4 metadata.

Pure guard/arg logic is split from the injectable `clone_fn`; unit-tested offline.

Outputs:
  repositories/selected/{owner__repo}/            (working tree at frozen SHA)
  data/processed/clone-manifest.{json,csv}
"""

from __future__ import annotations

import argparse
import csv
import sys
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

CLONE_FIELDS = ["repository_full_name", "anonymous_id", "status", "checked_out_sha",
                "size_mb", "file_count", "largest_file_mb", "exclusion_code", "reasons"]


# =========================================================================== #
# PURE FUNCTIONS
# =========================================================================== #
def build_working_tree_clone_args(url: str, dest: str, hooks_dir: str) -> list[str]:
    """Partial (blobless) clone with no checkout and the hardening switches."""
    return [
        "-c", "protocol.ext.allowed=never",
        "-c", "core.symlinks=false",
        "-c", f"core.hooksPath={hooks_dir}",
        "clone", "--no-checkout", "--filter=blob:none", "--no-tags",
        "--single-branch", url, dest,
    ]


def build_checkout_args(ref: str) -> list[str]:
    # --force materializes the tree; hooks/symlinks already disabled at clone.
    return ["checkout", "--force", ref]


def check_clone_guards(size_bytes: int, file_count: int, largest_file_bytes: int,
                       limits: dict) -> tuple[bool, list[str]]:
    """Return (ok, reasons). Any breach => reasons non-empty => EX_CLONE_FAILED."""
    reasons: list[str] = []
    max_repo = limits.get("max_repo_size_mb", 2048) * 1024 * 1024
    max_files = limits.get("max_file_count", 200000)
    max_single = limits.get("max_single_file_mb", 50) * 1024 * 1024
    if size_bytes > max_repo:
        reasons.append(f"repo_size>{limits.get('max_repo_size_mb')}mb")
    if file_count > max_files:
        reasons.append(f"file_count>{max_files}")
    if largest_file_bytes > max_single:
        reasons.append(f"single_file>{limits.get('max_single_file_mb')}mb")
    return (not reasons, reasons)


def _mb(nbytes: int) -> float:
    return round((nbytes or 0) / (1024 * 1024), 2)


def build_clone_record(full: str, anon_id: Optional[str], clone_result: dict,
                       limits: dict) -> dict:
    """Combine a clone_fn result with the guard decision into a manifest row."""
    if clone_result.get("status") != "OK":
        return {"repository_full_name": full, "anonymous_id": anon_id,
                "status": "CLONE_ERROR", "exclusion_code": "EX_CLONE_FAILED",
                "reasons": clone_result.get("error", "clone failed")}
    size = clone_result.get("size_bytes", 0)
    count = clone_result.get("file_count", 0)
    largest = clone_result.get("largest_file_bytes", 0)
    ok, reasons = check_clone_guards(size, count, largest, limits)
    return {
        "repository_full_name": full,
        "anonymous_id": anon_id,
        "status": "OK" if ok else "CLONE_ERROR",
        "checked_out_sha": clone_result.get("checked_out_sha"),
        "size_mb": _mb(size),
        "file_count": count,
        "largest_file_mb": _mb(largest),
        "exclusion_code": None if ok else "EX_CLONE_FAILED",
        "reasons": ";".join(reasons),
    }


# =========================================================================== #
# WRITERS
# =========================================================================== #
def write_manifest(records: list[dict], json_path: Path, csv_path: Path) -> None:
    import os
    common.atomic_write_json(json_path, records)
    common.ensure_dir(csv_path.parent)
    tmp = csv_path.with_suffix(".csv.tmp")
    with tmp.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CLONE_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for rec in records:
            writer.writerow(rec)
    os.replace(tmp, csv_path)


# =========================================================================== #
# ORCHESTRATION
# =========================================================================== #
# clone_fn: (full, url, ref, dest) -> {status, size_bytes, file_count,
#           largest_file_bytes, checked_out_sha, error}
CloneFn = Callable[[str, str, Optional[str], Path], dict]


def clone_all(selected: list[dict], metadata: dict, clone_root: Path, log_path: Path,
              clone_fn: CloneFn, limits: dict) -> list[dict]:
    common.ensure_dir(clone_root)
    records: list[dict] = []
    seen: set[str] = set()
    for row in selected:
        full = row.get("repository_full_name")
        if not full or full in seen:
            continue
        seen.add(full)
        meta = metadata.get(full) or {}
        url = meta.get("repository_url") or f"https://github.com/{full}"
        ref = meta.get("default_branch_head_sha") or meta.get("default_branch") or "HEAD"
        dest = clone_root / vca._safe_name(full)
        if not vca._is_within(clone_root, dest):
            records.append({"repository_full_name": full, "status": "CLONE_ERROR",
                            "exclusion_code": "EX_CLONE_FAILED", "reasons": "path escape"})
            continue
        try:
            result = clone_fn(full, url, ref, dest)
        except Exception as exc:
            result = {"status": "ERROR", "error": f"{type(exc).__name__}: {exc}"}
        rec = build_clone_record(full, row.get("anonymous_id"), result, limits)
        records.append(rec)
        common.append_jsonl(log_path, {"ts": common.iso_now(),
                                       "repository_full_name": full,
                                       "status": rec["status"],
                                       "sha": rec.get("checked_out_sha")})
    return records


# --------------------------------------------------------------------------- #
# Real git-backed clone_fn (partial clone + checkout + measure; no execution)
# --------------------------------------------------------------------------- #
def make_git_clone_fn(git_path: str, clone_root: Path, clone_timeout: int = 300) -> CloneFn:
    import shutil
    common.ensure_dir(clone_root)
    hooks_dir = clone_root / ".empty-hooks"
    common.ensure_dir(hooks_dir)
    env = vca._git_env()

    def _run(args, timeout):
        import subprocess
        return subprocess.run([git_path, *args], capture_output=True, text=True,
                              timeout=timeout, check=False, env=env)

    def _measure(path: Path) -> tuple[int, int, int]:
        total = count = largest = 0
        for p in path.rglob("*"):
            if ".git" in p.parts:
                continue
            if p.is_file() and not p.is_symlink():
                try:
                    sz = p.stat().st_size
                except OSError:
                    continue
                total += sz
                count += 1
                largest = max(largest, sz)
        return total, count, largest

    def _fn(full: str, url: str, ref: Optional[str], dest: Path) -> dict:
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        c = _run(build_working_tree_clone_args(url, str(dest), str(hooks_dir)), clone_timeout)
        if c.returncode != 0:
            return {"status": "ERROR", "error": f"clone: {c.stderr.strip()[:200]}"}
        co = _run(["-C", str(dest), *build_checkout_args(ref or "HEAD")], clone_timeout)
        if co.returncode != 0:
            return {"status": "ERROR", "error": f"checkout: {co.stderr.strip()[:200]}"}
        sha = _run(["-C", str(dest), "rev-parse", "HEAD"], 30)
        size, count, largest = _measure(dest)
        return {"status": "OK", "size_bytes": size, "file_count": count,
                "largest_file_bytes": largest,
                "checked_out_sha": sha.stdout.strip() if sha.returncode == 0 else ref}

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
    parser = argparse.ArgumentParser(description="Safely clone the selected sample (Phase 19).")
    parser.add_argument("--pilot", action="store_true", help="clone only the pilot subset")
    args = parser.parse_args(argv)

    cfg = common.load_study_config()
    scanner_cfg = common.load_yaml(common.CONFIG_DIR / "scanner-config.yaml")
    limits = scanner_cfg.get("clone", {}).get("limits", {})
    clone_timeout = int(limits.get("clone_timeout_seconds", 300))
    processed = STUDY_ROOT / cfg["paths"]["processed"]

    selected_path = processed / "selected-500-repositories.csv"
    frozen = processed / "eligible-population-checksum.txt"
    if not frozen.exists():
        print("REFUSING TO CLONE: population not frozen. Run 'make freeze' first.", file=sys.stderr)
        return 2
    if not selected_path.exists():
        print("REFUSING TO CLONE: sample not selected. Run 'make select' first.", file=sys.stderr)
        return 2

    with selected_path.open(encoding="utf-8") as fh:
        selected = list(csv.DictReader(fh))
    if args.pilot:
        pilot_size = int(scanner_cfg.get("pilot", {}).get("size", 10))
        selected = sorted(selected, key=lambda r: r.get("anonymous_id", ""))[:pilot_size]

    metadata = _index(STUDY_ROOT / cfg["paths"]["interim"] / "repository-metadata.json")

    git = vca.find_git()
    if git is None:
        print("ERROR: git not found on PATH.", file=sys.stderr)
        return 2
    clone_root = STUDY_ROOT / cfg["paths"]["selected_clone"]
    clone_fn = make_git_clone_fn(git, clone_root, clone_timeout)
    log_path = STUDY_ROOT / cfg["paths"]["logs"] / "clone_selected.jsonl"

    records = clone_all(selected, metadata, clone_root, log_path, clone_fn, limits)
    write_manifest(records, processed / "clone-manifest.json", processed / "clone-manifest.csv")

    ok = sum(1 for r in records if r["status"] == "OK")
    print(f"Cloned {ok}/{len(records)} selected repositories -> {clone_root}")
    failed = [r["repository_full_name"] for r in records if r["status"] != "OK"]
    if failed:
        print(f"  {len(failed)} clone failures (EX_CLONE_FAILED), recorded in the manifest.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
