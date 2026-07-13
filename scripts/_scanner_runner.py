#!/usr/bin/env python3
"""
_scanner_runner.py — shared harness for the five static scanners.

Builds the isolated `docker run` invocation (non-root, network none, read-only
repo mount, resource limits, no docker socket) that dispatches ONE scanner
against ONE cloned repository via scanner-entrypoint.sh, captures the raw output
immutably, parses a finding count, and writes an execution record. Repository
code is never executed — only the pinned scanner binary runs, offline.

The five run_*.py scripts are thin wrappers over `run_all` here. Pure argv
building + finding-count parsers are unit-tested offline.
"""

from __future__ import annotations

import csv
import json
import sys
import time
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
SCANNER_IMAGE = "claude-study-scanner:latest"

# scanner -> raw output file extension
OUTPUT_EXT = {"gitleaks": "json", "semgrep": "sarif", "trivy": "json",
              "osv-scanner": "json", "zizmor": "sarif"}

EXEC_FIELDS = ["repository_full_name", "anonymous_id", "scanner", "commit_sha",
               "status", "exit_code", "duration_seconds", "finding_count",
               "output_file", "error_message"]


# =========================================================================== #
# PURE: isolated docker run argv
# =========================================================================== #
def build_docker_run_args(scanner: str, repo_container_path: str,
                          output_container_path: str, mounts: list[tuple],
                          image: str, isolation: dict) -> list[str]:
    """`docker run` argv (excluding the docker executable) for one isolated scan."""
    limits = isolation.get("limits", {})
    args = [
        "run", "--rm",
        "--user", str(isolation.get("user_uid", "10001:10001")),
        "--network", "none",
        "--read-only",
        "--tmpfs", "/tmp:size=1g,mode=1777",
        "--security-opt", "no-new-privileges:true",
        "--cap-drop", "ALL",
        "--pids-limit", str(limits.get("pids", 512)),
        "--memory", str(limits.get("memory", "4g")),
        "--cpus", str(limits.get("cpus", "2.0")),
    ]
    for host, cont, mode in mounts:
        args += ["-v", f"{host}:{cont}:{mode}"]
    args += [image, scanner, repo_container_path, output_container_path]
    return args


# =========================================================================== #
# PURE: per-scanner finding-count parsers (None => unparseable => PARSER_ERROR)
# =========================================================================== #
def _load(text: str):
    try:
        return json.loads(text) if text and text.strip() else None
    except Exception:
        return None


def count_gitleaks(text: str) -> Optional[int]:
    obj = _load(text)
    if obj is None:
        return None
    return len(obj) if isinstance(obj, list) else 0


def _count_sarif(text: str) -> Optional[int]:
    obj = _load(text)
    if not isinstance(obj, dict):
        return None
    runs = obj.get("runs")
    if not isinstance(runs, list):
        return 0
    return sum(len(r.get("results") or []) for r in runs if isinstance(r, dict))


count_semgrep = _count_sarif
count_zizmor = _count_sarif


def count_trivy(text: str) -> Optional[int]:
    obj = _load(text)
    if not isinstance(obj, dict):
        return None
    total = 0
    for res in obj.get("Results") or []:
        if not isinstance(res, dict):
            continue
        for key in ("Vulnerabilities", "Misconfigurations", "Secrets"):
            total += len(res.get(key) or [])
    return total


def count_osv(text: str) -> Optional[int]:
    obj = _load(text)
    if not isinstance(obj, dict):
        return None
    total = 0
    for res in obj.get("results") or []:
        for pkg in (res.get("packages") or []) if isinstance(res, dict) else []:
            total += len(pkg.get("vulnerabilities") or []) if isinstance(pkg, dict) else 0
    return total


FINDING_PARSERS = {
    "gitleaks": count_gitleaks, "semgrep": count_semgrep, "trivy": count_trivy,
    "osv-scanner": count_osv, "zizmor": count_zizmor,
}


def exit_semantics_for(scanner: str, scanner_cfg: Optional[dict] = None) -> tuple[set, set]:
    """(ok_codes, findings_codes) for a scanner from scanner-config exit_semantics."""
    if scanner_cfg is None:
        scanner_cfg = common.load_yaml(common.CONFIG_DIR / "scanner-config.yaml")
    sem = (scanner_cfg.get("exit_semantics") or {}).get(scanner, {})
    return set(sem.get("ok", [0])), set(sem.get("findings", []))


def classify_execution(exit_code: int, timed_out: bool, finding_count: Optional[int],
                       accepted_exit_codes: Optional[set] = None) -> str:
    """Classify one scanner run. A scanner-specific 'findings' exit code counts as
    a successful run (accepted_exit_codes must include it), NOT a SCANNER_ERROR."""
    if timed_out:
        return "TIMEOUT"
    accepted = accepted_exit_codes if accepted_exit_codes is not None else {0}
    if exit_code not in accepted:
        return "SCANNER_ERROR"
    if finding_count is None:
        return "PARSER_ERROR"
    return "SUCCESS_WITH_FINDINGS" if finding_count > 0 else "NO_FINDINGS"


# =========================================================================== #
# ORCHESTRATION (injectable run_fn: (argv) -> (returncode, stdout, stderr))
# =========================================================================== #
RunFn = Callable[[list], tuple]


def run_one(scanner: str, repo_full: str, anon_id: Optional[str], commit_sha: Optional[str],
            repo_container_path: str, output_host: Path, output_container_path: str,
            mounts: list[tuple], image: str, isolation: dict,
            run_fn: RunFn, docker: str = "docker",
            accepted_exit_codes: Optional[set] = None) -> dict:
    """Run one scanner on one repo; the container writes `output_host`. Returns an
    execution record. A scanner-specific 'findings' exit code is a success (its
    output is parsed); a genuine failure is never recorded as zero findings."""
    if accepted_exit_codes is None:
        ok, findings = exit_semantics_for(scanner)
        accepted_exit_codes = ok | findings
    argv = build_docker_run_args(scanner, repo_container_path, output_container_path,
                                 mounts, image, isolation)
    common.ensure_dir(output_host.parent)
    start = time.monotonic()
    timed_out = False
    try:
        rc, _out, err = run_fn([docker, *argv])
    except TimeoutError:
        rc, err, timed_out = 124, "timeout", True
    duration = round(time.monotonic() - start, 2)

    finding_count: Optional[int] = None
    # Parse output for ANY accepted exit code (incl. the findings code), not just 0.
    if rc in accepted_exit_codes and not timed_out and output_host.exists():
        finding_count = FINDING_PARSERS[scanner](
            output_host.read_text(encoding="utf-8", errors="replace"))

    status = classify_execution(rc, timed_out, finding_count, accepted_exit_codes)
    return {
        "repository_full_name": repo_full,
        "anonymous_id": anon_id,
        "scanner": scanner,
        "commit_sha": commit_sha,
        "status": status,
        "exit_code": rc,
        "duration_seconds": duration,
        "finding_count": finding_count,
        "output_file": str(output_host.relative_to(STUDY_ROOT))
                       if _within(output_host, STUDY_ROOT) else str(output_host),
        "error_message": (err.strip()[:200] if rc != 0 and err else None),
    }


def _within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except Exception:
        return False


def run_all(scanner: str, clone_manifest: list[dict], run_fn: RunFn, *,
            image: str = SCANNER_IMAGE, docker: str = "docker",
            pilot: bool = False) -> list[dict]:
    """Run one scanner over every successfully-cloned repository."""
    cfg = common.load_study_config()
    scanner_cfg = common.load_yaml(common.CONFIG_DIR / "scanner-config.yaml")
    isolation = _isolation(scanner_cfg)
    repos_root = STUDY_ROOT / cfg["paths"]["selected_clone"]
    results_raw = STUDY_ROOT / cfg["paths"]["results_raw"] / scanner
    log_path = STUDY_ROOT / cfg["paths"]["logs"] / f"run_{scanner.replace('-', '_')}.jsonl"
    ext = OUTPUT_EXT[scanner]
    ok_codes, finding_codes = exit_semantics_for(scanner, scanner_cfg)
    accepted = ok_codes | finding_codes

    records: list[dict] = []
    for entry in clone_manifest:
        if entry.get("status") != "OK":
            continue
        full = entry["repository_full_name"]
        safe = vca._safe_name(full)
        repo_host = repos_root / safe
        if not repo_host.exists():
            continue
        output_host = results_raw / f"{safe}.{ext}"
        if common.is_valid_json_file(output_host) or output_host.exists():
            continue  # immutable: never re-scan/overwrite an existing raw output
        mounts = [
            (str(repos_root), "/scan/repositories", "ro"),
            (str(STUDY_ROOT / cfg["paths"]["results_raw"]), "/scan/results/raw", "rw"),
            (str(common.CONFIG_DIR), "/scan/config", "ro"),
            (str(STUDY_ROOT / "config" / "semgrep-rules-cache"), "/scan/semgrep-rules", "ro"),
        ]
        rec = run_one(
            scanner, full, entry.get("anonymous_id"), entry.get("checked_out_sha"),
            f"/scan/repositories/{safe}", output_host,
            f"/scan/results/raw/{scanner}/{safe}.{ext}", mounts, image, isolation,
            run_fn, docker, accepted_exit_codes=accepted)
        records.append(rec)
        common.append_jsonl(log_path, {"ts": common.iso_now(), **{
            k: rec[k] for k in ("repository_full_name", "status", "finding_count", "exit_code")}})
    _write_execution_records(records, results_raw / "execution-records")
    return records


def _isolation(scanner_cfg: dict) -> dict:
    iso = scanner_cfg.get("isolation", {})
    return {"user_uid": "10001:10001", "limits": iso.get("limits", {})}


def _write_execution_records(records: list[dict], base: Path) -> None:
    import os
    common.atomic_write_json(base.with_suffix(".json"), records)
    common.ensure_dir(base.parent)
    tmp = base.with_suffix(".csv.tmp")
    with tmp.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=EXEC_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for rec in records:
            writer.writerow(rec)
    os.replace(tmp, base.with_suffix(".csv"))


# =========================================================================== #
# Shared main for the thin run_*.py wrappers
# =========================================================================== #
def cli_main(scanner: str, argv: Optional[list[str]] = None) -> int:
    import argparse
    import shutil
    parser = argparse.ArgumentParser(description=f"Run {scanner} over the cloned sample.")
    parser.add_argument("--pilot", action="store_true")
    args = parser.parse_args(argv)

    cfg = common.load_study_config()
    processed = STUDY_ROOT / cfg["paths"]["processed"]
    selected = processed / "selected-500-repositories.csv"
    if not selected.exists():
        print(f"REFUSING TO SCAN: frozen sample not found ({selected}).", file=sys.stderr)
        print("Run 'make freeze' then 'make select' first.", file=sys.stderr)
        return 2
    manifest_path = processed / "clone-manifest.json"
    if not manifest_path.exists():
        print("ERROR: clone manifest not found. Run 'clone_selected_repositories.py' first.",
              file=sys.stderr)
        return 2

    docker = shutil.which("docker")
    if docker is None:
        print("ERROR: docker not found on PATH.", file=sys.stderr)
        return 2

    def run_fn(cmd: list) -> tuple:
        import subprocess
        iso = common.load_yaml(common.CONFIG_DIR / "scanner-config.yaml").get("isolation", {})
        timeout = int(iso.get("limits", {}).get("scan_timeout_seconds", 1200))
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return proc.returncode, proc.stdout or "", proc.stderr or ""

    clone_manifest = common.read_json(manifest_path)
    records = run_all(scanner, clone_manifest, run_fn, docker=docker, pilot=args.pilot)

    from collections import Counter
    statuses = Counter(r["status"] for r in records)
    findings = sum((r["finding_count"] or 0) for r in records)
    print(f"{scanner}: scanned {len(records)} repositories; statuses={dict(statuses)}; "
          f"total findings={findings}")
    return 0
