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
OUTPUT_EXT = {"gitleaks": "json", "gitleaks-history": "json", "semgrep": "sarif",
              "trivy": "json", "osv-scanner": "json", "zizmor": "sarif"}

EXEC_FIELDS = ["repository_full_name", "anonymous_id", "scanner", "commit_sha",
               "scanner_version", "ruleset_or_db_hash", "image_digest",
               "configuration_hash", "status", "exit_code", "start_time", "end_time",
               "duration_seconds", "timeout_status", "finding_count", "files_analysed",
               "schema_valid", "reused", "output_file", "error_message"]

# Identity fields that MUST match before an existing raw output may be reused.
IDENTITY_FIELDS = ["repository_full_name", "commit_sha", "scanner", "scanner_version",
                   "ruleset_or_db_hash", "image_digest", "configuration_hash"]


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
    "gitleaks": count_gitleaks, "gitleaks-history": count_gitleaks,
    "semgrep": count_semgrep, "trivy": count_trivy,
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


def build_run_context(scanner: str, ready_marker: Optional[dict]) -> dict:
    """Identity of the CURRENT pinned toolchain (from the SCANNERS_READY marker)
    that every raw output is stamped with and validated against."""
    m = ready_marker or {}
    versions = m.get("pinned_scanner_versions", {}) or {}
    version_key = "gitleaks" if scanner == "gitleaks-history" else scanner
    if scanner == "semgrep":
        rd_hash = m.get("semgrep_ruleset_hash")
    elif scanner == "trivy":
        rd_hash = (m.get("database_snapshots", {}).get("trivy_db", {}) or {}).get("snapshot_utc")
    elif scanner == "osv-scanner":
        rd_hash = (m.get("database_snapshots", {}).get("osv_db", {}) or {}).get("snapshot_utc")
    else:
        rd_hash = ""                       # gitleaks/zizmor: no external ruleset/DB
    return {
        "scanner_version": versions.get(version_key),
        "ruleset_or_db_hash": rd_hash,
        "image_digest": m.get("image_digest") or m.get("image_id"),
        "configuration_hash": m.get("configuration_hash") or common.config_bundle_hash(),
    }


def _files_analysed(scanner: str, text: str) -> Optional[int]:
    """Best-effort count of files the scanner reported on (not all expose this)."""
    obj = _load(text)
    if scanner in ("semgrep", "zizmor") and isinstance(obj, dict):
        uris = set()
        for run in obj.get("runs") or []:
            for r in (run.get("results") or []):
                for loc in (r.get("locations") or []):
                    uri = (loc.get("physicalLocation", {}).get("artifactLocation", {})
                           .get("uri"))
                    if uri:
                        uris.add(uri)
        return len(uris) or None
    if scanner == "trivy" and isinstance(obj, dict):
        return len(obj.get("Results") or []) or None
    return None


def run_one(scanner: str, repo_full: str, anon_id: Optional[str], commit_sha: Optional[str],
            repo_container_path: str, output_host: Path, output_container_path: str,
            mounts: list[tuple], image: str, isolation: dict,
            run_fn: RunFn, docker: str = "docker",
            accepted_exit_codes: Optional[set] = None,
            run_context: Optional[dict] = None) -> dict:
    """Run one scanner on one repo; the container writes `output_host`. Returns a
    COMPLETE execution record (identity + times + status). A 'findings' exit code
    is a success (output parsed); a genuine failure is never recorded as zero."""
    if accepted_exit_codes is None:
        ok, findings = exit_semantics_for(scanner)
        accepted_exit_codes = ok | findings
    ctx = run_context or {}
    argv = build_docker_run_args(scanner, repo_container_path, output_container_path,
                                 mounts, image, isolation)
    common.ensure_dir(output_host.parent)
    start_iso, start = common.iso_now(), time.monotonic()
    timed_out = False
    try:
        rc, _out, err = run_fn([docker, *argv])
    except TimeoutError:
        rc, err, timed_out = 124, "timeout", True
    duration = round(time.monotonic() - start, 2)
    end_iso = common.iso_now()

    finding_count: Optional[int] = None
    files_analysed: Optional[int] = None
    schema_valid = False
    if rc in accepted_exit_codes and not timed_out and output_host.exists():
        text = output_host.read_text(encoding="utf-8", errors="replace")
        finding_count = FINDING_PARSERS[scanner](text)
        schema_valid = finding_count is not None
        files_analysed = _files_analysed(scanner, text)

    status = classify_execution(rc, timed_out, finding_count, accepted_exit_codes)
    return {
        "repository_full_name": repo_full,
        "anonymous_id": anon_id,
        "scanner": scanner,
        "commit_sha": commit_sha,
        "scanner_version": ctx.get("scanner_version"),
        "ruleset_or_db_hash": ctx.get("ruleset_or_db_hash"),
        "image_digest": ctx.get("image_digest"),
        "configuration_hash": ctx.get("configuration_hash"),
        "status": status,
        "exit_code": rc,
        "start_time": start_iso,
        "end_time": end_iso,
        "duration_seconds": duration,
        "timeout_status": "TIMEOUT" if timed_out else "OK",
        "finding_count": finding_count,
        "files_analysed": files_analysed,
        "schema_valid": schema_valid,
        "reused": False,
        "output_file": str(output_host.relative_to(STUDY_ROOT))
                       if _within(output_host, STUDY_ROOT) else str(output_host),
        "error_message": (err.strip()[:200] if rc not in accepted_exit_codes and err else None),
    }


def _within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except Exception:
        return False


def validate_existing_output(output_host: Path, sidecar: Path, scanner: str,
                             repo_full: str, commit_sha: Optional[str],
                             ctx: dict) -> tuple[bool, list]:
    """True only if the cached raw output is schema-valid AND every identity field
    (repo, frozen SHA, scanner version, ruleset/DB hash, image digest, config hash)
    matches the current context. Otherwise the caller must quarantine + re-scan."""
    reasons: list[str] = []
    if not output_host.exists():
        return False, ["no_output"]
    if not sidecar.exists():
        return False, ["no_sidecar_record"]
    try:
        rec = common.read_json(sidecar)
    except Exception:
        return False, ["unreadable_sidecar"]
    if FINDING_PARSERS[scanner](output_host.read_text(encoding="utf-8", errors="replace")) is None:
        reasons.append("output_schema_invalid")
    expected = {"repository_full_name": repo_full, "commit_sha": commit_sha,
                "scanner": scanner, "scanner_version": ctx.get("scanner_version"),
                "ruleset_or_db_hash": ctx.get("ruleset_or_db_hash"),
                "image_digest": ctx.get("image_digest"),
                "configuration_hash": ctx.get("configuration_hash")}
    for field in IDENTITY_FIELDS:
        if rec.get(field) != expected[field]:
            reasons.append(f"identity_mismatch:{field}")
    return (not reasons), reasons


def _quarantine(output_host: Path, sidecar: Path, results_raw: Path, reasons: list) -> None:
    import shutil
    qdir = results_raw / "quarantine" / common.iso_now().replace(":", "").replace("-", "")
    common.ensure_dir(qdir)
    for p in (output_host, sidecar):
        if p.exists():
            shutil.move(str(p), str(qdir / p.name))
    common.atomic_write_json(qdir / "reason.json", {"reasons": reasons, "ts": common.iso_now()})


def run_all(scanner: str, clone_manifest: list[dict], run_fn: RunFn, *,
            image: Optional[str] = None, docker: str = "docker",
            ready_marker: Optional[dict] = None, pilot_ids: Optional[set] = None,
            repos_root: Optional[Path] = None) -> list[dict]:
    """Run one scanner over every successfully-cloned repository, with immutable
    append-only records + per-repo sidecars and validated/quarantined reuse.
    `repos_root` overrides the clone root (e.g. the history mirror for
    gitleaks-history); results are written under results/raw/<scanner>/."""
    cfg = common.load_study_config()
    scanner_cfg = common.load_yaml(common.CONFIG_DIR / "scanner-config.yaml")
    isolation = _isolation(scanner_cfg)
    ctx = build_run_context(scanner, ready_marker)
    image = image or (ctx.get("image_digest") or SCANNER_IMAGE)
    repos_root = repos_root or (STUDY_ROOT / cfg["paths"]["selected_clone"])
    results_raw = STUDY_ROOT / cfg["paths"]["results_raw"] / scanner
    events_path = results_raw / "execution-records.jsonl"       # append-only, never overwritten
    log_path = STUDY_ROOT / cfg["paths"]["logs"] / f"run_{scanner.replace('-', '_')}.jsonl"
    ext = OUTPUT_EXT[scanner]
    ok_codes, finding_codes = exit_semantics_for(scanner, scanner_cfg)
    accepted = ok_codes | finding_codes

    records: list[dict] = []
    for entry in clone_manifest:
        if entry.get("status") != "OK":
            continue
        full = entry["repository_full_name"]
        if pilot_ids is not None and entry.get("anonymous_id") not in pilot_ids:
            continue
        safe = vca._safe_name(full)
        repo_host = repos_root / safe
        if not repo_host.exists():
            continue
        output_host = results_raw / f"{safe}.{ext}"
        sidecar = results_raw / f"{safe}.record.json"
        commit_sha = entry.get("checked_out_sha")

        if output_host.exists() or sidecar.exists():
            valid, reasons = validate_existing_output(output_host, sidecar, scanner,
                                                      full, commit_sha, ctx)
            if valid:
                rec = common.read_json(sidecar)
                rec["reused"] = True
                records.append(rec)
                _append_event(events_path, log_path, rec)
                continue
            # Invalid/stale -> quarantine and re-scan (do NOT skip on path existence).
            _quarantine(output_host, sidecar, results_raw, reasons)

        mounts = [
            (str(repos_root), "/scan/repositories", "ro"),
            (str(STUDY_ROOT / cfg["paths"]["results_raw"]), "/scan/results/raw", "rw"),
            (str(common.CONFIG_DIR), "/scan/config", "ro"),
            (str(STUDY_ROOT / "config" / "semgrep-rules-cache"), "/scan/semgrep-rules", "ro"),
            (str(STUDY_ROOT / "config" / "trivy-cache"), "/scan/trivy-cache", "ro"),
            (str(STUDY_ROOT / "config" / "osv-db"), "/scan/osv-db", "ro"),
        ]
        rec = run_one(
            scanner, full, entry.get("anonymous_id"), commit_sha,
            f"/scan/repositories/{safe}", output_host,
            f"/scan/results/raw/{scanner}/{safe}.{ext}", mounts, image, isolation,
            run_fn, docker, accepted_exit_codes=accepted, run_context=ctx)
        common.atomic_write_json(sidecar, rec)          # one record per repo x scanner
        records.append(rec)
        _append_event(events_path, log_path, rec)
    return records


def _append_event(events_path: Path, log_path: Path, rec: dict) -> None:
    common.append_jsonl(events_path, {"event_ts": common.iso_now(), **rec})
    common.append_jsonl(log_path, {"ts": common.iso_now(), **{
        k: rec.get(k) for k in ("repository_full_name", "status", "finding_count",
                                "exit_code", "reused")}})


def _isolation(scanner_cfg: dict) -> dict:
    iso = scanner_cfg.get("isolation", {})
    return {"user_uid": "10001:10001", "limits": iso.get("limits", {})}


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

    # SCANNERS_READY gate: refuse (pilot AND scan) unless the pinned toolchain is
    # prepared and neither the config nor the image has drifted since prepare.
    try:
        from . import prepare_scanners as ps  # type: ignore
    except Exception:  # pragma: no cover
        import prepare_scanners as ps  # type: ignore
    marker = ps.load_ready_marker()
    state, reasons = ps.scanners_ready_state(
        marker, common.config_bundle_hash(), (marker or {}).get("image_digest"))
    if state != "READY":
        print(f"REFUSING TO SCAN: SCANNERS_READY is {state} ({reasons}).", file=sys.stderr)
        print("Run 'make prepare-scanners' first.", file=sys.stderr)
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
    pilot_ids = None
    if args.pilot:
        size = int(common.load_yaml(common.CONFIG_DIR / "scanner-config.yaml")
                   .get("pilot", {}).get("size", 10))
        ok_ids = sorted(r.get("anonymous_id") for r in clone_manifest
                        if r.get("status") == "OK" and r.get("anonymous_id"))
        pilot_ids = set(ok_ids[:size])

    # Gitleaks history scans the bare MIRROR clones, not the working tree.
    repos_root = None
    if scanner == "gitleaks-history":
        repos_root = STUDY_ROOT / cfg["paths"].get("history_clone", "repositories/history")

    records = run_all(scanner, clone_manifest, run_fn, docker=docker,
                      ready_marker=marker, pilot_ids=pilot_ids, repos_root=repos_root)

    from collections import Counter
    statuses = Counter(r["status"] for r in records)
    findings = sum((r["finding_count"] or 0) for r in records)
    print(f"{scanner}: scanned {len(records)} repositories; statuses={dict(statuses)}; "
          f"total findings={findings}")
    return 0
