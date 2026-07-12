#!/usr/bin/env python3
"""
check_environment.py

Phase 1 environment validation for the study
"Security Analysis of 500 Deployed Web Applications with Detectable Claude
Code-Attributed Development".

Verifies that all required tooling is present, records exact versions, hashes
the configuration files, checks GitHub authentication WITHOUT ever printing or
storing a token, and writes a reproducibility manifest to:

    results/reports/environment-manifest.json

Design constraints:
  * stdlib ONLY (must run before `pip install -r requirements.txt`).
  * Never print, log, or store authentication tokens or secrets.
  * Cross-platform (Windows/win32 primary host; Linux scanner container).
  * Exit non-zero if any REQUIRED tool is missing (unless --no-strict).

Usage:
    python scripts/check_environment.py [--no-strict] [--quiet]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #
STUDY_ROOT = Path(__file__).resolve().parents[1]
CONFIG_DIR = STUDY_ROOT / "config"
MANIFEST_PATH = STUDY_ROOT / "results" / "reports" / "environment-manifest.json"
DOCKERFILE_SCANNER = STUDY_ROOT / "docker" / "Dockerfile.scanner"
SCANNER_IMAGE = "claude-study-scanner:latest"

# Dockerfile build-arg -> scanner name. These pinned versions (not the host
# versions) are what actually run during scanning, so we record and reconcile them.
DOCKERFILE_SCANNER_ARGS = {
    "GITLEAKS_VERSION": "gitleaks",
    "TRIVY_VERSION": "trivy",
    "OSV_SCANNER_VERSION": "osv-scanner",
    "SEMGREP_VERSION": "semgrep",
    "ZIZMOR_VERSION": "zizmor",
}

# --------------------------------------------------------------------------- #
# Tool registry: name -> (executable, version_args, required)
# version_args is the argument list appended to the executable.
# --------------------------------------------------------------------------- #
TOOLS = {
    "git":         (["git"],         ["--version"], True),
    "gh":          (["gh"],          ["--version"], True),
    "docker":      (["docker"],      ["--version"], True),
    "gitleaks":    (["gitleaks"],    ["version"],   True),
    "semgrep":     (["semgrep"],     ["--version"], True),
    "trivy":       (["trivy"],       ["--version"], True),
    "osv-scanner": (["osv-scanner"], ["--version"], True),
    "zizmor":      (["zizmor"],      ["--version"], True),
    # LOC counters: at least one of these is required (checked separately).
    "tokei":       (["tokei"],       ["--version"], False),
    "cloc":        (["cloc"],        ["--version"], False),
}

# Python packages whose versions we record (not required for THIS script to run).
PYTHON_PACKAGES = [
    "pandas", "numpy", "scipy", "statsmodels", "matplotlib", "seaborn",
    "requests", "PyYAML", "yaml", "python-dateutil", "dateutil",
    "tenacity", "tqdm", "jsonschema", "pytest",
]

SUBPROCESS_TIMEOUT = 20  # seconds; never hang the check


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _run(cmd: list[str]) -> tuple[int, str, str]:
    """Run a command safely; return (returncode, stdout, stderr). Never raises."""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT,
            check=False,
            shell=False,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except FileNotFoundError:
        return 127, "", "not found"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as exc:  # pragma: no cover - defensive
        return 1, "", f"error: {type(exc).__name__}"


def _first_version_line(text: str) -> str:
    """Extract a compact version string from tool output."""
    text = (text or "").strip()
    if not text:
        return ""
    first = text.splitlines()[0].strip()
    # Prefer a semver-ish token if present, else the whole first line.
    m = re.search(r"\d+\.\d+(?:\.\d+)?(?:[-+.\w]*)?", first)
    return first if not m else first


def check_tool(name: str) -> dict:
    exe_list, version_args, required = TOOLS[name]
    exe = exe_list[0]
    resolved = shutil.which(exe)
    result = {
        "name": name,
        "required": required,
        "present": resolved is not None,
        "path": resolved,
        "version": None,
        "raw_version": None,
        "error": None,
    }
    if resolved is None:
        result["error"] = "executable not found on PATH"
        return result

    rc, out, err = _run([resolved, *version_args])
    combined = out if out.strip() else err
    if rc in (0,) or combined.strip():
        result["version"] = _first_version_line(combined)
        # Keep a short raw snippet for auditing (safe: version banners only).
        result["raw_version"] = (combined.strip().splitlines() or [""])[0][:200]
    else:
        result["error"] = f"version command exited {rc}"
    return result


def check_loc_counter(tools_report: dict) -> dict:
    """At least one of tokei/cloc must be present."""
    tokei_ok = tools_report.get("tokei", {}).get("present", False)
    cloc_ok = tools_report.get("cloc", {}).get("present", False)
    return {
        "requirement": "at least one of tokei/cloc",
        "tokei_present": tokei_ok,
        "cloc_present": cloc_ok,
        "satisfied": bool(tokei_ok or cloc_ok),
        "preferred": "tokei" if tokei_ok else ("cloc" if cloc_ok else None),
    }


def check_python() -> dict:
    return {
        "executable": sys.executable,
        "version": platform.python_version(),
        "version_tuple": list(sys.version_info[:3]),
        "meets_minimum_3_11": sys.version_info[:2] >= (3, 11),
        "implementation": platform.python_implementation(),
    }


def check_python_packages() -> dict:
    """Record installed versions of analysis packages (best effort)."""
    versions: dict[str, str | None] = {}
    try:
        from importlib import metadata as importlib_metadata
    except Exception:  # pragma: no cover
        importlib_metadata = None

    seen = set()
    for pkg in PYTHON_PACKAGES:
        key = pkg.lower()
        if key in seen:
            continue
        seen.add(key)
        ver = None
        if importlib_metadata is not None:
            try:
                ver = importlib_metadata.version(pkg)
            except Exception:
                ver = None
        versions[pkg] = ver
    return versions


def check_github_auth() -> dict:
    """
    Check `gh auth status` WITHOUT capturing tokens.

    We record only: authenticated (bool), hosts (list), and token scopes
    (scopes are not secret). Any line mentioning a token value is discarded.
    """
    gh = shutil.which("gh")
    report = {
        "gh_present": gh is not None,
        "authenticated": False,
        "hosts": [],
        "scopes": [],
        "note": "token values are never captured or stored",
    }
    if gh is None:
        report["note"] = "gh not installed"
        return report

    rc, out, err = _run([gh, "auth", "status"])
    text = f"{out}\n{err}"
    report["authenticated"] = rc == 0 and "Logged in to" in text

    for line in text.splitlines():
        low = line.lower()
        # Never process any line that could contain a token.
        if "token:" in low or re.search(r"gh[posu]_[A-Za-z0-9]", line):
            continue
        m_host = re.search(r"Logged in to ([\w.\-]+)", line)
        if m_host:
            host = m_host.group(1)
            if host not in report["hosts"]:
                report["hosts"].append(host)
        m_scopes = re.search(r"Token scopes:\s*(.+)$", line)
        if m_scopes:
            scopes = re.findall(r"'([^']+)'", m_scopes.group(1))
            report["scopes"] = scopes
    return report


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def hash_configs() -> dict:
    result = {}
    if not CONFIG_DIR.is_dir():
        return {"_error": f"config dir not found: {CONFIG_DIR}"}
    for path in sorted(CONFIG_DIR.iterdir()):
        if path.is_file():
            try:
                result[path.name] = _sha256_file(path)
            except Exception as exc:  # pragma: no cover
                result[path.name] = f"error: {type(exc).__name__}"
    return result


def docker_image_digests(image_names: list[str]) -> dict:
    """Best-effort image digest lookup; null when not built yet / docker absent."""
    docker = shutil.which("docker")
    digests: dict[str, str | None] = {}
    if docker is None:
        return {name: None for name in image_names}
    for name in image_names:
        rc, out, _ = _run([docker, "image", "inspect", name,
                           "--format", "{{index .RepoDigests 0}}"])
        digests[name] = out.strip() if rc == 0 and out.strip() else None
    return digests


def _extract_semver(text: str | None) -> str | None:
    """First semver-ish token in a version banner (e.g. 'Version: 0.72.0' -> '0.72.0')."""
    if not text:
        return None
    m = re.search(r"\d+\.\d+(?:\.\d+)?", text)
    return m.group(0) if m else None


def parse_scanner_pins(dockerfile_path: Path = DOCKERFILE_SCANNER) -> dict:
    """Read the scanner Dockerfile's `ARG *_VERSION=` pins (scanner -> version)."""
    pins: dict[str, str] = {}
    try:
        text = dockerfile_path.read_text(encoding="utf-8")
    except Exception:
        return pins
    for arg, scanner in DOCKERFILE_SCANNER_ARGS.items():
        m = re.search(rf"ARG\s+{arg}\s*=\s*(\S+)", text)
        if m:
            pins[scanner] = m.group(1).strip()
    return pins


def reconcile_scanner_versions(tools_report: dict, pins: dict) -> dict:
    """
    Compare host scanner versions against the Dockerfile-pinned versions.

    The PINNED (container) versions are authoritative for scanning; host versions
    are informational. Drift is recorded, never silently ignored — a reproducible
    scan must run the pinned toolchain, not whatever happens to be on the host.
    """
    scanners = []
    drift = []
    for scanner, pinned in sorted(pins.items()):
        rep = tools_report.get(scanner, {})
        host_present = rep.get("present", False)
        host_sem = _extract_semver(rep.get("version")) if host_present else None
        matches = (host_sem == pinned) if host_sem is not None else None
        if matches is False:
            drift.append(scanner)
        scanners.append({
            "scanner": scanner,
            "pinned_version": pinned,       # authoritative (runs in the container)
            "host_version": host_sem,       # informational only
            "host_present": host_present,
            "matches_host": matches,
        })
    return {
        "note": "pinned (container) versions are authoritative for scanning; "
                "host versions are informational only",
        "scanners": scanners,
        "host_pin_drift": drift,
        "drift_detected": bool(drift),
    }


def host_info() -> dict:
    tzname = time.tzname[0] if time.tzname else None
    try:
        local_offset = -time.timezone // 3600
    except Exception:
        local_offset = None
    return {
        "operating_system": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "platform": sys.platform,
        "architecture": platform.machine(),
        "processor": platform.processor(),
        "hostname_recorded": False,  # deliberately not recorded (privacy)
        "timezone_name": tzname,
        "utc_offset_hours": local_offset,
        "collection_date_utc": _now_iso(),
    }


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def build_manifest() -> dict:
    tools_report = {name: check_tool(name) for name in TOOLS}
    loc_report = check_loc_counter(tools_report)
    scanner_pins = parse_scanner_pins()
    manifest = {
        "study": "claude-deployed-security-study",
        "manifest_schema_version": 1,
        "generated_utc": _now_iso(),
        "host": host_info(),
        "python": check_python(),
        "python_packages": check_python_packages(),
        "tools": tools_report,
        "loc_counter": loc_report,
        "github_auth": check_github_auth(),
        "config_hashes": hash_configs(),
        "container_image_digests": docker_image_digests(
            ["claude-study-collector:latest", SCANNER_IMAGE]
        ),
        "pinned_scanner_versions": scanner_pins,
        "scanner_version_reconciliation": reconcile_scanner_versions(tools_report, scanner_pins),
    }
    return manifest


# Tools needed to DISCOVER candidates (Phases 2-18). LOC counter also needed pre-scan.
COLLECTION_TOOLS = {"git", "gh"}
# Static scanners (Phases 20-28). These run INSIDE the Linux scanner container,
# so host absence is acceptable when Docker is available.
SCANNER_TOOLS = {"gitleaks", "semgrep", "trivy", "osv-scanner", "zizmor"}
# Scanners with NO native Windows build — only ever provided via the container.
CONTAINER_ONLY_SCANNERS = {"semgrep"}


def evaluate_readiness(manifest: dict) -> dict:
    """
    Tiered readiness. Collection readiness gates candidate discovery (the near-term
    step); scanning readiness gates the scanner phases. Scanners run in the Docker
    scanner container, so their host absence is not a hard blocker when Docker is
    present (semgrep in particular has no native Windows build).
    """
    tools = manifest["tools"]
    py_ok = manifest["python"]["meets_minimum_3_11"]
    auth_ok = manifest["github_auth"]["authenticated"]
    docker_ok = tools.get("docker", {}).get("present", False)

    # --- collection tier ---
    collection_problems: list[str] = []
    if not py_ok:
        collection_problems.append("Python 3.11+ required")
    for name in sorted(COLLECTION_TOOLS):
        if not tools.get(name, {}).get("present"):
            collection_problems.append(f"required tool missing: {name}")
    if not auth_ok:
        collection_problems.append("GitHub CLI not authenticated (run: gh auth login)")
    collection_ready = not collection_problems

    # --- scanning tier ---
    # Scanning runs the PINNED toolchain inside the scanner container, so the
    # gate is: a LOC counter, Docker, and a BUILT+pinned scanner image. Host
    # scanner presence is informational only. Reporting "READY" while the image
    # is unbuilt (digest null) would misrepresent reproducibility.
    scanning_problems: list[str] = []
    host_scanner_missing = sorted(
        s for s in SCANNER_TOOLS if not tools.get(s, {}).get("present")
    )
    if not manifest["loc_counter"]["satisfied"]:
        scanning_problems.append("no LOC counter (need tokei or cloc)")
    if not docker_ok:
        scanning_problems.append(
            "docker not present: the scanner container cannot run (host-native "
            "scanning is unsupported; e.g. semgrep has no Windows build)"
        )
    scanner_image_digest = manifest.get("container_image_digests", {}).get(SCANNER_IMAGE)
    scanner_image_built = scanner_image_digest is not None
    if not scanner_image_built:
        scanning_problems.append(
            f"scanner image not built/pinned ({SCANNER_IMAGE} digest is null); "
            "build the image and record its digest before scanning"
        )
    scanning_ready = not scanning_problems

    recon = manifest.get("scanner_version_reconciliation", {})
    drift = recon.get("host_pin_drift", [])

    notes: list[str] = []
    if "semgrep" in host_scanner_missing:
        notes.append("semgrep has no native Windows build; it runs in the Linux scanner container (Docker).")
    if not scanner_image_built:
        notes.append(
            f"scanning is NOT ready until '{SCANNER_IMAGE}' is built and its digest recorded "
            "(this is the deliberate pin/freeze step, not a scan-time afterthought)."
        )
    if drift:
        notes.append(
            "host scanner versions differ from the Dockerfile-pinned versions "
            f"({', '.join(drift)}); the pinned (container) versions are authoritative for scanning."
        )

    return {
        "collection_ready": collection_ready,
        "collection_problems": collection_problems,
        "scanning_ready": scanning_ready,
        "scanning_problems": scanning_problems,
        "scanner_image_built": scanner_image_built,
        "host_scanners_missing": host_scanner_missing,
        "notes": notes,
        "ready": collection_ready and scanning_ready,
    }


def _atomic_write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=False), encoding="utf-8")
    os.replace(tmp, path)


def print_summary(manifest: dict, readiness: dict) -> None:
    print("=" * 70)
    print("Environment check -", manifest["study"])
    print("=" * 70)
    h = manifest["host"]
    print(f"OS         : {h['operating_system']} {h['os_release']} ({h['platform']}/{h['architecture']})")
    print(f"Python     : {manifest['python']['version']} "
          f"({'OK' if manifest['python']['meets_minimum_3_11'] else 'TOO OLD'})")
    print(f"Timezone   : {h['timezone_name']} (records stored in UTC)")
    print("-" * 70)
    for name, rep in manifest["tools"].items():
        flag = "REQ" if rep["required"] else "opt"
        status = rep["version"] if rep["present"] else "MISSING"
        mark = "OK " if rep["present"] else "-- "
        print(f"  [{mark}] ({flag}) {name:<12} {status}")
    lc = manifest["loc_counter"]
    print(f"  LOC counter satisfied: {lc['satisfied']} (preferred: {lc['preferred']})")
    ga = manifest["github_auth"]
    print(f"  GitHub auth : authenticated={ga['authenticated']} hosts={ga['hosts']} scopes={ga['scopes']}")
    print("-" * 70)

    def _tier(name: str, ok: bool, problems: list[str]) -> None:
        print(f"{name}: {'READY' if ok else 'NOT READY'}")
        for p in problems:
            print(f"   - {p}")

    _tier("Collection readiness", readiness["collection_ready"], readiness["collection_problems"])
    _tier("Scanning readiness  ", readiness["scanning_ready"], readiness["scanning_problems"])
    recon = manifest.get("scanner_version_reconciliation", {})
    if recon.get("scanners"):
        pins = ", ".join(f"{s['scanner']}={s['pinned_version']}" for s in recon["scanners"])
        print(f"Scanner pins (container, authoritative): {pins}")
        drift = recon.get("host_pin_drift", [])
        print(f"   host/pin drift: {', '.join(drift) if drift else 'none'}")
    for note in readiness["notes"]:
        print(f"   note: {note}")
    print("-" * 70)
    print(f"Manifest written to: {MANIFEST_PATH.relative_to(STUDY_ROOT)}")
    print("=" * 70)


def exit_code_for(readiness: dict, *, strict_scan: bool = False,
                  no_strict: bool = False) -> int:
    """
    Decide the process exit code from readiness.

    Default: collection readiness is the near-term gate (0 if collection is
    ready). `--strict-scan` additionally REQUIRES scanning readiness, so
    automation that treats a clean exit as full environment readiness cannot
    proceed into scanning phases while the scanner image is unbuilt/unpinned.
    `--no-strict` forces success regardless.
    """
    if no_strict:
        return 0
    ok = readiness["collection_ready"]
    if strict_scan:
        ok = ok and readiness["scanning_ready"]
    return 0 if ok else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate study environment.")
    parser.add_argument("--no-strict", action="store_true",
                        help="exit 0 even if required tools are missing")
    parser.add_argument("--strict-scan", action="store_true",
                        help="also require SCANNING readiness (built+pinned scanner image) to exit 0")
    parser.add_argument("--quiet", action="store_true",
                        help="suppress human-readable summary")
    args = parser.parse_args()

    manifest = build_manifest()
    readiness = evaluate_readiness(manifest)
    manifest["readiness"] = readiness

    _atomic_write_json(MANIFEST_PATH, manifest)

    if not args.quiet:
        print_summary(manifest, readiness)
        if args.strict_scan and not readiness["scanning_ready"]:
            print("STRICT-SCAN: scanning readiness required but NOT met (see problems above).")

    return exit_code_for(readiness, strict_scan=args.strict_scan, no_strict=args.no_strict)


if __name__ == "__main__":
    raise SystemExit(main())
