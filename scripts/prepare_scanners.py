#!/usr/bin/env python3
"""
prepare_scanners.py — Phase 19 scanner preparation (build + pin + freeze).

The deliberate pin/freeze step that MUST happen before any scanning. It:
  * builds the locked-down scanner image and records its digest;
  * exports + pins every Semgrep rule pack locally and hashes the rule files;
  * downloads + pins the Trivy vuln DB into an explicit cache dir;
  * downloads + pins the OSV offline DB into an explicit dir;
  * smoke-tests all five scanners in the image;
  * records scanner versions, DB snapshot dates, the Semgrep ruleset hash, the
    image digest, and the configuration hash into a SCANNERS_READY marker.

FAIL-CLOSED: if any required cache/ruleset is missing or any smoke test fails,
`ready` is false and pilot/scan refuse to run (see scanners_ready_state). Caches
are mounted under EXPLICIT container paths and passed to Trivy/OSV — never their
default cache locations.

MANDATORY ORDER (scanner-config.yaml offline_sequencing): pre-fetch + pin WITH
network here, snapshot locally, THEN scans run offline against these snapshots.

Pure command-building + marker logic is split from the injectable `run_fn`, so
the sequence + fail-closed + staleness logic are unit-tested WITHOUT docker/net.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Callable, Optional

try:
    from . import _common as common  # type: ignore
    from . import check_environment as ce  # type: ignore
except Exception:  # pragma: no cover
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _common as common  # type: ignore
    import check_environment as ce  # type: ignore

STUDY_ROOT = common.STUDY_ROOT
SCANNER_IMAGE = "claude-study-scanner:latest"
PREP_MANIFEST = STUDY_ROOT / "results" / "reports" / "scanner-preparation-manifest.json"
SCANNERS_READY_PATH = STUDY_ROOT / "results" / "reports" / "SCANNERS_READY.json"

SEMGREP_CACHE = STUDY_ROOT / "config" / "semgrep-rules-cache"
TRIVY_CACHE = STUDY_ROOT / "config" / "trivy-cache"
OSV_DB_DIR = STUDY_ROOT / "config" / "osv-db"
# Explicit in-container cache paths (passed to the scanners; never defaults).
CONTAINER_SEMGREP_RULES = "/scan/semgrep-rules"
CONTAINER_TRIVY_CACHE = "/scan/trivy-cache"
CONTAINER_OSV_DB = "/scan/osv-db"

FIVE_SCANNERS = ["gitleaks", "semgrep", "trivy", "osv-scanner", "zizmor"]
SMOKE_BIN = {"gitleaks": ["gitleaks", "version"], "semgrep": ["semgrep", "--version"],
             "trivy": ["trivy", "--version"], "osv-scanner": ["osv-scanner", "--version"],
             "zizmor": ["zizmor", "--version"]}


# =========================================================================== #
# PURE: command builders
# =========================================================================== #
def build_image_args(dockerfile: str, image: str, context: str = ".") -> list[str]:
    return ["build", "-f", dockerfile, "-t", image, context]


def inspect_digest_args(image: str) -> list[str]:
    return ["image", "inspect", image, "--format", "{{index .RepoDigests 0}}"]


def inspect_id_args(image: str) -> list[str]:
    return ["image", "inspect", image, "--format", "{{.Id}}"]


def build_semgrep_export_args(ruleset: str, out_file: str) -> list[str]:
    """Export/pin one Semgrep rule pack to a local file (network on)."""
    return ["--config", ruleset, "--dump-config", "--json", "--output", out_file]


def build_trivy_download_args(cache_dir: str) -> list[str]:
    return ["fs", "--download-db-only", "--cache-dir", cache_dir]


def build_osv_download_args(db_dir: str) -> list[str]:
    return ["--experimental-download-offline-databases", "--experimental-local-db-path", db_dir]


def build_smoke_args(scanner: str, image: str) -> list[str]:
    """`docker run` argv that runs a scanner's version check (entrypoint overridden)."""
    binargs = SMOKE_BIN[scanner]
    return ["run", "--rm", "--network", "none", "--entrypoint", binargs[0], image, *binargs[1:]]


# --------------------------------------------------------------------------- #
# In-container asset prep (host-independent; uses the IMAGE's pinned binaries).
# The host's trivy/osv/semgrep may be absent or a different version (e.g. host
# osv 2.x drops the flag image osv 1.9.2 needs, and semgrep has no Windows build).
# --------------------------------------------------------------------------- #
def semgrep_registry_url(ruleset: str) -> str:
    """Registry URL that returns a pinned ruleset as a single combined rule YAML."""
    return f"https://semgrep.dev/c/{ruleset}"


def build_trivy_incontainer_args(image: str, cache_host: str,
                                 cache_container: str = "/trivycache") -> list[str]:
    """`docker run` argv: download the Trivy DB with the IMAGE's trivy into a mount."""
    return ["run", "--rm", "-v", f"{cache_host}:{cache_container}:rw",
            "--entrypoint", "trivy", image,
            "fs", "--download-db-only", "--cache-dir", cache_container]


def build_osv_incontainer_args(image: str, target_host: str, db_host: str,
                               target_container: str = "/osvtarget",
                               db_container: str = "/osvdb") -> list[str]:
    """`docker run` argv: download the OSV offline DB with the IMAGE's osv-scanner
    (1.9.2 flags) into a mount. A tiny npm lockfile target drives the npm ecosystem."""
    return ["run", "--rm",
            "-v", f"{target_host}:{target_container}:ro",
            "-v", f"{db_host}:{db_container}:rw",
            "--entrypoint", "osv-scanner", image,
            "--experimental-offline", "--experimental-download-offline-databases",
            "--experimental-local-db-path", db_container, "--recursive", target_container]


def fetch_semgrep_rules(rulesets: list, cache_dir: Path, fetch_fn) -> int:
    """Write each pinned ruleset's registry YAML into cache_dir via injectable
    fetch_fn(url)->str|bytes. Returns the count written. Skips empty responses."""
    common.ensure_dir(cache_dir)
    written = 0
    for rs in rulesets:
        body = fetch_fn(semgrep_registry_url(rs))
        if not body:
            continue
        text = body.decode("utf-8", "replace") if isinstance(body, bytes) else body
        (cache_dir / f"{rs.replace('/', '_')}.yml").write_text(text, encoding="utf-8")
        written += 1
    return written


def _default_http_fetch(url: str) -> str:
    import urllib.request
    with urllib.request.urlopen(url, timeout=60) as resp:  # nosec - fixed semgrep.dev host
        return resp.read().decode("utf-8", "replace")


def run_incontainer_asset_prep(docker: str, image: str, run_fn: RunFn,
                               fetch_fn=None) -> int:
    """Populate the pinned offline caches using the IMAGE's binaries + the registry,
    so preparation does NOT depend on host scanner binaries (which may be absent or a
    different version). Returns 0 iff Trivy DB + OSV DB + Semgrep rules were produced."""
    fetch_fn = fetch_fn or _default_http_fetch
    scanner_cfg = common.load_yaml(common.CONFIG_DIR / "scanner-config.yaml")
    rulesets = scanner_cfg.get("scanners", {}).get("semgrep", {}).get("rulesets", [])
    rc = 0

    # Semgrep rules from the registry (semgrep has no Windows build; this is host-agnostic).
    try:
        n = fetch_semgrep_rules(rulesets, SEMGREP_CACHE, fetch_fn)
        if n == 0:
            rc = 1
    except Exception as exc:  # pragma: no cover
        print(f"semgrep rule fetch failed: {exc}", file=sys.stderr)
        rc = 1

    # Trivy DB via the image's trivy.
    common.ensure_dir(TRIVY_CACHE)
    trc, _, terr = run_fn([docker, *build_trivy_incontainer_args(image, str(TRIVY_CACHE))])
    if trc != 0:
        print(f"trivy DB download failed: {terr[:200]}", file=sys.stderr)
        rc = 1

    # OSV DB via the image's osv-scanner (needs a tiny npm lockfile target).
    common.ensure_dir(OSV_DB_DIR)
    target = STUDY_ROOT / "config" / "_osv-seed-target"
    common.ensure_dir(target)
    (target / "package-lock.json").write_text(
        '{"name":"seed","version":"1.0.0","lockfileVersion":3,'
        '"packages":{"":{"dependencies":{"lodash":"4.17.20"}},'
        '"node_modules/lodash":{"version":"4.17.20"}}}', encoding="utf-8")
    orc, _, oerr = run_fn([docker, *build_osv_incontainer_args(
        image, str(target), str(OSV_DB_DIR))])
    # osv-scanner exits 1 when it FINDS vulns in the seed (expected) -> not an error;
    # only a missing DB dir is a real failure.
    if common.hash_dir(OSV_DB_DIR) is None:
        print(f"osv DB download produced no database: {oerr[:200]}", file=sys.stderr)
        rc = 1
    return rc


def parse_digest(inspect_stdout: str) -> Optional[str]:
    val = (inspect_stdout or "").strip()
    return val or None


# =========================================================================== #
# PURE: SCANNERS_READY marker + staleness
# =========================================================================== #
def build_scanners_ready(*, image_digest: Optional[str], image_id: Optional[str],
                         scanner_versions: dict, semgrep_ruleset_hash: Optional[str],
                         db_info: dict, smoke: dict, config_hash: str,
                         rulesets: list) -> dict:
    required_ok = bool(
        (image_digest or image_id)
        and semgrep_ruleset_hash
        and db_info.get("trivy_db", {}).get("present")
        and db_info.get("osv_db", {}).get("present")
        and all(smoke.get(s, {}).get("ok") for s in FIVE_SCANNERS)
    )
    problems = []
    if not (image_digest or image_id):
        problems.append("scanner_image_not_built")
    if not semgrep_ruleset_hash:
        problems.append("semgrep_rules_cache_missing")
    if not db_info.get("trivy_db", {}).get("present"):
        problems.append("trivy_db_missing")
    if not db_info.get("osv_db", {}).get("present"):
        problems.append("osv_db_missing")
    for s in FIVE_SCANNERS:
        if not smoke.get(s, {}).get("ok"):
            problems.append(f"smoke_failed:{s}")
    return {
        "prepared_utc": common.iso_now(),
        "ready": required_ok,
        "problems": problems,
        "scanner_image": SCANNER_IMAGE,
        "image_digest": image_digest,
        "image_id": image_id,
        "configuration_hash": config_hash,
        "pinned_scanner_versions": scanner_versions,
        "semgrep_rulesets": rulesets,
        "semgrep_ruleset_hash": semgrep_ruleset_hash,
        "database_snapshots": db_info,
        "smoke_tests": smoke,
        "note": "pinned versions + these hashes are AUTHORITATIVE for all scans; "
                "network is disabled after this step.",
    }


def scanners_ready_state(marker: Optional[dict], current_config_hash: str,
                         current_image_digest: Optional[str] = None) -> tuple[str, list]:
    """READY / STALE / NOT_READY for the current config + image vs the marker."""
    if not isinstance(marker, dict) or not marker.get("ready"):
        return "NOT_READY", (marker.get("problems", []) if isinstance(marker, dict) else ["no_marker"])
    reasons = []
    if marker.get("configuration_hash") != current_config_hash:
        reasons.append("config_changed_since_prepare")
    if current_image_digest and marker.get("image_digest") \
            and marker["image_digest"] != current_image_digest:
        reasons.append("image_changed_since_prepare")
    return ("STALE", reasons) if reasons else ("READY", [])


def load_ready_marker(path: Path = SCANNERS_READY_PATH) -> Optional[dict]:
    if not path.exists():
        return None
    try:
        return common.read_json(path)
    except Exception:
        return None


# =========================================================================== #
# ORCHESTRATION (injectable run_fn: (argv) -> (returncode, stdout, stderr))
# =========================================================================== #
RunFn = Callable[[list], tuple]


def prepare(docker: str, semgrep: Optional[str], trivy: Optional[str],
            osv: Optional[str], run_fn: RunFn, *, build: bool = True) -> dict:
    """Run the full preparation sequence and assemble the SCANNERS_READY marker."""
    steps: list[dict] = []

    def step(name: str, exe: str, argv: list, optional: bool = False) -> tuple:
        rc, out, err = run_fn([exe, *argv])
        steps.append({"name": name, "exe": exe, "ok": rc == 0, "returncode": rc,
                      "optional": optional, "error": (err.strip()[:200] if rc != 0 and err else None)})
        return rc, out, err

    # CS-015: a FAILED build must never fall back to a stale image that happens to
    # still carry the :latest tag. If the build ran and returned non-zero, refuse to
    # inspect/accept any pre-existing image -- preparation is not ready.
    build_ok = True
    if build:
        brc, _, _ = step("build_scanner_image", docker,
                         build_image_args("docker/Dockerfile.scanner", SCANNER_IMAGE))
        build_ok = (brc == 0)
    if not build_ok:
        image_digest = image_id = None
    else:
        rc, out, _ = step("inspect_image_digest", docker, inspect_digest_args(SCANNER_IMAGE), optional=True)
        image_digest = parse_digest(out) if rc == 0 else None
        rc2, out2, _ = step("inspect_image_id", docker, inspect_id_args(SCANNER_IMAGE), optional=True)
        image_id = parse_digest(out2) if rc2 == 0 else None

    # --- Semgrep rule export + pin + hash ---
    scanner_cfg = common.load_yaml(common.CONFIG_DIR / "scanner-config.yaml")
    rulesets = scanner_cfg.get("scanners", {}).get("semgrep", {}).get("rulesets", [])
    if semgrep:
        common.ensure_dir(SEMGREP_CACHE)
        for rs in rulesets:
            safe = rs.replace("/", "_")
            step(f"export_semgrep_{safe}", semgrep,
                 build_semgrep_export_args(rs, str(SEMGREP_CACHE / f"{safe}.json")), optional=True)
    semgrep_ruleset_hash = common.hash_dir(SEMGREP_CACHE)

    # --- Trivy + OSV DB download to EXPLICIT cache dirs ---
    db_info: dict = {}
    if trivy:
        common.ensure_dir(TRIVY_CACHE)
        step("prefetch_trivy_db", trivy, build_trivy_download_args(str(TRIVY_CACHE)), optional=True)
    db_info["trivy_db"] = {"cache_dir": str(TRIVY_CACHE),
                           "container_path": CONTAINER_TRIVY_CACHE,
                           "present": common.hash_dir(TRIVY_CACHE) is not None,
                           "snapshot_utc": common.iso_now()}
    if osv:
        common.ensure_dir(OSV_DB_DIR)
        step("prefetch_osv_db", osv, build_osv_download_args(str(OSV_DB_DIR)), optional=True)
    db_info["osv_db"] = {"db_dir": str(OSV_DB_DIR), "container_path": CONTAINER_OSV_DB,
                         "present": common.hash_dir(OSV_DB_DIR) is not None,
                         "snapshot_utc": common.iso_now()}

    # --- Smoke test all five scanners in the image ---
    smoke: dict = {}
    for s in FIVE_SCANNERS:
        rc, out, err = run_fn([docker, *build_smoke_args(s, SCANNER_IMAGE)])
        smoke[s] = {"ok": rc == 0, "version": (out.strip().splitlines()[0][:80] if out.strip() else None),
                    "error": (err.strip()[:120] if rc != 0 and err else None)}

    marker = build_scanners_ready(
        image_digest=image_digest, image_id=image_id,
        scanner_versions=ce.parse_scanner_pins(),
        semgrep_ruleset_hash=semgrep_ruleset_hash, db_info=db_info, smoke=smoke,
        config_hash=common.config_bundle_hash(), rulesets=rulesets)
    marker["steps"] = steps
    return marker


# =========================================================================== #
# main
# =========================================================================== #
def main(argv: Optional[list[str]] = None) -> int:
    import shutil
    parser = argparse.ArgumentParser(description="Prepare + pin the scanner toolchain (Phase 19).")
    parser.add_argument("--no-build", action="store_true", help="skip docker build")
    parser.add_argument("--in-container-assets", action="store_true",
                        help="prepare Trivy/OSV DBs + Semgrep rules using the IMAGE's "
                             "pinned binaries + the registry (host-independent)")
    args = parser.parse_args(argv)

    docker = shutil.which("docker")
    if docker is None:
        print("ERROR: docker not found on PATH.", file=sys.stderr)
        return 2

    def run_fn(cmd: list) -> tuple:
        import subprocess
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1800, check=False)
            return proc.returncode, proc.stdout or "", proc.stderr or ""
        except Exception as exc:  # pragma: no cover
            return 1, "", f"{type(exc).__name__}: {exc}"

    if args.in_container_assets:
        rc = run_incontainer_asset_prep(docker, SCANNER_IMAGE, run_fn)
        if rc != 0:
            print(f"  in-container asset prep failed (rc={rc}); see stderr.", file=sys.stderr)

    marker = prepare(docker, shutil.which("semgrep"), shutil.which("trivy"),
                     shutil.which("osv-scanner"), run_fn, build=not args.no_build)
    common.atomic_write_json(PREP_MANIFEST, marker)
    common.atomic_write_json(SCANNERS_READY_PATH, marker)

    print(f"Scanner preparation -> {SCANNERS_READY_PATH.relative_to(STUDY_ROOT)}")
    if marker["ready"]:
        print("  SCANNERS_READY: ready=true (image + rules + DBs + smoke all present).")
    else:
        print(f"  SCANNERS_READY: ready=FALSE — fail-closed. Problems: {marker['problems']}")
    return 0 if marker["ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
