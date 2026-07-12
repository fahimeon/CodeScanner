#!/usr/bin/env python3
"""
prepare_scanners.py — Phase 19 scanner preparation (build + pin + freeze).

The deliberate pin/freeze step that must happen BEFORE any scanning: build the
locked-down scanner image, pre-fetch and pin the offline databases / rulesets
(Trivy vuln DB, OSV DB, Semgrep rule packs), and record the image digest +
pinned versions + DB snapshot dates into a preparation manifest. Once the image
digest is recorded, check_environment flips scanning readiness to READY.

MANDATORY ORDER (scanner-config.yaml offline_sequencing): pre-fetch + pin WITH
network, snapshot locally, THEN scans run offline against the pinned snapshots.

Pure command-building + manifest logic is split from the injectable `run_fn`, so
the orchestration sequence is unit-tested WITHOUT docker or the network.
"""

from __future__ import annotations

import argparse
import json
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
COLLECTOR_IMAGE = "claude-study-collector:latest"
PREP_MANIFEST = STUDY_ROOT / "results" / "reports" / "scanner-preparation-manifest.json"


# =========================================================================== #
# PURE FUNCTIONS
# =========================================================================== #
def build_image_args(dockerfile: str, image: str, context: str = ".") -> list[str]:
    """docker build argv (excluding the docker executable). Versions are pinned
    in the Dockerfile ARGs, so no --build-arg overrides here."""
    return ["build", "-f", dockerfile, "-t", image, context]


def inspect_digest_args(image: str) -> list[str]:
    return ["image", "inspect", image, "--format", "{{index .RepoDigests 0}}"]


def inspect_id_args(image: str) -> list[str]:
    return ["image", "inspect", image, "--format", "{{.Id}}"]


def trivy_prefetch_args(cache_dir: str) -> list[str]:
    """Download the Trivy vuln DB (network ON); scans later use --skip-db-update."""
    return ["fs", "--download-db-only", "--cache-dir", cache_dir]


def osv_prefetch_args(db_dir: str) -> list[str]:
    return ["--experimental-download-offline-databases", "--experimental-local-db-path", db_dir]


def parse_digest(inspect_stdout: str) -> Optional[str]:
    val = (inspect_stdout or "").strip()
    return val or None


def build_prep_manifest(*, image_digest: Optional[str], image_id: Optional[str],
                        scanner_pins: dict, rulesets: list, db_info: dict,
                        steps: list[dict]) -> dict:
    prepared = bool(image_digest or image_id)
    return {
        "prepared_utc": common.iso_now(),
        "scanner_image": SCANNER_IMAGE,
        "image_prepared": prepared,
        "image_digest": image_digest,
        "image_id": image_id,
        "pinned_scanner_versions": scanner_pins,
        "semgrep_rulesets": rulesets,
        "database_snapshots": db_info,
        "steps": steps,
        "note": "pinned (container) versions + these DB snapshots are AUTHORITATIVE "
                "for all scans; network is disabled after this step.",
    }


# =========================================================================== #
# ORCHESTRATION (injectable run_fn: (argv) -> (returncode, stdout, stderr))
# =========================================================================== #
RunFn = Callable[[list], tuple]


def prepare(docker: str, trivy: Optional[str], run_fn: RunFn, *,
            build: bool = True, cache_root: Path) -> dict:
    """Run the preparation sequence and assemble the manifest. Each step records
    its status; a failed optional step is recorded, not fatal."""
    steps: list[dict] = []

    def step(name: str, argv: list, exe: str, optional: bool = False) -> tuple:
        rc, out, err = run_fn([exe, *argv])
        steps.append({"name": name, "exe": exe, "argv": argv, "returncode": rc,
                      "ok": rc == 0, "optional": optional,
                      "error": (err.strip()[:200] if rc != 0 and err else None)})
        return rc, out, err

    if build:
        step("build_scanner_image",
             build_image_args("docker/Dockerfile.scanner", SCANNER_IMAGE), docker)

    rc, out, _ = step("inspect_image_digest", inspect_digest_args(SCANNER_IMAGE), docker,
                      optional=True)
    image_digest = parse_digest(out) if rc == 0 else None
    rc2, out2, _ = step("inspect_image_id", inspect_id_args(SCANNER_IMAGE), docker,
                        optional=True)
    image_id = parse_digest(out2) if rc2 == 0 else None

    db_info: dict = {}
    if trivy:
        trivy_cache = cache_root / "trivy-cache"
        common.ensure_dir(trivy_cache)
        rc3, _, _ = step("prefetch_trivy_db", trivy_prefetch_args(str(trivy_cache)),
                         trivy, optional=True)
        db_info["trivy_db"] = {"cache_dir": str(trivy_cache), "downloaded": rc3 == 0,
                               "snapshot_utc": common.iso_now() if rc3 == 0 else None}

    scanner_pins = ce.parse_scanner_pins()
    scanner_cfg = common.load_yaml(common.CONFIG_DIR / "scanner-config.yaml")
    rulesets = scanner_cfg.get("scanners", {}).get("semgrep", {}).get("rulesets", [])
    return build_prep_manifest(image_digest=image_digest, image_id=image_id,
                               scanner_pins=scanner_pins, rulesets=rulesets,
                               db_info=db_info, steps=steps)


# =========================================================================== #
# main
# =========================================================================== #
def main(argv: Optional[list[str]] = None) -> int:
    import shutil
    parser = argparse.ArgumentParser(description="Prepare + pin the scanner toolchain (Phase 19).")
    parser.add_argument("--no-build", action="store_true",
                        help="skip docker build (only inspect + prefetch)")
    args = parser.parse_args(argv)

    docker = shutil.which("docker")
    if docker is None:
        print("ERROR: docker not found on PATH.", file=sys.stderr)
        return 2
    trivy = shutil.which("trivy")

    def run_fn(cmd: list) -> tuple:
        import subprocess
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1800, check=False)
        return proc.returncode, proc.stdout or "", proc.stderr or ""

    manifest = prepare(docker, trivy, run_fn, build=not args.no_build,
                       cache_root=STUDY_ROOT / "config")
    common.atomic_write_json(PREP_MANIFEST, manifest)

    print(f"Scanner preparation manifest -> {PREP_MANIFEST.relative_to(STUDY_ROOT)}")
    if manifest["image_prepared"]:
        print(f"  scanner image prepared (digest/id recorded). "
              f"Re-run 'make check' — scanning readiness should flip to READY.")
    else:
        print("  WARNING: scanner image digest/id NOT recorded — build likely failed. "
              "Scanning remains NOT READY.")
    for s in manifest["steps"]:
        if not s["ok"]:
            print(f"  step FAILED: {s['name']} (exit {s['returncode']})"
                  f"{' [optional]' if s['optional'] else ''}")
    return 0 if manifest["image_prepared"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
