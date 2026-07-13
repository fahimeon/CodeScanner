#!/usr/bin/env python3
"""
pilot_gate.py — Phase 27 machine-readable pilot gate.

Evaluates the 10-repository seeded pilot scan and emits a PASS/FAIL record bound
to the exact sample / config / image / ruleset hashes. `make scan` (and the
scanner runners) REFUSE the full run unless a PASS pilot record matches the
CURRENT hashes — so a pilot only authorizes scanning the exact thing it tested.

Checks (all must hold for PASS):
  * coverage: every pilot id scanned by every scanner identity;
  * parser: every pilot output parsed (schema_valid / not PARSER_ERROR);
  * resources: no TIMEOUT / RESOURCE_LIMIT / SCANNER_ERROR;
  * redaction: no unredacted secret in any pilot Gitleaks output.

Pure evaluation split from I/O; unit-tested offline.

Output: results/reports/PILOT_GATE.json
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional

try:
    from . import _common as common  # type: ignore
    from . import prepare_scanners as ps  # type: ignore
    from . import redaction  # type: ignore
except Exception:  # pragma: no cover
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _common as common  # type: ignore
    import prepare_scanners as ps  # type: ignore
    import redaction  # type: ignore

STUDY_ROOT = common.STUDY_ROOT
PILOT_GATE_PATH = STUDY_ROOT / "results" / "reports" / "PILOT_GATE.json"
PILOT_SCANNERS = ["gitleaks", "gitleaks-history", "semgrep", "trivy", "osv-scanner", "zizmor"]
RAN_OK = {"NO_FINDINGS", "SUCCESS_WITH_FINDINGS"}


# =========================================================================== #
# PURE EVALUATION
# =========================================================================== #
def evaluate_pilot(records_by_scanner: dict, pilot_ids: set, scanners: list,
                   redaction_ok: bool = True) -> dict:
    """Coverage + parser + resource + redaction checks over the pilot records."""
    problems: list[str] = []
    coverage_ok = True
    parser_ok = True
    resources_ok = True

    for scanner in scanners:
        recs = {r.get("anonymous_id"): r for r in records_by_scanner.get(scanner, [])}
        for pid in sorted(pilot_ids):
            r = recs.get(pid)
            if r is None:
                coverage_ok = False
                problems.append(f"missing:{scanner}:{pid}")
                continue
            status = r.get("status")
            if status not in RAN_OK:
                parser_ok = False
                problems.append(f"bad_status:{scanner}:{pid}:{status}")
            if r.get("schema_valid") is False:
                parser_ok = False
                problems.append(f"schema_invalid:{scanner}:{pid}")
            if r.get("timeout_status") == "TIMEOUT" or status in ("TIMEOUT", "RESOURCE_LIMIT"):
                resources_ok = False
                problems.append(f"resource:{scanner}:{pid}:{status}")

    if not redaction_ok:
        problems.append("redaction_failed")

    result = "PASS" if (coverage_ok and parser_ok and resources_ok and redaction_ok) else "FAIL"
    return {"result": result, "coverage_ok": coverage_ok, "parser_ok": parser_ok,
            "resources_ok": resources_ok, "redaction_ok": redaction_ok,
            "problems": problems}


def sample_hash(pilot_rows: list) -> str:
    """Hash binding the gate to the exact pilot units (id + frozen sha)."""
    items = sorted((r.get("anonymous_id"), r.get("frozen_commit_sha") or r.get("checked_out_sha"))
                   for r in pilot_rows)
    return common.sha256_hex("\n".join(f"{a}:{b}" for a, b in items))


def build_pilot_gate(evaluation: dict, *, pilot_ids: list, scanners: list,
                     sample_sha: str, config_hash: str, image_digest: Optional[str],
                     ruleset_hash: Optional[str]) -> dict:
    return {
        "generated_utc": common.iso_now(),
        "result": evaluation["result"],
        "checks": {k: evaluation[k] for k in
                   ("coverage_ok", "parser_ok", "resources_ok", "redaction_ok")},
        "problems": evaluation["problems"],
        "pilot_ids": sorted(pilot_ids),
        "scanners": scanners,
        "binding": {
            "sample_hash": sample_sha,
            "configuration_hash": config_hash,
            "image_digest": image_digest,
            "ruleset_hash": ruleset_hash,
        },
    }


def pilot_gate_state(gate: Optional[dict], *, sample_sha: str, config_hash: str,
                     image_digest: Optional[str], ruleset_hash: Optional[str]) -> tuple:
    """PASS only if the recorded gate PASSED AND every binding hash matches now."""
    if not isinstance(gate, dict):
        return "MISSING", ["no_pilot_gate"]
    if gate.get("result") != "PASS":
        return "FAIL", gate.get("problems", ["pilot_failed"])
    b = gate.get("binding", {})
    drift = []
    if b.get("sample_hash") != sample_sha:
        drift.append("sample_changed")
    if b.get("configuration_hash") != config_hash:
        drift.append("config_changed")
    if image_digest and b.get("image_digest") and b["image_digest"] != image_digest:
        drift.append("image_changed")
    if ruleset_hash and b.get("ruleset_hash") and b["ruleset_hash"] != ruleset_hash:
        drift.append("ruleset_changed")
    return ("STALE", drift) if drift else ("PASS", [])


def load_gate(path: Path = PILOT_GATE_PATH) -> Optional[dict]:
    if not path.exists():
        return None
    try:
        return common.read_json(path)
    except Exception:
        return None


# =========================================================================== #
# ORCHESTRATION
# =========================================================================== #
def _load_records(scanner: str) -> list:
    """Latest record per repo from a scanner's per-repo sidecars."""
    raw = STUDY_ROOT / common.load_study_config()["paths"]["results_raw"] / scanner
    out = []
    if raw.is_dir():
        for f in raw.glob("*.record.json"):
            try:
                out.append(common.read_json(f))
            except Exception:
                pass
    return out


def _gitleaks_redaction_ok(pilot_ids: set) -> bool:
    cfg = common.load_study_config()
    for scanner in ("gitleaks", "gitleaks-history"):
        raw = STUDY_ROOT / cfg["paths"]["results_raw"] / scanner
        if not raw.is_dir():
            continue
        for f in raw.glob("*.json"):
            if f.name.endswith(".record.json"):
                continue
            if redaction.contains_unredacted_secret(f.read_text(encoding="utf-8", errors="replace")):
                return False
    return True


def main(argv: Optional[list[str]] = None) -> int:
    argparse.ArgumentParser(description="Evaluate the pilot gate (Phase 27).").parse_args(argv)
    cfg = common.load_study_config()
    processed = STUDY_ROOT / cfg["paths"]["processed"]
    manifest_path = processed / "clone-manifest.json"
    if not manifest_path.exists():
        print("ERROR: clone manifest not found; run the pilot first.", file=sys.stderr)
        return 2

    clone_manifest = common.read_json(manifest_path)
    size = int(common.load_yaml(common.CONFIG_DIR / "scanner-config.yaml")
               .get("pilot", {}).get("size", 10))
    pilot_rows = sorted((r for r in clone_manifest
                         if r.get("status") == "OK" and r.get("anonymous_id")),
                        key=lambda r: r["anonymous_id"])[:size]
    pilot_ids = {r["anonymous_id"] for r in pilot_rows}

    records_by_scanner = {s: [r for r in _load_records(s)
                              if r.get("anonymous_id") in pilot_ids] for s in PILOT_SCANNERS}
    evaluation = evaluate_pilot(records_by_scanner, pilot_ids, PILOT_SCANNERS,
                                redaction_ok=_gitleaks_redaction_ok(pilot_ids))

    # Bind the gate to the ENTIRE selected sample (so re-selection invalidates it),
    # while coverage is checked over the pilot subset.
    all_ok = [r for r in clone_manifest if r.get("status") == "OK" and r.get("anonymous_id")]
    marker = ps.load_ready_marker()
    gate = build_pilot_gate(
        evaluation, pilot_ids=list(pilot_ids), scanners=PILOT_SCANNERS,
        sample_sha=sample_hash(all_ok), config_hash=common.config_bundle_hash(),
        image_digest=(marker or {}).get("image_digest"),
        ruleset_hash=(marker or {}).get("semgrep_ruleset_hash"))
    common.atomic_write_json(PILOT_GATE_PATH, gate)

    print(f"PILOT GATE: {gate['result']} -> {PILOT_GATE_PATH.relative_to(STUDY_ROOT)}")
    if gate["result"] != "PASS":
        print(f"  problems: {gate['problems'][:10]}")
    return 0 if gate["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
