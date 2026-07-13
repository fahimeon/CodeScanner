"""Unit tests for pilot_gate.py + redaction.py (fully synthetic; fake secrets only)."""

import pilot_gate as pg
import redaction as rd


PILOT_IDS = {"CLR-0001", "CLR-0002"}
SCANNERS = ["gitleaks", "semgrep"]


def _rec(pid, status="NO_FINDINGS", schema_valid=True, timeout="OK"):
    return {"anonymous_id": pid, "status": status, "schema_valid": schema_valid,
            "timeout_status": timeout}


def _all_good():
    return {s: [_rec(p) for p in PILOT_IDS] for s in SCANNERS}


# --------------------------------------------------------------------------- #
# Redaction util (audit #19)
# --------------------------------------------------------------------------- #
def test_redaction_detects_and_redacts_fake_secrets():
    fake = "token AKIAABCDEFGHIJKLMNOP and ghp_abcdefghijklmnopqrstuvwxyz012345"
    assert rd.contains_unredacted_secret(fake) is True
    redacted = rd.redact_text(fake)
    assert "AKIA" not in redacted and "ghp_" not in redacted and "REDACTED" in redacted
    assert rd.contains_unredacted_secret("nothing secret here") is False


def test_redact_record_masks_sensitive_keys():
    rec = {"Secret": "hunter2", "file": "src/a.ts", "nested": {"token": "abc"}}
    out = rd.redact_record(rec)
    assert out["Secret"] == "REDACTED" and out["nested"]["token"] == "REDACTED"
    assert out["file"] == "src/a.ts"


# --------------------------------------------------------------------------- #
# Pilot evaluation
# --------------------------------------------------------------------------- #
def test_evaluate_pilot_pass():
    ev = pg.evaluate_pilot(_all_good(), PILOT_IDS, SCANNERS, redaction_ok=True)
    assert ev["result"] == "PASS" and ev["problems"] == []


def test_evaluate_pilot_fails_on_missing_coverage():
    recs = _all_good()
    recs["semgrep"] = [_rec("CLR-0001")]           # CLR-0002 missing for semgrep
    ev = pg.evaluate_pilot(recs, PILOT_IDS, SCANNERS, redaction_ok=True)
    assert ev["result"] == "FAIL" and ev["coverage_ok"] is False
    assert any("missing:semgrep:CLR-0002" in p for p in ev["problems"])


def test_evaluate_pilot_fails_on_scanner_error_and_redaction():
    recs = _all_good()
    recs["gitleaks"] = [_rec("CLR-0001", status="SCANNER_ERROR"), _rec("CLR-0002")]
    ev = pg.evaluate_pilot(recs, PILOT_IDS, SCANNERS, redaction_ok=False)
    assert ev["result"] == "FAIL"
    assert ev["parser_ok"] is False and ev["redaction_ok"] is False


# --------------------------------------------------------------------------- #
# Gate binding + state
# --------------------------------------------------------------------------- #
def _gate(result="PASS"):
    ev = {"result": result, "coverage_ok": True, "parser_ok": True,
          "resources_ok": True, "redaction_ok": True, "problems": []}
    return pg.build_pilot_gate(ev, pilot_ids=list(PILOT_IDS), scanners=SCANNERS,
                               sample_sha="SAMPLE", config_hash="CFG",
                               image_digest="IMG", ruleset_hash="RULES")


def test_pilot_gate_state_pass_and_drift():
    gate = _gate("PASS")
    assert pg.pilot_gate_state(gate, sample_sha="SAMPLE", config_hash="CFG",
                               image_digest="IMG", ruleset_hash="RULES")[0] == "PASS"
    # any binding drift -> STALE
    assert pg.pilot_gate_state(gate, sample_sha="OTHER", config_hash="CFG",
                               image_digest="IMG", ruleset_hash="RULES")[0] == "STALE"
    assert pg.pilot_gate_state(gate, sample_sha="SAMPLE", config_hash="X",
                               image_digest="IMG", ruleset_hash="RULES")[0] == "STALE"
    # a failed pilot never passes; missing gate never passes
    assert pg.pilot_gate_state(_gate("FAIL"), sample_sha="SAMPLE", config_hash="CFG",
                               image_digest="IMG", ruleset_hash="RULES")[0] == "FAIL"
    assert pg.pilot_gate_state(None, sample_sha="SAMPLE", config_hash="CFG",
                               image_digest=None, ruleset_hash=None)[0] == "MISSING"


def test_sample_hash_is_deterministic_and_binding():
    rows = [{"anonymous_id": "CLR-0002", "frozen_commit_sha": "b"},
            {"anonymous_id": "CLR-0001", "frozen_commit_sha": "a"}]
    h1 = pg.sample_hash(rows)
    h2 = pg.sample_hash(list(reversed(rows)))
    assert h1 == h2 and len(h1) == 64
    changed = pg.sample_hash([{"anonymous_id": "CLR-0001", "frozen_commit_sha": "DIFF"},
                              {"anonymous_id": "CLR-0002", "frozen_commit_sha": "b"}])
    assert changed != h1                           # changing a frozen SHA changes the hash
