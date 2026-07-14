# Audit remediation — `CodeScanner_Audit_for_Opus_4.8(3)` (CS-001 … CS-026)

**Branch:** `fix/audit-critical-correctness` (off `feat/results-phases` @ `68f54bc`)
**Date:** 2026-07-14 · **Tests:** 287 passing (was 270); all offline (no docker/git/network).

## Important context: what the audit reviewed

The audit was performed against the **public `main` branch, which contains only the
initial commit** — the report itself notes "one public commit" and "no
`.github/workflows`". A large share of its "Confirmed" blockers were **already fixed**
on the unmerged branches `fix/pre-scan-audit-blockers` (PR #1) and `feat/results-phases`
(PR #2). This changelog maps every CS finding to its **actual** status on the current code
and records the fixes made in this branch for the ones that were genuinely still open.

The static-only / no-repository-code-execution boundary and scan-time network isolation
were preserved throughout. **No live study run was started** — per the audit's own gate,
the full run stays blocked until these pass (they now do at the unit/integration layer;
Docker end-to-end smoke tests still require a host with Docker).

## Blocker table (audit ID → status → files → tests → remaining risk)

| ID | Sev | This branch | Files changed | Tests added | Remaining risk |
|----|-----|-------------|---------------|-------------|----------------|
| CS-001 | Crit | Already fixed (pre-existing) | `docker/scanner-entrypoint.sh`, `config/scanner-config.yaml` | exit-semantics tests | none known |
| CS-002 | Crit | **Fixed here** (runtime binding) | `docker/scanner-entrypoint.sh` | `test_entrypoint_binds_explicit_offline_asset_paths` | Docker smoke test with real DBs still pending |
| CS-003 | Crit | **Fixed here** | `scripts/_scanner_runner.py` | timeout→TIMEOUT record; batch-continues; container kill | container `rm -f` is best-effort |
| CS-004 | Crit | Already fixed + hardened by CS-014 | `scripts/_scanner_runner.py` | validate/quarantine/resume tests | none known |
| CS-005 | Crit | Already fixed (pre-existing) | `scripts/clone_selected_repositories.py` | frozen-SHA refusal tests | none known |
| CS-006 | Crit | Already fixed (pre-existing) | `scripts/_scanner_runner.py` | append-only ledger + resume tests | run_id/schema_version not yet in record (CS-011) |
| CS-007 | High | **Fixed here** | `scripts/_scanner_runner.py`, `config/scanner-config.yaml` | `test_run_exit_policy` | clone CLI exit policy not yet added (see below) |
| CS-008 | High | Already fixed (pre-existing) | `scripts/select_sample.py` | distinct-prefix selection tests | global cross-manifest uniqueness assert = follow-up |
| CS-009 | High | **Fixed here** | `scripts/freeze_population.py`, `select_sample.py`, `clone_selected_repositories.py` | `test_verify_population_integrity_*` | selected-CSV/clone-manifest own checksums = follow-up |
| CS-010 | High | **Fixed** (commit `5336973`) | `scripts/_scanner_runner.py`, `clone_selected_repositories.py` | `test_pilot_and_full_scope_are_isolated` | report writers not yet scope-tagged |
| CS-011 | High | **Fixed** (commit `5336973`) | `scripts/_scanner_runner.py` | `test_execution_record_v2_has_full_provenance` | none known |
| CS-012 | High | **Fixed here** | `scripts/_scanner_runner.py` | `test_wrong_schema_json_is_parser_error_not_zero`, run_one PARSER_ERROR | none known |
| CS-013 | High | **Fixed here** | `.gitignore`, `scripts/privacy_lint.py` | `tests/test_privacy_lint.py` (5) | pre-commit hook wiring = follow-up |
| CS-014 | High | **Fixed here** | `scripts/_scanner_runner.py`, `.gitignore` | single-rw-mount; publish/quarantine tests | Linux non-root UID write-preflight = follow-up |
| CS-015 | High | **Fixed here** | `scripts/prepare_scanners.py` | `test_prepare_fail_closed_when_build_fails_*` | unique temp-tag-then-retag = follow-up |
| CS-016 | High | Already fixed (pre-existing) | `docker/scanner-entrypoint.sh` | gitleaks working-tree vs history tests | none known |
| CS-017 | Med | **Fixed here** | `scripts/_scanner_runner.py`, `config/scanner-config.yaml` | `test_zizmor_not_applicable_without_workflows`, `test_count_workflow_files` | UNSUPPORTED state not distinguished |
| CS-019 | Med | Already correct on this branch | — | timeout path already `isolation.limits.scan_timeout_seconds` | none |
| CS-020 | Med | **Fixed here** (folded into CS-003) | `scripts/_scanner_runner.py` | golden-args (`--ulimit nofile`) | none known |

## Not-yet-addressed (audit CS-011 gaps, CS-018, CS-021–026)

These are **not release-blockers** per the audit's own sequencing (Phase 5 / "after the
blockers"). Tracked, not done in this branch (**CS-010 and CS-011 are now DONE — commit
`5336973` — see the gate table**):

- **CS-007 (clone side)** — the clone CLI still returns 0 on partial failure; a
  `min_clone_success_rate` gate mirroring the scanner policy is a follow-up.
- **CS-018** — env readiness accepting a local image ID (no RepoDigests) for local runs.
- **CS-021** — Dockerfile supply-chain (digest-pinned base, checksum-verified binaries, no `curl|sh`).
- **CS-022** — versioned config schema + CI key/cross-field validation.
- **CS-023** — optimal (vs greedy) control matching (SMD/caliper already present).
- **CS-024** — packaging metadata (`pyproject` installs nothing).
- **CS-025** — Docker network-disabled smoke tests (need a Docker host).
- **CS-026** — README status is already generated from `workflow_status.py` (P1 #15); verify no drift.

## Commits (this branch)

`5f7f433` CS-013 · `94b7dea` CS-003+CS-020 · `4ffa540` CS-012 · `bd29983` CS-007 ·
`21512c3` CS-009 · `4e96489` CS-015 · `8372cd3` CS-017 · `d1c9ac2` CS-002 · `23da884` CS-014
