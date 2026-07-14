# Pre-scan blocker gate — CS-001 … CS-015

**Run branch (the branch that will execute the study):** `fix/audit-critical-correctness`
(pushed to `origin`; PR #3 → `feat/results-phases`). It **descends from**
`fix/pre-scan-audit-blockers` (PR #1) and `feat/results-phases` (PR #2), so every
pre-existing fix is **present on the run branch transitively** — confirmed by
`git branch --contains 7d78197`. **No blocker exists only on another branch relative
to the run branch.** All three PRs are still open relative to `main`.

**Tests:** 289 passing, fully offline (no docker/git/network). Docker end-to-end
smoke tests (Phase 1) are the one remaining external check; Docker is now available
on the host.

| ID | Status | Fix commit(s) | Files | Regression tests | Only on another unmerged branch? | Remaining risk |
|----|--------|---------------|-------|------------------|----------------------------------|----------------|
| **CS-001** Semgrep exit-1 = findings, not error | ✅ Done | `88c0d57` (P0#2) | `docker/scanner-entrypoint.sh` (`--error` removed), `config/scanner-config.yaml` (`exit_semantics.semgrep findings:[1]`) | `test_exit_semantics_from_config`, `test_run_one_parses_real_fixture` | No (on run branch) | Confirm live exit codes in Docker smoke |
| **CS-002** Trivy/OSV bound to offline DBs | ✅ Done | `d1c9ac2` | `docker/scanner-entrypoint.sh` | `test_entrypoint_binds_explicit_offline_asset_paths` | No | Real DB smoke scan pending (Docker) |
| **CS-003** TimeoutExpired → TIMEOUT, batch continues | ✅ Done | `94b7dea` | `scripts/_scanner_runner.py` | `test_run_one_timeout_expired_becomes_timeout_record`, `test_run_all_continues_to_next_repo_after_timeout` | No | `docker rm -f` cleanup is best-effort |
| **CS-004** Corrupt/partial output quarantined, not skipped | ✅ Done | `028b6ca` (P0#4) + `23da884` (CS-014) | `scripts/_scanner_runner.py` | `test_validate_existing_output`, `test_bad_schema_staged_output_is_quarantined_not_published`, `test_run_all_records_accumulate_resume_and_quarantine` | No | none known |
| **CS-005** No fallback from frozen SHA to branch/HEAD | ✅ Done | `2a2d536` (P0#5) | `scripts/clone_selected_repositories.py` | clone frozen-SHA refusal + `HEAD==SHA` tests in `test_scanner_pipeline.py` | No | none known |
| **CS-006** Execution history preserved across resume | ✅ Done | `028b6ca` (P0#4) + `5336973` (CS-011) | `scripts/_scanner_runner.py` | `test_run_all_records_accumulate_resume_and_quarantine` (append-only jsonl) | No | none known |
| **CS-007** Non-zero exit on systemic/degraded run | ✅ Done | `bd29983` | `scripts/_scanner_runner.py`, `config/scanner-config.yaml` | `test_run_exit_policy` | No | clone-side `min_clone_success_rate` gate still TODO |
| **CS-008** Globally unique cohort IDs | ✅ Done | `0b40b02` (P1#12) | `scripts/select_sample.py` (deployed `CLR`, repo-only `CLO`) | `test_assign_anonymous_ids`, select-sample track tests | No | cross-manifest global-uniqueness assert (in `validate_selected_sample.py`) = follow-up |
| **CS-009** Frozen checksum recomputed + compared | ✅ Done | `21512c3` | `scripts/freeze_population.py`, `select_sample.py`, `clone_selected_repositories.py` | `test_verify_population_integrity_detects_post_freeze_edit` | No | selected-CSV / clone-manifest own checksums = follow-up |
| **CS-010** Pilot/full fully isolated | ✅ Done | `5336973` | `scripts/_scanner_runner.py`, `clone_selected_repositories.py` | `test_pilot_and_full_scope_are_isolated` | No | report writers not yet scope-tagged (same pattern) |
| **CS-011** Durable versioned ExecutionRecordV2 | ✅ Done | `5336973` | `scripts/_scanner_runner.py` | `test_execution_record_v2_has_full_provenance` | No | none known |
| **CS-012** Wrong-schema JSON → PARSER_ERROR | ✅ Done | `4ffa540` | `scripts/_scanner_runner.py` | `test_wrong_schema_json_is_parser_error_not_zero`, `test_run_one_wrong_schema_output_records_parser_error` | No | none known |
| **CS-013** Identity logs ungittable + privacy lint | ✅ Done | `5f7f433` | `.gitignore`, `scripts/privacy_lint.py` | `tests/test_privacy_lint.py` (5) | No | pre-commit hook wiring = follow-up |
| **CS-014** One writable staging mount + atomic publish | ✅ Done | `23da884` | `scripts/_scanner_runner.py`, `.gitignore` | `test_scanner_only_writable_mount_is_staging`, `test_bad_schema_staged_output_is_quarantined_not_published` | No | Linux non-root UID write-preflight = follow-up |
| **CS-015** Fail-closed on image build failure | ✅ Done | `4e96489` | `scripts/prepare_scanners.py` | `test_prepare_fail_closed_when_build_fails_even_if_stale_image_exists` | No | unique temp-tag-then-retag = follow-up |

**Also:** CS-016 (gitleaks scopes) `e412348`, CS-017 (zizmor NOT_APPLICABLE) `8372cd3`,
CS-019 (timeout path) already correct, CS-020 (nofile ulimit) `94b7dea` — all on the run branch.

**Gate verdict:** CS-001…CS-015 all pass at the unit/integration layer on the run
branch. The only outstanding pre-scan check is the Docker network-disabled smoke test
(Phase 1), which requires a Docker host — now available.
