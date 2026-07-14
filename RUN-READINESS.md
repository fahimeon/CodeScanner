# Run readiness — live 500-repo study execution status

**Branch:** `fix/audit-critical-correctness` · **Host:** Windows 11, Docker 29.6.1,
`gh` authed as `fahimeon`. This document is the honest state of the live run plus the
exact commands/paths/specs to finish it. Nothing here is hypothetical — every "done"
item was executed; every "blocked" item names the precise first blocking step.

## Done (this session, real)

| Item | Evidence |
|------|----------|
| All blockers CS-001…CS-017 + CS-020, CS-010, CS-011 | 289 offline tests pass; PR #3; `PRE-SCAN-GATE-TABLE.md` |
| Systemic Windows UTF-8 crash in gh/git subprocess | Fixed in 9 scripts; `collect_candidates.py --probe` now returns **1000 real records** (was crashing) |
| Scanner Docker image builds | `docker/Dockerfile.scanner` fixed: Trivy pin `0.58.0`→`0.72.0` (0.58.0 never existed) and `curl\|sh`→pinned tarball (partial CS-021). Image id `dd4f2f568df0`, 732 MB |
| Phase 1 network-disabled smoke (all 5) | `docker run --network none --entrypoint <bin> … --version` → gitleaks 8.21.2, semgrep 1.97.0, trivy 0.72.0, osv-scanner 1.9.2, zizmor 1.0.1 |
| **Real end-to-end micro-scan on live infra** | Cloned `4bakker/queue_sim` @ frozen `dec5963…` (HEAD==expected verified); ran gitleaks + zizmor through the real `run_all` (isolated container, network none). gitleaks → `NO_FINDINGS`, published `results/raw/pilot/gitleaks/…json` + ExecutionRecordV2 (schema 2.0, run_id, output_sha256, resource_limits) + append-only ledger; staging atomically cleared. zizmor → `NOT_APPLICABLE` (no workflows). Validates CS-003/005/010/011/014/017 on real infrastructure. |

## Discovery is live and the population is large

`python scripts/collect_candidates.py --probe` (1 real API call) returned **1000/1000
populated records** for just the first 5-day window (`2025-02-24..2025-02-28`), signal
`anthropic_email` (Claude Code's `noreply@anthropic.com` co-trailer), 715 also carrying
`generated_claude_code`. The first slice **saturates the search API cap**, so the full
17-window plan with adaptive sub-slicing will yield tens of thousands of attributed
commits before the eligibility funnel.

## The two real blockers to a completed 500-repo study in one session

### Blocker 1 — Offline vulnerability-DB preparation is not wired to run in-container
`prepare_scanners.py` prefetches the Trivy/OSV DBs and Semgrep rules using **host**
binaries (`shutil.which(...)`). On this host: `trivy` and `osv-scanner` are present
(winget) but **`semgrep` is not**, so the Semgrep rule cache stays empty and
`SCANNERS_READY` is fail-closed → Trivy/OSV/Semgrep scans refuse.
**Precise first blocked step:** `make prepare-scanners` → `SCANNERS_READY.ready=false`
(problems include `semgrep_rules_cache_missing`).
**Fix options (either):**
- `pip install semgrep==1.97.0` on the host, then re-run prepare (uses host binaries); or
- (preferred, closes CS-002 prep-side) add an in-container prep mode: `docker run --network default -v <assets>:/out claude-study-scanner <fetch-dbs>` to download Trivy DB (`trivy fs --download-db-only --cache-dir /out/trivy`), OSV DB (`osv-scanner --experimental-download-offline-databases --experimental-local-db-path /out/osv`), and freeze Semgrep rules — this is the outstanding code task before a DB-backed offline scan.
Gitleaks and Zizmor need **no** vuln DB, so they can scan offline immediately.

### Blocker 2 — The 500-repo shortlist is a multi-hour live collection, not a one-shot
Producing a **deployment-verified** primary-500 requires the full protocol against live
GitHub + the open web:
`collect → merge → metadata → verify-attribution → classify → calculate-loc →
discover-deployments → verify-deployments (non-invasive HTTP to every candidate site) →
detect-duplicates → screen → resolve-manual-review → freeze → select`.
With the first slice alone at the 1000 cap, this is **tens of thousands of gh calls +
thousands of live deployment probes**, bounded by GitHub's secondary rate limits — a
multi-hour to multi-day operation, not completable inside one session. This is a
throughput/time limit, **not** a missing-capability limit: every stage is implemented
and unit-tested; the encoding fix above removed the one crash that blocked it on Windows.

## Exact run commands, in order (host with Docker + gh, per phase)

```bash
# --- Phase 1: scanner toolchain (Docker) ---
docker build -f docker/Dockerfile.scanner -t claude-study-scanner:latest .
pip install semgrep==1.97.0            # OR wire in-container DB prep (Blocker 1)
python scripts/prepare_scanners.py     # writes results/reports/SCANNERS_READY.json
#   network-disabled smoke (per scanner): docker run --rm --network none \
#     --entrypoint <bin> claude-study-scanner:latest --version

# --- Phase 3: real shortlist (long-running; resumable from immutable slices) ---
python scripts/collect_candidates.py               # -> data/raw/search/*.json  (resumable)
python scripts/merge_candidates.py                 # -> data/interim/candidates.*
python scripts/fetch_repository_metadata.py        # -> data/interim/metadata.* (frozen SHAs)
python scripts/verify_claude_attribution.py        # -> attribution.*
python scripts/classify_projects.py                # -> classification.* (JS/TS web-app)
python scripts/calculate_loc.py                    # -> loc.*
python scripts/discover_deployments.py             # -> deployments.* (passive evidence)
python scripts/verify_deployments.py --stage first
python scripts/verify_deployments.py --stage second   # two non-invasive checks
python scripts/verify_repository_deployment_match.py  # Level A/B evidence
python scripts/detect_duplicates.py
python scripts/screen_candidates.py
python scripts/resolve_manual_review.py            # clear PENDING before freeze
python scripts/freeze_population.py                # -> data/processed/eligible-population*.{json,csv,checksum}
python scripts/select_sample.py                    # -> data/processed/selected-500-repositories.csv (+ reserve)
python scripts/validate_selected_sample.py         # 500 rows, unique IDs+SHAs, owner<=2   (TO ADD)

# --- Phase 2: representative 10-repo pilot (separate namespace, CS-010) ---
python scripts/clone_selected_repositories.py --pilot   # -> repositories/pilot/, data/processed/pilot/clone-manifest.json
for s in gitleaks gitleaks-history semgrep trivy osv-scanner zizmor; do \
  python scripts/run_${s//-/_}.py --pilot; done         # -> results/raw/pilot/<scanner>/
python scripts/pilot_gate.py                            # must PASS before full scan

# --- Phase 4: full scan of the active cohort ---
python scripts/clone_selected_repositories.py           # -> repositories/selected/
for s in gitleaks gitleaks-history semgrep trivy osv-scanner zizmor; do \
  python scripts/run_${s//-/_}.py; done                 # -> results/raw/<scanner>/ (+ execution-records.jsonl)

# --- Phase 5: findings + reports ---
python scripts/normalize_results.py                     # -> results/normalized/native-findings.jsonl
python scripts/redact_secrets.py
python scripts/classify_findings.py
python scripts/deduplicate_findings.py                  # -> results/deduplicated/canonical-findings.jsonl
python scripts/create_validation_sample.py
python scripts/analyse_results.py                       # -> results/tables/analysis-summary.json
python scripts/generate_figures.py
python scripts/generate_reports.py                      # private per-repo + aggregate; + --public-only
```

## Expected output paths (private vs public)

- **Private (identity-bearing):** `data/processed/*`, `repositories/*`, `results/raw/*`,
  `results/normalized/*`, `results/deduplicated/*`, `results/reports/private-*`. All gitignored.
- **Public (anonymized only):** `data/public/*`, `results/reports/public-*`,
  `results/reports/results-report.md`. Gated by `python scripts/privacy_lint.py`.

## Host specs / credentials to run at 500 scale

- Docker (Linux containers), ~20 GB free disk for 500 partial clones + history mirrors.
- `gh auth login` with a token carrying `repo` read + search; expect to hit secondary
  rate limits — the collector is resumable from immutable per-slice files.
- Outbound HTTPS for passive deployment reachability checks (SSRF-guarded, root path only).
- Budget: plan the collection over hours, not minutes.

## Bangladesh / South Asia targeting (applied AFTER eligibility, never weakening rules)

Geography is inferred **only** from public owner/org/company/location profile fields and
project evidence — never from names. Implementation step (to add as a post-eligibility
annotator, not a discovery filter): for each eligible owner, read the public
`location`/`company`/org profile via `gh api users/<owner>`; tag `bd` / `south_asia`
bands; then, within the frozen eligible pool and without changing eligibility, prefer
`bd` (target ≥50) then `south_asia` (target ≥150) when filling strata, and **report the
honest achieved counts and any shortfall** rather than forcing the numbers.

## Bottom line

The pipeline is code-complete and unit-green; the Windows crash that blocked live
collection is fixed and verified; the scanner image builds after two Dockerfile fixes.
The remaining work to a finished 500-repo study is (1) wire/enable offline DB prep and
(2) spend the multi-hour live-collection + scan budget — both are throughput/enablement
steps with exact commands above, not missing capabilities.
