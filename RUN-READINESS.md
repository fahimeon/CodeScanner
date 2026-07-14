# Run readiness — live 500-repo study execution status

**Branch:** `fix/audit-critical-correctness` · **Host:** Windows 11, Docker 29.6.1,
`gh` authed as `fahimeon`. This is the honest state of the live run plus the exact
commands/paths/specs to finish it. Nothing here is hypothetical — every "done" item
was executed; every "blocked" item names the precise first blocking step.

## Done (this session, real)

| Item | Evidence |
|------|----------|
| All blockers CS-001…CS-017 + CS-020, CS-010, CS-011 | 290 offline tests pass; PR #3; `PRE-SCAN-GATE-TABLE.md` |
| Systemic Windows UTF-8 crash in gh/git subprocess | Fixed in 9 scripts; `collect_candidates.py --probe` now returns **1000 real records** (was crashing) |
| Scanner Docker image builds | `docker/Dockerfile.scanner` fixed: Trivy pin `0.58.0`→`0.72.0` (never existed) and `curl\|sh`→pinned tarball (partial CS-021) |
| Phase 1 network-disabled smoke (all 5) | `docker run --network none --entrypoint <bin> … --version` → gitleaks 8.21.2, semgrep 1.97.0, trivy 0.72.0, osv-scanner 1.9.2, zizmor 1.0.1 |
| **`SCANNERS_READY.ready=true`** | Trivy DB + OSV DB (in-container) + Semgrep rules (registry) prepared; all smoke tests pass |
| **All 5 scanners validated OFFLINE via real `run_all`** | Controlled lodash-4.17.20 + eval() target: gitleaks NO_FINDINGS, semgrep 1, trivy 5, osv-scanner 3, zizmor 2 (with workflow) / NOT_APPLICABLE (without). Each a valid ExecutionRecordV2 with output hash/size, published to the immutable namespace. Caught + fixed osv `--offline`→`--experimental-offline` and zizmor `--output`→stdout redirect. |
| Real end-to-end micro-scan on live infra | Cloned `4bakker/queue_sim` @ frozen `dec5963…` (HEAD==expected verified); gitleaks+zizmor through real container, published output + ledger. Validates CS-003/005/010/011/014/017 on real infrastructure. |

## Discovery is live and the population is large

`python scripts/collect_candidates.py --probe` (1 real API call) returned **1000/1000
populated records** for just the first 5-day window (`2025-02-24..2025-02-28`), signal
`anthropic_email`, 715 also carrying `generated_claude_code`. The first slice
**saturates the search API cap**, so the full 17-window plan yields tens of thousands
of attributed commits before the eligibility funnel.

## Offline scanning — fully prepared and validated (was Blocker 1 — RESOLVED)

**`pip install semgrep` is impossible here** — Semgrep has **no Windows support**
(upstream). So the offline assets were prepared the CS-002-correct way (registry /
in-container), not via a host binary:

```bash
# Semgrep rules — fetch each pinned ruleset YAML from the registry into the cache:
for rs in p/javascript p/typescript p/react p/nextjs p/nodejs p/expressjs \
          p/security-audit p/secrets p/owasp-top-ten; do
  curl -fsSL "https://semgrep.dev/c/$rs" -o "config/semgrep-rules-cache/${rs//\//_}.yml"; done
# Trivy DB — host trivy into the pinned cache:
trivy fs --download-db-only --cache-dir config/trivy-cache
# OSV DB — download with the IMAGE binary (host osv 2.x lacks the flag); MSYS_NO_PATHCONV
# stops Git Bash mangling container paths:
MSYS_NO_PATHCONV=1 docker run --rm -v "$PWD/<npm-lockfile-target>:/t:ro" \
  -v "$PWD/config/osv-db:/db:rw" --entrypoint osv-scanner claude-study-scanner:latest \
  --experimental-offline --experimental-download-offline-databases \
  --experimental-local-db-path /db --recursive /t
python scripts/prepare_scanners.py --no-build   # -> SCANNERS_READY.ready=true
```

**Follow-up (not a blocker):** auto-wire the above into `prepare_scanners.py` so
`make prepare-scanners` populates the OSV DB + Semgrep rules in-container (it currently
prefetches via host binaries, which mismatch the pinned image versions — host osv 2.4.0
vs image 1.9.2). Assets are correct + validated; only their automation is outstanding.

## The remaining blocker (throughput) — the 500-repo shortlist is a multi-hour live collection

Producing a **deployment-verified** primary-500 requires the full protocol against live
GitHub + the open web:
`collect → merge → metadata → verify-attribution → classify → calculate-loc →
discover-deployments → verify-deployments (non-invasive HTTP to every candidate site) →
detect-duplicates → screen → resolve-manual-review → freeze → select`.
With the first slice alone at the 1000 cap, this is **tens of thousands of gh calls +
thousands of live deployment probes**, bounded by GitHub's secondary rate limits — a
multi-hour to multi-day operation, not completable inside one session. This is a
throughput/time limit, **not** a missing-capability limit: every stage is implemented,
unit-tested, and (for the scanners) validated offline end-to-end on real infrastructure.

## Exact run commands, in order (host with Docker + gh, per phase)

```bash
# --- Phase 1: scanner toolchain (Docker) --- DONE this session
docker build -f docker/Dockerfile.scanner -t claude-study-scanner:latest .
# prepare offline assets (see "Offline scanning" above), then:
python scripts/prepare_scanners.py --no-build       # -> SCANNERS_READY.ready=true

# --- Phase 3: real shortlist (long-running; resumable from immutable slices) ---
python scripts/collect_candidates.py               # -> data/raw/search/*.json  (resumable)
python scripts/merge_candidates.py                 # -> data/interim/candidates.*
python scripts/fetch_repository_metadata.py        # -> data/interim/metadata.* (frozen SHAs)
python scripts/verify_claude_attribution.py
python scripts/classify_projects.py                # JS/TS web-app
python scripts/calculate_loc.py
python scripts/discover_deployments.py             # passive evidence
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
python scripts/clone_selected_repositories.py --pilot   # -> repositories/pilot/, data/processed/pilot/
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

- Docker (Linux containers), ~20 GB free disk for 500 partial clones + history mirrors,
  plus ~1 GB for offline DBs (OSV npm DB alone is ~200 MB).
- `gh auth login` with a token carrying `repo` read + search; expect secondary rate
  limits — the collector is resumable from immutable per-slice files.
- Outbound HTTPS for passive deployment reachability checks (SSRF-guarded, root path only).
- Budget: plan the collection over hours, not minutes.

## Bangladesh / South Asia targeting (applied AFTER eligibility, never weakening rules)

Geography is inferred **only** from public owner/org/company/location profile fields and
project evidence — never from names. Add as a post-eligibility annotator (not a discovery
filter): for each eligible owner, read the public `location`/`company`/org profile via
`gh api users/<owner>`; tag `bd` / `south_asia`; then, within the frozen eligible pool and
without changing eligibility, prefer `bd` (target ≥50) then `south_asia` (target ≥150)
when filling strata, and **report honest achieved counts and any shortfall**.

## Bottom line

Blockers, tests, Windows crash, Docker image, and the **entire offline scanner stack**
are done and validated on real infrastructure (all five scanners produce valid findings
offline through the real pipeline). The only remaining work to a finished 500-repo study
is the multi-hour live-collection + scan budget (Phase 3 onward) — a throughput step with
exact commands above, not a missing capability.
