# =============================================================================
# Makefile — orchestration targets for the study.
#
# Requires GNU Make. On Windows, run from Git Bash or WSL, or invoke the
# underlying `python scripts/*.py` commands directly (see each recipe).
#
# HONESTY: many downstream phases are PLANNED but not yet implemented. Every
# recipe guards on its script existing and prints a clear "[NOT IMPLEMENTED]"
# notice instead of crashing with a Python file-not-found. Run `make status`
# for the authoritative built-vs-planned list.
#
# SAFETY: `make scan` refuses to run unless the frozen 500-repository sample
# exists (data/processed/selected-500-repositories.csv). Selection MUST happen
# before any scanning.
# =============================================================================

PYTHON ?= python
SCRIPTS := scripts
SELECTED := data/processed/selected-500-repositories.csv
FROZEN := data/processed/eligible-population-checksum.txt

# Every phase script, in pipeline order. Kept in sync with the authoritative
# list in scripts/workflow_status.py (run: python scripts/workflow_status.py).
ALL_PHASE_SCRIPTS := \
  check_environment.py collect_candidates.py merge_candidates.py \
  fetch_repository_metadata.py verify_claude_attribution.py \
  calculate_claude_contribution.py classify_projects.py calculate_loc.py \
  discover_deployments.py verify_deployments.py verify_repository_deployment_match.py \
  detect_duplicates.py screen_candidates.py freeze_population.py select_sample.py \
  prepare_scanners.py clone_selected_repositories.py run_gitleaks.py run_semgrep.py \
  run_trivy.py run_osv_scanner.py run_zizmor.py normalize_results.py redact_secrets.py \
  classify_findings.py deduplicate_findings.py create_validation_sample.py \
  analyse_results.py generate_figures.py generate_reports.py cleanup_repositories.py

# Guard: a phase whose script does not exist yet fails with a clear notice.
define require_script
	@test -f "$(1)" || { \
	  echo "[NOT IMPLEMENTED] $(1) does not exist yet (planned phase)."; \
	  echo "  See 'make status' for the built-vs-planned list and README section 7."; \
	  exit 2; }
endef

.DEFAULT_GOAL := help

.PHONY: help
help:
	@echo "Study pipeline targets. (built) = script exists; (planned) = not yet implemented."
	@echo "Run 'make status' (or, where make is unavailable, 'python scripts/workflow_status.py')."
	@echo ""
	@echo "  make check                 - (built)   validate environment, write manifest (Phase 1)"
	@echo "  make check-scan            - (built)   like check, but also require scanning readiness"
	@echo "  make collect               - (built)   discover Claude-attributed candidates (Phase 2)"
	@echo "  make collect-control       - (built)   discover matched non-Claude controls"
	@echo "  make merge                 - (built)   merge + deduplicate candidates (Phase 3)"
	@echo "  make metadata              - (built)   fetch repository metadata (Phase 4)"
	@echo "  make verify-attribution    - (built)   verify Claude attribution + involvement (Phase 6)"
	@echo "  make classify              - (built)   classify project type/framework (Phase 7)"
	@echo "  make calculate-loc         - (built)   compute relevant source LOC (Phase 8)"
	@echo "  make discover-deployments  - (built)   discover deployment URLs (Phase 9-10)"
	@echo "  make verify-deployments    - (built)   non-invasive availability + repo match (Phase 11-13)"
	@echo "  make detect-duplicates     - (built)   duplicate/template clustering (Phase 16)"
	@echo "  make screen                - (built)   apply eligibility screening (Phase 5/17)"
	@echo "  make freeze                - (built)   freeze eligible population + checksums (Phase 17)"
	@echo "  make select                - (built)   select exactly 500 (+control match) (Phase 18)"
	@echo "  make prepare-scanners      - (built)   build scanner image, prefetch/pin DBs, record digest (Phase 19)"
	@echo "  make pilot                 - (built)   10-repository scanner pilot (Phase 27)"
	@echo "  make scan                  - (built)   full static scan of frozen sample (Phase 20-28)"
	@echo "  make normalize             - (planned) normalize + redact scanner output (Phase 29-30)"
	@echo "  make deduplicate-findings  - (planned) dedup findings across scanners (Phase 32)"
	@echo "  make validation-sample     - (planned) sample findings for manual validation (Phase 33)"
	@echo "  make analyse               - (planned) statistical analysis (Phase 35-36)"
	@echo "  make figures               - (planned) generate figures (Phase 37)"
	@echo "  make report                - (planned) generate reports (Phase 40)"
	@echo "  make public-dataset        - (planned) emit anonymised public dataset (Phase 38)"
	@echo "  make test                  - run the test suite"
	@echo "  make status                - show which phase scripts are built vs planned"
	@echo "  make clean-repos           - (planned) remove cloned repositories (cleanup)"

.PHONY: status
status:
	@echo "Phase-script implementation status (scripts/):"
	@built=0; total=0; \
	for s in $(ALL_PHASE_SCRIPTS); do \
	  total=$$((total+1)); \
	  if test -f "$(SCRIPTS)/$$s"; then echo "  [built]   $$s"; built=$$((built+1)); \
	  else echo "  [planned] $$s"; fi; \
	done; \
	echo "-------------------------------------------"; \
	echo "  $$built / $$total phase scripts implemented"

# --- Phase 1 ---------------------------------------------------------------- #
.PHONY: check
check:
	$(call require_script,$(SCRIPTS)/check_environment.py)
	$(PYTHON) $(SCRIPTS)/check_environment.py

# Strict environment check that ALSO requires scanning readiness (built+pinned
# scanner image). Non-zero exit if scanning is not ready.
.PHONY: check-scan
check-scan:
	$(call require_script,$(SCRIPTS)/check_environment.py)
	$(PYTHON) $(SCRIPTS)/check_environment.py --strict-scan

# --- Phase 2-3: candidate discovery ---------------------------------------- #
.PHONY: collect
collect:
	$(call require_script,$(SCRIPTS)/collect_candidates.py)
	$(PYTHON) $(SCRIPTS)/collect_candidates.py

.PHONY: collect-control
collect-control:
	$(call require_script,$(SCRIPTS)/collect_candidates.py)
	$(PYTHON) $(SCRIPTS)/collect_candidates.py --control

.PHONY: merge
merge:
	$(call require_script,$(SCRIPTS)/merge_candidates.py)
	$(PYTHON) $(SCRIPTS)/merge_candidates.py

.PHONY: merge-control
merge-control:
	$(call require_script,$(SCRIPTS)/merge_candidates.py)
	$(PYTHON) $(SCRIPTS)/merge_candidates.py --control

# --- Phase 4-8: enrichment + eligibility inputs ---------------------------- #
.PHONY: metadata
metadata:
	$(call require_script,$(SCRIPTS)/fetch_repository_metadata.py)
	$(PYTHON) $(SCRIPTS)/fetch_repository_metadata.py

.PHONY: metadata-control
metadata-control:
	$(call require_script,$(SCRIPTS)/fetch_repository_metadata.py)
	$(PYTHON) $(SCRIPTS)/fetch_repository_metadata.py --control

.PHONY: verify-attribution
verify-attribution:
	$(call require_script,$(SCRIPTS)/verify_claude_attribution.py)
	$(call require_script,$(SCRIPTS)/calculate_claude_contribution.py)
	$(PYTHON) $(SCRIPTS)/verify_claude_attribution.py
	$(PYTHON) $(SCRIPTS)/calculate_claude_contribution.py

.PHONY: verify-attribution-control
verify-attribution-control:
	$(call require_script,$(SCRIPTS)/verify_claude_attribution.py)
	$(call require_script,$(SCRIPTS)/calculate_claude_contribution.py)
	$(PYTHON) $(SCRIPTS)/verify_claude_attribution.py --control
	$(PYTHON) $(SCRIPTS)/calculate_claude_contribution.py --control

.PHONY: classify
classify:
	$(call require_script,$(SCRIPTS)/classify_projects.py)
	$(PYTHON) $(SCRIPTS)/classify_projects.py

.PHONY: calculate-loc
calculate-loc:
	$(call require_script,$(SCRIPTS)/calculate_loc.py)
	$(PYTHON) $(SCRIPTS)/calculate_loc.py

# --- Phase 9-13: deployment ------------------------------------------------ #
.PHONY: discover-deployments
discover-deployments:
	$(call require_script,$(SCRIPTS)/discover_deployments.py)
	$(PYTHON) $(SCRIPTS)/discover_deployments.py

.PHONY: verify-deployments
verify-deployments:
	$(call require_script,$(SCRIPTS)/verify_deployments.py)
	$(call require_script,$(SCRIPTS)/verify_repository_deployment_match.py)
	$(PYTHON) $(SCRIPTS)/verify_deployments.py
	$(PYTHON) $(SCRIPTS)/verify_repository_deployment_match.py

# --- Phase 16-18: screening, freeze, selection ----------------------------- #
.PHONY: detect-duplicates
detect-duplicates:
	$(call require_script,$(SCRIPTS)/detect_duplicates.py)
	$(PYTHON) $(SCRIPTS)/detect_duplicates.py

.PHONY: screen
screen:
	$(call require_script,$(SCRIPTS)/screen_candidates.py)
	$(PYTHON) $(SCRIPTS)/screen_candidates.py

.PHONY: freeze
freeze:
	$(call require_script,$(SCRIPTS)/freeze_population.py)
	$(PYTHON) $(SCRIPTS)/freeze_population.py

.PHONY: select
select:
	$(call require_script,$(SCRIPTS)/select_sample.py)
	$(PYTHON) $(SCRIPTS)/select_sample.py

# --- Phase 19-28: scanner prep, cloning + scanning ------------------------- #
.PHONY: prepare-scanners
prepare-scanners:
	$(call require_script,$(SCRIPTS)/prepare_scanners.py)
	$(PYTHON) $(SCRIPTS)/prepare_scanners.py

.PHONY: pilot
pilot: guard-frozen
	$(call require_script,$(SCRIPTS)/clone_selected_repositories.py)
	$(call require_script,$(SCRIPTS)/run_gitleaks.py)
	$(call require_script,$(SCRIPTS)/run_semgrep.py)
	$(call require_script,$(SCRIPTS)/run_trivy.py)
	$(call require_script,$(SCRIPTS)/run_osv_scanner.py)
	$(call require_script,$(SCRIPTS)/run_zizmor.py)
	$(PYTHON) $(SCRIPTS)/clone_selected_repositories.py --pilot
	$(PYTHON) $(SCRIPTS)/run_gitleaks.py --pilot
	$(PYTHON) $(SCRIPTS)/run_gitleaks.py --history --pilot
	$(PYTHON) $(SCRIPTS)/run_semgrep.py --pilot
	$(PYTHON) $(SCRIPTS)/run_trivy.py --pilot
	$(PYTHON) $(SCRIPTS)/run_osv_scanner.py --pilot
	$(PYTHON) $(SCRIPTS)/run_zizmor.py --pilot
	$(MAKE) pilot-gate

# Evaluate the machine-readable pilot gate (must PASS before `make scan`).
.PHONY: pilot-gate
pilot-gate:
	$(call require_script,$(SCRIPTS)/pilot_gate.py)
	$(PYTHON) $(SCRIPTS)/pilot_gate.py

# HARD GUARD: no scanning without the frozen 500 sample.
.PHONY: scan
scan: guard-selected
	$(call require_script,$(SCRIPTS)/clone_selected_repositories.py)
	$(call require_script,$(SCRIPTS)/run_gitleaks.py)
	$(call require_script,$(SCRIPTS)/run_semgrep.py)
	$(call require_script,$(SCRIPTS)/run_trivy.py)
	$(call require_script,$(SCRIPTS)/run_osv_scanner.py)
	$(call require_script,$(SCRIPTS)/run_zizmor.py)
	$(PYTHON) $(SCRIPTS)/clone_selected_repositories.py
	$(PYTHON) $(SCRIPTS)/run_gitleaks.py
	$(PYTHON) $(SCRIPTS)/run_semgrep.py
	$(PYTHON) $(SCRIPTS)/run_trivy.py
	$(PYTHON) $(SCRIPTS)/run_osv_scanner.py
	$(PYTHON) $(SCRIPTS)/run_zizmor.py

.PHONY: guard-selected
guard-selected:
	@test -f "$(SELECTED)" || { \
	  echo "REFUSING TO SCAN: frozen sample not found ($(SELECTED))."; \
	  echo "Run 'make freeze' then 'make select' first."; exit 2; }

.PHONY: guard-frozen
guard-frozen:
	@test -f "$(FROZEN)" || { \
	  echo "REFUSING TO PILOT: population not frozen ($(FROZEN))."; \
	  echo "Run 'make freeze' then 'make select' first."; exit 2; }

# --- Phase 29-40: results -------------------------------------------------- #
.PHONY: normalize
normalize:
	$(call require_script,$(SCRIPTS)/normalize_results.py)
	$(call require_script,$(SCRIPTS)/redact_secrets.py)
	$(call require_script,$(SCRIPTS)/classify_findings.py)
	$(PYTHON) $(SCRIPTS)/normalize_results.py
	$(PYTHON) $(SCRIPTS)/redact_secrets.py
	$(PYTHON) $(SCRIPTS)/classify_findings.py

.PHONY: deduplicate-findings
deduplicate-findings:
	$(call require_script,$(SCRIPTS)/deduplicate_findings.py)
	$(PYTHON) $(SCRIPTS)/deduplicate_findings.py

.PHONY: validation-sample
validation-sample:
	$(call require_script,$(SCRIPTS)/create_validation_sample.py)
	$(PYTHON) $(SCRIPTS)/create_validation_sample.py

.PHONY: analyse
analyse:
	$(call require_script,$(SCRIPTS)/analyse_results.py)
	$(PYTHON) $(SCRIPTS)/analyse_results.py

.PHONY: figures
figures:
	$(call require_script,$(SCRIPTS)/generate_figures.py)
	$(PYTHON) $(SCRIPTS)/generate_figures.py

.PHONY: report
report:
	$(call require_script,$(SCRIPTS)/generate_reports.py)
	$(PYTHON) $(SCRIPTS)/generate_reports.py

.PHONY: public-dataset
public-dataset:
	$(call require_script,$(SCRIPTS)/generate_reports.py)
	$(PYTHON) $(SCRIPTS)/generate_reports.py --public-only

# --- Tests / cleanup ------------------------------------------------------- #
.PHONY: test
test:
	$(PYTHON) -m pytest

.PHONY: clean-repos
clean-repos:
	$(call require_script,$(SCRIPTS)/cleanup_repositories.py)
	$(PYTHON) $(SCRIPTS)/cleanup_repositories.py
