#!/usr/bin/env sh
# =============================================================================
# scanner-entrypoint.sh
# Defensive entrypoint for the scanner container. Enforces the "never execute
# repository code" rule at the container boundary and dispatches a single named
# scanner against a single mounted (read-only) repository path.
#
# Usage (inside container):
#   scanner-entrypoint.sh <scanner> <repo_path> <output_path> [extra args...]
#
# It NEVER runs npm/yarn/pnpm/pip/make/build/test/start and never invokes any
# script found inside the repository. Only the five approved scanner binaries
# are permitted.
# =============================================================================
set -eu

SCANNER="${1:?scanner name required}"
REPO_PATH="${2:?repository path required}"
OUTPUT_PATH="${3:?output path required}"
shift 3 || true

# --- Hard denylist guard: refuse if someone tries to smuggle a build command --
case "$SCANNER" in
  *npm*|*yarn*|*pnpm*|*pip*|*make*|*build*|*install*|*test*|*start*|*docker*|*node*|*sh|*bash)
    echo "REFUSED: '$SCANNER' is not an approved static scanner." >&2
    exit 64
    ;;
esac

if [ ! -d "$REPO_PATH" ]; then
  echo "REFUSED: repository path '$REPO_PATH' is not a directory." >&2
  exit 65
fi

mkdir -p "$(dirname "$OUTPUT_PATH")"

echo "[entrypoint] scanner=$SCANNER repo=$REPO_PATH -> $OUTPUT_PATH"

case "$SCANNER" in
  gitleaks)
    # WORKING-TREE scan (--no-git): this is the HEADLINE "currently exposed
    # secret" signal. Git history is scanned separately (gitleaks-history).
    exec gitleaks detect \
        --source "$REPO_PATH" \
        --no-git \
        --no-banner \
        --redact \
        --report-format json \
        --report-path "$OUTPUT_PATH" \
        --exit-code 0 "$@"
    ;;

  gitleaks-history)
    # FULL GIT-HISTORY scan over a bare mirror clone (removed-then-committed
    # secrets). Reported SEPARATELY from the working-tree headline metric.
    exec gitleaks detect \
        --source "$REPO_PATH" \
        --no-banner \
        --redact \
        --report-format json \
        --report-path "$OUTPUT_PATH" \
        --exit-code 0 "$@"
    ;;

  semgrep)
    # Offline: use pre-fetched pinned rules mounted at /scan/semgrep-rules.
    export SEMGREP_SEND_METRICS=off
    # NOTE: --error removed (audit P0 #2) so "findings found" is exit 1, not a hard
    # failure; the host runner treats exit 1 as SUCCESS_WITH_FINDINGS per
    # scanner-config.yaml exit_semantics. >=2 remains a genuine error.
    exec semgrep scan \
        --config /scan/semgrep-rules \
        --metrics=off \
        --sarif \
        --output "$OUTPUT_PATH" \
        --disable-version-check \
        "$REPO_PATH" "$@"
    ;;

  trivy)
    # Offline filesystem scan. DB must be pre-fetched into the trivy cache.
    # CS-002: bind Trivy to the EXPLICIT pinned cache mounted at /scan/trivy-cache
    # (HOME=/tmp is an ephemeral tmpfs, so the default cache would be empty).
    # The --scanners list below is AUTHORITATIVELY defined in
    # config/scanner-config.yaml (scanners.trivy.scanners) and must match it.
    # License scanning is intentionally NOT enabled (compliance, not security).
    export TRIVY_NO_PROGRESS=true
    exec trivy fs \
        --cache-dir /scan/trivy-cache \
        --scanners vuln,misconfig,secret \
        --format json \
        --output "$OUTPUT_PATH" \
        --offline-scan \
        --skip-db-update \
        --skip-java-db-update \
        "$REPO_PATH" "$@"
    ;;

  osv-scanner)
    # Offline dependency scan against the pre-fetched OSV database.
    # CS-002: point OSV at the EXPLICIT pinned local DB mounted at /scan/osv-db
    # (matches the --experimental-local-db-path used at prefetch time).
    exec osv-scanner \
        --recursive \
        --experimental-offline \
        --experimental-local-db-path /scan/osv-db \
        --format json \
        --output "$OUTPUT_PATH" \
        "$REPO_PATH" "$@"
    ;;

  zizmor)
    # Offline audits only (online audits disabled — no token/network in sandbox).
    # zizmor 1.x has no --output flag: it emits the report to STDOUT, so redirect it
    # to the mounted output path. Default exit codes are kept (findings -> nonzero)
    # per scanner-config exit_semantics.
    exec zizmor \
        --format sarif \
        --offline \
        "$REPO_PATH/.github/workflows" "$@" > "$OUTPUT_PATH"
    ;;

  *)
    echo "REFUSED: unknown scanner '$SCANNER'." >&2
    exit 66
    ;;
esac
