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
    # Working-tree scan (no git required for --no-git); history handled by a
    # separate invocation from the host with a full clone.
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
    # The --scanners list below is AUTHORITATIVELY defined in
    # config/scanner-config.yaml (scanners.trivy.scanners) and must match it.
    # License scanning is intentionally NOT enabled (compliance, not security).
    export TRIVY_NO_PROGRESS=true
    exec trivy fs \
        --scanners vuln,misconfig,secret \
        --format json \
        --output "$OUTPUT_PATH" \
        --offline-scan \
        --skip-db-update \
        --skip-java-db-update \
        "$REPO_PATH" "$@"
    ;;

  osv-scanner)
    # Offline dependency scan against pre-fetched OSV database.
    exec osv-scanner \
        --recursive \
        --offline \
        --format json \
        --output "$OUTPUT_PATH" \
        "$REPO_PATH" "$@"
    ;;

  zizmor)
    # Offline audits only (online audits disabled — no token/network in sandbox).
    exec zizmor \
        --format sarif \
        --offline \
        --output "$OUTPUT_PATH" \
        "$REPO_PATH/.github/workflows" "$@"
    ;;

  *)
    echo "REFUSED: unknown scanner '$SCANNER'." >&2
    exit 66
    ;;
esac
