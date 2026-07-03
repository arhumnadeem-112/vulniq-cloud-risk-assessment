#!/bin/bash
# scripts/run_collectors.sh
# Single-service end-to-end pipeline example (Salesforce).
# Runs all collectors, ETL, and scoring in sequence.
# Useful for a first-run smoke test or a focused single-vendor refresh.
#
# Usage:
#   bash scripts/run_collectors.sh

set -euo pipefail

# ── Load environment variables ────────────────────────────────────────────────
# Copy .env.example to .env and fill in your credentials before running.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/../.env"

if [ -f "$ENV_FILE" ]; then
  # shellcheck disable=SC1090
  set -a; source "$ENV_FILE"; set +a
fi

# ── Validate required variables ───────────────────────────────────────────────
REQUIRED_VARS=(DATABASE_URL GITHUB_TOKEN CHROMA_HOST CHROMA_PORT)
for var in "${REQUIRED_VARS[@]}"; do
  if [ -z "${!var:-}" ]; then
    echo "ERROR: $var is not set. Copy .env.example to .env and fill in your credentials."
    exit 1
  fi
done

NVD_API_KEY="${NVD_API_KEY:-}"
IMAGE="${IMAGE:-acrcloudriskdev.azurecr.io/cloudrisk:latest}"

# Shared run ID for the etl → score pair so both stages operate on the same data
TEST_RUN_ID="test-$(date +%Y%m%d-%H%M%S)"

# Ensure local data directories exist so ETL and scoring can share files across containers
mkdir -p "$(pwd)/data/etl" "$(pwd)/data/scores" "$(pwd)/data/manifests" "$(pwd)/data/raw"

# ── Helper ────────────────────────────────────────────────────────────────────
run() {
  local name="$1"
  local cmd="$2"

  echo ""
  echo "========================================"
  echo "  Running: $name"
  echo "========================================"

  docker run --rm \
    -e "DATABASE_URL=$DATABASE_URL" \
    -e "GITHUB_TOKEN=$GITHUB_TOKEN" \
    -e "NVD_API_KEY=$NVD_API_KEY" \
    -e "CHROMA_HOST=$CHROMA_HOST" \
    -e "CHROMA_PORT=$CHROMA_PORT" \
    -e "CLOUDRISK_COMMAND=$cmd" \
    -v "$(pwd)/data:/data" \
    "$IMAGE"

  if [ $? -ne 0 ]; then
    echo "FAILED: $name"
    exit 1
  else
    echo "PASSED: $name"
  fi
}

# ── Schema migration (run once before any collectors) ─────────────────────────
run "db_migrate" "db_migrate"

# ── Collectors ────────────────────────────────────────────────────────────────
run "collect_nvd"       "collect_nvd --service salesforce"
run "collect_osv"       "collect_osv --service salesforce --ecosystem npm"
run "collect_ghsa"      "collect_ghsa --service salesforce --ecosystem npm"
run "collect_kev"       "collect_kev --service salesforce"
run "collect_github"    "collect_github --service salesforce --repo forcedotcom/salesforcedx-vscode"
run "collect_status"    "collect_status --service salesforce --status-url https://status.salesforce.com"
run "collect_docs"      "collect_docs --service salesforce --urls \
  https://developer.salesforce.com/docs/atlas.en-us.secure_coding_guide.meta/secure_coding_guide/ \
  https://help.salesforce.com/s/articleView?id=sf.security_overview.htm"
run "collect_trust"     "collect_trust --service salesforce --urls \
  https://www.salesforce.com/company/privacy/ \
  https://security.salesforce.com \
  https://compliance.salesforce.com"
run "collect_vuln_text" "collect_vuln_text --service salesforce"
run "monitor_nvd"       "monitor_nvd --service salesforce"

# ── ETL ───────────────────────────────────────────────────────────────────────
# Reads from MySQL + ChromaDB, writes feature records to /data/etl/$TEST_RUN_ID/
run "etl" "etl --run-id $TEST_RUN_ID --ospc /data/config/ospc.json"

# ── Scoring ───────────────────────────────────────────────────────────────────
# Reads feature records written by ETL, computes risk scores,
# writes to MySQL scores table + /data/scores/$TEST_RUN_ID/
run "score" "score --run-id $TEST_RUN_ID --ospc /data/config/ospc.json"

echo ""
echo "========================================"
echo "  All steps completed successfully"
echo "========================================"
