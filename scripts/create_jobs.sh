#!/bin/bash
# scripts/create_jobs.sh
# Creates all Azure Container Apps Jobs for the cloudrisk pipeline.
# Run once to set up all jobs. Safe to re-run — existing jobs are skipped.
#
# Prerequisites:
#   - Azure CLI installed and logged in (az login)
#   - .env file populated with required credentials
#   - Container Apps Environment already provisioned
#
# Usage:
#   bash scripts/create_jobs.sh

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
REQUIRED_VARS=(
  DATABASE_URL GITHUB_TOKEN CHROMA_HOST CHROMA_PORT
  AZURE_RESOURCE_GROUP AZURE_CONTAINER_APP_ENV
  AZURE_REGISTRY AZURE_MANAGED_IDENTITY
)
for var in "${REQUIRED_VARS[@]}"; do
  if [ -z "${!var:-}" ]; then
    echo "ERROR: $var is not set. Copy .env.example to .env and fill in your credentials."
    exit 1
  fi
done

NVD_API_KEY="${NVD_API_KEY:-}"
IMAGE="${IMAGE:-${AZURE_REGISTRY}/cloudrisk:latest}"
DATA_DIR="${DATA_DIR:-/data}"

# ── Shared env vars string ────────────────────────────────────────────────────
ENV_VARS="DATABASE_URL=$DATABASE_URL \
  CHROMA_HOST=$CHROMA_HOST \
  CHROMA_PORT=$CHROMA_PORT \
  GITHUB_TOKEN=$GITHUB_TOKEN \
  NVD_API_KEY=$NVD_API_KEY \
  DATA_DIR=$DATA_DIR"

# ── Helper ────────────────────────────────────────────────────────────────────
create_job() {
  local name="$1"
  local cron="$2"
  local command="$3"
  local timeout="${4:-600}"

  echo ""
  echo "========================================"
  echo "  Creating job: $name"
  echo "  Cron: $cron"
  echo "  Command: $command"
  echo "========================================"

  # Skip if job already exists
  if az containerapp job show \
      --name "$name" \
      --resource-group "$AZURE_RESOURCE_GROUP" \
      --output none 2>/dev/null; then
    echo "  Job already exists — skipping"
    return
  fi

  az containerapp job create \
    --name "$name" \
    --resource-group "$AZURE_RESOURCE_GROUP" \
    --environment "$AZURE_CONTAINER_APP_ENV" \
    --image "$IMAGE" \
    --registry-server "$AZURE_REGISTRY" \
    --mi-user-assigned "$AZURE_MANAGED_IDENTITY" \
    --trigger-type Schedule \
    --cron-expression "$cron" \
    --replica-timeout "$timeout" \
    --replica-retry-limit 1 \
    --parallelism 1 \
    --replica-completion-count 1 \
    --cpu 1 \
    --memory 2Gi \
    --env-vars $ENV_VARS CLOUDRISK_COMMAND="$command"

  echo "  Created: $name"
}

# ── Jobs ──────────────────────────────────────────────────────────────────────

# db_migrate — monthly, 1st of month at midnight
create_job \
  "job-db-migrate" \
  "0 0 1 * *" \
  "db_migrate" \
  300

# collect_nvd — daily at 2am
create_job \
  "job-collect-nvd" \
  "0 2 * * *" \
  "collect_nvd --service salesforce" \
  600

# monitor_nvd — every 6 hours (catches CVE modifications)
create_job \
  "job-monitor-nvd" \
  "0 */6 * * *" \
  "monitor_nvd --service salesforce" \
  600

# collect_kev — daily at 3am
create_job \
  "job-collect-kev" \
  "0 3 * * *" \
  "collect_kev --service salesforce" \
  300

# collect_osv — daily at 4am
create_job \
  "job-collect-osv" \
  "0 4 * * *" \
  "collect_osv --service salesforce --ecosystem npm" \
  600

# collect_ghsa — daily at 4:30am
create_job \
  "job-collect-ghsa" \
  "30 4 * * *" \
  "collect_ghsa --service salesforce --ecosystem npm" \
  600

# collect_github — daily at 5am
create_job \
  "job-collect-github" \
  "0 5 * * *" \
  "collect_github --service salesforce --repo forcedotcom/salesforcedx-vscode" \
  600

# collect_status — every 4 hours
create_job \
  "job-collect-status" \
  "0 */4 * * *" \
  "collect_status --service salesforce --status-url https://status.salesforce.com" \
  300

# collect_docs — weekly on Sunday at 6am
create_job \
  "job-collect-docs" \
  "0 6 * * 0" \
  "collect_docs --service salesforce --urls https://help.salesforce.com/s/articleView?id=sf.security_overview.htm" \
  900

# collect_trust — weekly on Sunday at 6:30am
create_job \
  "job-collect-trust" \
  "30 6 * * 0" \
  "collect_trust --service salesforce --urls https://www.salesforce.com/company/privacy/ https://www.salesforce.com/trust/security/" \
  900

# collect_vuln_text — daily at 7am (after NVD/OSV/GHSA have run)
create_job \
  "job-collect-vuln-text" \
  "0 7 * * *" \
  "collect_vuln_text --service salesforce" \
  900

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "========================================"
echo "  All jobs created. Listing:"
echo "========================================"
az containerapp job list \
  --resource-group "$AZURE_RESOURCE_GROUP" \
  --output table
