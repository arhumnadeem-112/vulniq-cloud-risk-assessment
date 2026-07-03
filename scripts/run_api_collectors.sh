#!/bin/bash
# scripts/run_api_collectors.sh
# Runs only the structured-data API collectors → MySQL.
# No NLP, no ChromaDB text scraping.
#
# Outputs:  vulnerabilities, repo_health, service_incidents tables in MySQL
# Run this first before run_nlp_pipeline.sh (collect_vuln_text reads from MySQL)
#
# Usage:
#   bash scripts/run_api_collectors.sh               # collect all services
#   bash scripts/run_api_collectors.sh salesforce    # collect one service only

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

# NVD_API_KEY is optional (raises rate limit from 5 to 50 req/30s)
NVD_API_KEY="${NVD_API_KEY:-}"

IMAGE="${IMAGE:-acrcloudriskdev.azurecr.io/cloudrisk:latest}"

# ── Service definitions ───────────────────────────────────────────────────────
# Format per entry: "service_name|github_repo|status_flag"
#   github_repo  — leave empty to skip collect_github for that service
#   status_flag  — "--provider <name>" for custom handlers, or
#                  "--status-url <url>" for Statuspage.io-compatible pages
SERVICES=(
  # ── CRM / SaaS ──────────────────────────────────────────────────────────────
  "salesforce|forcedotcom/salesforcedx-vscode|--provider salesforce"
  "hubspot|HubSpot/hubspot-api-client-python|--status-url https://status.hubspot.com"
  "servicenow|ServiceNow/servicenow-devtools|--status-url https://status.servicenow.com"
  "workday|Workday/canvas-kit|--status-url https://status.workday.com"
  "deel||--status-url https://status.deel.com"

  # ── Cloud & Infrastructure (Big Tech OSS) ────────────────────────────────────
  "google|kubernetes/kubernetes|--provider gcp"
  "microsoft|microsoft/TypeScript|--provider azure"
  "amazon|opensearch-project/opensearch|--provider aws"
  "meta|facebook/react|--status-url https://metastatus.com"
  "ibm|IBM/ibm-watson-developer-cloud-python-sdk|--status-url https://status.ibm.com"

  # ── Security & Observability ─────────────────────────────────────────────────
  "cloudflare|cloudflare/pingora|--status-url https://www.cloudflarestatus.com"
  "elastic|elastic/elasticsearch|--status-url https://status.elastic.co"
  "datadog|DataDog/dd-trace-py|--status-url https://status.datadoghq.com"
  "crowdstrike|CrowdStrike/falconpy|--status-url https://status.crowdstrike.com"
  "okta|okta/okta-sdk-python|--status-url https://status.okta.com"

  # ── Data & AI ────────────────────────────────────────────────────────────────
  "snowflake|snowflakedb/snowflake-connector-python|--status-url https://status.snowflake.com"
  "databricks|mlflow/mlflow|--status-url https://status.databricks.com"
  "mongodb|mongodb/mongo-python-driver|--status-url https://status.mongodb.com"
  "confluent|confluentinc/confluent-kafka-python|--status-url https://status.confluent.io"
  "redis|redis/redis-py|--status-url https://status.redis.io"
  "palantir|palantir/conjure|--status-url https://status.palantir.com"

  # ── Dev Tools & Platform ─────────────────────────────────────────────────────
  "hashicorp|hashicorp/terraform|--status-url https://status.hashicorp.com"
  "gitlab|gitlabhq/gitlabhq|--status-url https://status.gitlab.com"
  "atlassian|atlassian/atlascode|--status-url https://status.atlassian.com"
  "shopify|Shopify/liquid|--status-url https://www.shopifystatus.com"
  "twilio|twilio/twilio-python|--status-url https://status.twilio.com"
  "stripe|stripe/stripe-python|--status-url https://status.stripe.com"
  "github|github/docs|--status-url https://githubstatus.com"
)

# ── Helpers ───────────────────────────────────────────────────────────────────
_docker_run() {
  docker run --rm \
    -e "DATABASE_URL=$DATABASE_URL" \
    -e "GITHUB_TOKEN=$GITHUB_TOKEN" \
    -e "NVD_API_KEY=$NVD_API_KEY" \
    -e "CHROMA_HOST=$CHROMA_HOST" \
    -e "CHROMA_PORT=$CHROMA_PORT" \
    -e "CLOUDRISK_COMMAND=$2" \
    -v "$(pwd)/data/config:/data/config:ro" \
    "$IMAGE"
}

# Fatal on failure — use for core collectors (NVD, OSV, GHSA, KEV, db_migrate)
run() {
  local name="$1"
  local cmd="$2"

  echo ""
  echo "========================================"
  echo "  Running: $name"
  echo "========================================"

  _docker_run "$name" "$cmd"

  if [ $? -ne 0 ]; then
    echo "FAILED: $name"
    exit 1
  else
    echo "PASSED: $name"
  fi
}

# Warn on failure but continue — use for external-URL collectors (status, github)
run_optional() {
  local name="$1"
  local cmd="$2"

  echo ""
  echo "========================================"
  echo "  Running: $name"
  echo "========================================"

  _docker_run "$name" "$cmd"

  if [ $? -ne 0 ]; then
    echo "SKIPPED (non-fatal): $name"
  else
    echo "PASSED: $name"
  fi
}

collect_service() {
  local service="$1"
  local github_repo="$2"
  local status_flag="$3"

  echo ""
  echo "######## $service ########"

  run "collect_nvd    [$service]" "collect_nvd --service $service"
  run "collect_osv    [$service]" "collect_osv --service $service"
  run "collect_ghsa   [$service]" "collect_ghsa --service $service"
  run "collect_kev    [$service]" "collect_kev --service $service"

  if [ -n "$github_repo" ]; then
    run_optional "collect_github [$service]" "collect_github --service $service --repo $github_repo"
  fi

  run_optional "collect_status [$service]" "collect_status --service $service $status_flag"
  run "monitor_nvd    [$service]" "monitor_nvd --service $service"
}

# ── Schema migration ──────────────────────────────────────────────────────────
run "db_migrate" "db_migrate"

# ── Collect all services (or just the one passed as $1) ──────────────────────
FILTER="${1:-}"

for entry in "${SERVICES[@]}"; do
  IFS='|' read -r svc repo status_flag <<< "$entry"

  if [ -n "$FILTER" ] && [ "$svc" != "$FILTER" ]; then
    continue
  fi

  collect_service "$svc" "$repo" "$status_flag"
done

echo ""
echo "========================================"
echo "  API collection complete"
echo "  MySQL tables populated: vulnerabilities, repo_health, service_incidents"
echo "  Run run_nlp_pipeline.sh next to collect text and score"
echo "========================================"
