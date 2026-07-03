#!/bin/bash
# scripts/run_nlp_pipeline.sh
# Runs the text collection (ChromaDB) and NLP scoring pipeline for all services.
# Depends on run_api_collectors.sh having populated MySQL first
# (collect_vuln_text reads CVE IDs from the vulnerabilities table).
#
# Text sources (all GitHub-derived — no external trust/doc sites):
#   collect_docs  → github_repos homepage + README (via service_aliases.py)
#   collect_trust → github_repos /security/policy + /security/advisories
#   collect_vuln_text → CVE descriptions from MySQL vulnerabilities table
#
# Outputs:
#   ChromaDB collections: documentation, trust_disclosures, vuln_text
#   ETL NDJSON:           /data/etl/<run-id>/
#   Risk scores:          /data/scores/<run-id>/ + MySQL scores table
#
# Usage:
#   bash scripts/run_nlp_pipeline.sh               # collect all services
#   bash scripts/run_nlp_pipeline.sh salesforce    # collect one service only

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

# Shared run ID ties the etl and score steps together
RUN_ID="nlp-$(date +%Y%m%d-%H%M%S)"

# ── Service list ──────────────────────────────────────────────────────────────
# collect_docs and collect_trust auto-derive GitHub URLs from service_aliases.py
# when no --urls flag is given, so only the service name is needed here.
SERVICES=(
  # CRM / SaaS
  salesforce hubspot servicenow workday deel
  # Cloud & Infrastructure
  google microsoft amazon meta ibm
  # Security & Observability
  cloudflare elastic datadog crowdstrike okta
  # Data & AI
  snowflake databricks mongodb confluent redis palantir
  # Dev Tools & Platform
  hashicorp gitlab atlassian shopify twilio stripe github
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
    -v "$(pwd)/data:/data" \
    "$IMAGE"
}

# Fatal on failure — core pipeline steps (etl, score, collect_vuln_text)
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

# Warn on failure but continue — GitHub pages that may 404 for some repos
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

collect_service_nlp() {
  local service="$1"

  echo ""
  echo "######## $service ########"

  # No --urls: both collectors auto-derive from github_repos in service_aliases.py
  # collect_docs  → repo homepage + GitHub repo page (README)
  # collect_trust → /security/policy + /security/advisories per repo
  run_optional "collect_docs  [$service]"     "collect_docs --service $service"
  run_optional "collect_trust [$service]"     "collect_trust --service $service"
  run          "collect_vuln_text [$service]" "collect_vuln_text --service $service"
}

# ── Collect NLP text for all services (or just the one passed as $1) ──────────
FILTER="${1:-}"

for svc in "${SERVICES[@]}"; do
  if [ -n "$FILTER" ] && [ "$svc" != "$FILTER" ]; then
    continue
  fi
  collect_service_nlp "$svc"
done

# ── ETL: extract features from MySQL + ChromaDB ───────────────────────────────
run "etl"   "etl --run-id $RUN_ID --ospc /data/config/ospc.json"

# ── Scoring: compute risk scores from ETL features ───────────────────────────
run "score" "score --run-id $RUN_ID --ospc /data/config/ospc.json"

echo ""
echo "========================================"
echo "  NLP pipeline complete  (run-id: $RUN_ID)"
echo "  ChromaDB: documentation, trust_disclosures, vuln_text updated"
echo "  MySQL scores table updated"
echo "========================================"
