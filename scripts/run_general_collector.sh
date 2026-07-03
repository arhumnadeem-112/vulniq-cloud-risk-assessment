#!/bin/bash
# scripts/run_general_collector.sh
# Collects the latest 6 months of CVEs from NVD, KEV, and GHSA
# without targeting any specific vendor — for general risk assessments.
#
# Outputs: vulnerabilities table rows with service_name derived from CPE/vendor/package
#
# Usage:
#   bash scripts/run_general_collector.sh                          # all sources, last 180 days
#   bash scripts/run_general_collector.sh --sources nvd,kev        # subset of sources
#   bash scripts/run_general_collector.sh --start-date 2024-11-01  # override start date

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

# ── Parse optional flags ──────────────────────────────────────────────────────
SOURCES=""
START_DATE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --sources)    SOURCES="$2";    shift 2 ;;
    --start-date) START_DATE="$2"; shift 2 ;;
    *) echo "Unknown argument: $1"; exit 1 ;;
  esac
done

# Build the CLOUDRISK_COMMAND args
GENERAL_ARGS=""
[ -n "$SOURCES" ]    && GENERAL_ARGS="$GENERAL_ARGS --sources $SOURCES"
[ -n "$START_DATE" ] && GENERAL_ARGS="$GENERAL_ARGS --start-date $START_DATE"

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

# ── Schema migration ──────────────────────────────────────────────────────────
run "db_migrate" "db_migrate"

# ── General CVE collection ────────────────────────────────────────────────────
run "collect_general" "collect_general${GENERAL_ARGS}"

echo ""
echo "========================================"
echo "  General collection complete"
echo "  MySQL table populated: vulnerabilities"
echo "========================================"
