# Dockerfile
# capstone-cloudrisk — data collection pipeline
# Runs all collection scripts inside Azure Container Apps Jobs
#
# The only thing that changes between jobs is CLOUDRISK_COMMAND.
# All scripts live in the same image — no rebuilds needed to switch scripts.
#
# ── Command reference ──────────────────────────────────────────────────────
#
#   ── Individual collectors ──────────────────────────────────────────────────
#   collect_nvd       →  CLOUDRISK_COMMAND='collect_nvd --service salesforce'
#   collect_osv       →  CLOUDRISK_COMMAND='collect_osv --service salesforce --ecosystem npm'
#   collect_ghsa      →  CLOUDRISK_COMMAND='collect_ghsa --service salesforce --ecosystem npm'
#   collect_kev       →  CLOUDRISK_COMMAND='collect_kev --service salesforce'
#   collect_github    →  CLOUDRISK_COMMAND='collect_github --service salesforce --repo forcedotcom/salesforcedx-vscode'
#   collect_vuln_text →  CLOUDRISK_COMMAND='collect_vuln_text --service salesforce'
#   collect_status    →  CLOUDRISK_COMMAND='collect_status --service salesforce --status-url https://status.salesforce.com'
#   collect_docs      →  CLOUDRISK_COMMAND='collect_docs --service salesforce --urls https://developer.salesforce.com/docs/security'
#   collect_trust     →  CLOUDRISK_COMMAND='collect_trust --service salesforce --urls https://trust.salesforce.com'
#   db_migrate        →  CLOUDRISK_COMMAND='db_migrate'
#   monitor_nvd       →  CLOUDRISK_COMMAND='monitor_nvd --service salesforce'
#
#   ── Pipeline stages ───────────────────────────────────────────────────────
#   etl               →  CLOUDRISK_COMMAND='etl --run-id <uuid> --ospc /data/config/ospc.json'
#   score             →  CLOUDRISK_COMMAND='score --run-id <uuid> --ospc /data/config/ospc.json'
#
#   ── Full pipeline (collect → etl → score) ─────────────────────────────────
#   run               →  CLOUDRISK_COMMAND='run --service salesforce --ospc /data/config/ospc.json'
#   run (subset)      →  CLOUDRISK_COMMAND='run --service salesforce --ospc /data/config/ospc.json --sources nvd,ghsa,kev'
#   run (etl+score only) → CLOUDRISK_COMMAND='run --service salesforce --ospc /data/config/ospc.json --skip-collect'
#
#   ── Utilities ─────────────────────────────────────────────────────────────
#   validate-ospc     →  CLOUDRISK_COMMAND='validate-ospc --ospc /data/config/ospc.json'
#
# ───────────────────────────────────────────────────────────────────────────

FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libxml2-dev \
    libxslt1-dev \
    default-libmysqlclient-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Pre-cache ChromaDB's own ONNX embedding model (used by chroma_writer)
RUN python -c "from chromadb.utils.embedding_functions.onnx_mini_lm_l6_v2 import ONNXMiniLM_L6_V2; ef = ONNXMiniLM_L6_V2(); ef(['warm up'])"

# Copy all collection scripts and the entrypoint
COPY collectors/ ./collectors/
COPY collectors/entrypoint.py ./collectors/entrypoint.py

# Create data directory structure
RUN mkdir -p /data/raw /data/etl /data/scores \
             /data/reports /data/manifests /data/config

# Single entrypoint — reads CLOUDRISK_COMMAND and routes to the right script
# Uses shlex parsing so URLs, quoted strings, and multi-value args all work correctly
CMD ["python", "-m", "collectors.entrypoint"]
