# capstone-cloudrisk — Project Status & Reference

> Last updated: 2026-06-02

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [What Has Been Built](#2-what-has-been-built)
3. [What Works End-to-End](#3-what-works-end-to-end)
4. [What Has Not Been Built Yet](#4-what-has-not-been-built-yet)
5. [Azure Infrastructure — Manual Setup Note](#5-azure-infrastructure--manual-setup-note)
6. [Bicep IaC — Work in Progress](#6-bicep-iac--work-in-progress)
7. [Database Schema & Column Definitions](#7-database-schema--column-definitions)
8. [Scoring Model Explained](#8-scoring-model-explained)
9. [OSPC Configuration](#9-ospc-configuration)
10. [Project Setup Guide](#10-project-setup-guide)

---

## 1. Project Overview

**capstone-cloudrisk** (also referred to as **VulnIQ**) is a cloud vendor risk intelligence platform that automatically collects security data about third-party cloud services your organisation depends on, computes a composite risk score per vendor, and surfaces the results in Power BI.

The pipeline works in four stages:

```
Collectors → MySQL / ChromaDB → ETL → Scoring → Power BI
```

| Stage | What it does |
|---|---|
| **Collectors** | Pull CVE data, incident history, repo health metrics, and compliance text from public APIs and status pages |
| **MySQL** | Stores structured records (vulnerabilities, incidents, repo health, services, scores) |
| **ChromaDB** | Stores unstructured text (documentation, advisory text, trust disclosures, postmortems) for NLP |
| **ETL** | Reads both stores, engineers six composite feature indices, flags data confidence level |
| **Scoring** | Applies a weighted scoring model (configurable via OSPC) and writes final scores back to MySQL |
| **Power BI** | Connects directly to the MySQL `scores` table for dashboards |

The platform covers **33 cloud services** spanning CRM/SaaS, cloud infrastructure, security tools, data/AI platforms, and developer tooling.

---

## 2. What Has Been Built

### 2.1 Data Collection Layer

All collectors live in `collectors/` and share a `BaseCollector` base class that handles retries, rate limiting, and HTTP session management.

| Collector | Source | What it collects | Output |
|---|---|---|---|
| `collect_nvd.py` | NIST NVD API v2 | CVE records, CVSS v3 scores, CWE IDs for the last 180 days | MySQL `vulnerabilities` |
| `collect_ghsa.py` | GitHub Security Advisory GraphQL API | Package-level advisories with severity, CVSS, CWE, and advisory narrative text | MySQL `vulnerabilities` + ChromaDB `advisory_text` |
| `collect_kev.py` | CISA Known Exploited Vulnerabilities catalog | KEV flags — marks `is_kev=1` on matching rows across all sources | MySQL `vulnerabilities` (update) |
| `collect_osv.py` | OSV.dev API + FIRST.org EPSS API | Open-source package vulnerabilities with EPSS exploit probability scores | MySQL `vulnerabilities` |
| `collect_status.py` | Statuspage.io API, AWS Health, Azure RSS, GCP JSON, Salesforce API | Incident history: severity, duration, affected components, postmortem text | MySQL `service_incidents` + ChromaDB `incident_postmortems` |
| `collect_docs.py` | Vendor documentation pages (scraped via BeautifulSoup) | Security documentation and developer guidance text | ChromaDB `documentation` |
| `collect_trust.py` | Vendor trust center / compliance pages (scraped) | SOC 2, ISO 27001, HIPAA, GDPR, PCI-DSS, FedRAMP certification disclosures | ChromaDB `trust_disclosures` |
| `collect_vuln_text.py` | NVD raw_json already in MySQL → NVD API fallback → MITRE CVE AWG API | CVE description text for NLP feature extraction | ChromaDB `vuln_text` |
| `collect_general.py` | NVD + KEV + GHSA (no vendor filter) | Broad CVE sweep for general risk assessment; service name derived from CPE/vendorProject/package fields | MySQL `vulnerabilities` |

### 2.2 Service Alias Registry (`service_aliases.py`)

Defines 33 canonical vendor entries. Each entry specifies:

- `nvd_keywords` — NVD keywordSearch terms (covers subsidiaries, e.g. Salesforce → also queries Tableau, MuleSoft, Heroku, Slack)
- `kev_vendors` — CISA KEV `vendorProject` substrings to match
- `packages` — `{ecosystem: [package_names]}` for GHSA/OSV package-registry lookups
- `status_url` — Statuspage.io-compatible root URL
- `status_provider` — named shorthand for built-in providers (aws, azure, gcp, salesforce)
- `github_repos` — public GitHub `owner/repo` slugs used by `collect_docs` and `collect_trust` to auto-derive documentation and security policy URLs without manual URL lists

Services covered:
- **CRM / SaaS**: salesforce, hubspot, servicenow, workday, deel
- **Cloud Infrastructure**: aws, azure, gcp, google, microsoft, amazon, meta, ibm
- **Security & Observability**: okta, cloudflare, elastic, datadog, crowdstrike
- **Data & AI**: snowflake, databricks, mongodb, confluent, redis, palantir
- **Dev Tools & Platform**: stripe, twilio, hashicorp, gitlab, atlassian, shopify, github

### 2.3 Database Migration (`db_migrate.py`)

Creates all five MySQL tables idempotently (`CREATE TABLE IF NOT EXISTS`). Also runs column-level migrations for existing deployments. Safe to re-run at any time.

### 2.4 ETL Pipeline (`etl.py`)

Reads from MySQL and ChromaDB, computes all feature vectors, and writes one NDJSON record per service to Azure Files at `/data/etl/{run_id}/features.ndjson`. Also writes a `manifest.json` summary.

Key transformations:
- Deduplicates CVEs by `cve_id` (keeps highest CVSS)
- Applies temporal decay weighting to older CVEs
- Computes NLP scores via keyword density (doc quality, security guidance, trust coverage) and VADER sentiment (incident postmortems)
- Engineers six composite feature indices: `security_posture_index`, `operational_maturity_index`, `reliability_index`, `governance_index`, `kev_severity_index`, `patch_velocity_index`
- Assigns a `data_confidence` flag (`full_data` / `partial_data` / `insufficient_data`) based on how many of the four data categories (CVEs, repo health, incidents, NLP docs) are populated

### 2.5 Scoring Pipeline (`scoring.py`)

Reads the NDJSON feature records from ETL, applies a weighted model, and writes results to:
1. `/data/scores/{run_id}/{service_name}_score.json` on Azure Files (per-service JSON report)
2. MySQL `scores` table (primary Power BI source)

Scoring features:
- Three-stage weight composition: default weights → regulatory framework adjustments (SOC2, PCI-DSS, HIPAA, ISO27001, GDPR, FedRAMP) → OSPC hard overrides
- Compensating control discounts applied multiplicatively (mfa_enforced, waf_deployed, network_segmentation, etc.)
- Confidence penalty: `insufficient_data` services receive a 0.75× multiplier on the final score
- Final score clamped to [0, 100]

### 2.6 Pipeline Orchestration

| Script | Purpose |
|---|---|
| `collectors/entrypoint.py` | Container entrypoint; reads `CLOUDRISK_COMMAND` env var and dispatches to the correct module. Supports meta-commands: `run` (collect→etl→score), `collect`, `validate-ospc` |
| `run_collectors.sh` | Local/manual pipeline run — Salesforce-focused example with all collectors, ETL, and scoring |
| `run_api_collectors.sh` | Runs all API-based vulnerability collectors (NVD, OSV, GHSA, KEV, status, repo health) for every service in the service list |
| `run_nlp_pipeline.sh` | Runs text collectors (docs, trust, vuln_text) and the full ETL+score pipeline for all 33 services |
| `run_general_collector.sh` | Runs `collect_general` for a broad non-vendor-specific CVE sweep |
| `create_jobs.sh` | Creates Azure Container Apps Jobs definitions for each collector |

### 2.7 Docker Image

A single `Dockerfile` packages all collectors into one image. The `CLOUDRISK_COMMAND` environment variable selects which script to run, so no image rebuilds are needed to switch jobs. The image pre-warms ChromaDB's ONNX embedding model at build time.

### 2.8 Bicep Infrastructure-as-Code (partial)

Located in `iac/`. Modules written for all components:

| Module | Resource |
|---|---|
| `main.bicep` | Entry point; wires all modules together |
| `modules/network.bicep` | VNet, subnets for Container Apps and ACI |
| `modules/storage.bicep` | Azure Files storage account |
| `modules/registry.bicep` | Azure Container Registry (ACR) |
| `modules/keyvault.bicep` | Key Vault for secrets injection |
| `modules/mysql.bicep` | Azure Database for MySQL Flexible Server |
| `modules/chromadb.bicep` | ChromaDB on Azure Container Instances (ACI) |
| `modules/monitoring.bicep` | Log Analytics workspace |
| `modules/container-apps.bicep` | Container Apps Environment + Jobs |

### 2.9 Tests

Located in `tests/`:
- `test_etl.py` — unit tests for ETL feature computation functions
- `test_scoring.py` — unit tests for scoring model: weight composition, compensating controls, confidence penalty

---

## 3. What Works End-to-End

The following has been verified working against the live Azure environment:

- **MySQL schema** — all five tables created and validated against the live MySQL Flexible Server
- **All API collectors** — NVD, GHSA, KEV, OSV collectors successfully write to MySQL
- **Status collectors** — incident data collected for Salesforce, AWS (Health API), Azure (RSS), GCP, and all Statuspage.io services
- **ChromaDB text collections** — `documentation`, `trust_disclosures`, `advisory_text`, `incident_postmortems`, `vuln_text` all populated
- **ETL pipeline** — feature extraction from both MySQL and ChromaDB works; NDJSON written to Azure Files
- **Scoring pipeline** — OSPC config loaded, weights computed, scores written to MySQL `scores` table and per-service JSON files
- **Docker image** — builds successfully; all collectors run inside the container via `CLOUDRISK_COMMAND` dispatch
- **`run_nlp_pipeline.sh`** — full end-to-end run for all 33 services
- **`collect_general.py`** — broad NVD/KEV/GHSA sweep without vendor targeting

---

## 4. What Has Not Been Built Yet

| Item | Status | Notes |
|---|---|---|
| **Power BI dashboard** | Stub only | `powerbi/` directory exists but the `.pbix` file is not in the repo. The MySQL `scores` table is ready for connection. |
| **`collect_github.py`** (repo health) | Not implemented | Referenced in `entrypoint.py` and `run_collectors.sh` but the file does not exist. Intended to collect commit count, contributor count, open issues, security policy presence from the GitHub API and write to `repo_health` table. |
| **Automated scheduling** | Not configured | `create_jobs.sh` creates the ACA Job definitions and `main.bicep` has a `pipelineCronSchedule` parameter, but the cron trigger has not been applied to the live environment. |
| **Bicep deployment** | WIP — blocked by Entra permissions | See Section 6. |
| **Front-end / API layer** | Not started | No REST API or web UI for querying scores. Power BI is the intended consumer. |
| **Alerting** | Not started | No alert rules on high-risk scores or new KEV matches. The Log Analytics workspace is provisioned but no alert rules have been written. |
| **EPSS enrichment for NVD records** | Partial | `collect_osv.py` fetches EPSS scores via FIRST.org API. NVD records have `epss_score = NULL` because NVD does not expose EPSS. A standalone EPSS backfill job could update existing rows. |
| **`monitor_nvd.py`** | Exists but untested in production | Intended for incremental CVE monitoring; not yet scheduled. |

---

## 5. Azure Infrastructure — Manual Setup Note

**The Azure environment was provisioned manually, not via the Bicep templates.** The following resources exist in the Azure subscription and were created through the Azure Portal / Azure CLI:

| Resource | Name |
|---|---|
| Resource Group | `rg-capstone-cloudrisk` |
| MySQL Flexible Server | `<mysql-host>` |
| MySQL Database | `cloudrisk` |
| MySQL Admin User | `<admin-user>` |
| Container Registry | `acr<admin-user>.azurecr.io` |
| ChromaDB (ACI) | Private IP `<chromadb-internal-ip>

<chromadb-internal-ip>

<chromadb-internal-ip>

<chromadb-internal-ip>

<chromadb-internal-ip>`, port `8000` |
| Azure Files | Mounted at `/data` inside containers |

The database connection string used throughout the shell scripts is:
```
mysql+pymysql://<admin-user>:<password>@<mysql-host>:3306/cloudrisk
```

SSL is enforced on the MySQL Flexible Server. The connection code in `db_migrate.py`, `etl.py`, and `scoring.py` all set `ssl_disabled: False` and `verify_mode: 0` (accept the server's self-signed cert without hostname verification).

---

## 6. Bicep IaC — Work in Progress

The Bicep templates in `iac/` are complete in code but **cannot be deployed end-to-end** due to Azure Entra ID (formerly AAD) permission restrictions in the shared academic/lab subscription:

- **Key Vault secret management** requires the deploying identity to have the `Key Vault Secrets Officer` role. This role assignment (`Microsoft.Authorization/roleAssignments/write`) was blocked by the Entra account's RBAC restrictions.
- **Container Apps managed identity** binding to Key Vault references also requires role assignments that could not be created.
- **ACI subnet delegation** for ChromaDB required a resource provider registration (`Microsoft.ContainerInstance`) that is blocked in the subscription.

As a workaround, secrets (database password, GitHub token, NVD API key) are injected directly as environment variables in the shell scripts rather than via Key Vault secret references.

**To complete the Bicep deployment in a permissioned environment**, the following are needed:
1. `Contributor` + `User Access Administrator` roles on the resource group (to allow `roleAssignments/write`)
2. Registration of `Microsoft.ContainerInstance` and `Microsoft.App` resource providers
3. A Service Principal or managed identity with `Key Vault Secrets Officer`

---

## 7. Database Schema & Column Definitions

### 7.1 `services` table

Canonical registry of all monitored cloud services.

| Column | Type | Why it exists |
|---|---|---|
| `id` | BIGINT PK AUTO_INCREMENT | Surrogate key |
| `name` | VARCHAR(256) UNIQUE | Canonical service name; used as the join key across all tables (e.g. `"salesforce"`, `"stripe"`) |
| `vendor` | VARCHAR(256) | Commercial vendor name, may differ from the canonical name (e.g. name=`"aws"`, vendor=`"Amazon Web Services"`) |
| `ecosystem` | VARCHAR(64) | Primary package ecosystem if the service is an open-source library (PyPI, npm, Maven, etc.); NULL for pure SaaS |
| `is_oss` | TINYINT(1) | 1 if the service has a significant open-source footprint; drives GHSA/OSV collection |
| `is_saas` | TINYINT(1) | 1 if the service is a SaaS product; drives status-page and trust-center collection |
| `github_repo` | VARCHAR(512) | Primary GitHub `owner/repo` slug; used by `collect_docs` and `collect_trust` for auto-URL derivation |
| `service_tier` | TINYINT | Criticality tier assigned by the OSPC config (1=critical, 2=important, 3=standard); used for reporting prioritisation |
| `status_page_url` | VARCHAR(1024) | Root URL of the vendor's Statuspage.io-compatible status page |
| `trust_center_url` | VARCHAR(1024) | Root URL of the vendor's trust/compliance center |
| `ingested_at` | DATETIME | Row creation timestamp |

---

### 7.2 `vulnerabilities` table

One row per unique (source, advisory_id) pair. Records from NVD, GHSA, OSV, and KEV all land here.

| Column | Type | Why it exists |
|---|---|---|
| `id` | BIGINT PK | Surrogate key |
| `source` | VARCHAR(64) | Which collector wrote the row: `nvd`, `ghsa`, `osv`, `kev`. Needed because the same CVE can appear in multiple sources with different metadata; the unique key is `(source, advisory_id)` so each source's view is preserved |
| `cve_id` | VARCHAR(32) | Canonical CVE identifier (e.g. `CVE-2024-1234`). NULL for GHSA-only advisories with no CVE mapping. Indexed for cross-source joins and KEV backfill updates |
| `advisory_id` | VARCHAR(128) | Source-native ID: CVE ID for NVD/KEV, GHSA-YYYY-MMDD-NNNN for GHSA, OSV-YYYY-NNNN for OSV. Forms the unique key with `source` |
| `service_name` | VARCHAR(256) | FK to `services.name`; which vendor this CVE was collected for. For `collect_general` rows this is derived from the CPE vendor field or package name rather than a pre-defined alias |
| `ecosystem` | VARCHAR(64) | Package ecosystem (PyPI, npm, Maven, etc.) for GHSA/OSV rows; `"SaaS"` for NVD/KEV rows where no ecosystem is meaningful |
| `severity` | VARCHAR(16) | CVSS v3 severity band: CRITICAL / HIGH / MEDIUM / LOW / NONE. Normalised from each source's own severity vocabulary (e.g. GHSA uses "MODERATE" → mapped to "MEDIUM") |
| `cvss_v3_score` | DECIMAL(4,1) | CVSS v3 base score [0.0–10.0]. NULL for KEV-only rows (CISA KEV does not publish scores) |
| `cvss_v3_vector` | VARCHAR(256) | Full CVSS v3 vector string (e.g. `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`). Used by analysts; not consumed by the scoring model |
| `epss_score` | DECIMAL(6,5) | EPSS (Exploit Prediction Scoring System) probability [0.0–1.0] from FIRST.org, fetched by `collect_osv`. NULL for NVD/GHSA rows. The ETL pipeline uses this as the `exploit_maturity_score` signal |
| `is_kev` | TINYINT(1) | 1 if this CVE appears in the CISA Known Exploited Vulnerabilities catalog. Updated by `collect_kev` across all rows regardless of source, so NVD rows also get this flag if the CVE is in KEV |
| `cwe_id` | VARCHAR(512) | Comma-separated CWE IDs (e.g. `"CWE-89,CWE-79"`). Collected from NVD weakness data and GHSA `cwes` field. Multiple CWEs can apply to one CVE |
| `published_at` | DATETIME | Date the CVE or advisory was first published. Used for temporal decay weighting in ETL and for the 180-day lookback filter |
| `modified_at` | DATETIME | Date the record was last updated at the source. Useful for detecting records that have been updated with new scores or affected-version data |
| `raw_json` | LONGTEXT | Full raw API response stored as JSON. Used by `collect_vuln_text` to extract CVE description text without a second API call |
| `ingested_at` | DATETIME | Row creation/update timestamp |

---

### 7.3 `repo_health` table

One row per (service_name, repo_full_name) snapshot. Updated on each collector run.

| Column | Type | Why it exists |
|---|---|---|
| `id` | BIGINT PK | Surrogate key |
| `service_name` | VARCHAR(256) | FK to `services.name` |
| `repo_full_name` | VARCHAR(512) | GitHub `owner/repo` (e.g. `"forcedotcom/salesforcedx-vscode"`). A service may have multiple repos |
| `commit_count_90d` | INT | Number of commits in the last 90 days. Measures project activity; very low values indicate a potentially abandoned project with slower security fixes |
| `contributor_count_90d` | INT | Number of unique contributors in the last 90 days. Single-maintainer projects have higher bus-factor risk |
| `open_issues` | INT | Total open GitHub issues. Context for the security-specific issue count |
| `security_issues_open` | INT | Open issues labelled `security` or `vulnerability`. A large backlog suggests slow triage |
| `mean_days_close_security` | DECIMAL(6,1) | Mean calendar days between opening and closing a security-labelled issue. Feeds `patch_velocity_index` in the ETL — lower is better |
| `days_since_last_release` | INT | Days since the most recent tagged release. Projects with no recent release may not be shipping security fixes to users |
| `has_security_policy` | TINYINT(1) | 1 if a `SECURITY.md` file exists in the repo. Indicates the project has a formal vulnerability disclosure process |
| `raw_json` | LONGTEXT | Raw GitHub API response |
| `collected_at` | DATETIME | Snapshot timestamp |

---

### 7.4 `service_incidents` table

One row per incident per service. Covers the last 180 days by default.

| Column | Type | Why it exists |
|---|---|---|
| `id` | BIGINT PK | Surrogate key |
| `service_name` | VARCHAR(256) | FK to `services.name` |
| `incident_id` | VARCHAR(128) | Source-native incident identifier (Statuspage.io incident ID, AWS event ARN, GCP incident ID). Forms the unique key with `service_name` |
| `severity` | VARCHAR(32) | Incident severity: `major`, `minor`, `maintenance`. Mapped from each source's own vocabulary (Statuspage.io `impact`, AWS event category, etc.) |
| `status` | VARCHAR(32) | Current resolution status: `resolved`, `investigating`, `monitoring`, etc. |
| `started_at` | DATETIME | When the incident began. Indexed for 12-month lookback queries in ETL |
| `resolved_at` | DATETIME | When the incident was resolved. NULL if still open |
| `duration_minutes` | INT | `resolved_at - started_at` in minutes, computed during collection. Used to derive `total_incident_hours_12m` in ETL |
| `affected_components` | VARCHAR(1024) | Comma-separated list of affected service components (e.g. `"API, Dashboard, Webhooks"`). Stored as a string because Statuspage.io returns component names as an array |
| `raw_json` | LONGTEXT | Full incident object from the source API |
| `collected_at` | DATETIME | Row creation/update timestamp |

---

### 7.5 `scores` table

One row per (run_id, service_name). The primary output table consumed by Power BI. A new run_id is generated for each pipeline execution, so historical scores are preserved.

| Column | Type | Why it exists |
|---|---|---|
| `id` | BIGINT PK | Surrogate key |
| `run_id` | VARCHAR(36) | UUID generated at pipeline start. Ties the ETL NDJSON and the score rows from the same run together. Allows trend analysis over time |
| `scored_at` | DATETIME | Timestamp when the score was computed |
| `service_name` | VARCHAR(256) | FK to `services.name` |
| `vendor` | VARCHAR(256) | Denormalised from `services.vendor` for convenience in Power BI |
| `ecosystem` | VARCHAR(64) | Denormalised from `services.ecosystem` |
| **`final_risk_score`** | DECIMAL(5,1) | **The primary output: composite risk score [0–100].** Higher = more risk. Derived from `raw_score` after applying compensating control discounts and the confidence penalty |
| `raw_score` | DECIMAL(5,1) | Weighted dot product of the four dimension indices × 100, before any discounts or penalties |
| `security_posture_score` | DECIMAL(5,1) | Contribution of the security posture dimension to the raw score (default weight 40%) |
| `operational_maturity_score` | DECIMAL(5,1) | Contribution of the operational maturity dimension (default weight 25%). Higher means more risk from poor repo hygiene |
| `service_reliability_score` | DECIMAL(5,1) | Contribution of the service reliability dimension (default weight 20%). Higher means more downtime/incidents |
| `governance_score` | DECIMAL(5,1) | Contribution of the governance & transparency dimension (default weight 15%). Higher means poor documentation, missing compliance certs, negative incident sentiment |
| `cve_count` | INT | Total deduplicated CVEs collected for this service in the current run |
| `highest_cvss` | DECIMAL(4,1) | Highest CVSS v3 base score across all CVEs for this service |
| `is_kev_present` | TINYINT(1) | 1 if any CVE for this service is in the CISA KEV catalog — a strong risk signal |
| `critical_cve_count` | INT | Count of CRITICAL-severity CVEs (CVSS ≥ 9.0) |
| `high_cve_count` | INT | Count of HIGH-severity CVEs (7.0 ≤ CVSS < 9.0) |
| `medium_cve_count` | INT | Count of MEDIUM-severity CVEs (4.0 ≤ CVSS < 7.0) |
| `low_cve_count` | INT | Count of LOW-severity CVEs (CVSS < 4.0) |
| `major_incident_count_12m` | INT | Count of major/critical incidents in the last 12 months. Feeds `service_reliability_score` |
| `total_incident_hours_12m` | DECIMAL(8,2) | Sum of `duration_minutes/60` for all incidents in the last 12 months |
| `commit_count_90d` | INT | Raw from `repo_health`; exposed in Power BI for trend analysis |
| `contributor_count_90d` | INT | Raw from `repo_health` |
| `days_since_release` | INT | Raw from `repo_health`; 999 if no data |
| `has_security_policy` | TINYINT(1) | Raw from `repo_health` |
| `doc_quality_score` | DECIMAL(5,4) | NLP keyword density of security-relevant documentation text [0–1]. Uses 20 security keywords (authentication, encryption, audit, etc.) |
| `security_guidance_score` | DECIMAL(5,4) | NLP keyword density of advisory/vendor security pages [0–1]. Uses 20 security hardening keywords (zero trust, MFA, WAF, penetration test, etc.) |
| `trust_coverage_score` | DECIMAL(5,4) | Fraction of the org's regulatory frameworks detected in vendor trust disclosures [0–1]. e.g. if your OSPC lists SOC2 and ISO27001, a vendor with both detected scores 1.0 |
| `incident_sentiment_score` | DECIMAL(5,4) | Inverted VADER compound sentiment of incident postmortem text [0–1]. Higher = more negative sentiment = more operational risk |
| `data_confidence` | VARCHAR(20) | `full_data` (all 4 data categories present), `partial_data` (2–3 categories), or `insufficient_data` (0–1 categories). `insufficient_data` services receive a 0.75× penalty on their final score |
| `ospc_org_name` | VARCHAR(256) | The `org_name` from the OSPC config used for this run; allows multi-tenant score comparison |
| `active_controls` | VARCHAR(512) | Comma-separated list of compensating controls active at scoring time (from OSPC config). Documents which discounts were applied |

---

## 8. Scoring Model Explained

```
raw_score = (W_security × security_posture_index
           + W_maturity × operational_maturity_index
           + W_reliability × reliability_index
           + W_governance × governance_index) × 100

discounted_score = raw_score × ∏(1 − discount_rate_i)  for each active control i

final_risk_score = discounted_score × 0.75  if data_confidence == "insufficient_data"
                   else discounted_score

final_risk_score = clamp(final_risk_score, 0, 100)
```

### Default Weights

| Dimension | Default Weight | Rationale |
|---|---|---|
| Security Posture | 0.40 | CVE severity, EPSS, KEV status are the most direct risk signals |
| Operational Maturity | 0.25 | Repo health and patch velocity indicate future vulnerability management |
| Service Reliability | 0.20 | Downtime history affects availability risk |
| Governance | 0.15 | Documentation and compliance transparency are lagging indicators |

### Regulatory Framework Adjustments

When the OSPC lists regulatory frameworks, the weights shift:

| Framework | Effect |
|---|---|
| PCI-DSS | +8% security posture, +4% governance, −6% maturity, −6% reliability |
| FedRAMP | +10% security posture, +5% governance, −8% maturity, −7% reliability |
| HIPAA | +7% governance, +5% security posture, −7% maturity, −5% reliability |
| GDPR | +8% governance, +2% security posture, −5% maturity, −5% reliability |
| SOC2 | +5% governance, +2% maturity, −5% security posture, −2% reliability |
| ISO27001 | +5% governance, +3% security posture, −5% maturity, −3% reliability |

Weights are re-normalised to sum to 1.0 after each framework's adjustments.

### Compensating Control Discounts

| Control | Discount |
|---|---|
| `mfa_enforced` | −5% |
| `waf_deployed` | −4% |
| `network_segmentation` | −3% |
| `endpoint_detection` | −3% |
| `vulnerability_scanning` | −3% |
| `data_encryption_at_rest` | −2% |
| `incident_response_plan` | −2% |

---

## 9. OSPC Configuration

The **Org Security Posture Config (OSPC)** is a JSON file at `/data/config/ospc.json` that tailors the scoring model to your organisation's risk profile.

```json
{
  "org_name": "Your Org Name",
  "regulatory_frameworks": ["SOC2", "ISO27001"],
  "compensating_controls": [
    "mfa_enforced",
    "network_segmentation",
    "waf_deployed"
  ],
  "service_tiers": {
    "salesforce": 1,
    "stripe": 1,
    "aws": 2
  },
  "patch_sla_days": {
    "CRITICAL": 7,
    "HIGH": 30,
    "MEDIUM": 90,
    "LOW": 180
  },
  "dimension_weight_overrides": {
    "security_posture": 0.50,
    "governance": 0.20
  }
}
```

| Field | Required | Purpose |
|---|---|---|
| `org_name` | Yes | Stored in `scores.ospc_org_name` for multi-tenant comparison |
| `regulatory_frameworks` | Yes | Drives weight adjustments and `trust_coverage_score` calculation |
| `compensating_controls` | Yes | Each active control applies a multiplicative discount to all services' scores |
| `service_tiers` | No | Maps service names to tier numbers (1=critical, 2=important, 3=standard); written to `services.service_tier` |
| `patch_sla_days` | No | Informational; not yet consumed by the scoring model but reserved for future SLA-breach flagging |
| `dimension_weight_overrides` | No | Hard overrides for specific dimension weights; applied after framework adjustments |

---

## 10. Project Setup Guide

### Prerequisites

- Docker Desktop (or Docker Engine on Linux)
- An Azure subscription with the following resources provisioned (see Section 5):
  - MySQL Flexible Server with the `cloudrisk` database created
  - Azure Container Instances running ChromaDB
  - Azure Files share mounted at `/data`
  - Azure Container Registry with the `cloudrisk:latest` image pushed
- API keys:
  - `GITHUB_TOKEN` — GitHub Personal Access Token with `read:packages` scope
  - `NVD_API_KEY` — optional but recommended; raises NVD rate limit from 5 to 50 req/30s (register free at https://nvd.nist.gov/developers/request-an-api-key)

---

### Step 1 — Clone the repository

```bash
git clone https://github.com/NeMuTaNK/capstone-cloudrisk.git
cd capstone-cloudrisk
```

---

### Step 2 — Create your environment file

```bash
cp .env.example .env
```

Edit `.env` with your actual credentials:

```bash
DATABASE_URL=mysql+pymysql://<user>:<password>@<mysql-host>:3306/cloudrisk
CHROMA_HOST=<chromadb-aci-ip>
CHROMA_PORT=8000
GITHUB_TOKEN=ghp_...
NVD_API_KEY=<your-nvd-api-key>
```

---

### Step 3 — Build the Docker image

```bash
docker build -t acr<admin-user>.azurecr.io/cloudrisk:latest .
```

To push to ACR:

```bash
az acr login --name acr<admin-user>
docker push acr<admin-user>.azurecr.io/cloudrisk:latest
```

---

### Step 4 — Run the database migration

This creates all five MySQL tables. Safe to re-run.

```bash
docker run --rm \
  -e "DATABASE_URL=$DATABASE_URL" \
  -e "CLOUDRISK_COMMAND=db_migrate" \
  acr<admin-user>.azurecr.io/cloudrisk:latest
```

---

### Step 5 — Create your OSPC config

```bash
mkdir -p data/config
cp data/config/ospc.example.json data/config/ospc.json
# Edit data/config/ospc.json with your org name, frameworks, and controls
```

---

### Step 6 — Run the API collectors (vulnerability + incident data)

The `run_api_collectors.sh` script runs all API-based collectors for all 33 services. Edit the environment variables at the top of the file, then:

```bash
bash run_api_collectors.sh
```

Or to collect for a single service manually:

```bash
docker run --rm \
  -e "DATABASE_URL=$DATABASE_URL" \
  -e "GITHUB_TOKEN=$GITHUB_TOKEN" \
  -e "NVD_API_KEY=$NVD_API_KEY" \
  -e "CHROMA_HOST=$CHROMA_HOST" \
  -e "CHROMA_PORT=$CHROMA_PORT" \
  -e "CLOUDRISK_COMMAND=collect_nvd --service salesforce" \
  acr<admin-user>.azurecr.io/cloudrisk:latest
```

---

### Step 7 — Run the NLP pipeline (text collection + ETL + scoring)

```bash
# Ensure the data directories exist for file sharing between containers
mkdir -p data/etl data/scores data/manifests data/raw

bash run_nlp_pipeline.sh
```

To run for a single service only:

```bash
bash run_nlp_pipeline.sh salesforce
```

---

### Step 8 — Verify scores in MySQL

```bash
mysql -h <mysql-host> \
      -u <admin-user> -p cloudrisk \
      -e "SELECT service_name, final_risk_score, data_confidence, scored_at \
          FROM scores ORDER BY scored_at DESC LIMIT 10;"
```

---

### Step 9 — Connect Power BI

1. Open Power BI Desktop
2. **Get Data** → **MySQL database**
3. Server: `<mysql-host>`
4. Database: `cloudrisk`
5. Select the `scores` table (and optionally `vulnerabilities`, `service_incidents`)
6. Build visuals on `final_risk_score`, `is_kev_present`, `critical_cve_count`, `data_confidence`

---

### Running a specific pipeline command

All commands go through the container entrypoint via `CLOUDRISK_COMMAND`. Common examples:

```bash
# Validate OSPC config before a run
CLOUDRISK_COMMAND='validate-ospc --ospc /data/config/ospc.json'

# Full pipeline for one service (collect → etl → score)
CLOUDRISK_COMMAND='run --service stripe --ospc /data/config/ospc.json'

# ETL only (reuse existing collected data with a new run_id)
CLOUDRISK_COMMAND='etl --run-id my-run-001 --ospc /data/config/ospc.json'

# Scoring only (reuse an existing ETL run)
CLOUDRISK_COMMAND='score --run-id my-run-001 --ospc /data/config/ospc.json'

# General broad CVE sweep (no vendor targeting)
CLOUDRISK_COMMAND='collect_general --sources nvd,kev'

# Collect just GHSA for one service, all ecosystems
CLOUDRISK_COMMAND='collect_ghsa --service snowflake'

# Collect trust disclosures for a service
CLOUDRISK_COMMAND='collect_trust --service stripe'
```

---

### Adding a new service

1. Add an entry to `SERVICE_ALIASES` in `collectors/service_aliases.py` with at minimum `nvd_keywords`, `kev_vendors`, `packages`, `status_url`, and `github_repos`.
2. Insert a row into the `services` table:
   ```sql
   INSERT INTO services (name, vendor, ecosystem, is_oss, is_saas, github_repo)
   VALUES ('newservice', 'New Vendor Inc', 'PyPI', 1, 1, 'newvendor/sdk');
   ```
3. Add the service name to the `SERVICES` array in `run_api_collectors.sh` and `run_nlp_pipeline.sh`.
4. Run the collectors for the new service:
   ```bash
   bash run_api_collectors.sh newservice
   bash run_nlp_pipeline.sh newservice
   ```
