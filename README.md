# VulnIQ: Cloud Service Adoption Risk Intelligence

A cloud vendor risk intelligence platform that automatically collects 
security
data on third-party cloud services, computes a composite risk score per
vendor, and surfaces the results in an interactive Power BI dashboard.

Built as a capstone practicum for Microsoft, using publicly available 
security
data (CVE records, incident histories, repository health metrics, and 
public
compliance disclosures). No proprietary Microsoft data is used or exposed.

## The problem

Organizations depend on dozens or hundreds of third-party cloud services,
each with its own security posture, vulnerability history, and compliance
record. Tracking that risk manually does not scale. VulnIQ automates the
collection and scoring of that risk so security and procurement teams can
see, at a glance, which vendors need attention.

![Data Overview dashboard showing 33,600 total CVEs, 2,733 services 
monitored, CVSS score distribution, and top services by vulnerability 
volume](docs/screenshots/data-overview.png)

## How it works

The pipeline runs in five stages:

**Collectors → MySQL / ChromaDB → ETL → Scoring → Power BI**

- **Collectors** pull CVE data, incident history, repository health 
metrics,
  and compliance text from public APIs and status pages.
- **MySQL** stores structured records: vulnerabilities, incidents, repo
  health, services, and computed scores.
- **ChromaDB** stores unstructured text (documentation, advisory text, 
trust
  disclosures, postmortems) for downstream NLP use.
- **ETL** reads from both stores, engineers six composite feature indices,
  and flags a data confidence level for each record.
- **Scoring** applies a weighted, configurable risk model and writes final
  scores back to MySQL.
- **Power BI** connects directly to the MySQL scores table to power the
  dashboards below.

The platform tracks 33 core vendors with deep, multi-source monitoring
(vulnerability data, incident history, repository health, and compliance
signals), plus broader automatic discovery that surfaces thousands of
additional related vendors and products picked up through unfiltered CVE
sweeps. In total, 2,733 services appear in the risk-scoring dashboard, 
with
data confidence varying by how many signal types are available for each.

## The risk model

Each vendor gets a composite risk score built from six weighted factors,
including vulnerability severity, vulnerability volume, active 
exploitation
signals, incident history, repository health, and known attack-type
patterns. The weights are configurable directly in Power BI, changing a
parameter reruns the underlying Python scoring model without touching 
code.

The dashboard also flags anomalies using an isolation forest model, and
plots risk score against both mean CVSS and vulnerability volume to 
surface
vendors whose risk score doesn't move in lockstep with raw vulnerability
count alone.

![Risk Model Score dashboard showing configurable risk weights, a service 
risk leaderboard, a full risk scorecard, and risk score plotted against 
CVSS and vulnerability count](docs/screenshots/risk-model-score.png)

## Architecture

- **Collectors** (`collectors/`): source-specific modules for NVD, CISA 
KEV,
  GitHub Security Advisories, OSV, GitHub repo health, service status 
pages,
  documentation, and trust-center disclosures, plus a broad unfiltered
  sweep collector for automatic vendor discovery.
- **ETL** (`collectors/etl.py`): reads from MySQL and ChromaDB, engineers
  feature vectors, writes per-run NDJSON output.
- **Scoring** (`collectors/scoring.py`): applies the configurable weighted
  risk model.
- **Infrastructure as Code** (`iac/`): Bicep templates for MySQL, Key 
Vault,
  Container Apps, networking, and monitoring on Azure.
- **Tests** (`tests/`): unit tests for ETL, scoring, and collector logic.

## Tech stack

Python, MySQL, ChromaDB, Power BI, Docker, Azure (Bicep IaC).

## What's in this repo

| Path | What it is |
|---|---|
| `collectors/` | Data collection modules (NVD, KEV, GHSA, OSV, GitHub, 
status pages, docs, trust) |
| `collectors/etl.py` | Feature engineering pipeline |
| `collectors/scoring.py` | Weighted risk scoring model |
| `tests/` | Unit tests |
| `iac/` | Azure Bicep infrastructure templates |
| `scripts/` | Pipeline run scripts |
| `CloudRisk_Model.ipynb` | Exploratory notebook: model development and 
validation |
| `MSFT Cloud - Risk Score Dashboard.pbix` | Full Power BI dashboard file 
|
| `Cloud_Risk_Assessment_Capstone_Presentation.pdf` | Capstone 
presentation deck |
| `PROJECT_STATUS.md` | Full technical reference: architecture, schema, 
scoring logic, setup guide |

## Roadmap

This was built and delivered as a working proof of concept within a
practicum timeline. The Bicep IaC is code-complete but not fully deployed
end-to-end due to permission restrictions in the academic Azure 
subscription
it was built under. Full technical detail on current scope and planned 
work
is in `PROJECT_STATUS.md`.
