"""
cloudrisk ETL Pipeline — etl.py
================================
Extract  : MySQL Flexible Server (vulnerabilities, repo_health, service_incidents, services)
           ChromaDB ACI (documentation, advisory_text, trust_disclosures, incident_postmortems)
Transform : Normalize structured fields; compute NLP features; engineer six composite features;
           flag data-confidence level; deduplicate CVEs; apply null defaults
Load      : Write one NDJSON record per service to /data/etl/{run_id}/ on Azure Files
           Write companion manifest.json to the same directory

Usage (via cloudrisk CLI):
    CLOUDRISK_COMMAND='etl --run-id <uuid> --ospc /data/config/ospc.json' az containerapp job start ...

Environment variables (injected from Key Vault via Container Apps Job secret references):
    DATABASE_URL  — SQLAlchemy connection string for MySQL Flexible Server
    CHROMA_HOST   — Private IP of ChromaDB ACI container
    CHROMA_PORT   — ChromaDB port (default: 8000)
"""

from __future__ import annotations

import json
import logging
import math
import os
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

import chromadb
import sqlalchemy as sa
from sqlalchemy import text
from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] cloudrisk.etl: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ETL_OUTPUT_BASE = Path(os.getenv("ETL_OUTPUT_BASE", "/data/etl"))

# CVSS v3 thresholds (NIST definitions)
CVSS_CRITICAL = 9.0
CVSS_HIGH = 7.0
CVSS_MEDIUM = 4.0

# Temporal decay half-life in days — a CVE published 365 days ago contributes 50% of its weight
DECAY_HALF_LIFE_DAYS = 365

# Minimum CVE count to qualify as "full_data" on the security dimension
MIN_VULN_ROWS_FULL = 3

# NLP keyword sets used for doc_quality and security_guidance scoring
DOC_QUALITY_KEYWORDS = {
    "authentication", "authorization", "encryption", "tls", "ssl",
    "certificate", "token", "secret", "credential", "password",
    "audit", "log", "monitor", "alert", "incident", "breach",
    "patch", "update", "vulnerability", "cve", "cvss",
}

SECURITY_GUIDANCE_KEYWORDS = {
    "security", "hardening", "least privilege", "zero trust", "mfa",
    "multi-factor", "firewall", "waf", "ddos", "intrusion",
    "penetration test", "pentest", "sast", "dast", "soc 2", "iso 27001",
    "gdpr", "hipaa", "pci", "compliance", "access control",
}

FRAMEWORK_KEYWORDS = {
    "SOC2": {"soc 2", "soc2", "service organization"},
    "ISO27001": {"iso 27001", "iso27001", "iso/iec 27001"},
    "HIPAA": {"hipaa", "health insurance portability"},
    "PCI-DSS": {"pci dss", "pci-dss", "payment card industry"},
    "GDPR": {"gdpr", "general data protection"},
    "FedRAMP": {"fedramp", "federal risk"},
}

# Compensating control discount rates — applied multiplicatively
CONTROL_DISCOUNTS: dict[str, float] = {
    "mfa_enforced": 0.05,
    "network_segmentation": 0.03,
    "waf_deployed": 0.04,
    "endpoint_detection": 0.03,
    "data_encryption_at_rest": 0.02,
    "vulnerability_scanning": 0.03,
    "incident_response_plan": 0.02,
}

# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------


def get_engine() -> sa.Engine:
    url = os.environ["DATABASE_URL"]
    return sa.create_engine(
        url,
        pool_pre_ping=True,
        pool_size=2,
        max_overflow=0,
        connect_args={"ssl": {"ssl_disabled": False}},
    )


def get_chroma_client() -> chromadb.HttpClient:
    host = os.environ["CHROMA_HOST"]
    port = int(os.getenv("CHROMA_PORT", "8000"))
    return chromadb.HttpClient(host=host, port=port)


# ---------------------------------------------------------------------------
# Extract — MySQL
# ---------------------------------------------------------------------------


def extract_services(engine: sa.Engine) -> list[dict]:
    """Return all rows from the services table."""
    with engine.connect() as conn:
        rows = conn.execute(text(
            "SELECT id, name, vendor, ecosystem, github_repo, service_tier "
            "FROM services ORDER BY id"
        )).mappings().fetchall()
    return [dict(r) for r in rows]


def extract_vulnerabilities(engine: sa.Engine, service_name: str) -> list[dict]:
    """Return all CVE records for a given service name."""
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT cve_id, cvss_v3_score, epss_score, severity, "
                "       is_kev, published_at "
                "FROM vulnerabilities "
                "WHERE service_name = :svc "
                "ORDER BY cvss_v3_score DESC"
            ),
            {"svc": service_name},
        ).mappings().fetchall()
    return [dict(r) for r in rows]


def extract_repo_health(engine: sa.Engine, service_name: str) -> dict | None:
    """Return the most recent repo_health record for a service."""
    with engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT commit_count_90d, contributor_count_90d, "
                "       days_since_last_release  AS days_since_release, "
                "       has_security_policy, "
                "       security_issues_open     AS open_critical_issues, "
                "       mean_days_close_security AS mean_sec_close_days "
                "FROM repo_health "
                "WHERE service_name = :svc "
                "ORDER BY collected_at DESC LIMIT 1"
            ),
            {"svc": service_name},
        ).mappings().fetchone()
    return dict(row) if row else None


def extract_incidents(engine: sa.Engine, service_name: str) -> list[dict]:
    """Return service_incidents from the past 12 months."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=365)
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT severity, duration_minutes / 60.0 AS duration_hours, started_at "
                "FROM service_incidents "
                "WHERE service_name = :svc AND started_at >= :cutoff "
                "ORDER BY started_at DESC"
            ),
            {"svc": service_name, "cutoff": cutoff},
        ).mappings().fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Extract — ChromaDB
# ---------------------------------------------------------------------------


def _chroma_get_text(
    client: chromadb.HttpClient, collection_name: str, service_name: str, n_results: int = 10
) -> list[str]:
    """
    Query a ChromaDB collection for documents related to service_name.
    Returns a list of document strings. Returns [] if collection is empty or service not found.
    """
    try:
        col = client.get_collection(collection_name)
        results = col.query(
            query_texts=[service_name],
            n_results=n_results,
            include=["documents"],
        )
        docs = results.get("documents", [[]])[0]
        return [d for d in docs if d]
    except Exception as exc:  # noqa: BLE001
        log.warning("ChromaDB query failed for collection=%s service=%s: %s", collection_name, service_name, exc)
        return []


# ---------------------------------------------------------------------------
# Transform — NLP features
# ---------------------------------------------------------------------------


def _keyword_density(text_blob: str, keyword_set: set[str]) -> float:
    """
    Fraction of keywords present in the lowercased text_blob.
    Returns a float in [0.0, 1.0].
    """
    if not text_blob:
        return 0.0
    lower = text_blob.lower()
    hits = sum(1 for kw in keyword_set if kw in lower)
    return round(hits / len(keyword_set), 4)


def compute_doc_quality_score(docs: list[str]) -> float:
    """NLP doc quality: keyword density of security-relevant documentation."""
    if not docs:
        return 0.0
    blob = " ".join(docs)
    return _keyword_density(blob, DOC_QUALITY_KEYWORDS)


def compute_security_guidance_score(advisory_docs: list[str]) -> float:
    """NLP security guidance density from advisory / vendor security pages."""
    if not advisory_docs:
        return 0.0
    blob = " ".join(advisory_docs)
    return _keyword_density(blob, SECURITY_GUIDANCE_KEYWORDS)


def compute_trust_coverage_score(trust_docs: list[str], target_frameworks: list[str]) -> float:
    """
    Fraction of target compliance frameworks detected in trust disclosure documents.
    target_frameworks comes from the OSPC regulatory_frameworks list.
    """
    if not trust_docs or not target_frameworks:
        return 0.0
    blob = " ".join(trust_docs).lower()
    detected = 0
    for fw in target_frameworks:
        keywords = FRAMEWORK_KEYWORDS.get(fw, {fw.lower()})
        if any(kw in blob for kw in keywords):
            detected += 1
    return round(detected / len(target_frameworks), 4)


def compute_incident_sentiment_score(incident_docs: list[str]) -> float:
    """
    Inverted VADER compound sentiment of incident postmortem text.
    Higher score = more negative sentiment = higher operational risk.
    Returns float in [0.0, 1.0].
    """
    if not incident_docs:
        return 0.0
    analyzer = SentimentIntensityAnalyzer()
    scores = [analyzer.polarity_scores(doc)["compound"] for doc in incident_docs if doc.strip()]
    if not scores:
        return 0.0
    mean_compound = sum(scores) / len(scores)
    # compound is in [-1, 1]; invert and scale to [0, 1]
    inverted = (1.0 - mean_compound) / 2.0
    return round(max(0.0, min(1.0, inverted)), 4)


# ---------------------------------------------------------------------------
# Transform — Structured feature normalization
# ---------------------------------------------------------------------------


def _safe_float(val: Any, default: float = 0.0) -> float:
    try:
        return float(val) if val is not None else default
    except (TypeError, ValueError):
        return default


def _safe_int(val: Any, default: int = 0) -> int:
    try:
        return int(val) if val is not None else default
    except (TypeError, ValueError):
        return default


def _temporal_decay(published_at: datetime | None) -> float:
    """
    Exponential decay weight for a CVE based on publication date.
    Recent CVEs weight more; half-life = DECAY_HALF_LIFE_DAYS.
    Returns float in (0.0, 1.0].
    """
    if published_at is None:
        return 0.5  # unknown age — assume moderate recency
    if published_at.tzinfo is None:
        published_at = published_at.replace(tzinfo=timezone.utc)
    age_days = (datetime.now(timezone.utc) - published_at).days
    return round(math.exp(-math.log(2) * age_days / DECAY_HALF_LIFE_DAYS), 4)


def compute_vulnerability_features(vulns: list[dict]) -> dict:
    """
    Derive all Security Posture dimension inputs from raw CVE records.

    Returns:
        cvss_normalized          — weighted mean CVSS [0–1]
        exploit_maturity_score   — fraction of vulns with EPSS > 0.1 [0–1]
        epss_score               — mean EPSS across all CVEs [0–1]
        severity_ordinal_norm    — weighted mean severity ordinal [0–1]
        temporal_decay           — mean temporal decay weight [0–1]
        cve_count                — total distinct CVEs
        highest_cvss             — max CVSS score
        is_kev_present           — 1 if any CVE is in CISA KEV
        critical_cve_count       — count of CRITICAL CVEs
        high_cve_count           — count of HIGH CVEs
        medium_cve_count         — count of MEDIUM CVEs
        low_cve_count            — count of LOW CVEs
    """
    SEVERITY_ORDINAL = {"CRITICAL": 1.0, "HIGH": 0.75, "MEDIUM": 0.5, "LOW": 0.25, "UNKNOWN": 0.1}

    if not vulns:
        return {
            "cvss_normalized": 0.0,
            "exploit_maturity_score": 0.0,
            "epss_score": 0.0,
            "severity_ordinal_norm": 0.0,
            "temporal_decay": 0.0,
            "cve_count": 0,
            "highest_cvss": 0.0,
            "is_kev_present": 0,
            "critical_cve_count": 0,
            "high_cve_count": 0,
            "medium_cve_count": 0,
            "low_cve_count": 0,
        }

    # Deduplicate by CVE ID — keep record with highest CVSS
    seen: dict[str, dict] = {}
    for v in vulns:
        cid = v.get("cve_id") or f"unknown-{id(v)}"
        if cid not in seen or _safe_float(v["cvss_v3_score"]) > _safe_float(seen[cid]["cvss_v3_score"]):
            seen[cid] = v
    vulns = list(seen.values())

    cvss_scores = [_safe_float(v["cvss_v3_score"]) for v in vulns]
    epss_scores = [_safe_float(v["epss_score"]) for v in vulns]
    severities = [str(v.get("severity") or "UNKNOWN").upper() for v in vulns]
    kev_flags = [bool(v.get("is_kev")) for v in vulns]

    pub_dates: list[datetime | None] = []
    for v in vulns:
        pa = v.get("published_at")
        if isinstance(pa, str):
            try:
                pa = datetime.fromisoformat(pa)
            except ValueError:
                pa = None
        pub_dates.append(pa)

    decay_weights = [_temporal_decay(d) for d in pub_dates]

    n = len(vulns)
    mean_cvss = sum(cvss_scores) / n if n else 0.0
    mean_epss = sum(epss_scores) / n if n else 0.0
    mean_decay = sum(decay_weights) / n if n else 0.0
    mean_severity = sum(SEVERITY_ORDINAL.get(s, 0.1) for s in severities) / n if n else 0.0
    exploit_maturity = sum(1 for e in epss_scores if e > 0.1) / n if n else 0.0

    sev_counts = {k: 0 for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    for s in severities:
        if s in sev_counts:
            sev_counts[s] += 1

    return {
        "cvss_normalized": round(mean_cvss / 10.0, 4),
        "exploit_maturity_score": round(exploit_maturity, 4),
        "epss_score": round(mean_epss, 4),
        "severity_ordinal_norm": round(mean_severity, 4),
        "temporal_decay": round(mean_decay, 4),
        "cve_count": n,
        "highest_cvss": round(max(cvss_scores, default=0.0), 1),
        "is_kev_present": 1 if any(kev_flags) else 0,
        "critical_cve_count": sev_counts["CRITICAL"],
        "high_cve_count": sev_counts["HIGH"],
        "medium_cve_count": sev_counts["MEDIUM"],
        "low_cve_count": sev_counts["LOW"],
    }


def compute_repo_features(repo: dict | None) -> dict:
    """
    Derive Operational Maturity dimension inputs from repo_health record.

    Returns:
        repo_maturity_score        — composite [0–1]: activity + security policy + release freshness
        mean_sec_close_days_norm   — normalized mean days to close security issues [0–1]
        days_since_release_norm    — normalized days since last release [0–1]
        commit_count_90d           — raw value for Power BI
        contributor_count_90d      — raw value for Power BI
        days_since_release         — raw value for Power BI
        has_security_policy        — 0/1 for Power BI
    """
    if repo is None:
        return {
            "repo_maturity_score": 0.0,
            "mean_sec_close_days_norm": 0.0,
            "days_since_release_norm": 0.0,
            "commit_count_90d": 0,
            "contributor_count_90d": 0,
            "days_since_release": 999,
            "has_security_policy": 0,
        }

    commits = _safe_int(repo.get("commit_count_90d"))
    contributors = _safe_int(repo.get("contributor_count_90d"))
    days_release = _safe_int(repo.get("days_since_release"), default=999)
    has_sec_policy = _safe_int(repo.get("has_security_policy"))
    mean_close = _safe_float(repo.get("mean_sec_close_days"), default=90.0)

    # Activity signal: cap commits at 500, contributors at 50 for normalization
    activity_score = min(commits / 500.0, 1.0) * 0.5 + min(contributors / 50.0, 1.0) * 0.5
    # Release freshness: penalize stale projects (>365 days since release)
    release_freshness = max(0.0, 1.0 - days_release / 365.0)
    # Security policy is a hard boolean signal
    repo_maturity = (activity_score * 0.5 + release_freshness * 0.3 + has_sec_policy * 0.2)

    # Normalize close days: 0 days → 0.0 (best), 180+ days → 1.0 (worst)
    close_norm = min(mean_close / 180.0, 1.0)
    # Normalize days since release: same scale
    release_norm = min(days_release / 365.0, 1.0)

    return {
        "repo_maturity_score": round(repo_maturity, 4),
        "mean_sec_close_days_norm": round(close_norm, 4),
        "days_since_release_norm": round(release_norm, 4),
        "commit_count_90d": commits,
        "contributor_count_90d": contributors,
        "days_since_release": days_release,
        "has_security_policy": has_sec_policy,
    }


def compute_incident_features(incidents: list[dict]) -> dict:
    """
    Derive Service Reliability dimension inputs from incident records.

    Returns:
        operational_risk_score     — composite [0–1]: major incident count + total downtime
        major_incident_count_12m   — raw count for Power BI
        total_incident_hours_12m   — raw sum for Power BI
    """
    MAJOR_SEVERITIES = {"critical", "major", "high", "p1", "sev1", "sev2"}

    major_count = sum(
        1 for i in incidents
        if str(i.get("severity") or "").lower() in MAJOR_SEVERITIES
    )
    total_hours = sum(_safe_float(i.get("duration_hours")) for i in incidents)

    # Normalize: 12+ major incidents in a year → 1.0 risk; 100+ hours downtime → 1.0
    count_norm = min(major_count / 12.0, 1.0)
    hours_norm = min(total_hours / 100.0, 1.0)
    operational_risk = count_norm * 0.6 + hours_norm * 0.4

    return {
        "operational_risk_score": round(operational_risk, 4),
        "major_incident_count_12m": major_count,
        "total_incident_hours_12m": round(total_hours, 2),
    }


def compute_governance_score(
    doc_quality: float,
    security_guidance: float,
    trust_coverage: float,
    incident_sentiment: float,
) -> float:
    """
    Composite Governance & Transparency score [0–1].
    Higher = worse governance (more risk), consistent with the other dimension scores.
    """
    # Invert doc quality and security guidance (high quality = lower risk)
    # trust_coverage is already "fraction detected" — invert (missing = risk)
    # incident_sentiment is already inverted (high = negative sentiment = risk)
    risk = (
        (1.0 - doc_quality) * 0.25
        + (1.0 - security_guidance) * 0.25
        + (1.0 - trust_coverage) * 0.25
        + incident_sentiment * 0.25
    )
    return round(max(0.0, min(1.0, risk)), 4)


# ---------------------------------------------------------------------------
# Transform — Six engineered features
# ---------------------------------------------------------------------------


def compute_engineered_features(
    vuln_feats: dict,
    repo_feats: dict,
    incident_feats: dict,
    doc_quality: float,
    security_guidance: float,
    trust_coverage: float,
    incident_sentiment: float,
) -> dict:
    """
    The six engineered composite features that feed the scoring model directly.

    1. security_posture_index   — weighted composite of all security signals
    2. operational_maturity_index — weighted composite of all repo health signals
    3. reliability_index        — weighted incident composite
    4. governance_index         — weighted governance composite
    5. kev_severity_index       — amplified signal if KEV is present + critical CVEs
    6. patch_velocity_index     — how quickly the project closes security issues (inverse risk)
    """

    # 1. Security Posture Index
    security_posture_index = (
        vuln_feats["cvss_normalized"] * 0.30
        + vuln_feats["exploit_maturity_score"] * 0.25
        + vuln_feats["epss_score"] * 0.20
        + vuln_feats["severity_ordinal_norm"] * 0.15
        + (1.0 - vuln_feats["temporal_decay"]) * 0.10  # old CVEs reduce risk slightly
    )

    # 2. Operational Maturity Index (higher = better maturity = lower risk contribution)
    operational_maturity_index = (
        repo_feats["repo_maturity_score"] * 0.50
        + (1.0 - repo_feats["mean_sec_close_days_norm"]) * 0.30
        + (1.0 - repo_feats["days_since_release_norm"]) * 0.20
    )

    # 3. Reliability Index
    reliability_index = incident_feats["operational_risk_score"]

    # 4. Governance Index
    governance_index = compute_governance_score(
        doc_quality, security_guidance, trust_coverage, incident_sentiment
    )

    # 5. KEV + Critical Severity Amplifier
    # If no KEV and no critical CVEs → 0. Scales up with both signals.
    kev_weight = 1 if vuln_feats["is_kev_present"] else 0
    critical_ratio = min(vuln_feats["critical_cve_count"] / max(vuln_feats["cve_count"], 1), 1.0)
    kev_severity_index = round(kev_weight * 0.6 + critical_ratio * 0.4, 4)

    # 6. Patch Velocity Index (inverse of close_days_norm — lower close time = lower risk)
    # A project with a fast close time and security policy gets the best score
    patch_velocity_index = round(
        (1.0 - repo_feats["mean_sec_close_days_norm"]) * 0.7
        + repo_feats["has_security_policy"] * 0.3,
        4,
    )

    return {
        "security_posture_index": round(security_posture_index, 4),
        "operational_maturity_index": round(operational_maturity_index, 4),
        "reliability_index": round(reliability_index, 4),
        "governance_index": round(governance_index, 4),
        "kev_severity_index": round(kev_severity_index, 4),
        "patch_velocity_index": round(patch_velocity_index, 4),
    }


# ---------------------------------------------------------------------------
# Transform — Data confidence flag
# ---------------------------------------------------------------------------


def compute_data_confidence(
    vuln_count: int,
    has_repo: bool,
    has_incidents: bool,
    has_nlp_docs: bool,
) -> str:
    """
    Determine data confidence level for a service.

    full_data        — all four data categories present
    partial_data     — two or three categories present
    insufficient_data — zero or one category; score will receive 0.75× penalty
    """
    sources_present = sum([
        vuln_count >= MIN_VULN_ROWS_FULL,
        has_repo,
        has_incidents,
        has_nlp_docs,
    ])
    if sources_present == 4:
        return "full_data"
    elif sources_present >= 2:
        return "partial_data"
    else:
        return "insufficient_data"


# ---------------------------------------------------------------------------
# Load — NDJSON + manifest
# ---------------------------------------------------------------------------


def write_etl_outputs(run_id: str, records: list[dict]) -> Path:
    """
    Write NDJSON feature records to /data/etl/{run_id}/features.ndjson.
    Write manifest.json alongside it.
    Returns the output directory path.
    """
    out_dir = ETL_OUTPUT_BASE / run_id
    out_dir.mkdir(parents=True, exist_ok=True)

    ndjson_path = out_dir / "features.ndjson"
    with ndjson_path.open("w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, default=str) + "\n")

    manifest = {
        "run_id": run_id,
        "etl_completed_at": datetime.now(timezone.utc).isoformat(),
        "service_count": len(records),
        "services": [r["service_name"] for r in records],
        "confidence_breakdown": {
            "full_data": sum(1 for r in records if r["data_confidence"] == "full_data"),
            "partial_data": sum(1 for r in records if r["data_confidence"] == "partial_data"),
            "insufficient_data": sum(1 for r in records if r["data_confidence"] == "insufficient_data"),
        },
        "output_path": str(ndjson_path),
    }
    manifest_path = out_dir / "manifest.json"
    with manifest_path.open("w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, default=str)

    log.info("ETL outputs written to %s (%d services)", out_dir, len(records))
    return out_dir


# ---------------------------------------------------------------------------
# Main ETL orchestration
# ---------------------------------------------------------------------------


def run_etl(run_id: str | None = None, ospc_path: str = "/data/config/ospc.json") -> str:
    """
    Execute the full ETL pipeline for all services in the services table.

    Args:
        run_id   — UUID string for this pipeline run. Auto-generated if not provided.
        ospc_path — path to the OSPC JSON config on Azure Files.

    Returns:
        run_id used for this ETL run (for downstream scoring.py to consume).
    """
    if run_id is None:
        run_id = str(uuid.uuid4())

    log.info("ETL run starting — run_id=%s", run_id)

    # Load OSPC for regulatory framework list (used in trust_coverage)
    ospc: dict = {}
    try:
        with open(ospc_path, encoding="utf-8") as f:
            ospc = json.load(f)
        log.info("OSPC loaded from %s — org=%s", ospc_path, ospc.get("org_name", "unknown"))
    except FileNotFoundError:
        log.warning("OSPC not found at %s — using empty regulatory_frameworks", ospc_path)

    regulatory_frameworks: list[str] = ospc.get("regulatory_frameworks", [])

    # Connect to data sources
    engine = get_engine()
    chroma = get_chroma_client()
    log.info("Connected to MySQL and ChromaDB")

    services = extract_services(engine)
    if not services:
        log.warning("No services found in services table — ETL complete with 0 records")
        write_etl_outputs(run_id, [])
        return run_id

    log.info("Processing %d services", len(services))
    records: list[dict] = []

    for svc in services:
        name = svc["name"]
        log.info("Processing service: %s", name)

        # ── Extract ──────────────────────────────────────────────────────────
        vulns = extract_vulnerabilities(engine, name)
        repo = extract_repo_health(engine, name)
        incidents = extract_incidents(engine, name)

        # ChromaDB NLP extracts
        doc_texts = _chroma_get_text(chroma, "documentation", name)
        advisory_texts = _chroma_get_text(chroma, "advisory_text", name)
        trust_texts = _chroma_get_text(chroma, "trust_disclosures", name)
        incident_texts = _chroma_get_text(chroma, "incident_postmortems", name)

        # ── Transform — structured features ─────────────────────────────────
        vuln_feats = compute_vulnerability_features(vulns)
        repo_feats = compute_repo_features(repo)
        incident_feats = compute_incident_features(incidents)

        # ── Transform — NLP features ─────────────────────────────────────────
        doc_quality = compute_doc_quality_score(doc_texts)
        security_guidance = compute_security_guidance_score(advisory_texts)
        trust_coverage = compute_trust_coverage_score(trust_texts, regulatory_frameworks)
        incident_sentiment = compute_incident_sentiment_score(incident_texts)

        # ── Transform — Six engineered features ──────────────────────────────
        engineered = compute_engineered_features(
            vuln_feats, repo_feats, incident_feats,
            doc_quality, security_guidance, trust_coverage, incident_sentiment,
        )

        # ── Transform — Governance composite ────────────────────────────────
        gov_score = compute_governance_score(
            doc_quality, security_guidance, trust_coverage, incident_sentiment
        )

        # ── Transform — Data confidence flag ─────────────────────────────────
        has_nlp = bool(doc_texts or advisory_texts or trust_texts)
        confidence = compute_data_confidence(
            vuln_count=vuln_feats["cve_count"],
            has_repo=(repo is not None),
            has_incidents=bool(incidents),
            has_nlp_docs=has_nlp,
        )

        # ── Assemble feature record ───────────────────────────────────────────
        record: dict = {
            # Identity
            "run_id": run_id,
            "service_name": name,
            "vendor": svc.get("vendor"),
            "ecosystem": svc.get("ecosystem"),
            "github_repo": svc.get("github_repo"),
            "service_tier": svc.get("service_tier"),
            "extracted_at": datetime.now(timezone.utc).isoformat(),
            # Vulnerability features
            **vuln_feats,
            # Repo features
            **repo_feats,
            # Incident features
            **incident_feats,
            # NLP features
            "doc_quality_score": doc_quality,
            "security_guidance_score": security_guidance,
            "trust_coverage_score": trust_coverage,
            "incident_sentiment_score": incident_sentiment,
            # Governance composite
            "governance_composite": gov_score,
            # Six engineered features
            **engineered,
            # Data confidence
            "data_confidence": confidence,
        }

        records.append(record)
        log.info(
            "  %s — CVEs=%d confidence=%s kev=%d",
            name, vuln_feats["cve_count"], confidence, vuln_feats["is_kev_present"],
        )

    # ── Load ────────────────────────────────────────────────────────────────
    out_dir = write_etl_outputs(run_id, records)

    log.info(
        "ETL complete — run_id=%s services=%d output=%s",
        run_id, len(records), out_dir,
    )
    return run_id


# ---------------------------------------------------------------------------
# CLI entrypoint (called by vulniq CLI dispatcher)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="cloudrisk ETL pipeline")
    parser.add_argument("--run-id", default=None, help="Pipeline run UUID (auto-generated if omitted)")
    parser.add_argument("--ospc", default="/data/config/ospc.json", help="Path to OSPC config JSON")
    args = parser.parse_args()

    resulting_run_id = run_etl(run_id=args.run_id, ospc_path=args.ospc)
    print(resulting_run_id)  # stdout — captured by CLI dispatcher to pass to scoring.py
