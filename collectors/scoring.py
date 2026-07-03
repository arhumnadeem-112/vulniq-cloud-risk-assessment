"""
cloudrisk Scoring Pipeline — scoring.py
========================================
Reads the NDJSON feature records produced by etl.py, loads the OSPC configuration,
computes a risk score for every service, and writes results to two destinations:

  1. /data/scores/{run_id}/{service_name}_score.json  — Azure Files (Markdown report input)
  2. scores MySQL table                               — primary output for Power BI (v2.0)

Scoring model:
    raw_score = dot(W_final, X) × 100
    W_final   = default weights → regulatory framework adjustments → OSPC overrides
    X         = [security_posture_index, operational_maturity_index,
                 reliability_index, governance_index]

Post-processing:
    - Compensating control discounts applied multiplicatively to raw_score
    - Confidence penalty: insufficient_data services receive × 0.75
    - Final score clamped to [0, 100]

Usage (via cloudrisk CLI):
    CLOUDRISK_COMMAND='score --run-id <uuid> --ospc /data/config/ospc.json' az containerapp job start ...

Environment variables:
    DATABASE_URL  — SQLAlchemy connection string for MySQL Flexible Server
    SCORES_OUTPUT_BASE — override output path (default: /data/scores)
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import jsonschema
import sqlalchemy as sa
from sqlalchemy import text

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] cloudrisk.scoring: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ETL_OUTPUT_BASE = Path(os.getenv("ETL_OUTPUT_BASE", "/data/etl"))
SCORES_OUTPUT_BASE = Path(os.getenv("SCORES_OUTPUT_BASE", "/data/scores"))

# Confidence penalty multiplier for insufficient_data services
CONFIDENCE_PENALTY = 0.75

# Default dimension weights (must sum to 1.0)
DEFAULT_WEIGHTS: dict[str, float] = {
    "security_posture": 0.40,
    "operational_maturity": 0.25,
    "service_reliability": 0.20,
    "governance": 0.15,
}

# Regulatory framework → weight adjustments
# Keys are framework names from OSPC; values are delta adjustments to default weights.
# Weights are re-normalized to 1.0 after applying adjustments.
FRAMEWORK_WEIGHT_ADJUSTMENTS: dict[str, dict[str, float]] = {
    "SOC2": {
        "governance": +0.05,
        "operational_maturity": +0.02,
        "security_posture": -0.05,
        "service_reliability": -0.02,
    },
    "PCI-DSS": {
        "security_posture": +0.08,
        "governance": +0.04,
        "operational_maturity": -0.06,
        "service_reliability": -0.06,
    },
    "HIPAA": {
        "governance": +0.07,
        "security_posture": +0.05,
        "operational_maturity": -0.07,
        "service_reliability": -0.05,
    },
    "ISO27001": {
        "governance": +0.05,
        "security_posture": +0.03,
        "operational_maturity": -0.05,
        "service_reliability": -0.03,
    },
    "GDPR": {
        "governance": +0.08,
        "security_posture": +0.02,
        "operational_maturity": -0.05,
        "service_reliability": -0.05,
    },
    "FedRAMP": {
        "security_posture": +0.10,
        "governance": +0.05,
        "operational_maturity": -0.08,
        "service_reliability": -0.07,
    },
}

# Compensating control discount rates — applied multiplicatively to raw_score
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
# OSPC JSON schema — validated before scoring begins
# ---------------------------------------------------------------------------

OSPC_SCHEMA: dict = {
    "type": "object",
    "required": ["org_name", "regulatory_frameworks", "compensating_controls"],
    "properties": {
        "org_name": {"type": "string", "minLength": 1},
        "regulatory_frameworks": {
            "type": "array",
            "items": {"type": "string"},
        },
        "service_tiers": {
            "type": "object",
            "additionalProperties": {"type": "integer", "minimum": 1, "maximum": 3},
        },
        "patch_sla_days": {
            "type": "object",
            "properties": {
                "CRITICAL": {"type": "integer"},
                "HIGH": {"type": "integer"},
                "MEDIUM": {"type": "integer"},
                "LOW": {"type": "integer"},
            },
        },
        "compensating_controls": {
            "type": "array",
            "items": {"type": "string"},
        },
        "dimension_weight_overrides": {
            "type": "object",
            "additionalProperties": {"type": "number", "minimum": 0.0, "maximum": 1.0},
        },
    },
    "additionalProperties": True,
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


# ---------------------------------------------------------------------------
# OSPC loading & validation
# ---------------------------------------------------------------------------


def load_ospc(ospc_path: str) -> dict:
    """
    Load and validate the OSPC JSON config from Azure Files.
    Raises FileNotFoundError or jsonschema.ValidationError on failure.
    """
    with open(ospc_path, encoding="utf-8") as f:
        ospc = json.load(f)

    jsonschema.validate(instance=ospc, schema=OSPC_SCHEMA)
    log.info("OSPC validated — org=%s frameworks=%s", ospc["org_name"], ospc["regulatory_frameworks"])
    return ospc


# ---------------------------------------------------------------------------
# Weight composition
# ---------------------------------------------------------------------------


def compose_weights(ospc: dict) -> dict[str, float]:
    """
    Build the final weight vector W_final via three-stage composition:

    Stage 1: Start from DEFAULT_WEIGHTS
    Stage 2: Apply additive adjustments for each regulatory framework in the OSPC
    Stage 3: Apply OSPC dimension_weight_overrides (hard overrides — no re-normalization
             beyond clamping; analyst is responsible for valid overrides)

    After stages 1+2, weights are re-normalized so they sum to 1.0.
    After stage 3, only the overridden dimensions are replaced; remaining dimensions
    are re-normalized proportionally to preserve the sum = 1.0 invariant.

    Returns a dict with keys: security_posture, operational_maturity,
                               service_reliability, governance
    """
    weights = dict(DEFAULT_WEIGHTS)

    # Stage 2 — regulatory framework adjustments
    for framework in ospc.get("regulatory_frameworks", []):
        adjustments = FRAMEWORK_WEIGHT_ADJUSTMENTS.get(framework, {})
        for dim, delta in adjustments.items():
            weights[dim] = max(0.0, weights[dim] + delta)

    # Re-normalize after framework adjustments
    weights = _normalize_weights(weights)
    log.debug("Weights after framework adjustments: %s", weights)

    # Stage 3 — OSPC hard overrides
    overrides: dict[str, float] = ospc.get("dimension_weight_overrides", {})
    if overrides:
        for dim, val in overrides.items():
            if dim in weights:
                weights[dim] = float(val)
        weights = _normalize_weights(weights)
        log.info("Weight overrides applied: %s → final weights: %s", overrides, weights)

    return weights


def _normalize_weights(weights: dict[str, float]) -> dict[str, float]:
    """Re-normalize a weight dict so values sum to 1.0."""
    total = sum(weights.values())
    if total == 0:
        # Fallback to equal weights to avoid division by zero
        n = len(weights)
        return {k: round(1.0 / n, 6) for k in weights}
    return {k: round(v / total, 6) for k, v in weights.items()}


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


def compute_dimension_scores(record: dict, weights: dict[str, float]) -> dict[str, float]:
    """
    Compute each dimension's weighted sub-score on a [0–100] scale.

    The engineered indices from etl.py are the feature inputs X for each dimension:
      security_posture     ← security_posture_index
      operational_maturity ← operational_maturity_index
      service_reliability  ← reliability_index
      governance           ← governance_index

    Each sub-score = index × weight × 100, so they sum to raw_score.
    """
    return {
        "security_posture_score": round(
            record.get("security_posture_index", 0.0) * weights["security_posture"] * 100, 1
        ),
        "operational_maturity_score": round(
            record.get("operational_maturity_index", 0.0) * weights["operational_maturity"] * 100, 1
        ),
        "service_reliability_score": round(
            record.get("reliability_index", 0.0) * weights["service_reliability"] * 100, 1
        ),
        "governance_score": round(
            record.get("governance_index", 0.0) * weights["governance"] * 100, 1
        ),
    }


def compute_raw_score(record: dict, weights: dict[str, float]) -> float:
    """
    raw_score = dot(W_final, X) × 100

    X = [security_posture_index, operational_maturity_index, reliability_index, governance_index]
    """
    x = {
        "security_posture": record.get("security_posture_index", 0.0),
        "operational_maturity": record.get("operational_maturity_index", 0.0),
        "service_reliability": record.get("reliability_index", 0.0),
        "governance": record.get("governance_index", 0.0),
    }
    raw = sum(weights[dim] * x[dim] for dim in weights) * 100
    return round(raw, 1)


def apply_compensating_controls(raw_score: float, active_controls: list[str]) -> float:
    """
    Apply compensating control discounts multiplicatively.
    Each recognized control reduces the score by its discount rate.
    Unknown control names are logged and skipped.

    Example: raw_score=60, controls=[mfa_enforced(5%), network_segmentation(3%)]
        after mfa_enforced:        60 × (1 - 0.05) = 57.0
        after network_segmentation: 57.0 × (1 - 0.03) = 55.29
    """
    score = raw_score
    for control in active_controls:
        rate = CONTROL_DISCOUNTS.get(control)
        if rate is None:
            log.warning("Unknown compensating control '%s' — skipped", control)
            continue
        score = score * (1.0 - rate)
        log.debug("Applied control '%s' (-%s%%) → score=%.2f", control, rate * 100, score)
    return round(score, 1)


def apply_confidence_penalty(score: float, data_confidence: str) -> float:
    """
    Apply 0.75× penalty for insufficient_data services.
    full_data and partial_data services are unaffected.
    """
    if data_confidence == "insufficient_data":
        penalized = round(score * CONFIDENCE_PENALTY, 1)
        log.debug("Confidence penalty applied (×%.2f): %.1f → %.1f", CONFIDENCE_PENALTY, score, penalized)
        return penalized
    return score


def score_record(record: dict, weights: dict[str, float], ospc: dict) -> dict:
    """
    Compute all scores for a single ETL feature record.

    Returns a flat dict matching the scores MySQL table schema.
    """
    active_controls: list[str] = ospc.get("compensating_controls", [])
    data_confidence: str = record.get("data_confidence", "insufficient_data")

    dim_scores = compute_dimension_scores(record, weights)
    raw_score = compute_raw_score(record, weights)
    discounted_score = apply_compensating_controls(raw_score, active_controls)
    final_score = apply_confidence_penalty(discounted_score, data_confidence)
    final_score = round(max(0.0, min(100.0, final_score)), 1)

    return {
        # Identity
        "run_id": record["run_id"],
        "scored_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "service_name": record["service_name"],
        "vendor": record.get("vendor"),
        "ecosystem": record.get("ecosystem"),
        # Scores
        "raw_score": raw_score,
        "final_risk_score": final_score,
        **dim_scores,
        # CVE summary
        "cve_count": record.get("cve_count", 0),
        "highest_cvss": record.get("highest_cvss", 0.0),
        "is_kev_present": record.get("is_kev_present", 0),
        "critical_cve_count": record.get("critical_cve_count", 0),
        "high_cve_count": record.get("high_cve_count", 0),
        "medium_cve_count": record.get("medium_cve_count", 0),
        "low_cve_count": record.get("low_cve_count", 0),
        # Incident summary
        "major_incident_count_12m": record.get("major_incident_count_12m", 0),
        "total_incident_hours_12m": record.get("total_incident_hours_12m", 0.0),
        # Repo summary
        "commit_count_90d": record.get("commit_count_90d", 0),
        "contributor_count_90d": record.get("contributor_count_90d", 0),
        "days_since_release": record.get("days_since_release", 999),
        "has_security_policy": record.get("has_security_policy", 0),
        # NLP scores
        "doc_quality_score": record.get("doc_quality_score", 0.0),
        "security_guidance_score": record.get("security_guidance_score", 0.0),
        "trust_coverage_score": record.get("trust_coverage_score", 0.0),
        "incident_sentiment_score": record.get("incident_sentiment_score", 0.0),
        # Metadata
        "data_confidence": data_confidence,
        "ospc_org_name": ospc.get("org_name", ""),
        "active_controls": ",".join(active_controls),
    }


# ---------------------------------------------------------------------------
# Load — Azure Files JSON
# ---------------------------------------------------------------------------


def write_score_json(run_id: str, scored: dict) -> Path:
    """Write per-service score JSON to /data/scores/{run_id}/{service_name}_score.json."""
    out_dir = SCORES_OUTPUT_BASE / run_id
    out_dir.mkdir(parents=True, exist_ok=True)

    safe_name = scored["service_name"].replace("/", "_").replace(" ", "_")
    out_path = out_dir / f"{safe_name}_score.json"

    with out_path.open("w", encoding="utf-8") as f:
        json.dump(scored, f, indent=2, default=str)

    return out_path


# ---------------------------------------------------------------------------
# Load — MySQL scores table
# ---------------------------------------------------------------------------

# Columns that map directly to the scores table (insertion order matches schema)
_SCORES_TABLE_COLUMNS = [
    "run_id", "scored_at", "service_name", "vendor", "ecosystem",
    "final_risk_score", "raw_score",
    "security_posture_score", "operational_maturity_score",
    "service_reliability_score", "governance_score",
    "cve_count", "highest_cvss", "is_kev_present",
    "critical_cve_count", "high_cve_count", "medium_cve_count", "low_cve_count",
    "major_incident_count_12m", "total_incident_hours_12m",
    "commit_count_90d", "contributor_count_90d",
    "days_since_release", "has_security_policy",
    "doc_quality_score", "security_guidance_score",
    "trust_coverage_score", "incident_sentiment_score",
    "data_confidence", "ospc_org_name", "active_controls",
]


def write_scores_to_mysql(engine: sa.Engine, scored_records: list[dict]) -> int:
    """
    Upsert scored records into the scores MySQL table.
    On duplicate (run_id, service_name) the row is updated in place.
    Returns the number of rows affected.
    """
    if not scored_records:
        return 0

    col_list = ", ".join(_SCORES_TABLE_COLUMNS)
    bind_list = ", ".join(f":{c}" for c in _SCORES_TABLE_COLUMNS)
    update_clause = ", ".join(
        f"{c} = VALUES({c})"
        for c in _SCORES_TABLE_COLUMNS
        if c not in ("run_id", "service_name")
    )
    stmt = text(
        f"INSERT INTO scores ({col_list}) VALUES ({bind_list}) "
        f"ON DUPLICATE KEY UPDATE {update_clause}"
    )

    rows = [
        {col: rec.get(col) for col in _SCORES_TABLE_COLUMNS}
        for rec in scored_records
    ]

    with engine.begin() as conn:
        result = conn.execute(stmt, rows)
        affected = result.rowcount

    log.info("MySQL: %d/%d rows upserted into scores table", affected, len(rows))
    return affected


# ---------------------------------------------------------------------------
# Main scoring orchestration
# ---------------------------------------------------------------------------


def run_scoring(run_id: str, ospc_path: str = "/data/config/ospc.json") -> list[dict]:
    """
    Execute the full scoring pipeline for a given ETL run_id.

    Args:
        run_id    — UUID of the ETL run to score (must exist under /data/etl/{run_id}/)
        ospc_path — path to the OSPC JSON config on Azure Files

    Returns:
        List of scored record dicts (also written to MySQL and Azure Files).
    """
    log.info("Scoring run starting — run_id=%s", run_id)

    # ── Validate OSPC before touching any data ────────────────────────────
    ospc = load_ospc(ospc_path)

    # ── Compose final weight vector ───────────────────────────────────────
    weights = compose_weights(ospc)
    log.info("Final weights: %s", {k: f"{v:.4f}" for k, v in weights.items()})

    # ── Load ETL feature records ──────────────────────────────────────────
    ndjson_path = ETL_OUTPUT_BASE / run_id / "features.ndjson"
    if not ndjson_path.exists():
        raise FileNotFoundError(
            f"ETL output not found at {ndjson_path}. "
            f"Run etl.py with --run-id {run_id} first."
        )

    records: list[dict] = []
    with ndjson_path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))

    if not records:
        log.warning("No ETL records found for run_id=%s — scoring complete with 0 services", run_id)
        return []

    log.info("Loaded %d ETL records from %s", len(records), ndjson_path)

    # ── Score each record ─────────────────────────────────────────────────
    scored_records: list[dict] = []
    for record in records:
        name = record.get("service_name", "unknown")
        try:
            scored = score_record(record, weights, ospc)
            scored_records.append(scored)
            log.info(
                "  %s — raw=%.1f final=%.1f confidence=%s controls=%s",
                name,
                scored["raw_score"],
                scored["final_risk_score"],
                scored["data_confidence"],
                scored["active_controls"] or "none",
            )
        except Exception as exc:  # noqa: BLE001
            log.error("Failed to score service '%s': %s", name, exc)

    # ── Write to Azure Files (per-service JSON) ───────────────────────────
    for scored in scored_records:
        path = write_score_json(run_id, scored)
        log.debug("Score JSON written: %s", path)

    log.info("Azure Files: %d score JSON files written to %s", len(scored_records), SCORES_OUTPUT_BASE / run_id)

    # ── Write to MySQL scores table (primary Power BI source) ─────────────
    engine = get_engine()
    write_scores_to_mysql(engine, scored_records)

    log.info(
        "Scoring complete — run_id=%s services=%d",
        run_id, len(scored_records),
    )
    return scored_records


# ---------------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="cloudrisk scoring pipeline")
    parser.add_argument("--run-id", required=True, help="ETL run UUID to score")
    parser.add_argument("--ospc", default="/data/config/ospc.json", help="Path to OSPC config JSON")
    args = parser.parse_args()

    results = run_scoring(run_id=args.run_id, ospc_path=args.ospc)

    # Print summary to stdout for CLI dispatcher / logging
    summary = {
        "run_id": args.run_id,
        "services_scored": len(results),
        "avg_final_score": round(
            sum(r["final_risk_score"] for r in results) / len(results), 1
        ) if results else 0.0,
        "kev_services": sum(1 for r in results if r["is_kev_present"]),
        "insufficient_data_services": sum(1 for r in results if r["data_confidence"] == "insufficient_data"),
    }
    print(json.dumps(summary))
