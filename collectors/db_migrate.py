"""
db_migrate.py
-------------
Creates all MySQL tables required by the capstone-cloudrisk collection pipeline.
Safe to run multiple times — uses CREATE TABLE IF NOT EXISTS throughout.

Usage:
    python -m collectors.db_migrate

Or via Container Apps Job:
    CLOUDRISK_COMMAND='db_migrate' az containerapp job start ...
"""

import os
import logging
from sqlalchemy import create_engine, text

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s — %(message)s")
log = logging.getLogger("db_migrate")

SCHEMA = [

    # ── services ──────────────────────────────────────────────────────────────
    """
    CREATE TABLE IF NOT EXISTS services (
        id               BIGINT        NOT NULL AUTO_INCREMENT,
        name             VARCHAR(256)  NOT NULL,
        vendor           VARCHAR(256)  DEFAULT NULL,
        ecosystem        VARCHAR(64)   DEFAULT NULL,
        is_oss           TINYINT(1)    DEFAULT 0,
        is_saas          TINYINT(1)    DEFAULT 0,
        github_repo      VARCHAR(512)  DEFAULT NULL,
        service_tier     TINYINT       DEFAULT NULL,
        status_page_url  VARCHAR(1024) DEFAULT NULL,
        trust_center_url VARCHAR(1024) DEFAULT NULL,
        ingested_at      DATETIME      DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY uq_service_name (name)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    """,

    # ── vulnerabilities ───────────────────────────────────────────────────────
    """
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        id              BIGINT         NOT NULL AUTO_INCREMENT,
        source          VARCHAR(64)    NOT NULL,
        cve_id          VARCHAR(32)    DEFAULT NULL,
        advisory_id     VARCHAR(128)   DEFAULT NULL,
        service_name    VARCHAR(256)   DEFAULT NULL,
        ecosystem       VARCHAR(64)    DEFAULT NULL,
        severity        VARCHAR(16)    DEFAULT 'NONE',
        cvss_v3_score   DECIMAL(4,1)   DEFAULT NULL,
        cvss_v3_vector  VARCHAR(256)   DEFAULT NULL,
        epss_score      DECIMAL(6,5)   DEFAULT NULL,
        is_kev          TINYINT(1)     DEFAULT 0,
        cwe_id          VARCHAR(512)   DEFAULT NULL,
        published_at    DATETIME       DEFAULT NULL,
        modified_at     DATETIME       DEFAULT NULL,
        raw_json        LONGTEXT       DEFAULT NULL,
        ingested_at     DATETIME       DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY uq_source_advisory (source, advisory_id),
        KEY idx_service_name (service_name),
        KEY idx_cve_id (cve_id),
        KEY idx_severity (severity),
        KEY idx_is_kev (is_kev)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    """,

    # ── repo_health ───────────────────────────────────────────────────────────
    """
    CREATE TABLE IF NOT EXISTS repo_health (
        id                        BIGINT       NOT NULL AUTO_INCREMENT,
        service_name              VARCHAR(256) NOT NULL,
        repo_full_name            VARCHAR(512) DEFAULT NULL,
        commit_count_90d          INT          DEFAULT NULL,
        contributor_count_90d     INT          DEFAULT NULL,
        open_issues               INT          DEFAULT NULL,
        security_issues_open      INT          DEFAULT NULL,
        mean_days_close_security  DECIMAL(6,1) DEFAULT NULL,
        days_since_last_release   INT          DEFAULT NULL,
        has_security_policy       TINYINT(1)   DEFAULT 0,
        raw_json                  LONGTEXT     DEFAULT NULL,
        collected_at              DATETIME     DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY uq_service_repo (service_name, repo_full_name),
        KEY idx_service_name (service_name)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    """,

    # ── service_incidents ─────────────────────────────────────────────────────
    """
    CREATE TABLE IF NOT EXISTS service_incidents (
        id                   BIGINT        NOT NULL AUTO_INCREMENT,
        service_name         VARCHAR(256)  NOT NULL,
        incident_id          VARCHAR(128)  DEFAULT NULL,
        severity             VARCHAR(32)   DEFAULT NULL,
        status               VARCHAR(32)   DEFAULT NULL,
        started_at           DATETIME      DEFAULT NULL,
        resolved_at          DATETIME      DEFAULT NULL,
        duration_minutes     INT           DEFAULT NULL,
        affected_components  VARCHAR(1024) DEFAULT NULL,
        raw_json             LONGTEXT      DEFAULT NULL,
        collected_at         DATETIME      DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY uq_service_incident (service_name, incident_id),
        KEY idx_service_name (service_name),
        KEY idx_started_at (started_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    """,

    # ── scores ────────────────────────────────────────────────────────────────
    # Flattened score record per service per pipeline run — primary Power BI source
    """
    CREATE TABLE IF NOT EXISTS scores (
        id                        BIGINT        NOT NULL AUTO_INCREMENT,
        run_id                    VARCHAR(36)   NOT NULL,
        scored_at                 DATETIME      DEFAULT CURRENT_TIMESTAMP,
        service_name              VARCHAR(256)  NOT NULL,
        vendor                    VARCHAR(256)  DEFAULT NULL,
        ecosystem                 VARCHAR(64)   DEFAULT NULL,
        final_risk_score          DECIMAL(5,1)  DEFAULT NULL,
        raw_score                 DECIMAL(5,1)  DEFAULT NULL,
        security_posture_score    DECIMAL(5,1)  DEFAULT NULL,
        operational_maturity_score DECIMAL(5,1) DEFAULT NULL,
        service_reliability_score DECIMAL(5,1)  DEFAULT NULL,
        governance_score          DECIMAL(5,1)  DEFAULT NULL,
        cve_count                 INT           DEFAULT 0,
        highest_cvss              DECIMAL(4,1)  DEFAULT NULL,
        is_kev_present            TINYINT(1)    DEFAULT 0,
        critical_cve_count        INT           DEFAULT 0,
        high_cve_count            INT           DEFAULT 0,
        medium_cve_count          INT           DEFAULT 0,
        low_cve_count             INT           DEFAULT 0,
        major_incident_count_12m  INT           DEFAULT 0,
        total_incident_hours_12m  DECIMAL(8,2)  DEFAULT 0,
        commit_count_90d          INT           DEFAULT NULL,
        contributor_count_90d     INT           DEFAULT NULL,
        days_since_release        INT           DEFAULT NULL,
        has_security_policy       TINYINT(1)    DEFAULT 0,
        doc_quality_score         DECIMAL(5,4)  DEFAULT NULL,
        security_guidance_score   DECIMAL(5,4)  DEFAULT NULL,
        trust_coverage_score      DECIMAL(5,4)  DEFAULT NULL,
        incident_sentiment_score  DECIMAL(5,4)  DEFAULT NULL,
        data_confidence           VARCHAR(20)   DEFAULT 'insufficient_data',
        ospc_org_name             VARCHAR(256)  DEFAULT NULL,
        active_controls           VARCHAR(512)  DEFAULT NULL,
        PRIMARY KEY (id),
        UNIQUE KEY uq_run_service (run_id, service_name),
        KEY idx_service_name (service_name),
        KEY idx_scored_at (scored_at),
        KEY idx_final_risk_score (final_risk_score)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    """,
]

# Idempotent column additions for existing tables.
# Each tuple: (table, column, ALTER TABLE statement).
# Run after SCHEMA so new installs get the column via CREATE TABLE;
# existing installs get it here. Duplicate-column errors are silently skipped.
COLUMN_MIGRATIONS: list[tuple[str, str, str]] = [
    (
        "services",
        "service_tier",
        "ALTER TABLE services ADD COLUMN service_tier TINYINT DEFAULT NULL",
    ),
]


def run_migration():
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise EnvironmentError("DATABASE_URL environment variable is not set")

    log.info("Connecting to database...")
    engine = create_engine(
        url,
        pool_pre_ping=True,
        connect_args={
            "ssl": {
                "ssl_disabled": False,
                "check_hostname": False,
                "verify_mode": 0,
            }
        },
    )

    with engine.begin() as conn:
        for statement in SCHEMA:
            # Extract table name for logging
            for line in statement.strip().splitlines():
                if "CREATE TABLE" in line.upper():
                    table_name = line.strip().split()[-1].strip("(")
                    log.info("Creating table if not exists: %s", table_name)
                    break
            conn.execute(text(statement.strip()))

    log.info("Migration complete — all tables created successfully")

    for table, column, stmt in COLUMN_MIGRATIONS:
        try:
            with engine.begin() as conn:
                conn.execute(text(stmt))
            log.info("Column migration: added %s.%s", table, column)
        except Exception as exc:
            if "1060" in str(exc) or "Duplicate column" in str(exc):
                log.info("Column %s.%s already exists — skipping", table, column)
            else:
                raise

    # Print table summary
    with engine.connect() as conn:
        result = conn.execute(text("SHOW TABLES"))
        tables = [row[0] for row in result]
        log.info("Tables in database: %s", ", ".join(tables))


if __name__ == "__main__":
    run_migration()
