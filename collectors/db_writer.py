"""
db_writer.py
------------
Shared MySQL upsert module used by all collection scripts.
Reads DATABASE_URL from environment (injected at job start).

Usage:
    from collectors.db_writer import upsert_records
    upsert_records("vulnerabilities", records, conflict_keys=["source", "cve_id"])
"""

import os
import json
import logging
from datetime import datetime
from sqlalchemy import create_engine, text, MetaData
from sqlalchemy.dialects.mysql import insert as mysql_insert

log = logging.getLogger(__name__)

_engine = None


def get_engine():
    global _engine
    if _engine is None:
        url = os.environ["DATABASE_URL"]
        _engine = create_engine(
            url,
            pool_pre_ping=True,
            pool_recycle=1800,
            connect_args={
                "ssl": {
                    "ssl_disabled": False,
                    "check_hostname": False,
                    "verify_mode": 0
                }
            }
        )
    return _engine


def upsert_records(table_name: str, records: list[dict],
                   conflict_keys: list[str]) -> int:
    """
    Insert or update a list of records into the given table.
    On duplicate conflict_keys, all other columns are updated.
    Returns the number of rows affected.
    """
    if not records:
        return 0

    engine = get_engine()
    meta   = MetaData()
    meta.reflect(bind=engine, only=[table_name])
    table  = meta.tables[table_name]

    table_cols = {c.name for c in table.columns}
    affected = 0
    with engine.begin() as conn:
        for record in records:
            clean = {}
            for k, v in record.items():
                if k not in table_cols:
                    continue
                if isinstance(v, (dict, list)):
                    clean[k] = json.dumps(v)
                elif isinstance(v, datetime):
                    clean[k] = v.isoformat()
                else:
                    clean[k] = v

            stmt = mysql_insert(table).values(**clean)

            update_cols = {
                k: stmt.inserted[k]
                for k in clean.keys()  # Iterate over the keys we actually HAVE
                if k not in conflict_keys and k != "id"
            }
            stmt = stmt.on_duplicate_key_update(**update_cols)
            result = conn.execute(stmt)
            affected += result.rowcount

    log.info("upsert_records: table=%s rows_affected=%d", table_name, affected)
    return affected


def register_service(service_name: str) -> None:
    """
    Ensure service_name exists in the services table.
    Uses INSERT IGNORE so it's safe to call on every collection run.
    """
    engine = get_engine()
    with engine.begin() as conn:
        conn.execute(
            text("INSERT IGNORE INTO services (name) VALUES (:name)"),
            {"name": service_name},
        )
    log.debug("register_service: ensured '%s' in services table", service_name)


def execute_sql(sql: str, params: dict | None = None) -> list[dict]:
    """Run a raw SELECT and return rows as dicts."""
    engine = get_engine()
    with engine.connect() as conn:
        result = conn.execute(text(sql), params or {})
        return [dict(row._mapping) for row in result]
