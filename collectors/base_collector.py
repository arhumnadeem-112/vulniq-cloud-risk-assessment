"""
base_collector.py
-----------------
Base class and manifest writer shared by all collection scripts.
Provides:
  - Backoff-aware HTTP client (httpx)
  - Run manifest writing to /data/manifests/
  - NDJSON raw output to /data/raw/
  - Standardised logging
"""

import os
import json
import logging
import time
import uuid
from datetime import datetime, date
from pathlib import Path
import httpx

from collectors.db_writer import register_service

log = logging.getLogger(__name__)

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
RAW_DIR  = DATA_DIR / "raw"
MAN_DIR  = DATA_DIR / "manifests"

RAW_DIR.mkdir(parents=True, exist_ok=True)
MAN_DIR.mkdir(parents=True, exist_ok=True)


def _json_default(obj):
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj)} is not JSON serialisable")


def write_ndjson(source: str, service_name: str, records: list[dict]) -> Path:
    """Write raw records as NDJSON before any DB write."""
    today = date.today().isoformat()
    path  = RAW_DIR / source / f"{service_name}_{today}.ndjson"
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        for rec in records:
            f.write(json.dumps(rec, default=_json_default) + "\n")
    log.debug("Raw NDJSON written: %s (%d records)", path, len(records))
    return path


def write_manifest(
    source: str,
    service_name: str,
    record_count: int,
    errors: list[str],
    extra: dict | None = None,
) -> Path:
    """Write a run manifest JSON file."""
    manifest = {
        "run_id":       str(uuid.uuid4()),
        "source":       source,
        "service_name": service_name,
        "timestamp":    datetime.utcnow().isoformat(),
        "record_count": record_count,
        "errors":       errors,
        **(extra or {}),
    }
    today = date.today().isoformat()
    path  = MAN_DIR / f"{source}_{service_name}_{today}.json"
    with open(path, "w") as f:
        json.dump(manifest, f, indent=2)
    log.info("Manifest written: %s", path)
    return path


class BaseCollector:
    """
    Base HTTP collector with exponential backoff retry.
    Subclasses implement collect().
    """
    SOURCE = "base"
    DEFAULT_HEADERS: dict = {}
    TIMEOUT = 30.0
    MAX_RETRIES = 5

    def __init__(self, service_name: str,
                 start_date: str | None = None,
                 end_date:   str | None = None):
        self.service_name = service_name
        self.start_date   = start_date
        self.end_date     = end_date
        self.errors: list[str] = []
        self._client = httpx.Client(
            headers=self.DEFAULT_HEADERS,
            timeout=self.TIMEOUT,
            follow_redirects=True,
        )

    def get(self, url: str, **kwargs) -> httpx.Response:
        """GET with exponential backoff on 403 / 429 / 5xx. Fails fast on 404."""
        for attempt in range(self.MAX_RETRIES):
            try:
                resp = self._client.get(url, **kwargs)
                if resp.status_code == 404:
                    # 404 is a definitive answer — do not retry.
                    msg = f"404 Not Found: {url}"
                    self.errors.append(msg)
                    raise RuntimeError(msg)
                if resp.status_code == 429:
                    wait = int(resp.headers.get("Retry-After", 2 ** attempt))
                    log.warning("Rate limited by %s — waiting %ds", url, wait)
                    time.sleep(wait)
                    continue
                if resp.status_code == 403:
                    # NVD (and some others) return 403 as a transient throttle,
                    # not a permanent auth failure — back off aggressively.
                    wait = 2 ** (attempt + 3)  # 8s → 16s → 32s → 64s → 128s
                    log.warning("403 Forbidden from %s — possible rate-limit, "
                                "waiting %ds (attempt %d/%d)",
                                url, wait, attempt + 1, self.MAX_RETRIES)
                    time.sleep(wait)
                    continue
                if resp.status_code >= 500:
                    wait = 2 ** attempt
                    log.warning("Server error %d from %s — retrying in %ds",
                                resp.status_code, url, wait)
                    time.sleep(wait)
                    continue
                resp.raise_for_status()
                return resp
            except (httpx.HTTPError, OSError, ConnectionError) as exc:
                wait = 2 ** attempt
                log.warning("HTTP error on attempt %d: %s — retrying in %ds",
                            attempt + 1, exc, wait)
                time.sleep(wait)
        msg = f"Failed to GET {url} after {self.MAX_RETRIES} attempts"
        self.errors.append(msg)
        raise RuntimeError(msg)

    def post(self, url: str, **kwargs) -> httpx.Response:
        """POST with exponential backoff on 429 / 5xx."""
        for attempt in range(self.MAX_RETRIES):
            try:
                resp = self._client.post(url, **kwargs)
                if resp.status_code == 429:
                    wait = int(resp.headers.get("Retry-After", 2 ** attempt))
                    time.sleep(wait)
                    continue
                if resp.status_code >= 500:
                    time.sleep(2 ** attempt)
                    continue
                resp.raise_for_status()
                return resp
            except httpx.HTTPError as exc:
                time.sleep(2 ** attempt)
        msg = f"Failed to POST {url} after {self.MAX_RETRIES} attempts"
        self.errors.append(msg)
        raise RuntimeError(msg)

    def collect(self) -> list[dict]:
        raise NotImplementedError

    def run(self) -> list[dict]:
        """Collect, write raw NDJSON, write manifest, return records."""
        log.info("[%s] Starting collection for service=%s",
                 self.SOURCE, self.service_name)
        if os.environ.get("DATABASE_URL"):
            try:
                register_service(self.service_name)
            except Exception as exc:
                log.warning("Could not register service '%s': %s", self.service_name, exc)
        records = self.collect()
        write_ndjson(self.SOURCE, self.service_name, records)
        write_manifest(self.SOURCE, self.service_name,
                       len(records), self.errors)
        log.info("[%s] Collected %d records for service=%s",
                 self.SOURCE, len(records), self.service_name)
        return records

    def close(self):
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
