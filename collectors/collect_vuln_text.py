"""
collect_vuln_text.py
--------------------
Extracts vulnerability narrative text for ChromaDB (vuln_text collection).

Sources (in priority order, no scraping of bot-blocked sites):
  1. raw_json stored in MySQL by collect_nvd — NVD description text (instant,
     no extra HTTP calls; the data was already fetched during collection)
  2. NVD CVE API — fallback for CVEs collected by OSV/GHSA that have no raw_json
     or whose raw_json lacks a description
  3. MITRE CVE AWG API (cveawg.mitre.org) — second fallback; public, no auth
     required, handles cases where NVD returns 403 due to rate-limiting

Removed: cvedetails.com scraping (blocks automated requests with 403/CloudFlare)
         exploit-db scraping (rarely has Salesforce-related PoCs; high noise)

Text is stored in ChromaDB for NLP feature extraction in the ETL pipeline.
No MySQL writes — this is ChromaDB-only.

Usage:
    python collect_vuln_text.py --service salesforce
    python collect_vuln_text.py --service salesforce --limit 50
"""

import json
import logging
import argparse
import os
import time

from collectors.base_collector import BaseCollector
from collectors.db_writer import execute_sql
from collectors.chroma_writer import upsert_documents

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s — %(message)s")
log = logging.getLogger("collect_vuln_text")

NVD_CVE_URL   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MITRE_CVE_URL = "https://cveawg.mitre.org/api/cve"
SLEEP_NVD     = 0.7   # NVD rate limit: ~100 req/30s with API key, 10 req/30s without
SLEEP_MITRE   = 0.2   # MITRE AWG API is generous; light throttle to be polite


class VulnTextCollector(BaseCollector):
    SOURCE = "vuln_text"

    def __init__(self, service_name: str, limit: int = 100,
                 start_date: str | None = None, end_date: str | None = None):
        super().__init__(service_name, start_date, end_date)
        self.limit = limit
        api_key = os.environ.get("NVD_API_KEY", "")
        if api_key:
            self._client.headers.update({"apiKey": api_key})

    def _get_cve_rows(self) -> list[dict]:
        """
        Return rows from MySQL: cve_id + raw_json for this service.
        raw_json from NVD already contains the description; we only call
        the NVD API for rows where it is absent (OSV/GHSA sources).
        """
        rows = execute_sql(
            "SELECT DISTINCT cve_id, raw_json, published_at FROM vulnerabilities "
            "WHERE service_name = :svc AND cve_id LIKE 'CVE-%' "
            "ORDER BY published_at DESC "
            "LIMIT :lim",
            {"svc": self.service_name, "lim": self.limit},
        )
        return rows

    def _description_from_raw_json(self, raw_json) -> str | None:
        """
        Extract the English description from an NVD raw_json blob already
        stored in MySQL.  Returns None if the field is absent or empty.
        """
        try:
            data = raw_json if isinstance(raw_json, dict) else json.loads(raw_json or "{}")
            descs = (data.get("cve") or data).get("descriptions", [])
            for d in descs:
                if d.get("lang") == "en":
                    return d.get("value", "").strip() or None
        except Exception:
            pass
        return None

    def _fetch_nvd_description(self, cve_id: str) -> str | None:
        """
        Fallback: call the NVD API for a single CVE and return its description.
        Used only when raw_json is missing or contains no description (e.g. OSV rows).
        """
        try:
            resp = self.get(NVD_CVE_URL, params={"cveId": cve_id})
            vulns = resp.json().get("vulnerabilities", [])
            if vulns:
                return self._description_from_raw_json(vulns[0])
        except Exception as exc:
            log.warning("NVD API fallback failed for %s: %s", cve_id, exc)
            self.errors.append(f"nvd_fallback {cve_id}: {exc}")
        return None

    def _fetch_mitre_description(self, cve_id: str) -> str | None:
        """
        Second fallback: MITRE CVE AWG API — public, no API key required.
        Covers cases where NVD returns 403 due to rate-limiting or missing key.
        Response format (CVE 5.x): containers.cna.descriptions[].{lang, value}
        """
        try:
            resp = self.get(f"{MITRE_CVE_URL}/{cve_id}")
            data = resp.json()
            cna = data.get("containers", {}).get("cna", {})
            for desc in cna.get("descriptions", []):
                if desc.get("lang", "").startswith("en"):
                    val = desc.get("value", "").strip()
                    if val:
                        return val
        except Exception as exc:
            log.warning("MITRE API fallback failed for %s: %s", cve_id, exc)
            self.errors.append(f"mitre_fallback {cve_id}: {exc}")
        return None

    # ── Main collect ──────────────────────────────────────────────────────────

    def collect(self) -> list[dict]:
        rows = self._get_cve_rows()

        # Deduplicate by cve_id — same CVE can appear from multiple sources
        # (NVD, GHSA, OSV). Prefer rows that already have raw_json.
        seen: dict[str, dict] = {}
        for row in rows:
            cid = row["cve_id"]
            if cid not in seen or (row.get("raw_json") and not seen[cid].get("raw_json")):
                seen[cid] = row
        rows = list(seen.values())

        log.info("vuln_text: processing %d CVE IDs for %s",
                 len(rows), self.service_name)

        texts, metadatas, ids = [], [], []
        nvd_api_calls = 0
        mitre_api_calls = 0

        for row in rows:
            cve_id   = row["cve_id"]
            raw_json = row.get("raw_json")
            source   = "raw_json"

            # 1 — Try description from stored raw_json (free — no HTTP call)
            description = self._description_from_raw_json(raw_json)

            # 2 — Fallback to NVD API if description missing
            if not description:
                description = self._fetch_nvd_description(cve_id)
                nvd_api_calls += 1
                source = "nvd_api"
                time.sleep(SLEEP_NVD)

            # 3 — Fallback to MITRE CVE AWG API (public, no auth, avoids NVD 403)
            if not description:
                description = self._fetch_mitre_description(cve_id)
                mitre_api_calls += 1
                source = "mitre_api"
                time.sleep(SLEEP_MITRE)

            if not description:
                log.debug("vuln_text: no description found for %s — skipping", cve_id)
                continue

            texts.append(description)
            metadatas.append({
                "cve_id":       cve_id,
                "source":       source,
                "service_name": self.service_name,
                "date":         "",
            })
            ids.append(f"nvd_desc::{cve_id}")

        log.info(
            "vuln_text: %d descriptions found "
            "(%d raw_json / %d NVD API / %d MITRE API) for %s",
            len(texts),
            len(texts) - nvd_api_calls - mitre_api_calls,
            nvd_api_calls,
            mitre_api_calls,
            self.service_name,
        )

        if texts:
            upsert_documents("vuln_text", texts, metadatas, ids)
            log.info("vuln_text: %d chunks written to ChromaDB", len(texts))

        return [{"cve_id": ids[i].split("::")[-1], "text_length": len(t)}
                for i, t in enumerate(texts)]


def main():
    parser = argparse.ArgumentParser(
        description="Collect vulnerability text for ChromaDB")
    # TARGET: --service must match the service_name stored in the vulnerabilities table
    # (i.e. the same value passed to collect_nvd / collect_osv / collect_ghsa).
    # For Salesforce: use 'salesforce'.
    parser.add_argument("--service", required=True)
    parser.add_argument("--limit",   type=int, default=100,
                        help="Max CVE IDs to process")
    args = parser.parse_args()

    with VulnTextCollector(args.service, limit=args.limit) as col:
        records = col.run()
        log.info("vuln_text collection complete: %d text chunks", len(records))


if __name__ == "__main__":
    main()
