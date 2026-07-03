# """
# collect_nvd.py
# --------------
# Collects CVE records from the NIST National Vulnerability Database (NVD) REST API v2.
# Stores structured records in MySQL → vulnerabilities table.

# API docs: https://nvd.nist.gov/developers/vulnerabilities
# Rate limit: 5 req/30s without key, 50 req/30s with NVD_API_KEY env var.

# Usage:
#     python collect_nvd.py --service stripe
#     python collect_nvd.py --service stripe --start-date 2024-01-01 --end-date 2024-12-31
# """

# import os
# import logging
# import argparse
# from datetime import datetime, timedelta

# from collectors.base_collector import BaseCollector
# from collectors.db_writer import upsert_records

# logging.basicConfig(level=logging.INFO,
#                     format="%(asctime)s %(levelname)s %(name)s — %(message)s")
# log = logging.getLogger("collect_nvd")

# NVD_BASE   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# PAGE_SIZE  = 2000
# SEVERITY_MAP = {
#     "CRITICAL": "CRITICAL",
#     "HIGH":     "HIGH",
#     "MEDIUM":   "MEDIUM",
#     "LOW":      "LOW",
#     "NONE":     "NONE",
# }


# def _normalise_cve_id(cve_id: str) -> str:
#     return cve_id.upper().strip()


# class NVDCollector(BaseCollector):
#     SOURCE = "nvd"

#     def __init__(self, service_name: str,
#                  start_date: str | None = None,
#                  end_date:   str | None = None):
#         api_key = os.environ.get("NVD_API_KEY", "")
#         headers = {"apiKey": api_key} if api_key else {}
#         super().__init__(service_name, start_date, end_date)
#         self.DEFAULT_HEADERS = headers
#         self._client.headers.update(headers)

#         # Default date window: last 90 days
#         if not self.start_date:
#             self.start_date = (datetime.utcnow() - timedelta(days=90)
#                                ).strftime("%Y-%m-%dT00:00:00.000")
#         if not self.end_date:
#             self.end_date = datetime.utcnow().strftime("%Y-%m-%dT23:59:59.999")

#     def _fetch_page(self, start_index: int) -> dict:
#         params = {
#             "keywordSearch":    self.service_name,
#             "pubStartDate":     self.start_date,
#             "pubEndDate":       self.end_date,
#             "resultsPerPage":   PAGE_SIZE,
#             "startIndex":       start_index,
#         }
#         resp = self.get(NVD_BASE, params=params)
#         return resp.json()

#     def _parse_cve(self, item: dict) -> dict | None:
#         """Parse a single CVE item from the NVD API response."""
#         try:
#             cve    = item.get("cve", {})
#             cve_id = _normalise_cve_id(cve.get("id", ""))
#             if not cve_id:
#                 return None

#             # CVSS v3 metrics
#             metrics     = cve.get("metrics", {})
#             cvss_v3     = (metrics.get("cvssMetricV31") or
#                            metrics.get("cvssMetricV30") or [])
#             cvss_score  = None
#             cvss_vector = None
#             severity    = "NONE"
#             if cvss_v3:
#                 primary = next(
#                     (m for m in cvss_v3 if m.get("type") == "Primary"),
#                     cvss_v3[0]
#                 )
#                 cvss_data   = primary.get("cvssData", {})
#                 cvss_score  = cvss_data.get("baseScore")
#                 cvss_vector = cvss_data.get("vectorString")
#                 severity    = SEVERITY_MAP.get(
#                     cvss_data.get("baseSeverity", "NONE").upper(), "NONE")

#             # EPSS is not in NVD v2 — left null; populated by collect_osv if available
#             published_at = cve.get("published", "")[:19].replace("T", " ") or None
#             modified_at  = cve.get("lastModified", "")[:19].replace("T", " ") or None

#             return {
#                 "source":        "nvd",
#                 "cve_id":        cve_id,
#                 "advisory_id":   cve_id,
#                 "service_name":  self.service_name,
#                 "ecosystem":     "SaaS",        # refined by ETL
#                 "severity":      severity,
#                 "cvss_v3_score": float(cvss_score) if cvss_score else None,
#                 "cvss_v3_vector":cvss_vector,
#                 "epss_score":    None,
#                 "is_kev":        0,             # updated by collect_kev
#                 "published_at":  published_at,
#                 "modified_at":   modified_at,
#                 "raw_json":      item,
#             }
#         except Exception as exc:
#             self.errors.append(f"Failed to parse CVE {item}: {exc}")
#             log.warning("CVE parse error: %s", exc)
#             return None

#     def collect(self) -> list[dict]:
#         records     = []
#         start_index = 0

#         while True:
#             log.info("NVD page startIndex=%d service=%s",
#                      start_index, self.service_name)
#             data        = self._fetch_page(start_index)
#             total       = data.get("totalResults", 0)
#             items       = data.get("vulnerabilities", [])

#             for item in items:
#                 parsed = self._parse_cve(item)
#                 if parsed:
#                     records.append(parsed)

#             start_index += len(items)
#             if start_index >= total or not items:
#                 break

#         log.info("NVD: %d CVEs collected for %s", len(records), self.service_name)
#         return records


# def main():
#     parser = argparse.ArgumentParser(description="Collect CVEs from NVD")
#     parser.add_argument("--service",    required=True, help="Service name to search")
#     parser.add_argument("--start-date", default=None,  help="ISO date YYYY-MM-DD")
#     parser.add_argument("--end-date",   default=None,  help="ISO date YYYY-MM-DD")
#     args = parser.parse_args()

#     with NVDCollector(args.service, args.start_date, args.end_date) as col:
#         records = col.run()
#         if records:
#             upsert_records(
#                 "vulnerabilities",
#                 records,
#                 conflict_keys=["source", "cve_id"],
#             )
#         log.info("NVD collection complete: %d records", len(records))


# if __name__ == "__main__":
#     main()

"""
collect_nvd.py
--------------
Collects NEWLY PUBLISHED CVE records from NIST NVD API v2.
"""

import os
import logging
import argparse
from datetime import datetime, timedelta, timezone

from collectors.base_collector import BaseCollector
from collectors.db_writer import upsert_records
from collectors.service_aliases import get_nvd_keywords

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s — %(message)s")
log = logging.getLogger("collect_nvd")

NVD_BASE     = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE    = 2000
LOOKBACK_DAYS = 180   # total window we want
NVD_MAX_DAYS  = 119   # NVD API rejects windows > 120 days; stay safely under
SEVERITY_MAP = {
    "CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW", "NONE": "NONE",
}


def _make_windows(start: str, end: str, max_days: int = NVD_MAX_DAYS) -> list[tuple[str, str]]:
    """
    Split the [start, end] date range into consecutive chunks of at most
    max_days each.  Used to chain NVD API calls and cover windows wider than
    the 120-day per-request limit.

    Example — 180 days with max_days=119:
        window 1: day -180 … day -61   (119 days)
        window 2: day -60  … day 0     (61 days)
    """
    def _parse(s: str) -> datetime:
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S.000",
                    "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
            try:
                return datetime.strptime(s, fmt)
            except ValueError:
                continue
        raise ValueError(f"Cannot parse NVD date string: {s!r}")

    s_dt = _parse(start)
    e_dt = _parse(end)
    windows: list[tuple[str, str]] = []
    chunk_s = s_dt
    while chunk_s < e_dt:
        chunk_e = min(chunk_s + timedelta(days=max_days), e_dt)
        windows.append((
            chunk_s.strftime("%Y-%m-%dT%H:%M:%S.000"),
            chunk_e.strftime("%Y-%m-%dT%H:%M:%S.000"),
        ))
        chunk_s = chunk_e + timedelta(seconds=1)
    return windows


class NVDCollector(BaseCollector):
    SOURCE = "nvd"

    def __init__(self, service_name: str, start_date: str | None = None,
                 end_date: str | None = None, keywords: list[str] | None = None):
        api_key = os.environ.get("NVD_API_KEY", "")
        headers = {"apiKey": api_key} if api_key else {}
        super().__init__(service_name, start_date, end_date)
        self.DEFAULT_HEADERS = headers
        self._client.headers.update(headers)

        # Default: last 180 days.  collect() chains ≤119-day windows automatically.
        now = datetime.now(timezone.utc)
        if not self.end_date:
            self.end_date = now.strftime("%Y-%m-%dT23:59:59.999")
        if not self.start_date:
            self.start_date = (now - timedelta(days=LOOKBACK_DAYS)).strftime("%Y-%m-%dT00:00:00.000")

        # Explicit keywords override service_aliases lookup.
        # All results are stored under the canonical service_name regardless of keyword.
        self.keywords = keywords if keywords is not None else get_nvd_keywords(service_name)
        log.info("NVD keywords for %s: %s", service_name, self.keywords)

    def _fetch_page(self, start_index: int, keyword: str,
                    start: str | None = None, end: str | None = None) -> dict:
        params = {
            "keywordSearch":  keyword,
            "pubStartDate":   start or self.start_date,
            "pubEndDate":     end   or self.end_date,
            "resultsPerPage": PAGE_SIZE,
            "startIndex":     start_index,
        }
        resp = self.get(NVD_BASE, params=params)
        return resp.json()

    def _parse_cve(self, item: dict) -> dict | None:
        try:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "").upper().strip()
            if not cve_id: return None

            metrics = cve.get("metrics", {})
            cvss_v3 = (metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or [])
            cvss_score, cvss_vector, severity = None, None, "NONE"
            
            if cvss_v3:
                primary = next((m for m in cvss_v3 if m.get("type") == "Primary"), cvss_v3[0])
                cvss_data = primary.get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_vector = cvss_data.get("vectorString")
                severity = SEVERITY_MAP.get(cvss_data.get("baseSeverity", "NONE").upper(), "NONE")

            # Extract CWE IDs — prefer Primary source, fall back to all listed
            weaknesses = cve.get("weaknesses", [])
            primary_cwes = [w for w in weaknesses if w.get("type") == "Primary"]
            cwe_source = primary_cwes if primary_cwes else weaknesses
            cwe_ids = []
            for w in cwe_source:
                for desc in w.get("description", []):
                    val = desc.get("value", "")
                    if val.startswith("CWE-") and val not in cwe_ids:
                        cwe_ids.append(val)
            cwe_id = ",".join(cwe_ids) or None

            return {
                "source": "nvd", "cve_id": cve_id, "advisory_id": cve_id,
                "service_name": self.service_name, "ecosystem": "SaaS",
                "severity": severity, "cvss_v3_score": float(cvss_score) if cvss_score else None,
                "cvss_v3_vector": cvss_vector, "epss_score": None, "is_kev": 0,
                "cwe_id": cwe_id,
                "published_at": cve.get("published", "")[:19].replace("T", " "),
                "modified_at": cve.get("lastModified", "")[:19].replace("T", " "),
                "raw_json": item,
            }
        except Exception as exc:
            log.warning("CVE parse error: %s", exc)
            return None

    def _collect_keyword(self, keyword: str, seen: set[str]) -> list[dict]:
        """Fetch all CVEs matching a single NVD keyword across chunked date windows."""
        records: list[dict] = []
        windows = _make_windows(self.start_date, self.end_date)
        log.info("NVD: fetching %d window(s) for keyword=%r (%s → %s)",
                 len(windows), keyword, self.start_date[:10], self.end_date[:10])

        for win_start, win_end in windows:
            log.info("NVD window: %s → %s  keyword=%r", win_start[:10], win_end[:10], keyword)
            start_index = 0
            while True:
                data  = self._fetch_page(start_index, keyword, start=win_start, end=win_end)
                items = data.get("vulnerabilities", [])
                for item in items:
                    parsed = self._parse_cve(item)
                    if parsed and parsed["advisory_id"] not in seen:
                        seen.add(parsed["advisory_id"])
                        records.append(parsed)
                start_index += len(items)
                if start_index >= data.get("totalResults", 0) or not items:
                    break

        log.info("NVD: %d new CVEs for keyword=%r", len(records), keyword)
        return records

    def collect(self) -> list[dict]:
        seen: set[str] = set()
        all_records: list[dict] = []

        for keyword in self.keywords:
            keyword_records = self._collect_keyword(keyword, seen)
            all_records.extend(keyword_records)

        log.info("NVD: %d unique CVEs across all windows for %s",
                 len(all_records), self.service_name)
        return all_records

def main():
    parser = argparse.ArgumentParser(description="Collect CVEs from NVD")
    # --service is the canonical service name stored in the DB (e.g. 'salesforce').
    # NVD search keywords are resolved from service_aliases automatically (covers
    # subsidiaries like Tableau, MuleSoft, Heroku).
    # Override with --keywords for an explicit comma-separated keyword list.
    parser.add_argument("--service",    required=True, help="Canonical service name")
    parser.add_argument("--keywords",   default=None,
                        help="Comma-separated NVD keywords (overrides service_aliases)")
    parser.add_argument("--start-date", default=None, help="ISO date YYYY-MM-DD")
    parser.add_argument("--end-date",   default=None, help="ISO date YYYY-MM-DD")
    args = parser.parse_args()

    keywords = [k.strip() for k in args.keywords.split(",")] if args.keywords else None
    log.info("Processing service: %s", args.service)

    with NVDCollector(args.service, args.start_date, args.end_date, keywords) as col:
        records = col.run()
        if records:
            upsert_records("vulnerabilities", records, conflict_keys=["source", "cve_id"])
    log.info("Finished %s: %d records", args.service, len(records))

if __name__ == "__main__":
    main()