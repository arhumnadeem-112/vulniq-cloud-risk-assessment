"""
collect_osv.py
--------------
Collects vulnerability records from OSV.dev (Open Source Vulnerabilities).
Also enriches records with EPSS scores from the FIRST.org EPSS API.
Stores structured records in MySQL → vulnerabilities table.

API docs: https://google.github.io/osv.dev/api/
EPSS API: https://api.first.org/data/v1/epss

Usage:
    python collect_osv.py --service requests --ecosystem PyPI
    python collect_osv.py --service express --ecosystem npm
"""

import logging
import argparse
import time
from datetime import datetime, timedelta, timezone

from collectors.base_collector import BaseCollector
from collectors.db_writer import upsert_records
from collectors.service_aliases import get_packages, normalize_ecosystem

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s — %(message)s")
log = logging.getLogger("collect_osv")

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_VULN_URL  = "https://api.osv.dev/v1/vulns/{}"
EPSS_URL      = "https://api.first.org/data/v1/epss"
LOOKBACK_DAYS = 180   # only keep advisories published within this window

SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH":     "HIGH",
    "MEDIUM":   "MEDIUM",
    "LOW":      "LOW",
    "NONE":     "NONE",
}

ECOSYSTEM_MAP = {
    "pypi":   "PyPI",
    "npm":    "npm",
    "maven":  "Maven",
    "go":     "Go",
    "cargo":  "Cargo",
    "nuget":  "NuGet",
    "rubygems":"RubyGems",
}


class OSVCollector(BaseCollector):
    SOURCE = "osv"

    def __init__(self, service_name: str, ecosystem: str | None = None,
                 packages: list[str] | None = None,
                 start_date: str | None = None, end_date: str | None = None):
        super().__init__(service_name, start_date, end_date)
        # ecosystem=None → query all ecosystems from service_aliases
        self.ecosystem = ECOSYSTEM_MAP.get((ecosystem or "PyPI").lower(), ecosystem or "PyPI")

        # Build (ecosystem, package) query targets via service_aliases
        if packages:
            self.query_targets = [(self.ecosystem, p) for p in packages]
        else:
            pkg_map = get_packages(service_name, ecosystem)  # None = all ecosystems
            self.query_targets = [
                (normalize_ecosystem(eco), pkg)
                for eco, pkg_list in pkg_map.items()
                for pkg in pkg_list
            ]
        log.info("OSV targets for %s: %s", service_name, self.query_targets)

    def _fetch_osv_ids(self, ecosystem: str, package: str) -> list[str]:
        """Query OSV for all vulnerability IDs affecting this package."""
        payload  = {"package": {"name": package, "ecosystem": ecosystem}}
        resp     = self.post(OSV_QUERY_URL, json=payload)
        data     = resp.json()
        ids      = [v["id"] for v in data.get("vulns", [])]
        log.info("OSV: %d vulns found for %s/%s", len(ids), ecosystem, package)
        return ids

    def _fetch_vuln_detail(self, osv_id: str) -> dict:
        """Fetch full detail for one OSV vulnerability."""
        resp = self.get(OSV_VULN_URL.format(osv_id))
        return resp.json()

    def _fetch_epss_batch(self, cve_ids: list[str]) -> dict[str, float]:
        """
        Fetch EPSS scores for a batch of CVE IDs.
        Returns {cve_id: epss_score} dict.
        """
        if not cve_ids:
            return {}
        scores = {}
        BATCH = 100
        for i in range(0, len(cve_ids), BATCH):
            batch = cve_ids[i:i+BATCH]
            params = {"cve": ",".join(batch)}
            try:
                resp = self.get(EPSS_URL, params=params)
                for item in resp.json().get("data", []):
                    scores[item["cve"].upper()] = float(item["epss"])
            except Exception as exc:
                log.warning("EPSS batch error: %s", exc)
                self.errors.append(f"EPSS batch error: {exc}")
            time.sleep(0.2)  # gentle rate limit
        return scores

    def _parse_severity(self, vuln: dict) -> tuple[str, float | None, str | None]:
        """Extract severity, CVSS score, and vector from an OSV record."""
        # OSV may embed CVSS in severity array or database_specific
        for sev in vuln.get("severity", []):
            if sev.get("type") == "CVSS_V3":
                vector = sev.get("score", "")
                # Parse base score from vector string
                score = None
                for part in vector.split("/"):
                    if part.startswith("CVSS:"):
                        continue
                # Try database_specific for score
                db = vuln.get("database_specific", {})
                score = db.get("cvss_score") or db.get("base_score")
                severity_str = db.get("severity", "NONE").upper()
                return SEVERITY_MAP.get(severity_str, "NONE"), score, vector

        # Fallback: check database_specific
        db = vuln.get("database_specific", {})
        severity_str = db.get("severity", "NONE").upper()
        score        = db.get("cvss_score") or db.get("base_score")
        return SEVERITY_MAP.get(severity_str, "NONE"), score, None

    def _parse_record(self, vuln: dict, epss_map: dict) -> dict | None:
        try:
            osv_id   = vuln.get("id", "")
            # Extract the canonical CVE ID if present
            cve_id   = None
            for alias in vuln.get("aliases", []):
                if alias.upper().startswith("CVE-"):
                    cve_id = alias.upper()
                    break
            cve_id = cve_id or osv_id

            severity, cvss_score, cvss_vector = self._parse_severity(vuln)
            epss = epss_map.get(cve_id)

            pub_raw = vuln.get("published", "")
            mod_raw = vuln.get("modified",  "")

            def _parse_dt(s):
                if not s:
                    return None
                return s[:19].replace("T", " ")

            db_specific = vuln.get("database_specific", {})
            cwe_list = db_specific.get("cwe_ids", [])
            cwe_id   = ",".join(cwe_list) if cwe_list else None

            return {
                "source":         "osv",
                "cve_id":         cve_id,
                "advisory_id":    osv_id,
                "service_name":   self.service_name,
                "ecosystem":      self.ecosystem,
                "severity":       severity,
                "cvss_v3_score":  float(cvss_score) if cvss_score else None,
                "cvss_v3_vector": cvss_vector,
                "epss_score":     epss,
                "is_kev":         0,
                "cwe_id":         cwe_id,
                "published_at":   _parse_dt(pub_raw),
                "modified_at":    _parse_dt(mod_raw),
                "raw_json":       vuln,
            }
        except Exception as exc:
            self.errors.append(f"Failed to parse OSV {vuln.get('id')}: {exc}")
            log.warning("OSV parse error: %s", exc)
            return None

    def collect(self) -> list[dict]:
        # Gather vuln details across all (ecosystem, package) targets, deduplicating by OSV ID
        seen_osv_ids: set[str] = set()
        vulns: list[dict] = []

        for ecosystem, package in self.query_targets:
            try:
                osv_ids = self._fetch_osv_ids(ecosystem, package)
            except Exception as exc:
                log.warning("OSV: id-fetch failed for %s/%s — %s", ecosystem, package, exc)
                self.errors.append(f"OSV {ecosystem}/{package} id-fetch: {exc}")
                continue

            for osv_id in osv_ids:
                if osv_id in seen_osv_ids:
                    continue
                seen_osv_ids.add(osv_id)
                try:
                    vulns.append(self._fetch_vuln_detail(osv_id))
                    time.sleep(0.1)
                except Exception as exc:
                    self.errors.append(f"Failed to fetch {osv_id}: {exc}")
                    log.warning("OSV detail fetch error: %s", exc)

        # Collect all CVE IDs for EPSS lookup
        cve_ids = []
        for v in vulns:
            for alias in v.get("aliases", []):
                if alias.upper().startswith("CVE-"):
                    cve_ids.append(alias.upper())

        epss_map = self._fetch_epss_batch(cve_ids)

        records = []
        for v in vulns:
            parsed = self._parse_record(v, epss_map)
            if parsed:
                records.append(parsed)

        # Filter to the last LOOKBACK_DAYS days.
        cutoff = (datetime.now(timezone.utc) - timedelta(days=LOOKBACK_DAYS)).date()
        before = len(records)
        records = [
            r for r in records
            if not r.get("published_at")
            or datetime.fromisoformat(r["published_at"].replace(" ", "T")).date() >= cutoff
        ]
        log.info("OSV: %d → %d records after %d-day filter for %s (across %d package targets)",
                 before, len(records), LOOKBACK_DAYS, self.service_name, len(self.query_targets))
        return records


def main():
    parser = argparse.ArgumentParser(description="Collect vulnerabilities from OSV.dev")
    # --service is the canonical service name (e.g. 'salesforce').
    # Package targets are resolved from service_aliases automatically.
    # Override with --packages for a comma-separated explicit list.
    # --ecosystem scopes the lookup to a single registry when set.
    parser.add_argument("--service",    required=True, help="Service/vendor name")
    parser.add_argument("--ecosystem",  default=None,
                        help="Restrict to one ecosystem (PyPI/npm/Maven/…). "
                             "Omit to query all ecosystems in service_aliases.")
    parser.add_argument("--packages",   default=None,
                        help="Comma-separated package names (overrides service_aliases)")
    parser.add_argument("--start-date", default=None)
    parser.add_argument("--end-date",   default=None)
    args = parser.parse_args()

    packages = [p.strip() for p in args.packages.split(",")] if args.packages else None

    with OSVCollector(args.service, args.ecosystem, packages,
                      args.start_date, args.end_date) as col:
        records = col.run()
        if records:
            upsert_records("vulnerabilities", records,
                           conflict_keys=["source", "advisory_id"])
        log.info("OSV collection complete: %d records", len(records))


if __name__ == "__main__":
    main()
