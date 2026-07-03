"""
collect_general.py
------------------
Collects the latest 6 months of CVE records from NVD, KEV, and GHSA
without targeting any specific vendor or package.  Intended for
broad / general risk assessments.

service_name is derived from the CVE data itself rather than a fixed label:
  NVD   – vendor extracted from the first vulnerable CPE string
           (e.g. cpe:2.3:a:microsoft:... → "microsoft")
  KEV   – vendorProject field from the CISA catalog entry
           (e.g. "Microsoft", "Apache HTTP Server" → lowercased)
  GHSA  – package name from the advisory
           (e.g. "django", "lodash", "@angular/core")

Sources:
  NVD   – all CVEs published in the last 180 days (no keyword filter)
  KEV   – full CISA Known Exploited Vulnerabilities catalog (last 180 days)
  GHSA  – all GitHub Security Advisories by ecosystem (last 180 days)
  OSV   – skipped; OSV requires a specific package to query

All records are written to the vulnerabilities table via db_writer
with the same schema used by vendor-targeted collectors.

Usage:
    python -m collectors.collect_general
    python -m collectors.collect_general --sources nvd,kev
    python -m collectors.collect_general --start-date 2024-11-01
"""

import os
import logging
import argparse
import time
from datetime import datetime, timedelta, timezone

from collectors.base_collector import BaseCollector
from collectors.db_writer import upsert_records, get_engine

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s — %(message)s")
log = logging.getLogger("collect_general")

LOOKBACK_DAYS = 180
FALLBACK_NAME = "unknown"

SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH":     "HIGH",
    "MEDIUM":   "MEDIUM",
    "LOW":      "LOW",
    "NONE":     "NONE",
}


def _vendor_from_cpe(cve: dict) -> str:
    """
    Walk configurations → nodes → cpeMatch and return the vendor component
    of the first vulnerable CPE string.  CPE 2.3 format:
        cpe:2.3:<type>:<vendor>:<product>:...
    Returns FALLBACK_NAME if no usable CPE is found.
    """
    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable", False):
                    continue
                parts = match.get("criteria", "").split(":")
                # parts[3] is the vendor field in CPE 2.3
                if len(parts) > 3 and parts[3] not in ("*", "-", ""):
                    return parts[3]
    return FALLBACK_NAME


# ─── NVD ─────────────────────────────────────────────────────────────────────

NVD_BASE      = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_PAGE_SIZE = 2000
NVD_MAX_DAYS  = 119   # NVD rejects windows > 120 days; stay safely under


def _make_windows(start: str, end: str, max_days: int = NVD_MAX_DAYS) -> list[tuple[str, str]]:
    def _parse(s: str) -> datetime:
        for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S.000",
                    "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
            try:
                return datetime.strptime(s, fmt)
            except ValueError:
                continue
        raise ValueError(f"Cannot parse NVD date: {s!r}")

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


class NVDGeneralCollector(BaseCollector):
    SOURCE = "nvd"

    def __init__(self, start_date: str | None = None, end_date: str | None = None):
        super().__init__("general", start_date, end_date)
        api_key = os.environ.get("NVD_API_KEY", "")
        if api_key:
            self._client.headers.update({"apiKey": api_key})

        now = datetime.now(timezone.utc)
        if not self.end_date:
            self.end_date = now.strftime("%Y-%m-%dT23:59:59.999")
        if not self.start_date:
            self.start_date = (now - timedelta(days=LOOKBACK_DAYS)).strftime("%Y-%m-%dT00:00:00.000")

    def _fetch_page(self, start_index: int, win_start: str, win_end: str) -> dict:
        params = {
            "pubStartDate":   win_start,
            "pubEndDate":     win_end,
            "resultsPerPage": NVD_PAGE_SIZE,
            "startIndex":     start_index,
        }
        return self.get(NVD_BASE, params=params).json()

    def _parse_cve(self, item: dict) -> dict | None:
        try:
            cve    = item.get("cve", {})
            cve_id = cve.get("id", "").upper().strip()
            if not cve_id:
                return None

            metrics     = cve.get("metrics", {})
            cvss_v3     = (metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or [])
            cvss_score, cvss_vector, severity = None, None, "NONE"
            if cvss_v3:
                primary     = next((m for m in cvss_v3 if m.get("type") == "Primary"), cvss_v3[0])
                cvss_data   = primary.get("cvssData", {})
                cvss_score  = cvss_data.get("baseScore")
                cvss_vector = cvss_data.get("vectorString")
                severity    = SEVERITY_MAP.get(cvss_data.get("baseSeverity", "NONE").upper(), "NONE")

            weaknesses   = cve.get("weaknesses", [])
            primary_cwes = [w for w in weaknesses if w.get("type") == "Primary"]
            cwe_source   = primary_cwes if primary_cwes else weaknesses
            cwe_ids: list[str] = []
            for w in cwe_source:
                for desc in w.get("description", []):
                    val = desc.get("value", "")
                    if val.startswith("CWE-") and val not in cwe_ids:
                        cwe_ids.append(val)

            return {
                "source":         "nvd",
                "cve_id":         cve_id,
                "advisory_id":    cve_id,
                "service_name":   _vendor_from_cpe(cve),
                "ecosystem":      "SaaS",
                "severity":       severity,
                "cvss_v3_score":  float(cvss_score) if cvss_score else None,
                "cvss_v3_vector": cvss_vector,
                "epss_score":     None,
                "is_kev":         0,
                "cwe_id":         ",".join(cwe_ids) or None,
                "published_at":   cve.get("published", "")[:19].replace("T", " ") or None,
                "modified_at":    cve.get("lastModified", "")[:19].replace("T", " ") or None,
                "raw_json":       item,
            }
        except Exception as exc:
            log.warning("NVD parse error: %s", exc)
            return None

    def collect(self) -> list[dict]:
        windows = _make_windows(self.start_date, self.end_date)
        log.info("NVD general: %d window(s) (%s → %s)",
                 len(windows), self.start_date[:10], self.end_date[:10])

        seen: set[str] = set()
        records: list[dict] = []

        for win_start, win_end in windows:
            log.info("NVD window: %s → %s", win_start[:10], win_end[:10])
            start_index = 0
            while True:
                data  = self._fetch_page(start_index, win_start, win_end)
                items = data.get("vulnerabilities", [])
                total = data.get("totalResults", 0)
                for item in items:
                    parsed = self._parse_cve(item)
                    if parsed and parsed["cve_id"] not in seen:
                        seen.add(parsed["cve_id"])
                        records.append(parsed)
                start_index += len(items)
                if start_index >= total or not items:
                    break
                time.sleep(0.6)  # stay under NVD rate limit (~5 req/30s without key)

        log.info("NVD general: %d unique CVEs collected", len(records))
        return records


# ─── KEV ─────────────────────────────────────────────────────────────────────

KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")


class KEVGeneralCollector(BaseCollector):
    SOURCE = "kev"

    def __init__(self, start_date: str | None = None):
        super().__init__("general")
        now = datetime.now(timezone.utc)
        self.cutoff = (now - timedelta(days=LOOKBACK_DAYS)).strftime("%Y-%m-%d")
        if start_date:
            self.cutoff = start_date[:10]

    def collect(self) -> list[dict]:
        log.info("KEV general: fetching full CISA catalog")
        resp    = self.get(KEV_URL)
        entries = resp.json().get("vulnerabilities", [])
        kev_ids = {e["cveID"].upper() for e in entries if e.get("cveID")}
        log.info("KEV catalog: %d total entries", len(entries))

        records = []
        for entry in entries:
            cve_id     = entry.get("cveID", "").upper()
            date_added = entry.get("dateAdded", "")
            if not cve_id or (date_added and date_added < self.cutoff):
                continue
            vendor = entry.get("vendorProject", "").lower().strip() or FALLBACK_NAME
            records.append({
                "source":         "kev",
                "cve_id":         cve_id,
                "advisory_id":    cve_id,
                "service_name":   vendor,
                "ecosystem":      "SaaS",
                "severity":       "CRITICAL",
                "cvss_v3_score":  None,
                "cvss_v3_vector": None,
                "epss_score":     None,
                "is_kev":         1,
                "cwe_id":         None,
                "published_at":   date_added or None,
                "modified_at":    date_added or None,
                "raw_json":       entry,
            })

        log.info("KEV general: %d entries since %s", len(records), self.cutoff)
        self._backfill_kev_flag(kev_ids)
        return records

    def _backfill_kev_flag(self, kev_ids: set[str]):
        """Set is_kev=1 on all matching rows regardless of which source collected them."""
        if not kev_ids:
            return
        from sqlalchemy import text
        engine   = get_engine()
        kev_list = list(kev_ids)
        BATCH    = 500
        total    = 0
        with engine.begin() as conn:
            for i in range(0, len(kev_list), BATCH):
                batch        = kev_list[i:i + BATCH]
                placeholders = ",".join([f"'{cid}'" for cid in batch])
                result       = conn.execute(text(
                    f"UPDATE vulnerabilities SET is_kev = 1 "
                    f"WHERE cve_id IN ({placeholders})"
                ))
                total += result.rowcount
        log.info("KEV backfill: updated is_kev=1 on %d existing rows", total)


# ─── GHSA ─────────────────────────────────────────────────────────────────────

GRAPHQL_URL = "https://api.github.com/graphql"

GHSA_SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH":     "HIGH",
    "MODERATE": "MEDIUM",
    "LOW":      "LOW",
    "UNKNOWN":  "NONE",
}

# All ecosystems swept without a package filter for a broad general pull
GHSA_ECOSYSTEMS = ["NPM", "PIP", "MAVEN", "GO", "NUGET", "RUST", "RUBYGEMS", "COMPOSER"]

# Omitting $package returns all advisories for the ecosystem
GHSA_QUERY = """
query($ecosystem: SecurityAdvisoryEcosystem, $after: String) {
  securityVulnerabilities(
    ecosystem: $ecosystem
    first: 100
    after: $after
  ) {
    pageInfo { hasNextPage endCursor }
    nodes {
      advisory {
        ghsaId
        severity
        publishedAt
        updatedAt
        cvss { score vectorString }
        cwes { cweId }
        identifiers { type value }
        withdrawnAt
      }
      package { ecosystem name }
    }
  }
}
"""


class GHSAGeneralCollector(BaseCollector):
    SOURCE = "ghsa"

    def __init__(self, start_date: str | None = None):
        super().__init__("general")
        token = os.environ.get("GITHUB_TOKEN", "")
        if not token:
            raise EnvironmentError("GITHUB_TOKEN is required for GHSA collection")
        self._client.headers.update({
            "Authorization": f"Bearer {token}",
            "Content-Type":  "application/json",
        })
        now = datetime.now(timezone.utc)
        self.cutoff = (
            datetime.fromisoformat(start_date).replace(tzinfo=timezone.utc)
            if start_date
            else now - timedelta(days=LOOKBACK_DAYS)
        )

    def _run_query(self, ecosystem: str, cursor: str | None = None) -> dict:
        variables = {"ecosystem": ecosystem, "after": cursor}
        resp = self.post(GRAPHQL_URL, json={"query": GHSA_QUERY, "variables": variables})
        data = resp.json()
        if "errors" in data:
            raise RuntimeError(f"GraphQL errors: {data['errors']}")
        return data["data"]["securityVulnerabilities"]

    def _parse_node(self, node: dict) -> dict | None:
        try:
            adv = node.get("advisory", {})
            if adv.get("withdrawnAt"):
                return None
            ghsa   = adv.get("ghsaId", "")
            cve_id = next(
                (i["value"].upper() for i in adv.get("identifiers", []) if i["type"] == "CVE"),
                ghsa,
            )
            severity = GHSA_SEVERITY_MAP.get(adv.get("severity", "UNKNOWN"), "NONE")
            cvss     = adv.get("cvss") or {}
            pkg      = node.get("package", {})
            eco      = pkg.get("ecosystem", "Unknown")
            cwe_ids  = [c["cweId"] for c in adv.get("cwes", []) if c.get("cweId")]

            def dt(s: str | None) -> str | None:
                return s[:19].replace("T", " ") if s else None

            pkg_name = pkg.get("name", "").strip() or FALLBACK_NAME
            return {
                "source":         "ghsa",
                "cve_id":         cve_id,
                "advisory_id":    ghsa,
                "service_name":   pkg_name,
                "ecosystem":      eco,
                "severity":       severity,
                "cvss_v3_score":  float(cvss["score"]) if cvss.get("score") else None,
                "cvss_v3_vector": cvss.get("vectorString"),
                "epss_score":     None,
                "is_kev":         0,
                "cwe_id":         ",".join(cwe_ids) or None,
                "published_at":   dt(adv.get("publishedAt")),
                "modified_at":    dt(adv.get("updatedAt")),
                "raw_json":       node,
            }
        except Exception as exc:
            log.warning("GHSA parse error: %s", exc)
            return None

    def _collect_ecosystem(self, ecosystem: str, seen: set[str]) -> list[dict]:
        records: list[dict] = []
        cursor              = None
        stop                = False

        while not stop:
            try:
                page = self._run_query(ecosystem, cursor)
            except Exception as exc:
                log.warning("GHSA ecosystem=%s query failed — %s", ecosystem, exc)
                self.errors.append(f"GHSA {ecosystem}: {exc}")
                break

            nodes     = page.get("nodes", [])
            page_info = page.get("pageInfo", {})

            for node in nodes:
                pub_str = (node.get("advisory") or {}).get("publishedAt", "")
                if pub_str:
                    try:
                        pub_dt = datetime.fromisoformat(
                            pub_str.rstrip("Z")).replace(tzinfo=timezone.utc)
                        if pub_dt < self.cutoff:
                            stop = True
                            break
                    except ValueError:
                        pass

                parsed = self._parse_node(node)
                if parsed and parsed["advisory_id"] not in seen:
                    seen.add(parsed["advisory_id"])
                    records.append(parsed)

            if not page_info.get("hasNextPage") or stop:
                break
            cursor = page_info.get("endCursor")
            time.sleep(0.3)

        log.info("GHSA general: %d records for ecosystem=%s", len(records), ecosystem)
        return records

    def collect(self) -> list[dict]:
        seen: set[str]      = set()
        all_records: list[dict] = []

        for ecosystem in GHSA_ECOSYSTEMS:
            recs = self._collect_ecosystem(ecosystem, seen)
            all_records.extend(recs)

        log.info("GHSA general: %d unique advisories across all ecosystems", len(all_records))
        return all_records


# ─── Entrypoint ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Collect last 6 months of CVEs from NVD/KEV/GHSA for general risk assessment"
    )
    parser.add_argument(
        "--sources", default="nvd,kev,ghsa",
        help="Comma-separated sources to run (nvd, kev, ghsa). Default: all three.",
    )
    parser.add_argument(
        "--start-date", default=None,
        help="Override start date (YYYY-MM-DD). Default: 180 days ago.",
    )
    parser.add_argument(
        "--end-date", default=None,
        help="Override end date for NVD (YYYY-MM-DD). Default: today.",
    )
    args = parser.parse_args()

    sources = [s.strip().lower() for s in args.sources.split(",") if s.strip()]
    total   = 0

    if "nvd" in sources:
        log.info("=== NVD (general) ===")
        with NVDGeneralCollector(args.start_date, args.end_date) as col:
            records = col.run()
            if records:
                upsert_records("vulnerabilities", records,
                               conflict_keys=["source", "cve_id"])
                total += len(records)
        log.info("NVD general: %d records written", len(records))

    if "kev" in sources:
        log.info("=== KEV (general) ===")
        with KEVGeneralCollector(args.start_date) as col:
            records = col.run()
            if records:
                upsert_records("vulnerabilities", records,
                               conflict_keys=["source", "cve_id"])
                total += len(records)
        log.info("KEV general: %d records written", len(records))

    if "ghsa" in sources:
        log.info("=== GHSA (general) ===")
        with GHSAGeneralCollector(args.start_date) as col:
            records = col.run()
            if records:
                upsert_records("vulnerabilities", records,
                               conflict_keys=["source", "advisory_id"])
                total += len(records)
        log.info("GHSA general: %d records written", len(records))

    log.info("General collection complete: %d total records written (sources: %s)",
             total, ", ".join(sources))


if __name__ == "__main__":
    main()
