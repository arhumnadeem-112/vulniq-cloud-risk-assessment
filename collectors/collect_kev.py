"""
collect_kev.py
--------------
Collects the CISA Known Exploited Vulnerabilities (KEV) catalog and
updates the is_kev flag on matching rows in MySQL vulnerabilities table.

API: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
No API key required.

Usage:
    python collect_kev.py --service stripe
    python collect_kev.py --service all   # marks KEV flag for all known CVEs
"""

import logging
import argparse
from datetime import datetime, timedelta

from collectors.base_collector import BaseCollector
from collectors.db_writer import upsert_records, execute_sql
from collectors.service_aliases import get_kev_vendors

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s — %(message)s")
log = logging.getLogger("collect_kev")

KEV_URL       = ("https://www.cisa.gov/sites/default/files/feeds/"
                 "known_exploited_vulnerabilities.json")
LOOKBACK_DAYS = 180   # only insert KEV entries added within this window


class KEVCollector(BaseCollector):
    SOURCE = "kev"

    def collect(self) -> list[dict]:
        log.info("Fetching CISA KEV catalog")
        resp = self.get(KEV_URL)
        data = resp.json()

        entries   = data.get("vulnerabilities", [])
        kev_ids   = {e["cveID"].upper() for e in entries if e.get("cveID")}
        log.info("KEV catalog: %d known-exploited CVEs", len(kev_ids))

        # Resolve vendor aliases once — covers subsidiaries / acquired brands
        vendor_aliases = get_kev_vendors(self.service_name)
        log.info("KEV vendor aliases for %s: %s", self.service_name, vendor_aliases)

        # Build KEV records for all entries (stored for audit and cross-reference)
        records = []
        for entry in entries:
            cve_id = entry.get("cveID", "").upper()
            if not cve_id:
                continue

            # Filter to service if not "all"
            vendor  = entry.get("vendorProject", "").lower()
            product = entry.get("product", "").lower()
            if self.service_name.lower() != "all":
                if not any(alias in vendor or alias in product
                           for alias in vendor_aliases):
                    continue

            pub = entry.get("dateAdded", "")
            records.append({
                "source":         "kev",
                "cve_id":         cve_id,
                "advisory_id":    cve_id,
                "service_name":   self.service_name,
                "ecosystem":      "SaaS",
                "severity":       "CRITICAL",   # KEV entries are by definition high-risk
                "cvss_v3_score":  None,          # not provided in KEV catalog
                "cvss_v3_vector": None,
                "epss_score":     None,
                "is_kev":         1,
                "published_at":   pub if pub else None,
                "modified_at":    pub if pub else None,
                "raw_json":       entry,
            })

        # Filter inserted records to the last LOOKBACK_DAYS days.
        # We still backfill is_kev=1 across ALL catalog entries (full kev_ids set)
        # so previously-collected CVEs get flagged regardless of when KEV added them.
        cutoff  = (datetime.utcnow() - timedelta(days=LOOKBACK_DAYS)).strftime("%Y-%m-%d")
        before  = len(records)
        records = [r for r in records if (r.get("published_at") or "") >= cutoff]
        log.info("KEV: %d → %d records after %d-day filter for service=%s",
                 before, len(records), LOOKBACK_DAYS, self.service_name)

        # Update is_kev=1 on any existing vulnerabilities rows with these CVE IDs
        self._backfill_kev_flag(kev_ids)

        return records

    def _backfill_kev_flag(self, kev_ids: set[str]):
        """
        For every CVE ID in the KEV catalog, set is_kev=1 in the
        vulnerabilities table regardless of which source collected it.
        """
        if not kev_ids:
            return
        # Chunk into batches of 500 to stay under MySQL IN() limit
        kev_list = list(kev_ids)
        BATCH    = 500
        total    = 0
        from sqlalchemy import text
        from collectors.db_writer import get_engine
        engine = get_engine()
        with engine.begin() as conn:
            for start in range(0, len(kev_list), BATCH):
                batch = kev_list[start:start+BATCH]
                placeholders = ",".join([f"'{cid}'" for cid in batch])
                result = conn.execute(text(
                    f"UPDATE vulnerabilities SET is_kev = 1 "
                    f"WHERE cve_id IN ({placeholders})"
                ))
                total += result.rowcount
        log.info("KEV backfill: updated is_kev=1 on %d existing rows", total)


def main():
    parser = argparse.ArgumentParser(description="Collect CISA KEV catalog")
    # TARGET: --service filters the CISA KEV catalog by matching the vendorProject field.
    # For Salesforce: use 'salesforce'. Use 'all' to import the entire catalog without filtering.
    parser.add_argument("--service", required=True,
                        help="Service/vendor name to filter, or 'all' for full catalog")
    args = parser.parse_args()

    with KEVCollector(args.service) as col:
        records = col.run()
        if records:
            upsert_records("vulnerabilities", records,
                           conflict_keys=["source", "cve_id"])
        log.info("KEV collection complete: %d records", len(records))


if __name__ == "__main__":
    main()
