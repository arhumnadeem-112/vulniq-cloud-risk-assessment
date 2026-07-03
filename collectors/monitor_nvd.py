"""
monitor_nvd.py
--------------
Tracks MODIFICATIONS to CVEs. Use this for daily synchronization.
"""

import os
import logging
import argparse
from datetime import datetime, timedelta, timezone

from collectors.collect_nvd import NVDCollector # Inherit parsing logic
from collectors.db_writer import upsert_records

log = logging.getLogger("monitor_nvd")

class NVDMonitor(NVDCollector):
    def _fetch_page(self, start_index: int, keyword: str,
                    start: str | None = None, end: str | None = None) -> dict:
        # Use lastMod parameters instead of pubStartDate so we catch updated CVEs
        params = {
            "keywordSearch":    keyword,
            "lastModStartDate": start or self.start_date,
            "lastModEndDate":   end   or self.end_date,
            "resultsPerPage":   2000,
            "startIndex":       start_index,
        }
        resp = self.get("https://services.nvd.nist.gov/rest/json/cves/2.0", params=params)
        return resp.json()

def main():
    parser = argparse.ArgumentParser(description="Monitor NVD for updates")
    parser.add_argument("--service",  required=True, help="Canonical service name")
    parser.add_argument("--keywords", default=None,
                        help="Comma-separated NVD keywords (overrides service_aliases)")
    args = parser.parse_args()

    # Monitors typically look at the last 24-48 hours
    now = datetime.now(timezone.utc)
    start = (now - timedelta(days=2)).strftime("%Y-%m-%dT00:00:00.000")
    end = now.strftime("%Y-%m-%dT23:59:59.999")

    keywords = [k.strip() for k in args.keywords.split(",")] if args.keywords else None
    log.info("Monitoring updates for: %s", args.service)
    with NVDMonitor(args.service, start, end, keywords) as col:
        records = col.run()
        if records:
            upsert_records("vulnerabilities", records, conflict_keys=["source", "cve_id"])

if __name__ == "__main__":
    main()