"""
collect_status.py
-----------------
Collects service incident history from public status pages.

MySQL    → service_incidents table
ChromaDB → incident_postmortems collection (RCA / postmortem text)

Supports:
  - Statuspage.io format (most SaaS vendors: Stripe, Slack, GitHub, etc.)
  - AWS Health API (public feed)
  - Azure Service Health (public RSS)
  - GCP Status (public JSON)
  - Generic RSS / Atom feeds

Usage:
    python collect_status.py --service stripe --status-url https://status.stripe.com
    python collect_status.py --service aws    --provider aws
    python collect_status.py --service azure  --provider azure
"""

import logging
import argparse
import time
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from bs4 import BeautifulSoup

from collectors.base_collector import BaseCollector
from collectors.db_writer import upsert_records
from collectors.chroma_writer import upsert_documents

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s — %(message)s")
log = logging.getLogger("collect_status")

# Public cloud provider status endpoints
PROVIDER_URLS = {
    "aws":        "https://health.aws.amazon.com/public/currentevents",
    "azure":      "https://azurestatuscdn.azureedge.net/en-us/status/feed/",
    "gcp":        "https://status.cloud.google.com/incidents.json",
    # Salesforce public incident API — returns JSON arrays of incident objects
    "salesforce": "https://api.status.salesforce.com/v1/incidents/active",
    "salesforce_history": "https://api.status.salesforce.com/v1/incidents",
}

SEVERITY_MAP = {
    "major_outage":           "major",
    "partial_outage":         "major",
    "degraded_performance":   "minor",
    "under_maintenance":      "maintenance",
    "operational":            "minor",
}


class StatusCollector(BaseCollector):
    SOURCE = "status"

    def __init__(self, service_name: str, status_url: str | None = None,
                 provider: str | None = None,
                 start_date: str | None = None, end_date: str | None = None):
        super().__init__(service_name, start_date, end_date)
        self.status_url = status_url
        self.provider   = (provider or "").lower()

        # Default lookback: 180 days
        if not self.start_date:
            self.start_date = (datetime.utcnow() - timedelta(days=180)
                               ).strftime("%Y-%m-%d")

    # ── Statuspage.io ─────────────────────────────────────────────────────────

    def _collect_statuspage(self) -> tuple[list[dict], list[str], list[dict], list[str]]:
        """
        Fetch incidents from a Statuspage.io-compatible endpoint.
        Returns (mysql_records, chroma_docs, chroma_metas, chroma_ids).
        """
        base = self.status_url.rstrip("/")
        # Try the Statuspage API v2 endpoint first
        api_url = f"{base}/api/v2/incidents.json"
        try:
            resp = self.get(api_url)
            data = resp.json()
        except Exception:
            log.warning("Statuspage API failed for %s — trying page scrape", base)
            return self._collect_statuspage_scrape()

        incidents      = data.get("incidents", [])
        mysql_records  = []
        chroma_docs    = []
        chroma_metas   = []
        chroma_ids     = []

        for inc in incidents:
            inc_id   = inc.get("id", "")
            name     = inc.get("name", "")
            status   = inc.get("status", "")
            impact   = inc.get("impact", "none")
            severity = SEVERITY_MAP.get(
                ("major_outage" if impact in ("critical", "major") else
                 "degraded_performance" if impact == "minor" else
                 "under_maintenance"), "minor")

            started  = inc.get("created_at", "")
            resolved = inc.get("resolved_at", "")

            # Skip incidents outside the lookback window.
            # Statuspage.io returns the full history; we filter client-side.
            if started and started[:10] < self.start_date:
                continue

            def dt(s):
                if not s:
                    return None
                return s[:19].replace("T", " ")

            duration = None
            if started and resolved:
                try:
                    s = datetime.fromisoformat(started.rstrip("Z"))
                    r = datetime.fromisoformat(resolved.rstrip("Z"))
                    duration = int((r - s).total_seconds() / 60)
                except Exception:
                    pass

            components = ", ".join(
                c.get("name", "") for c in inc.get("components", []))

            mysql_records.append({
                "service_name":       self.service_name,
                "incident_id":        inc_id,
                "severity":           severity,
                "status":             status if status else "resolved",
                "started_at":         dt(started),
                "resolved_at":        dt(resolved),
                "duration_minutes":   duration,
                "affected_components":components[:1024],
                "raw_json":           inc,
                "collected_at":       datetime.utcnow().isoformat(),
            })

            # Build postmortem text for ChromaDB
            updates = inc.get("incident_updates", [])
            update_text = "\n\n".join(
                f"[{u.get('status','')}] {u.get('body','')}"
                for u in updates)
            full_text = f"Incident: {name}\n\n{update_text}".strip()
            if len(full_text) > 100:
                chroma_docs.append(full_text)
                chroma_metas.append({
                    "service_name": self.service_name,
                    "incident_id":  inc_id,
                    "source":       "statuspage",
                    "date":         (started or "")[:10],
                })
                chroma_ids.append(f"statuspage::{self.service_name}::{inc_id}")

        return mysql_records, chroma_docs, chroma_metas, chroma_ids

    def _collect_statuspage_scrape(self) -> tuple[list, list, list, list]:
        """Fallback HTML scrape for non-standard status pages."""
        log.info("Falling back to HTML scrape for %s", self.status_url)
        try:
            resp = self.get(self.status_url)
            soup = BeautifulSoup(resp.text, "lxml")
            incidents = soup.find_all("div", class_=re.compile(r"incident"))
            records   = []
            for inc in incidents[:50]:
                title = inc.find(class_=re.compile(r"title|name"))
                body  = inc.find(class_=re.compile(r"body|update|details"))
                if not title:
                    continue
                text = f"{title.get_text(strip=True)}\n{body.get_text(strip=True) if body else ''}"
                records.append(text)
            if records:
                docs   = records
                metas  = [{"service_name": self.service_name, "source": "scrape", "date": "", "incident_id": str(i)} for i in range(len(records))]
                ids    = [f"scrape::{self.service_name}::{i}" for i in range(len(records))]
                return [], docs, metas, ids
        except Exception as exc:
            self.errors.append(f"Status page scrape failed: {exc}")
        return [], [], [], []

    # ── AWS ───────────────────────────────────────────────────────────────────

    def _collect_aws(self) -> tuple[list[dict], list[str], list[dict], list[str]]:
        try:
            resp = self.get(PROVIDER_URLS["aws"])
            data = resp.json()
        except Exception as exc:
            self.errors.append(f"AWS health fetch failed: {exc}")
            return [], [], [], []

        records = []
        docs, metas, ids = [], [], []
        for event in data.get("events", []):
            records.append({
                "service_name":        self.service_name,
                "incident_id":         event.get("eventArn", "").split("/")[-1],
                "severity":            "major" if event.get("eventTypeCategory") == "issue" else "minor",
                "status":              event.get("statusCode", "resolved"),
                "started_at":          event.get("startTime", ""),
                "resolved_at":         event.get("endTime", ""),
                "duration_minutes":    None,
                "affected_components": event.get("service", ""),
                "raw_json":            event,
                "collected_at":        datetime.utcnow().isoformat(),
            })
            desc = event.get("eventDescription", {}).get("latestDescription", "")
            if desc:
                docs.append(desc)
                metas.append({"service_name": "aws", "source": "aws_health",
                               "incident_id": records[-1]["incident_id"], "date": ""})
                ids.append(f"aws_health::{records[-1]['incident_id']}")
        return records, docs, metas, ids

    # ── Azure ─────────────────────────────────────────────────────────────────

    def _collect_azure(self) -> tuple[list[dict], list[str], list[dict], list[str]]:
        try:
            resp = self.get(PROVIDER_URLS["azure"])
            root = ET.fromstring(resp.text)
        except Exception as exc:
            self.errors.append(f"Azure status RSS failed: {exc}")
            return [], [], [], []

        ns      = {"atom": "http://www.w3.org/2005/Atom"}
        entries = root.findall(".//atom:entry", ns) or root.findall(".//entry")
        records = []
        docs, metas, ids = [], [], []
        for entry in entries:
            title   = (entry.findtext("atom:title", namespaces=ns) or
                       entry.findtext("title") or "")
            summary = (entry.findtext("atom:summary", namespaces=ns) or
                       entry.findtext("summary") or "")
            pub     = (entry.findtext("atom:published", namespaces=ns) or
                       entry.findtext("published") or "")
            entry_id = (entry.findtext("atom:id", namespaces=ns) or
                        entry.findtext("id") or "")
            short_id = entry_id.split("/")[-1] or entry_id[:50]

            # Skip entries older than the lookback window
            if pub and pub[:10] < self.start_date:
                continue

            records.append({
                "service_name":        "azure",
                "incident_id":         short_id,
                "severity":            "major",
                "status":              "resolved",
                "started_at":          pub[:19].replace("T"," ") if pub else None,
                "resolved_at":         None,
                "duration_minutes":    None,
                "affected_components": title[:256],
                "raw_json":            {"title": title, "summary": summary},
                "collected_at":        datetime.utcnow().isoformat(),
            })
            text = f"{title}\n\n{summary}".strip()
            if len(text) > 30:
                docs.append(text)
                metas.append({"service_name": "azure", "source": "azure_rss",
                               "incident_id": short_id, "date": pub[:10] if pub else ""})
                ids.append(f"azure_rss::{short_id}")
        return records, docs, metas, ids

    # ── Salesforce ────────────────────────────────────────────────────────────

    def _collect_salesforce(self) -> tuple[list[dict], list[str], list[dict], list[str]]:
        """
        Fetch incidents from the Salesforce public status API.

        Salesforce exposes two endpoints:
          /v1/incidents/active  — currently open incidents
          /v1/incidents         — historical incidents (paginated)

        Response shape per incident:
          { "id", "message", "messageType", "createdAt", "updatedAt",
            "instanceKeys", "serviceKeys", "isCore",
            "affectedInstances": [{"key","location","environment","releaseVersion",
                                   "status","Incident":{...}}] }
        """
        records, docs, metas, ids = [], [], [], []

        # Try active incidents first, then fall back to history endpoint
        for url in (PROVIDER_URLS["salesforce"], PROVIDER_URLS["salesforce_history"]):
            try:
                resp = self.get(url)
                incidents = resp.json()
                # History endpoint may wrap results in {"data": [...]}
                if isinstance(incidents, dict):
                    incidents = incidents.get("data", incidents.get("incidents", []))
                if not isinstance(incidents, list):
                    continue
                break
            except Exception as exc:
                log.warning("Salesforce status fetch failed for %s — %s", url, exc)
                self.errors.append(f"Salesforce status {url}: {exc}")
                incidents = []

        for inc in incidents:
            inc_id   = str(inc.get("id", ""))
            message  = inc.get("message", "")
            msg_type = inc.get("messageType", "").lower()
            created  = inc.get("createdAt", "") or inc.get("created_at", "")
            updated  = inc.get("updatedAt",  "") or inc.get("updated_at", "")

            if not inc_id:
                continue
            if created and created[:10] < self.start_date:
                continue

            # Map Salesforce messageType to severity
            severity = (
                "major" if msg_type in ("major", "core", "incident")
                else "minor"
            )
            status = "resolved" if inc.get("resolvedAt") else "investigating"

            resolved = inc.get("resolvedAt", "") or inc.get("resolved_at", "")

            duration = None
            if created and resolved:
                try:
                    s = datetime.fromisoformat(created.rstrip("Z"))
                    r = datetime.fromisoformat(resolved.rstrip("Z"))
                    duration = int((r - s).total_seconds() / 60)
                except Exception:
                    pass

            affected = ", ".join(
                str(ai.get("key", ""))
                for ai in inc.get("affectedInstances", [])
                if ai.get("key")
            ) or ", ".join(inc.get("instanceKeys", []))

            def _dt(s):
                return s[:19].replace("T", " ") if s else None

            records.append({
                "service_name":        self.service_name,
                "incident_id":         inc_id,
                "severity":            severity,
                "status":              status,
                "started_at":          _dt(created),
                "resolved_at":         _dt(resolved),
                "duration_minutes":    duration,
                "affected_components": affected[:1024],
                "raw_json":            inc,
                "collected_at":        datetime.utcnow().isoformat(),
            })

            text = f"Salesforce Incident {inc_id}: {message}".strip()
            if len(text) > 30:
                docs.append(text)
                metas.append({
                    "service_name": self.service_name,
                    "incident_id":  inc_id,
                    "source":       "salesforce_status",
                    "date":         created[:10] if created else "",
                })
                ids.append(f"sf_status::{inc_id}")

        log.info("Salesforce status: %d incidents fetched", len(records))
        return records, docs, metas, ids

    # ── GCP ───────────────────────────────────────────────────────────────────

    def _collect_gcp(self) -> tuple[list[dict], list[str], list[dict], list[str]]:
        try:
            resp = self.get(PROVIDER_URLS["gcp"])
            incidents = resp.json()
        except Exception as exc:
            self.errors.append(f"GCP status fetch failed: {exc}")
            return [], [], [], []

        records = []
        docs, metas, ids = [], [], []
        for inc in incidents:
            inc_id = inc.get("id", "")
            # Skip GCP incidents outside the lookback window
            begin = (inc.get("begin") or "")[:10]
            if begin and begin < self.start_date:
                continue
            updates = inc.get("updates", [])
            records.append({
                "service_name":        "gcp",
                "incident_id":         inc_id,
                "severity":            "major" if inc.get("severity") == "high" else "minor",
                "status":              "resolved" if inc.get("end") else "investigating",
                "started_at":          (inc.get("begin") or "")[:19].replace("T"," "),
                "resolved_at":         (inc.get("end")   or "")[:19].replace("T"," ") or None,
                "duration_minutes":    None,
                "affected_components": ", ".join(inc.get("affected_products", [])),
                "raw_json":            inc,
                "collected_at":        datetime.utcnow().isoformat(),
            })
            desc = " ".join(u.get("text", "") for u in updates)
            if desc:
                docs.append(f"{inc.get('external_desc','')}\n\n{desc}".strip())
                metas.append({"service_name": "gcp", "source": "gcp_status",
                               "incident_id": inc_id, "date": (inc.get("begin",""))[:10]})
                ids.append(f"gcp_status::{inc_id}")
        return records, docs, metas, ids

    # ── Dispatch ──────────────────────────────────────────────────────────────

    def collect(self) -> list[dict]:
        if self.provider == "aws":
            mysql_recs, docs, metas, ids = self._collect_aws()
        elif self.provider == "azure":
            mysql_recs, docs, metas, ids = self._collect_azure()
        elif self.provider == "gcp":
            mysql_recs, docs, metas, ids = self._collect_gcp()
        elif self.provider == "salesforce":
            mysql_recs, docs, metas, ids = self._collect_salesforce()
        elif self.status_url:
            mysql_recs, docs, metas, ids = self._collect_statuspage()
        else:
            log.error("Provide --status-url or --provider (aws|azure|gcp|salesforce)")
            return []

        if docs:
            upsert_documents("incident_postmortems", docs, metas, ids)
            log.info("status: %d incident texts written to ChromaDB", len(docs))

        log.info("status: %d incident records for %s",
                 len(mysql_recs), self.service_name)
        return mysql_recs


def main():
    parser = argparse.ArgumentParser(
        description="Collect service incident history")
    # TARGET: --status-url is the root URL of a Statuspage.io-compatible status page.
    # For Salesforce: https://status.salesforce.com
    # To target a different vendor, replace the URL with their status page root.
    # Alternatively, use --provider aws|azure|gcp for built-in cloud provider support.
    parser.add_argument("--service",    required=True)
    parser.add_argument("--status-url", default=None,
                        help="Statuspage.io-compatible URL")
    parser.add_argument("--provider",   default=None,
                        choices=["aws", "azure", "gcp", "salesforce"],
                        help="Cloud/SaaS provider shorthand")
    parser.add_argument("--start-date", default=None)
    parser.add_argument("--end-date",   default=None)
    args = parser.parse_args()

    with StatusCollector(args.service, args.status_url, args.provider,
                         args.start_date, args.end_date) as col:
        records = col.run()
        if records:
            upsert_records("service_incidents", records,
                           conflict_keys=["service_name", "incident_id"])
        log.info("Status collection complete: %d records", len(records))


if __name__ == "__main__":
    main()
