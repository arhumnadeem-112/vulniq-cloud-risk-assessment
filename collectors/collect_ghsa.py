"""
collect_ghsa.py
---------------
Collects security advisories from the GitHub Advisory Database (GHSA)
via the GitHub GraphQL API.
- Structured records → MySQL vulnerabilities table
- Advisory narrative text → ChromaDB advisory_text collection

API docs: https://docs.github.com/en/graphql/reference/objects#securityadvisory
Requires: GITHUB_TOKEN env var

Usage:
    python collect_ghsa.py --service django --ecosystem PyPI
"""

import os
import logging
import argparse
import time
from datetime import datetime, timedelta, timezone

from collectors.base_collector import BaseCollector
from collectors.db_writer import upsert_records
from collectors.chroma_writer import upsert_documents
from collectors.service_aliases import get_packages, normalize_ecosystem

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s — %(message)s")
log = logging.getLogger("collect_ghsa")

GRAPHQL_URL   = "https://api.github.com/graphql"
LOOKBACK_DAYS = 180   # only keep advisories published within this window

SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH":     "HIGH",
    "MODERATE": "MEDIUM",
    "LOW":      "LOW",
    "UNKNOWN":  "NONE",
}

ECOSYSTEM_MAP = {
    "pypi":    "PyPI",
    "npm":     "npm",
    "maven":   "Maven",
    "go":      "Go",
    "rubygems":"RubyGems",
    "nuget":   "NuGet",
    "rust":    "Cargo",
    "composer":"Composer",
}

QUERY = """
query($ecosystem: SecurityAdvisoryEcosystem, $package: String, $after: String) {
  securityVulnerabilities(
    ecosystem: $ecosystem
    package: $package
    first: 100
    after: $after
  ) {
    pageInfo { hasNextPage endCursor }
    nodes {
      advisory {
        ghsaId
        summary
        description
        severity
        publishedAt
        updatedAt
        cvss { score vectorString }
        cwes { cweId }
        identifiers { type value }
        references { url }
        withdrawnAt
      }
      package { ecosystem name }
      firstPatchedVersion { identifier }
      vulnerableVersionRange
    }
  }
}
"""

# GraphQL ecosystem enum values
GH_ECOSYSTEM_ENUM = {
    "PyPI":     "PIP",
    "npm":      "NPM",
    "Maven":    "MAVEN",
    "Go":       "GO",
    "RubyGems": "RUBYGEMS",
    "NuGet":    "NUGET",
    "Cargo":    "RUST",
    "Composer": "COMPOSER",
}


class GHSACollector(BaseCollector):
    SOURCE = "ghsa"

    def __init__(self, service_name: str, ecosystem: str | None = None,
                 packages: list[str] | None = None,
                 start_date: str | None = None, end_date: str | None = None):
        super().__init__(service_name, start_date, end_date)
        token = os.environ.get("GITHUB_TOKEN", "")
        if not token:
            raise EnvironmentError("GITHUB_TOKEN is required for GHSA collection")
        self._client.headers.update({
            "Authorization": f"Bearer {token}",
            "Content-Type":  "application/json",
        })
        # ecosystem=None → query all ecosystems from service_aliases
        eco_str = ecosystem or "PyPI"
        raw_eco = ECOSYSTEM_MAP.get(eco_str.lower(), eco_str)
        self.ecosystem    = raw_eco
        self.gh_ecosystem = GH_ECOSYSTEM_ENUM.get(raw_eco, raw_eco.upper())

        # Build the list of (ecosystem, package) pairs to query.
        # Explicit --packages arg wins; otherwise look up service_aliases.
        if packages:
            self.query_targets = [(self.ecosystem, self.gh_ecosystem, p) for p in packages]
        else:
            pkg_map = get_packages(service_name, ecosystem)  # None = all ecosystems
            self.query_targets = []
            for eco_key, pkg_list in pkg_map.items():
                gh_eco = GH_ECOSYSTEM_ENUM.get(eco_key, eco_key.upper())
                for pkg in pkg_list:
                    self.query_targets.append((eco_key, gh_eco, pkg))
        log.info("GHSA targets for %s: %s", service_name,
                 [(t[0], t[2]) for t in self.query_targets])

    def _run_query(self, gh_ecosystem: str, package: str,
                   cursor: str | None = None) -> dict:
        variables = {
            "ecosystem": gh_ecosystem,
            "package":   package,
            "after":     cursor,
        }
        resp = self.post(GRAPHQL_URL, json={"query": QUERY, "variables": variables})
        data = resp.json()
        if "errors" in data:
            raise RuntimeError(f"GraphQL errors: {data['errors']}")
        return data["data"]["securityVulnerabilities"]

    def _parse_node(self, node: dict) -> dict | None:
        try:
            adv  = node.get("advisory", {})
            ghsa = adv.get("ghsaId", "")

            # Extract canonical CVE ID
            cve_id = None
            for ident in adv.get("identifiers", []):
                if ident["type"] == "CVE":
                    cve_id = ident["value"].upper()
                    break
            cve_id = cve_id or ghsa

            severity    = SEVERITY_MAP.get(adv.get("severity", "UNKNOWN"), "NONE")
            cvss        = adv.get("cvss") or {}
            cvss_score  = cvss.get("score")
            cvss_vector = cvss.get("vectorString")

            pub = adv.get("publishedAt", "")
            upd = adv.get("updatedAt",   "")

            def dt(s):
                return s[:19].replace("T", " ") if s else None

            cwe_ids = [c["cweId"] for c in adv.get("cwes", []) if c.get("cweId")]
            cwe_id  = ",".join(cwe_ids) or None

            return {
                "source":         "ghsa",
                "cve_id":         cve_id,
                "advisory_id":    ghsa,
                "service_name":   self.service_name,
                "ecosystem":      self.ecosystem,
                "severity":       severity,
                "cvss_v3_score":  float(cvss_score) if cvss_score else None,
                "cvss_v3_vector": cvss_vector,
                "epss_score":     None,
                "is_kev":         0,
                "cwe_id":         cwe_id,
                "published_at":   dt(pub),
                "modified_at":    dt(upd),
                "raw_json":       node,
            }, adv  # return advisory for ChromaDB text
        except Exception as exc:
            self.errors.append(f"Parse error {node}: {exc}")
            log.warning("GHSA parse error: %s", exc)
            return None, None

    def _collect_package(self, eco_key: str, gh_ecosystem: str, package: str,
                         cutoff: datetime) -> tuple[list[dict], list[str], list[dict], list[str]]:
        """Fetch all GHSA records for a single (ecosystem, package) pair."""
        records, texts, metadatas, ids = [], [], [], []
        cursor = None
        while True:
            page      = self._run_query(gh_ecosystem, package, cursor)
            nodes     = page.get("nodes", [])
            page_info = page.get("pageInfo", {})

            for node in nodes:
                result = self._parse_node(node)
                if len(result) != 2:
                    continue
                parsed, adv = result
                if not parsed:
                    continue
                # Skip advisories older than the lookback window
                pub_str = (adv or {}).get("publishedAt", "") if adv else ""
                if pub_str:
                    try:
                        pub_dt = datetime.fromisoformat(
                            pub_str.rstrip("Z")).replace(tzinfo=timezone.utc)
                        if pub_dt < cutoff:
                            continue
                    except ValueError:
                        pass
                # Tag which package this came from for traceability
                parsed["ecosystem"] = eco_key
                records.append(parsed)
                if adv:
                    body = f"{adv.get('summary','')}\n\n{adv.get('description','')}"
                    if body.strip():
                        texts.append(body)
                        metadatas.append({
                            "advisory_id":  parsed["advisory_id"],
                            "cve_id":       parsed["cve_id"],
                            "service_name": self.service_name,
                            "package":      package,
                            "source":       "ghsa",
                            "date":         adv.get("publishedAt", "")[:10],
                        })
                        ids.append(f"ghsa::{parsed['advisory_id']}")

            if not page_info.get("hasNextPage"):
                break
            cursor = page_info.get("endCursor")
            time.sleep(0.3)

        log.info("GHSA: %d records for %s/%s", len(records), eco_key, package)
        return records, texts, metadatas, ids

    def collect(self) -> list[dict]:
        # Only keep advisories published within the last LOOKBACK_DAYS days.
        cutoff = datetime.now(timezone.utc) - timedelta(days=LOOKBACK_DAYS)

        all_records:   list[dict] = []
        all_texts:     list[str]  = []
        all_metadatas: list[dict] = []
        all_ids:       list[str]  = []
        seen_advisory_ids:        set[str] = set()

        for eco_key, gh_ecosystem, package in self.query_targets:
            try:
                recs, texts, metas, doc_ids = self._collect_package(
                    eco_key, gh_ecosystem, package, cutoff)
            except Exception as exc:
                log.warning("GHSA: failed for %s/%s — %s", eco_key, package, exc)
                self.errors.append(f"GHSA {eco_key}/{package}: {exc}")
                continue

            for rec in recs:
                aid = rec.get("advisory_id", "")
                if aid not in seen_advisory_ids:
                    seen_advisory_ids.add(aid)
                    all_records.append(rec)

            for text, meta, doc_id in zip(texts, metas, doc_ids):
                if doc_id not in set(all_ids):
                    all_texts.append(text)
                    all_metadatas.append(meta)
                    all_ids.append(doc_id)

        if all_texts:
            upsert_documents("advisory_text", all_texts, all_metadatas, all_ids)
            log.info("GHSA: %d advisory texts written to ChromaDB", len(all_texts))

        log.info("GHSA: %d unique records within last %d days for %s (across %d package targets)",
                 len(all_records), LOOKBACK_DAYS, self.service_name, len(self.query_targets))
        return all_records


def main():
    parser = argparse.ArgumentParser(description="Collect from GitHub Advisory DB")
    # --service is the canonical service name (e.g. 'salesforce').
    # Package targets are resolved from service_aliases automatically.
    # Override with --packages for a comma-separated explicit list.
    # --ecosystem scopes the lookup to a single registry when set.
    parser.add_argument("--service",    required=True)
    parser.add_argument("--ecosystem",  default=None,
                        help="Restrict to one ecosystem (PyPI/npm/Maven/…). "
                             "Omit to query all ecosystems in service_aliases.")
    parser.add_argument("--packages",   default=None,
                        help="Comma-separated package names (overrides service_aliases)")
    parser.add_argument("--start-date", default=None)
    parser.add_argument("--end-date",   default=None)
    args = parser.parse_args()

    packages = [p.strip() for p in args.packages.split(",")] if args.packages else None

    with GHSACollector(args.service, args.ecosystem, packages,
                       args.start_date, args.end_date) as col:
        records = col.run()
        if records:
            upsert_records("vulnerabilities", records,
                           conflict_keys=["source", "advisory_id"])
        log.info("GHSA collection complete: %d records", len(records))


if __name__ == "__main__":
    main()
