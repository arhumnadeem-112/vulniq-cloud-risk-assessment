"""
collect_trust.py
----------------
Scrapes vendor trust center pages, SOC 2 summaries, ISO certification pages,
and compliance statement pages. Stores cleaned text in ChromaDB
(trust_disclosures collection).

No MySQL writes — ChromaDB only.

The trust_coverage_score NLP feature in the ETL pipeline looks for mentions of:
  SOC 2, ISO 27001, ISO 27017, ISO 27018, GDPR, HIPAA, PCI-DSS

Usage:
    python collect_trust.py --service stripe \\
        --urls https://stripe.com/privacy https://stripe.com/guides/compliance
    python collect_trust.py --service aws --provider aws
"""

import logging
import argparse
import time
import re
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

from collectors.base_collector import BaseCollector
from collectors.chroma_writer import upsert_documents

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s — %(message)s")
log = logging.getLogger("collect_trust")

# Known trust center URLs for major cloud providers
PROVIDER_TRUST_URLS = {
    "aws": [
        "https://aws.amazon.com/compliance/",
        "https://aws.amazon.com/compliance/soc/",
        "https://aws.amazon.com/compliance/iso/",
        "https://aws.amazon.com/compliance/hipaa-compliance/",
        "https://aws.amazon.com/compliance/pci-dss-level-1-faqs/",
        "https://aws.amazon.com/compliance/gdpr-center/",
    ],
    "azure": [
        "https://learn.microsoft.com/en-us/compliance/regulatory/offering-home",
        "https://learn.microsoft.com/en-us/azure/compliance/",
        "https://servicetrust.microsoft.com/",
        "https://learn.microsoft.com/en-us/compliance/regulatory/offering-SOC-2",
        "https://learn.microsoft.com/en-us/compliance/regulatory/offering-ISO-27001",
        "https://learn.microsoft.com/en-us/compliance/regulatory/offering-HIPAA-HITECH",
    ],
    "gcp": [
        "https://cloud.google.com/security/compliance",
        "https://cloud.google.com/security/compliance/compliance-reports-manager",
        "https://cloud.google.com/privacy",
        "https://cloud.google.com/security/compliance/hipaa",
        "https://cloud.google.com/security/compliance/pci-dss",
    ],
}

# Target compliance keywords — used to detect relevance of a page
COMPLIANCE_KEYWORDS = [
    "SOC 2", "SOC2", "ISO 27001", "ISO 27017", "ISO 27018",
    "GDPR", "HIPAA", "PCI-DSS", "PCI DSS", "FedRAMP",
    "CCPA", "NIST", "CSA STAR", "certif", "attestation",
    "audit report", "third.party audit", "compliance",
]
COMPLIANCE_RE = re.compile("|".join(COMPLIANCE_KEYWORDS), re.IGNORECASE)

BOILERPLATE_RE = re.compile(
    r"cookie|privacy policy|terms of service|copyright \d{4}|"
    r"all rights reserved|sign in|create account",
    re.IGNORECASE
)

MIN_TEXT_LENGTH = 150
SLEEP_BETWEEN   = 2.5


def _clean_text(soup: BeautifulSoup) -> str:
    """Extract and clean main content text from a parsed page."""
    for tag in soup.find_all(["nav", "footer", "script", "style",
                               "aside", "form", "noscript"]):
        tag.decompose()

    main = (soup.find("main") or
            soup.find("article") or
            soup.find("div", {"id": re.compile(r"content|main", re.I)}) or
            soup.body)
    if not main:
        return ""

    raw   = main.get_text(separator="\n", strip=True)
    lines = [l for l in raw.splitlines()
             if l.strip() and not BOILERPLATE_RE.search(l) and len(l.strip()) > 15]
    return "\n".join(lines).strip()


def _detect_frameworks(text: str) -> list[str]:
    """Return list of compliance framework names detected in the text."""
    found = []
    checks = {
        "SOC 2":     r"SOC\s*2|SOC-2",
        "ISO 27001":  r"ISO\s*27001",
        "ISO 27017":  r"ISO\s*27017",
        "ISO 27018":  r"ISO\s*27018",
        "GDPR":       r"GDPR|General Data Protection",
        "HIPAA":      r"HIPAA",
        "PCI-DSS":    r"PCI[\s-]DSS|Payment Card Industry",
        "FedRAMP":    r"FedRAMP",
        "CCPA":       r"CCPA|California Consumer Privacy",
        "NIST":       r"NIST",
    }
    for name, pattern in checks.items():
        if re.search(pattern, text, re.IGNORECASE):
            found.append(name)
    return found


def _repos_to_trust_urls(service_name: str) -> list[str]:
    """
    Derive trust/security URLs from a service's github_repos.
    Uses each repo's security policy page and security advisories index.
    """
    from collectors.service_aliases import get_github_repos

    repos = get_github_repos(service_name)
    urls: list[str] = []
    for repo in repos:
        urls.append(f"https://github.com/{repo}/security/policy")
        urls.append(f"https://github.com/{repo}/security/advisories")
    return urls


class TrustCollector(BaseCollector):
    SOURCE = "trust"

    def __init__(self, service_name: str, urls: list[str],
                 provider: str | None = None,
                 start_date: str | None = None, end_date: str | None = None):
        super().__init__(service_name, start_date, end_date)
        self._client.headers.update({
            "User-Agent":      ("Mozilla/5.0 (compatible; CloudRisk/1.0; "
                                "+https://github.com/NeMuTaNK/capstone-cloudrisk)"),
            "Accept":          "text/html,application/xhtml+xml",
            "Accept-Language": "en-US,en;q=0.9",
        })
        self.provider = (provider or "").lower()
        provider_urls = PROVIDER_TRUST_URLS.get(self.provider, [])
        self.urls = provider_urls + (urls or [])
        # Auto-derive trust URLs from github_repos when nothing else was provided
        if not self.urls:
            self.urls = _repos_to_trust_urls(service_name)

    def _scrape_page(self, url: str) -> tuple[str, str, list[str]] | None:
        """
        Scrape a trust/compliance page.
        Returns (title, text, detected_frameworks) or None on failure.
        """
        try:
            resp = self.get(url)
            soup = BeautifulSoup(resp.text, "lxml")
            title_tag = soup.find("h1") or soup.find("title")
            title = title_tag.get_text(strip=True) if title_tag else urlparse(url).path
            text  = _clean_text(soup)

            if len(text) < MIN_TEXT_LENGTH:
                log.debug("Skipping %s — too short (%d chars)", url, len(text))
                return None

            # Only keep pages that actually mention compliance topics
            if not COMPLIANCE_RE.search(text):
                log.debug("Skipping %s — no compliance keywords found", url)
                return None

            frameworks = _detect_frameworks(text)
            log.debug("Page %s: detected frameworks=%s", url, frameworks)
            return title, text, frameworks

        except Exception as exc:
            log.warning("Trust scrape failed for %s: %s", url, exc)
            self.errors.append(f"scrape {url}: {exc}")
            return None

    def collect(self) -> list[dict]:
        if not self.urls:
            log.warning("No URLs provided for trust collection — skipping")
            return []

        log.info("trust: scraping %d URLs for %s", len(self.urls), self.service_name)

        docs, metas, ids = [], [], []

        for url in self.urls:
            result = self._scrape_page(url)
            if result:
                title, text, frameworks = result
                full_text = f"{title}\n\n{text}"
                docs.append(full_text)
                metas.append({
                    "service_name": self.service_name,
                    "source":       "trust",
                    "vendor":       self.service_name,
                    "framework":    ",".join(frameworks),
                    "date":         "",
                    "url":          url,
                })
                ids.append(f"trust::{self.service_name}::{url[-60:]}")
                log.info("trust: scraped %s — %d chars, frameworks=%s",
                         url, len(full_text), frameworks)
            time.sleep(SLEEP_BETWEEN)

        if docs:
            upsert_documents("trust_disclosures", docs, metas, ids)
            log.info("trust: %d pages written to ChromaDB for %s",
                     len(docs), self.service_name)

        # Return summary records for manifest
        return [{"url": ids[i], "text_length": len(d),
                 "frameworks": metas[i]["framework"]}
                for i, d in enumerate(docs)]


def main():
    parser = argparse.ArgumentParser(
        description="Collect trust and compliance disclosure text")
    # TARGET: --urls lists the trust center and compliance disclosure pages to scrape.
    # For Salesforce, replace with the pages you want indexed:
    #   https://trust.salesforce.com                       — real-time trust & compliance portal
    #   https://www.salesforce.com/company/privacy/        — privacy policy
    #   https://www.salesforce.com/company/legal/compliance/ — compliance certifications (SOC 2, ISO 27001, etc.)
    # Separate multiple URLs with spaces on the command line.
    parser.add_argument("--service",  required=True)
    parser.add_argument("--urls",     nargs="*", default=[],
                        help="Trust center / compliance page URLs")
    parser.add_argument("--provider", default=None,
                        choices=["aws", "azure", "gcp"],
                        help="Cloud provider shorthand")
    args = parser.parse_args()

    with TrustCollector(args.service, args.urls, args.provider) as col:
        records = col.run()
        log.info("Trust collection complete: %d pages scraped", len(records))


if __name__ == "__main__":
    main()
