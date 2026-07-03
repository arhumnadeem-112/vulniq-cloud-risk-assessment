"""
collect_docs.py
---------------
Scrapes vendor security documentation and cloud provider security guidance
pages and stores the cleaned text in ChromaDB (documentation collection).

No MySQL writes — ChromaDB only.

Supports:
  - Arbitrary vendor documentation / trust center URLs
  - AWS security documentation index
  - Azure security documentation index
  - GCP security documentation index

Usage:
    python collect_docs.py --service stripe --urls https://stripe.com/docs/security
    python collect_docs.py --service aws    --provider aws
    python collect_docs.py --service azure  --provider azure
    python collect_docs.py --service gcp    --provider gcp
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
log = logging.getLogger("collect_docs")

# Cloud provider security doc entry points
PROVIDER_DOC_URLS = {
    "aws": [
        "https://docs.aws.amazon.com/security/",
        "https://aws.amazon.com/security/security-resources/",
        "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html",
    ],
    "azure": [
        "https://learn.microsoft.com/en-us/azure/security/fundamentals/overview",
        "https://learn.microsoft.com/en-us/azure/security/",
        "https://learn.microsoft.com/en-us/compliance/",
    ],
    "gcp": [
        "https://cloud.google.com/security",
        "https://cloud.google.com/docs/security/overview/whitepaper",
        "https://cloud.google.com/security/compliance",
    ],
}

BOILERPLATE_PATTERNS = [
    r"cookie",
    r"privacy policy",
    r"terms of service",
    r"copyright \d{4}",
    r"all rights reserved",
    r"subscribe to newsletter",
    r"sign in",
    r"create account",
]
BOILERPLATE_RE = re.compile("|".join(BOILERPLATE_PATTERNS), re.IGNORECASE)

MIN_TEXT_LENGTH = 200   # discard pages with < 200 chars of content
SLEEP_BETWEEN   = 2.0   # seconds between requests


def _clean_text(soup: BeautifulSoup) -> str:
    """Extract and clean main content text from a parsed HTML page."""
    # Remove nav, footer, script, style, aside, header
    for tag in soup.find_all(["nav", "footer", "script", "style",
                               "aside", "header", "form", "noscript"]):
        tag.decompose()

    # Try semantic content containers first
    main = (soup.find("main") or
            soup.find("article") or
            soup.find("div", {"id": re.compile(r"content|main|body", re.I)}) or
            soup.find("div", {"class": re.compile(r"content|main|body", re.I)}) or
            soup.body)

    if not main:
        return ""

    raw  = main.get_text(separator="\n", strip=True)
    # Remove boilerplate lines
    lines = [l for l in raw.splitlines()
             if l.strip() and not BOILERPLATE_RE.search(l)]
    # Remove very short lines (nav remnants)
    lines = [l for l in lines if len(l.strip()) > 15]
    return "\n".join(lines).strip()


def _repos_to_doc_urls(service_name: str, github_token: str = "") -> list[str]:
    """
    Derive documentation URLs from a service's github_repos.
    For each repo, fetches the GitHub API to get the project homepage URL.
    Always includes the GitHub repo page itself as a fallback.
    """
    import os
    import httpx
    from collectors.service_aliases import get_github_repos

    repos = get_github_repos(service_name)
    if not repos:
        return []

    token = github_token or os.environ.get("GITHUB_TOKEN", "")
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    urls: list[str] = []
    for repo in repos:
        try:
            resp = httpx.get(f"https://api.github.com/repos/{repo}",
                             headers=headers, timeout=10, follow_redirects=True)
            if resp.status_code == 200:
                homepage = (resp.json() or {}).get("homepage") or ""
                if homepage.startswith("http"):
                    urls.append(homepage)
        except Exception as exc:
            log.debug("GitHub API lookup failed for %s: %s", repo, exc)
        urls.append(f"https://github.com/{repo}")
    return urls


class DocsCollector(BaseCollector):
    SOURCE = "docs"

    def __init__(self, service_name: str, urls: list[str],
                 provider: str | None = None,
                 start_date: str | None = None, end_date: str | None = None):
        super().__init__(service_name, start_date, end_date)
        self._client.headers.update({
            "User-Agent": ("Mozilla/5.0 (compatible; CloudRisk/1.0; "
                           "+https://github.com/NeMuTaNK/capstone-cloudrisk)"),
            "Accept":          "text/html,application/xhtml+xml",
            "Accept-Language": "en-US,en;q=0.9",
        })
        self.provider = (provider or "").lower()
        # If provider given, prepend provider URLs
        provider_urls = PROVIDER_DOC_URLS.get(self.provider, [])
        self.urls = provider_urls + (urls or [])
        # Auto-derive docs URLs from github_repos when nothing else was provided
        if not self.urls:
            self.urls = _repos_to_doc_urls(service_name)

    def _scrape_page(self, url: str) -> tuple[str, str] | None:
        """
        Scrape a single URL.
        Returns (title, cleaned_text) or None on failure.
        """
        try:
            resp = self.get(url)
            soup = BeautifulSoup(resp.text, "lxml")
            title = (soup.find("h1") or soup.find("title"))
            title = title.get_text(strip=True) if title else urlparse(url).path
            text  = _clean_text(soup)
            if len(text) < MIN_TEXT_LENGTH:
                log.debug("Skipping %s — content too short (%d chars)", url, len(text))
                return None
            return title, text
        except Exception as exc:
            log.warning("Failed to scrape %s: %s", url, exc)
            self.errors.append(f"scrape {url}: {exc}")
            return None

    def _discover_links(self, url: str, depth: int = 1) -> list[str]:
        """
        Discover child documentation links from a page (shallow crawl, depth=1).
        Only follows links on the same domain.
        """
        if depth == 0:
            return []
        domain = urlparse(url).netloc
        links  = [url]
        try:
            resp = self.get(url)
            soup = BeautifulSoup(resp.text, "lxml")
            main = (soup.find("main") or
                    soup.find("nav", {"aria-label": re.compile(r"doc|sec|toc", re.I)}) or
                    soup.body)
            if not main:
                return links
            for a in main.find_all("a", href=True):
                href     = urljoin(url, a["href"]).split("#")[0]
                href_dom = urlparse(href).netloc
                if (href_dom == domain and
                        href not in links and
                        href.startswith("http") and
                        len(links) < 20):  # cap at 20 child pages per root
                    links.append(href)
        except Exception as exc:
            log.warning("Link discovery failed for %s: %s", url, exc)
        return links

    def collect(self) -> list[dict]:
        if not self.urls:
            log.warning("No URLs provided for docs collection — skipping")
            return []

        all_urls: list[str] = []
        for root_url in self.urls:
            all_urls.extend(self._discover_links(root_url, depth=1))
            time.sleep(SLEEP_BETWEEN)

        # Deduplicate while preserving order
        seen: set[str] = set()
        unique_urls = []
        for u in all_urls:
            if u not in seen:
                seen.add(u)
                unique_urls.append(u)

        log.info("docs: scraping %d URLs for %s", len(unique_urls), self.service_name)

        docs, metas, ids = [], [], []
        for url in unique_urls:
            result = self._scrape_page(url)
            if result:
                title, text = result
                docs.append(f"{title}\n\n{text}")
                metas.append({
                    "service_name": self.service_name,
                    "source":       "docs",
                    "vendor":       self.service_name,
                    "doc_type":     "security_documentation",
                    "date":         "",
                    "url":          url,
                })
                ids.append(f"docs::{self.service_name}::{url[-60:]}")
            time.sleep(SLEEP_BETWEEN)

        if docs:
            upsert_documents("documentation", docs, metas, ids)
            log.info("docs: %d pages written to ChromaDB for %s",
                     len(docs), self.service_name)

        # Return summary records for manifest
        return [{"url": ids[i], "text_length": len(d)} for i, d in enumerate(docs)]


def main():
    parser = argparse.ArgumentParser(
        description="Collect vendor security documentation for ChromaDB")
    # TARGET: --urls lists the security/developer documentation pages to scrape.
    # For Salesforce, replace with the pages you want indexed:
    #   https://help.salesforce.com/s/articleView?id=sf.security_overview.htm
    #   https://developer.salesforce.com/docs/atlas.en-us.secure_coding_guide.meta/secure_coding_guide/
    #   https://developer.salesforce.com/docs/atlas.en-us.apexcode.meta/apexcode/apex_security_sharing_chapter.htm
    # Separate multiple URLs with spaces on the command line.
    parser.add_argument("--service",  required=True)
    parser.add_argument("--urls",     nargs="*", default=[],
                        help="One or more documentation URLs to scrape")
    parser.add_argument("--provider", default=None,
                        choices=["aws", "azure", "gcp"],
                        help="Cloud provider shorthand for known doc URLs")
    args = parser.parse_args()

    with DocsCollector(args.service, args.urls, args.provider) as col:
        records = col.run()
        log.info("Docs collection complete: %d pages scraped", len(records))


if __name__ == "__main__":
    main()
