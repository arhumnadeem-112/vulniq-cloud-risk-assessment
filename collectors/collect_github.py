"""
collect_github.py
-----------------
Collects GitHub repository health signals and security advisory text.

MySQL  → repo_health table (commit frequency, issues, release cadence, security policy)
ChromaDB → advisory_text collection (GHSA body text)
           issue_text collection (security-labelled issue bodies)

Requires: GITHUB_TOKEN env var

Usage:
    python collect_github.py --service requests --repo psf/requests
    python collect_github.py --service stripe   --repo stripe/stripe-python
"""

import os
import logging
import argparse
import time
from datetime import datetime, timedelta, timezone

from collectors.base_collector import BaseCollector
from collectors.db_writer import upsert_records
from collectors.chroma_writer import upsert_documents

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s — %(message)s")
log = logging.getLogger("collect_github")

REST_BASE   = "https://api.github.com"
GRAPHQL_URL = "https://api.github.com/graphql"
CUTOFF_DAYS = 180  # commit / contributor / issue window


class GitHubCollector(BaseCollector):
    SOURCE = "github"

    def __init__(self, service_name: str, repo: str,
                 start_date: str | None = None, end_date: str | None = None):
        super().__init__(service_name, start_date, end_date)
        token = os.environ.get("GITHUB_TOKEN", "")
        if not token:
            raise EnvironmentError("GITHUB_TOKEN is required")
        self._client.headers.update({
            "Authorization": f"Bearer {token}",
            "Accept":        "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        })
        self.repo = repo   # e.g. "psf/requests"

    # ── REST helpers ──────────────────────────────────────────────────────────

    def _get(self, path: str, **params) -> dict | list:
        url  = f"{REST_BASE}/{path.lstrip('/')}"
        resp = self.get(url, params=params)
        return resp.json()

    def _paginate(self, path: str, **params) -> list:
        """Fetch all pages from a GitHub REST list endpoint."""
        results = []
        page    = 1
        while True:
            data = self._get(path, per_page=100, page=page, **params)
            if not data:
                break
            results.extend(data if isinstance(data, list) else [data])
            if len(data) < 100:
                break
            page += 1
            time.sleep(0.2)
        return results

    # ── Commit frequency ──────────────────────────────────────────────────────

    def _commit_stats(self) -> tuple[int, int]:
        """Return (commit_count, contributor_count) for the last CUTOFF_DAYS days."""
        since = (datetime.now(timezone.utc) - timedelta(days=CUTOFF_DAYS)
                 ).strftime("%Y-%m-%dT%H:%M:%SZ")
        commits = self._paginate(f"repos/{self.repo}/commits", since=since)
        authors = {c["author"]["login"] for c in commits
                   if c.get("author") and c["author"].get("login")}
        return len(commits), len(authors)

    # ── Issues ────────────────────────────────────────────────────────────────

    def _issue_stats(self) -> tuple[int, int, float]:
        """
        Return (open_issues, security_issues_open, mean_days_to_close_security).
        Only considers issues created within the last CUTOFF_DAYS days.
        """
        since = (datetime.now(timezone.utc) - timedelta(days=CUTOFF_DAYS)
                 ).strftime("%Y-%m-%dT%H:%M:%SZ")

        # All open issues
        open_issues = self._get(f"repos/{self.repo}")
        total_open  = open_issues.get("open_issues_count", 0) \
                      if isinstance(open_issues, dict) else 0

        # Security-labelled open issues within window
        sec_open = self._paginate(
            f"repos/{self.repo}/issues", state="open", labels="security", since=since)
        # Security-labelled closed issues (for mean close time)
        sec_closed = self._paginate(
            f"repos/{self.repo}/issues", state="closed", labels="security", since=since)

        durations = []
        for issue in sec_closed:
            created = issue.get("created_at")
            closed  = issue.get("closed_at")
            if created and closed:
                delta = (datetime.fromisoformat(closed.rstrip("Z")) -
                         datetime.fromisoformat(created.rstrip("Z")))
                durations.append(delta.total_seconds() / 86400)

        mean_close = round(sum(durations) / len(durations), 1) if durations else None
        return total_open, len(sec_open), mean_close

    # ── Issue text for ChromaDB ───────────────────────────────────────────────

    def _collect_issue_text(self) -> tuple[list, list, list]:
        """Return (documents, metadatas, ids) for security-labelled issues within CUTOFF_DAYS."""
        since  = (datetime.now(timezone.utc) - timedelta(days=CUTOFF_DAYS)
                  ).strftime("%Y-%m-%dT%H:%M:%SZ")
        issues = self._paginate(f"repos/{self.repo}/issues",
                                state="all", labels="security", since=since)
        docs, metas, ids = [], [], []
        for issue in issues[:50]:   # cap at 50 per service
            body = issue.get("body") or ""
            title = issue.get("title") or ""
            text  = f"{title}\n\n{body}".strip()
            if len(text) < 50:
                continue
            docs.append(text)
            metas.append({
                "service_name": self.service_name,
                "source":       "github_issue",
                "repo":         self.repo,
                "issue_number": str(issue.get("number", "")),
                "date":         (issue.get("created_at") or "")[:10],
            })
            ids.append(f"github_issue::{self.repo}::{issue.get('number','')}")
        return docs, metas, ids

    # ── Release cadence ───────────────────────────────────────────────────────

    def _days_since_release(self) -> int | None:
        try:
            release = self._get(f"repos/{self.repo}/releases/latest")
            pub     = release.get("published_at", "")
            if not pub:
                return None
            dt    = datetime.fromisoformat(pub.rstrip("Z"))
            delta = datetime.utcnow() - dt
            return delta.days
        except Exception:
            return None

    # ── Security policy ───────────────────────────────────────────────────────

    def _has_security_policy(self) -> int:
        try:
            resp = self._client.get(
                f"{REST_BASE}/repos/{self.repo}/contents/SECURITY.md")
            return 1 if resp.status_code == 200 else 0
        except Exception:
            return 0

    # ── Main collect ──────────────────────────────────────────────────────────

    def collect(self) -> list[dict]:
        log.info("GitHub: collecting repo health for %s (%s)",
                 self.service_name, self.repo)

        commit_count, contributor_count = self._commit_stats()
        open_issues, sec_open, mean_close = self._issue_stats()
        days_since_release = self._days_since_release()
        has_sec_policy     = self._has_security_policy()

        # Fetch repo metadata for stars/forks
        meta = self._get(f"repos/{self.repo}")
        stars = meta.get("stargazers_count", 0) if isinstance(meta, dict) else 0
        forks = meta.get("forks_count",       0) if isinstance(meta, dict) else 0

        record = {
            "service_name":             self.service_name,
            "repo_full_name":           self.repo,
            "commit_count_90d":         commit_count,
            "contributor_count_90d":    contributor_count,
            "open_issues":              open_issues,
            "security_issues_open":     sec_open,
            "mean_days_close_security": mean_close,
            "days_since_last_release":  days_since_release,
            "has_security_policy":      has_sec_policy,
            "raw_json": {
                "stars": stars,
                "forks": forks,
                "repo":  self.repo,
            },
            "collected_at": datetime.utcnow().isoformat(),
        }

        # Issue text → ChromaDB
        docs, metas, ids = self._collect_issue_text()
        if docs:
            upsert_documents("issue_text", docs, metas, ids)
            log.info("GitHub: %d issue texts written to ChromaDB", len(docs))

        log.info("GitHub: repo_health record built for %s", self.service_name)
        return [record]


def main():
    parser = argparse.ArgumentParser(description="Collect GitHub repo health signals")
    # TARGET: --service is the label stored in the database; --repo is the GitHub owner/repo slug.
    # For Salesforce, choose one of the official repos to profile:
    #   forcedotcom/SalesforceMobileSDK-iOS   — Mobile SDK (iOS)
    #   forcedotcom/SalesforceMobileSDK-Android — Mobile SDK (Android)
    #   simple-salesforce/simple-salesforce    — community Python SDK
    #   salesforce/cli                         — Salesforce CLI
    parser.add_argument("--service",    required=True, help="Service name")
    parser.add_argument("--repo",       default=None,
                        help="GitHub owner/repo slug (optional; uses service_aliases if omitted)")
    parser.add_argument("--start-date", default=None)
    parser.add_argument("--end-date",   default=None)
    args = parser.parse_args()

    from collectors.service_aliases import get_github_repos

    repos = [args.repo] if args.repo else get_github_repos(args.service)
    if not repos:
        log.warning("No github_repos configured for '%s' and no --repo given — skipping", args.service)
        return

    for repo in repos:
        log.info("Processing repo: %s for service: %s", repo, args.service)
        with GitHubCollector(args.service, repo, args.start_date, args.end_date) as col:
            records = col.run()
            if records:
                upsert_records("repo_health", records,
                               conflict_keys=["service_name", "repo_full_name"])
        log.info("GitHub collection complete for %s (%s)", args.service, repo)


if __name__ == "__main__":
    main()
