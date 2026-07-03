"""
tests/test_etl.py — pytest unit + integration tests for etl.py
================================================================
Covers all transform functions and the full run_etl() integration path
against in-memory fakes (no real MySQL or ChromaDB required).

Run:
    pytest tests/test_etl.py -v
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ── Make DATABASE_URL and CHROMA_HOST available before importing etl ──────
os.environ.setdefault("DATABASE_URL", "mysql+pymysql://cloudrisk:test@localhost/cloudrisk_test")
os.environ.setdefault("CHROMA_HOST", "127.0.0.1")

import etl  # noqa: E402  (import after env vars set)


# ===========================================================================
# Fixtures — shared test data
# ===========================================================================

RECENT = datetime.now(timezone.utc) - timedelta(days=30)
OLD = datetime.now(timezone.utc) - timedelta(days=500)


@pytest.fixture()
def sample_vulns():
    return [
        {
            "cve_id": "CVE-2024-0001",
            "cvss_v3_score": 9.8,
            "epss_score": 0.85,
            "severity": "CRITICAL",
            "is_kev": True,
            "published_at": RECENT,
        },
        {
            "cve_id": "CVE-2023-0002",
            "cvss_v3_score": 7.2,
            "epss_score": 0.12,
            "severity": "HIGH",
            "is_kev": False,
            "published_at": OLD,
        },
        {
            "cve_id": "CVE-2023-0003",
            "cvss_v3_score": 4.5,
            "epss_score": 0.03,
            "severity": "MEDIUM",
            "is_kev": False,
            "published_at": RECENT,
        },
    ]


@pytest.fixture()
def sample_repo():
    return {
        "commit_count_90d": 120,
        "contributor_count_90d": 15,
        "days_since_release": 45,
        "has_security_policy": 1,
        "open_critical_issues": 2,
        "mean_sec_close_days": 14.0,
    }


@pytest.fixture()
def sample_incidents():
    return [
        {"severity": "critical", "duration_hours": 4.5, "started_at": RECENT, "description": "Database outage"},
        {"severity": "major", "duration_hours": 1.0, "started_at": RECENT, "description": "API degraded"},
        {"severity": "minor", "duration_hours": 0.25, "started_at": RECENT, "description": "Slow queries"},
    ]


# ===========================================================================
# Vulnerability feature tests
# ===========================================================================

class TestVulnerabilityFeatures:

    def test_empty_vulns_returns_zeros(self):
        f = etl.compute_vulnerability_features([])
        assert f["cve_count"] == 0
        assert f["cvss_normalized"] == 0.0
        assert f["is_kev_present"] == 0
        assert f["critical_cve_count"] == 0

    def test_cve_count_and_dedup(self, sample_vulns):
        # Add a duplicate CVE with lower CVSS — should be deduplicated
        duped = sample_vulns + [{
            "cve_id": "CVE-2024-0001",
            "cvss_v3_score": 5.0,
            "epss_score": 0.1,
            "severity": "MEDIUM",
            "is_kev": False,
            "published_at": RECENT,
        }]
        f = etl.compute_vulnerability_features(duped)
        assert f["cve_count"] == 3  # duplicate removed

    def test_kev_detection(self, sample_vulns):
        f = etl.compute_vulnerability_features(sample_vulns)
        assert f["is_kev_present"] == 1

    def test_no_kev(self):
        vulns = [{
            "cve_id": "CVE-2024-9999",
            "cvss_v3_score": 5.0,
            "epss_score": 0.05,
            "severity": "MEDIUM",
            "is_kev": False,
            "published_at": RECENT,
        }]
        f = etl.compute_vulnerability_features(vulns)
        assert f["is_kev_present"] == 0

    def test_severity_counts(self, sample_vulns):
        f = etl.compute_vulnerability_features(sample_vulns)
        assert f["critical_cve_count"] == 1
        assert f["high_cve_count"] == 1
        assert f["medium_cve_count"] == 1
        assert f["low_cve_count"] == 0

    def test_cvss_normalized_in_range(self, sample_vulns):
        f = etl.compute_vulnerability_features(sample_vulns)
        assert 0.0 <= f["cvss_normalized"] <= 1.0

    def test_exploit_maturity_high_epss(self):
        vulns = [
            {"cve_id": f"CVE-X-{i}", "cvss_v3_score": 8.0, "epss_score": 0.5,
             "severity": "HIGH", "is_kev": False, "published_at": RECENT}
            for i in range(5)
        ]
        f = etl.compute_vulnerability_features(vulns)
        assert f["exploit_maturity_score"] == 1.0  # all > 0.1

    def test_highest_cvss(self, sample_vulns):
        f = etl.compute_vulnerability_features(sample_vulns)
        assert f["highest_cvss"] == 9.8


# ===========================================================================
# Temporal decay tests
# ===========================================================================

class TestTemporalDecay:

    def test_very_recent_cve_near_one(self):
        d = etl._temporal_decay(datetime.now(timezone.utc) - timedelta(days=1))
        assert d > 0.99

    def test_old_cve_decays(self):
        # 730 days = exactly 2 half-lives → decay = 0.25; use <= not <
        d = etl._temporal_decay(datetime.now(timezone.utc) - timedelta(days=730))
        assert d <= 0.25

    def test_half_life(self):
        d = etl._temporal_decay(datetime.now(timezone.utc) - timedelta(days=etl.DECAY_HALF_LIFE_DAYS))
        assert abs(d - 0.5) < 0.02  # should be ~0.5

    def test_none_date_returns_default(self):
        d = etl._temporal_decay(None)
        assert d == 0.5


# ===========================================================================
# Repo feature tests
# ===========================================================================

class TestRepoFeatures:

    def test_none_repo_returns_safe_defaults(self):
        f = etl.compute_repo_features(None)
        assert f["repo_maturity_score"] == 0.0
        assert f["days_since_release"] == 999
        assert f["has_security_policy"] == 0

    def test_active_repo_high_maturity(self, sample_repo):
        f = etl.compute_repo_features(sample_repo)
        assert f["repo_maturity_score"] > 0.5
        assert f["has_security_policy"] == 1

    def test_stale_repo_low_maturity(self):
        repo = {
            "commit_count_90d": 0,
            "contributor_count_90d": 0,
            "days_since_release": 730,
            "has_security_policy": 0,
            "open_critical_issues": 10,
            "mean_sec_close_days": 180.0,
        }
        f = etl.compute_repo_features(repo)
        assert f["repo_maturity_score"] < 0.1

    def test_close_days_normalized(self, sample_repo):
        f = etl.compute_repo_features(sample_repo)
        # 14 days / 180 max = ~0.077
        assert f["mean_sec_close_days_norm"] < 0.1

    def test_all_values_in_range(self, sample_repo):
        f = etl.compute_repo_features(sample_repo)
        for key in ("repo_maturity_score", "mean_sec_close_days_norm", "days_since_release_norm"):
            assert 0.0 <= f[key] <= 1.0, f"{key} out of range"


# ===========================================================================
# Incident feature tests
# ===========================================================================

class TestIncidentFeatures:

    def test_no_incidents(self):
        f = etl.compute_incident_features([])
        assert f["operational_risk_score"] == 0.0
        assert f["major_incident_count_12m"] == 0
        assert f["total_incident_hours_12m"] == 0.0

    def test_major_incidents_counted(self, sample_incidents):
        f = etl.compute_incident_features(sample_incidents)
        assert f["major_incident_count_12m"] == 2  # critical + major
        assert f["total_incident_hours_12m"] == pytest.approx(5.75)

    def test_minor_incidents_excluded_from_major_count(self):
        incidents = [{"severity": "minor", "duration_hours": 10.0, "started_at": RECENT, "description": ""}]
        f = etl.compute_incident_features(incidents)
        assert f["major_incident_count_12m"] == 0

    def test_risk_score_in_range(self, sample_incidents):
        f = etl.compute_incident_features(sample_incidents)
        assert 0.0 <= f["operational_risk_score"] <= 1.0

    def test_many_incidents_caps_at_one(self):
        incidents = [
            {"severity": "critical", "duration_hours": 20.0, "started_at": RECENT, "description": ""}
            for _ in range(20)
        ]
        f = etl.compute_incident_features(incidents)
        assert f["operational_risk_score"] == pytest.approx(1.0)


# ===========================================================================
# NLP feature tests
# ===========================================================================

class TestNLPFeatures:

    def test_empty_docs_zero_quality(self):
        assert etl.compute_doc_quality_score([]) == 0.0

    def test_security_rich_docs_high_quality(self):
        docs = ["tls encryption authentication authorization audit log vulnerability cve cvss patch"]
        score = etl.compute_doc_quality_score(docs)
        assert score > 0.3

    def test_empty_advisory_zero_guidance(self):
        assert etl.compute_security_guidance_score([]) == 0.0

    def test_trust_coverage_full(self):
        docs = ["We are SOC 2 compliant and maintain ISO 27001 certification for all systems."]
        score = etl.compute_trust_coverage_score(docs, ["SOC2", "ISO27001"])
        assert score == 1.0

    def test_trust_coverage_partial(self):
        docs = ["We are SOC 2 certified."]
        score = etl.compute_trust_coverage_score(docs, ["SOC2", "ISO27001", "HIPAA"])
        assert score == pytest.approx(1 / 3, abs=0.01)

    def test_trust_coverage_empty_frameworks(self):
        docs = ["SOC 2 ISO 27001"]
        assert etl.compute_trust_coverage_score(docs, []) == 0.0

    def test_incident_sentiment_negative_text(self):
        docs = ["Critical outage. Major failure. Severe downtime. Customers lost data."]
        score = etl.compute_incident_sentiment_score(docs)
        assert score > 0.6  # negative sentiment → high inverted score

    def test_incident_sentiment_positive_text(self):
        docs = ["Excellent recovery. Resolved quickly. Outstanding performance maintained."]
        score = etl.compute_incident_sentiment_score(docs)
        assert score < 0.5

    def test_incident_sentiment_empty(self):
        assert etl.compute_incident_sentiment_score([]) == 0.0


# ===========================================================================
# Governance composite tests
# ===========================================================================

class TestGovernanceScore:

    def test_perfect_governance_near_zero(self):
        # High doc quality, high security guidance, full trust coverage, neutral sentiment
        score = etl.compute_governance_score(1.0, 1.0, 1.0, 0.0)
        assert score == pytest.approx(0.0)

    def test_no_data_high_risk(self):
        score = etl.compute_governance_score(0.0, 0.0, 0.0, 1.0)
        assert score == pytest.approx(1.0)

    def test_in_range(self):
        for combo in [(0.5, 0.5, 0.5, 0.5), (0.1, 0.9, 0.3, 0.7)]:
            s = etl.compute_governance_score(*combo)
            assert 0.0 <= s <= 1.0


# ===========================================================================
# Engineered feature tests
# ===========================================================================

class TestEngineeredFeatures:

    def _make_feats(self, sample_vulns, sample_repo, sample_incidents):
        vf = etl.compute_vulnerability_features(sample_vulns)
        rf = etl.compute_repo_features(sample_repo)
        inf = etl.compute_incident_features(sample_incidents)
        return vf, rf, inf

    def test_all_six_keys_present(self, sample_vulns, sample_repo, sample_incidents):
        vf, rf, inf = self._make_feats(sample_vulns, sample_repo, sample_incidents)
        eng = etl.compute_engineered_features(vf, rf, inf, 0.5, 0.5, 0.5, 0.5)
        expected_keys = {
            "security_posture_index", "operational_maturity_index",
            "reliability_index", "governance_index",
            "kev_severity_index", "patch_velocity_index",
        }
        assert expected_keys == set(eng.keys())

    def test_all_values_in_range(self, sample_vulns, sample_repo, sample_incidents):
        vf, rf, inf = self._make_feats(sample_vulns, sample_repo, sample_incidents)
        eng = etl.compute_engineered_features(vf, rf, inf, 0.6, 0.4, 0.8, 0.3)
        for k, v in eng.items():
            assert 0.0 <= v <= 1.0, f"{k}={v} out of [0,1]"

    def test_kev_severity_index_zero_without_kev(self):
        vf = etl.compute_vulnerability_features([{
            "cve_id": "CVE-X", "cvss_v3_score": 5.0, "epss_score": 0.05,
            "severity": "MEDIUM", "is_kev": False, "published_at": RECENT,
        }])
        rf = etl.compute_repo_features(None)
        inf = etl.compute_incident_features([])
        eng = etl.compute_engineered_features(vf, rf, inf, 0.5, 0.5, 0.5, 0.5)
        assert eng["kev_severity_index"] == pytest.approx(0.0)

    def test_kev_severity_index_elevated_with_kev(self, sample_vulns):
        vf = etl.compute_vulnerability_features(sample_vulns)
        rf = etl.compute_repo_features(None)
        inf = etl.compute_incident_features([])
        eng = etl.compute_engineered_features(vf, rf, inf, 0.5, 0.5, 0.5, 0.5)
        assert eng["kev_severity_index"] > 0.5


# ===========================================================================
# Data confidence tests
# ===========================================================================

class TestDataConfidence:

    def test_full_data_all_present(self):
        assert etl.compute_data_confidence(5, True, True, True) == "full_data"

    def test_partial_data_some_missing(self):
        assert etl.compute_data_confidence(5, True, False, False) == "partial_data"

    def test_insufficient_data_almost_nothing(self):
        assert etl.compute_data_confidence(0, False, False, False) == "insufficient_data"

    def test_min_vuln_threshold(self):
        # Exactly at threshold
        assert etl.compute_data_confidence(etl.MIN_VULN_ROWS_FULL, True, True, True) == "full_data"
        # Below threshold
        result = etl.compute_data_confidence(etl.MIN_VULN_ROWS_FULL - 1, True, True, True)
        assert result == "partial_data"


# ===========================================================================
# Integration test — full run_etl() with mocked dependencies
# ===========================================================================

MOCK_SERVICES = [
    {"id": 1, "name": "stripe", "vendor": "Stripe Inc.", "ecosystem": "SaaS", "github_repo": None, "service_tier": 1},
    {"id": 2, "name": "requests", "vendor": "PSF", "ecosystem": "PyPI", "github_repo": "psf/requests", "service_tier": 2},
    {"id": 3, "name": "empty-svc", "vendor": None, "ecosystem": "Other", "github_repo": None, "service_tier": 3},
]

MOCK_VULNS = {
    "stripe": [
        {"cve_id": "CVE-2024-1111", "cvss_v3_score": 8.5, "epss_score": 0.3,
         "severity": "HIGH", "is_kev": False, "published_at": RECENT},
        {"cve_id": "CVE-2023-2222", "cvss_v3_score": 9.1, "epss_score": 0.75,
         "severity": "CRITICAL", "is_kev": True, "published_at": RECENT},
    ],
    "requests": [
        {"cve_id": "CVE-2022-3333", "cvss_v3_score": 5.0, "epss_score": 0.05,
         "severity": "MEDIUM", "is_kev": False, "published_at": OLD},
    ],
    "empty-svc": [],
}

MOCK_REPO = {
    "stripe": {"commit_count_90d": 200, "contributor_count_90d": 25,
               "days_since_release": 10, "has_security_policy": 1,
               "open_critical_issues": 0, "mean_sec_close_days": 7.0},
    "requests": {"commit_count_90d": 50, "contributor_count_90d": 8,
                 "days_since_release": 90, "has_security_policy": 1,
                 "open_critical_issues": 1, "mean_sec_close_days": 30.0},
    "empty-svc": None,
}

MOCK_INCIDENTS = {
    "stripe": [{"severity": "major", "duration_hours": 2.0, "started_at": RECENT, "description": "Outage"}],
    "requests": [],
    "empty-svc": [],
}


class TestRunETLIntegration:

    @pytest.fixture(autouse=True)
    def patch_dependencies(self, tmp_path, monkeypatch):
        """Replace MySQL and ChromaDB with fakes; redirect output to tmp_path."""
        # ETL_OUTPUT_BASE is a module-level constant read at import time,
        # so setenv is too late — patch the attribute directly instead.
        monkeypatch.setattr(etl, "ETL_OUTPUT_BASE", tmp_path)

        # Patch get_engine and get_chroma_client at module level
        mock_engine = MagicMock()
        mock_chroma = MagicMock()

        with patch("etl.get_engine", return_value=mock_engine), \
             patch("etl.get_chroma_client", return_value=mock_chroma), \
             patch("etl.extract_services", return_value=MOCK_SERVICES), \
             patch("etl.extract_vulnerabilities", side_effect=lambda e, n: MOCK_VULNS.get(n, [])), \
             patch("etl.extract_repo_health", side_effect=lambda e, n: MOCK_REPO.get(n)), \
             patch("etl.extract_incidents", side_effect=lambda e, n: MOCK_INCIDENTS.get(n, [])), \
             patch("etl._chroma_get_text", side_effect=self._fake_chroma):
            self.tmp_path = tmp_path
            yield

    @staticmethod
    def _fake_chroma(client, collection_name, service_name, n_results=10):
        if service_name == "stripe":
            return ["tls encryption soc 2 security authentication audit"]
        if service_name == "requests":
            return ["requests library python http"]
        return []

    def test_run_etl_creates_output_files(self):
        run_id = etl.run_etl(run_id="test-run-001", ospc_path="/nonexistent/ospc.json")
        out_dir = etl.ETL_OUTPUT_BASE / run_id
        assert (out_dir / "features.ndjson").exists()
        assert (out_dir / "manifest.json").exists()

    def test_run_etl_returns_run_id(self):
        run_id = etl.run_etl(run_id="test-run-002", ospc_path="/nonexistent/ospc.json")
        assert run_id == "test-run-002"

    def test_run_etl_autogenerates_run_id(self):
        run_id = etl.run_etl(ospc_path="/nonexistent/ospc.json")
        assert len(run_id) == 36  # UUID format

    def test_ndjson_has_correct_record_count(self):
        run_id = etl.run_etl(run_id="test-run-003", ospc_path="/nonexistent/ospc.json")
        ndjson_path = etl.ETL_OUTPUT_BASE / run_id / "features.ndjson"
        records = [json.loads(line) for line in ndjson_path.read_text().strip().splitlines()]
        assert len(records) == len(MOCK_SERVICES)

    def test_ndjson_records_have_required_keys(self):
        run_id = etl.run_etl(run_id="test-run-004", ospc_path="/nonexistent/ospc.json")
        ndjson_path = etl.ETL_OUTPUT_BASE / run_id / "features.ndjson"
        records = [json.loads(line) for line in ndjson_path.read_text().strip().splitlines()]

        required_keys = {
            "run_id", "service_name", "vendor", "ecosystem",
            "cve_count", "highest_cvss", "is_kev_present",
            "critical_cve_count", "high_cve_count", "medium_cve_count", "low_cve_count",
            "cvss_normalized", "exploit_maturity_score", "epss_score",
            "severity_ordinal_norm", "temporal_decay",
            "repo_maturity_score", "mean_sec_close_days_norm", "days_since_release_norm",
            "commit_count_90d", "contributor_count_90d", "days_since_release", "has_security_policy",
            "operational_risk_score", "major_incident_count_12m", "total_incident_hours_12m",
            "doc_quality_score", "security_guidance_score", "trust_coverage_score", "incident_sentiment_score",
            "governance_composite",
            "security_posture_index", "operational_maturity_index", "reliability_index",
            "governance_index", "kev_severity_index", "patch_velocity_index",
            "data_confidence",
        }
        for rec in records:
            missing = required_keys - set(rec.keys())
            assert not missing, f"Record for {rec['service_name']} missing keys: {missing}"

    def test_manifest_service_count(self):
        run_id = etl.run_etl(run_id="test-run-005", ospc_path="/nonexistent/ospc.json")
        manifest_path = etl.ETL_OUTPUT_BASE / run_id / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        assert manifest["service_count"] == len(MOCK_SERVICES)
        assert manifest["run_id"] == run_id

    def test_stripe_is_kev(self):
        run_id = etl.run_etl(run_id="test-run-006", ospc_path="/nonexistent/ospc.json")
        ndjson_path = etl.ETL_OUTPUT_BASE / run_id / "features.ndjson"
        records = {
            json.loads(line)["service_name"]: json.loads(line)
            for line in ndjson_path.read_text().strip().splitlines()
        }
        assert records["stripe"]["is_kev_present"] == 1
        assert records["requests"]["is_kev_present"] == 0

    def test_empty_svc_insufficient_data(self):
        run_id = etl.run_etl(run_id="test-run-007", ospc_path="/nonexistent/ospc.json")
        ndjson_path = etl.ETL_OUTPUT_BASE / run_id / "features.ndjson"
        records = {
            json.loads(line)["service_name"]: json.loads(line)
            for line in ndjson_path.read_text().strip().splitlines()
        }
        assert records["empty-svc"]["data_confidence"] == "insufficient_data"

    def test_all_feature_values_in_range(self):
        run_id = etl.run_etl(run_id="test-run-008", ospc_path="/nonexistent/ospc.json")
        ndjson_path = etl.ETL_OUTPUT_BASE / run_id / "features.ndjson"
        normalized_keys = {
            "cvss_normalized", "exploit_maturity_score", "epss_score",
            "severity_ordinal_norm", "temporal_decay",
            "repo_maturity_score", "mean_sec_close_days_norm", "days_since_release_norm",
            "operational_risk_score",
            "doc_quality_score", "security_guidance_score", "trust_coverage_score", "incident_sentiment_score",
            "governance_composite",
            "security_posture_index", "operational_maturity_index", "reliability_index",
            "governance_index", "kev_severity_index", "patch_velocity_index",
        }
        for line in ndjson_path.read_text().strip().splitlines():
            rec = json.loads(line)
            for k in normalized_keys:
                v = rec[k]
                assert 0.0 <= v <= 1.0, f"{rec['service_name']}.{k}={v} out of [0,1]"
