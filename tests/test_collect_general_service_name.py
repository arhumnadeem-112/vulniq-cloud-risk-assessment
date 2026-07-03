"""
tests/test_collect_general_service_name.py
==========================================
Unit tests for service_name extraction in collect_general.py.
Verifies that vendor/package names are populated correctly for
NVD (CPE parsing), KEV (vendorProject field), and GHSA (package name).

No database, no network calls required.

Run:
    pytest tests/test_collect_general_service_name.py -v
"""

from __future__ import annotations

import os
import sys

import pytest

# ── Bootstrap env before importing anything that touches the DB or /data ───
os.environ.setdefault("DATA_DIR", "/tmp/cloudrisk_test")
os.environ.setdefault("DATABASE_URL", "mysql+pymysql://x:x@localhost/x")
os.environ.setdefault("GITHUB_TOKEN", "fake-token-for-tests")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from collectors.collect_general import (  # noqa: E402
    FALLBACK_NAME,
    GHSAGeneralCollector,
    KEVGeneralCollector,
    NVDGeneralCollector,
    _vendor_from_cpe,
)


# ===========================================================================
# _vendor_from_cpe — NVD CPE extraction helper
# ===========================================================================

class TestVendorFromCpe:
    def _make_cve(self, criteria: str, vulnerable: bool = True) -> dict:
        return {
            "configurations": [{
                "nodes": [{
                    "cpeMatch": [{
                        "vulnerable": vulnerable,
                        "criteria": criteria,
                    }]
                }]
            }]
        }

    def test_microsoft_cpe(self):
        cve = self._make_cve("cpe:2.3:a:microsoft:internet_explorer:11:*:*:*:*:*:*:*")
        assert _vendor_from_cpe(cve) == "microsoft"

    def test_apache_cpe(self):
        cve = self._make_cve("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
        assert _vendor_from_cpe(cve) == "apache"

    def test_google_cpe(self):
        cve = self._make_cve("cpe:2.3:a:google:chrome:109.0.5414.119:*:*:*:*:*:*:*")
        assert _vendor_from_cpe(cve) == "google"

    def test_skips_non_vulnerable_cpe(self):
        """Only vulnerable=True CPEs should be considered."""
        cve = {
            "configurations": [{
                "nodes": [{
                    "cpeMatch": [
                        {"vulnerable": False, "criteria": "cpe:2.3:a:microsoft:windows:*:*:*:*:*:*:*:*"},
                        {"vulnerable": True,  "criteria": "cpe:2.3:a:adobe:acrobat:22.0:*:*:*:*:*:*:*"},
                    ]
                }]
            }]
        }
        assert _vendor_from_cpe(cve) == "adobe"

    def test_wildcard_vendor_falls_back(self):
        """A CPE with vendor='*' should not be used."""
        cve = self._make_cve("cpe:2.3:a:*:someproduct:1.0:*:*:*:*:*:*:*")
        assert _vendor_from_cpe(cve) == FALLBACK_NAME

    def test_empty_configurations_falls_back(self):
        assert _vendor_from_cpe({}) == FALLBACK_NAME

    def test_multiple_nodes_first_vendor_wins(self):
        """First vulnerable CPE vendor is returned."""
        cve = {
            "configurations": [{
                "nodes": [
                    {"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:oracle:java:8:*:*:*:*:*:*:*"}]},
                    {"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:redhat:enterprise_linux:7:*:*:*:*:*:*:*"}]},
                ]
            }]
        }
        assert _vendor_from_cpe(cve) == "oracle"


# ===========================================================================
# NVDGeneralCollector._parse_cve — service_name via CPE
# ===========================================================================

class TestNVDServiceName:
    @pytest.fixture
    def collector(self):
        col = NVDGeneralCollector.__new__(NVDGeneralCollector)
        col.errors = []
        return col

    def _make_item(self, vendor: str, cve_id: str = "CVE-2024-99999") -> dict:
        return {
            "cve": {
                "id": cve_id,
                "published": "2024-11-01T12:00:00.000",
                "lastModified": "2024-11-02T12:00:00.000",
                "metrics": {},
                "weaknesses": [],
                "configurations": [{
                    "nodes": [{
                        "cpeMatch": [{
                            "vulnerable": True,
                            "criteria": f"cpe:2.3:a:{vendor}:someproduct:1.0:*:*:*:*:*:*:*",
                        }]
                    }]
                }],
            }
        }

    def test_service_name_from_cpe_vendor(self, collector):
        item = self._make_item("cisco")
        record = collector._parse_cve(item)
        assert record is not None
        assert record["service_name"] == "cisco"

    def test_service_name_fallback_no_configurations(self, collector):
        item = {"cve": {
            "id": "CVE-2024-00001",
            "published": "2024-11-01T12:00:00.000",
            "lastModified": "2024-11-01T12:00:00.000",
            "metrics": {}, "weaknesses": [], "configurations": [],
        }}
        record = collector._parse_cve(item)
        assert record is not None
        assert record["service_name"] == FALLBACK_NAME

    def test_other_fields_unaffected(self, collector):
        item = self._make_item("fortinet", "CVE-2024-12345")
        record = collector._parse_cve(item)
        assert record["source"] == "nvd"
        assert record["cve_id"] == "CVE-2024-12345"
        assert record["advisory_id"] == "CVE-2024-12345"


# ===========================================================================
# KEVGeneralCollector.collect — service_name via vendorProject
# ===========================================================================

class TestKEVServiceName:
    @pytest.fixture
    def collector(self, monkeypatch):
        col = KEVGeneralCollector.__new__(KEVGeneralCollector)
        col.errors = []
        col.cutoff = "2024-01-01"
        monkeypatch.setattr(col, "_backfill_kev_flag", lambda ids: None)
        return col

    def _fake_get(self, entries: list[dict]):
        """Return a fake get() method that yields a fixed KEV payload."""
        class FakeResp:
            def json(self_inner):
                return {"vulnerabilities": entries}
        def _get(url, **kw):
            return FakeResp()
        return _get

    def test_vendor_project_lowercased(self, collector, monkeypatch):
        entries = [{
            "cveID": "CVE-2024-1111",
            "vendorProject": "Microsoft",
            "product": "Windows",
            "dateAdded": "2024-06-01",
        }]
        monkeypatch.setattr(collector, "get", self._fake_get(entries))
        records = collector.collect()
        assert len(records) == 1
        assert records[0]["service_name"] == "microsoft"

    def test_multi_word_vendor_preserved(self, collector, monkeypatch):
        entries = [{
            "cveID": "CVE-2024-2222",
            "vendorProject": "Apache HTTP Server",
            "product": "httpd",
            "dateAdded": "2024-06-01",
        }]
        monkeypatch.setattr(collector, "get", self._fake_get(entries))
        records = collector.collect()
        assert records[0]["service_name"] == "apache http server"

    def test_missing_vendor_project_falls_back(self, collector, monkeypatch):
        entries = [{
            "cveID": "CVE-2024-3333",
            "vendorProject": "",
            "product": "something",
            "dateAdded": "2024-06-01",
        }]
        monkeypatch.setattr(collector, "get", self._fake_get(entries))
        records = collector.collect()
        assert records[0]["service_name"] == FALLBACK_NAME

    def test_old_entries_filtered_out(self, collector, monkeypatch):
        entries = [
            {"cveID": "CVE-2024-4444", "vendorProject": "Adobe", "dateAdded": "2024-06-01"},
            {"cveID": "CVE-2020-0001", "vendorProject": "Oracle", "dateAdded": "2020-01-01"},
        ]
        monkeypatch.setattr(collector, "get", self._fake_get(entries))
        records = collector.collect()
        assert len(records) == 1
        assert records[0]["cve_id"] == "CVE-2024-4444"


# ===========================================================================
# GHSAGeneralCollector._parse_node — service_name via package name
# ===========================================================================

class TestGHSAServiceName:
    @pytest.fixture
    def collector(self):
        col = GHSAGeneralCollector.__new__(GHSAGeneralCollector)
        col.errors = []
        return col

    def _make_node(self, pkg_name: str, ghsa_id: str = "GHSA-xxxx-yyyy-zzzz",
                   withdrawn: bool = False) -> dict:
        return {
            "advisory": {
                "ghsaId": ghsa_id,
                "severity": "HIGH",
                "publishedAt": "2024-11-01T00:00:00Z",
                "updatedAt": "2024-11-01T00:00:00Z",
                "cvss": {"score": 7.5, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
                "cwes": [],
                "identifiers": [{"type": "CVE", "value": "CVE-2024-55555"}],
                "withdrawnAt": "2024-11-02T00:00:00Z" if withdrawn else None,
            },
            "package": {"ecosystem": "NPM", "name": pkg_name},
        }

    def test_npm_package_name(self, collector):
        node = self._make_node("lodash")
        record = collector._parse_node(node)
        assert record is not None
        assert record["service_name"] == "lodash"

    def test_scoped_npm_package(self, collector):
        node = self._make_node("@angular/core")
        record = collector._parse_node(node)
        assert record["service_name"] == "@angular/core"

    def test_maven_package_name(self, collector):
        node = self._make_node("org.springframework:spring-core")
        record = collector._parse_node(node)
        assert record["service_name"] == "org.springframework:spring-core"

    def test_pypi_package_name(self, collector):
        node = self._make_node("django")
        record = collector._parse_node(node)
        assert record["service_name"] == "django"

    def test_empty_package_name_falls_back(self, collector):
        node = self._make_node("")
        record = collector._parse_node(node)
        assert record["service_name"] == FALLBACK_NAME

    def test_withdrawn_advisory_returns_none(self, collector):
        node = self._make_node("somepackage", withdrawn=True)
        assert collector._parse_node(node) is None

    def test_other_fields_correct(self, collector):
        node = self._make_node("flask", ghsa_id="GHSA-aaaa-bbbb-cccc")
        record = collector._parse_node(node)
        assert record["source"] == "ghsa"
        assert record["advisory_id"] == "GHSA-aaaa-bbbb-cccc"
        assert record["cve_id"] == "CVE-2024-55555"
        assert record["ecosystem"] == "NPM"
