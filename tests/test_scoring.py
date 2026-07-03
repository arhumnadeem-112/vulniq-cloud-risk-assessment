"""
tests/test_scoring.py — pytest unit + integration tests for scoring.py
========================================================================
Covers weight composition, all scoring transforms, dual-write outputs,
and the full run_scoring() integration path with mocked dependencies.

Run:
    pytest tests/test_scoring.py -v
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import jsonschema
import pytest

os.environ.setdefault("DATABASE_URL", "mysql+pymysql://cloudrisk:test@localhost/cloudrisk_test")

import scoring  # noqa: E402


# ===========================================================================
# Fixtures
# ===========================================================================

@pytest.fixture()
def base_ospc():
    return {
        "org_name": "Acme Corp",
        "regulatory_frameworks": [],
        "service_tiers": {"stripe": 1},
        "patch_sla_days": {"CRITICAL": 7, "HIGH": 30, "MEDIUM": 90, "LOW": 180},
        "compensating_controls": [],
        "dimension_weight_overrides": {},
    }


@pytest.fixture()
def ospc_with_soc2(base_ospc):
    ospc = dict(base_ospc)
    ospc["regulatory_frameworks"] = ["SOC2"]
    return ospc


@pytest.fixture()
def ospc_with_controls(base_ospc):
    ospc = dict(base_ospc)
    ospc["compensating_controls"] = ["mfa_enforced", "network_segmentation"]
    return ospc


@pytest.fixture()
def full_etl_record():
    """A realistic ETL record with all fields populated."""
    return {
        "run_id": "test-run-001",
        "service_name": "stripe",
        "vendor": "Stripe Inc.",
        "ecosystem": "SaaS",
        "github_repo": None,
        "service_tier": 1,
        # Vulnerability features
        "cvss_normalized": 0.85,
        "exploit_maturity_score": 0.70,
        "epss_score": 0.60,
        "severity_ordinal_norm": 0.90,
        "temporal_decay": 0.95,
        "cve_count": 5,
        "highest_cvss": 9.1,
        "is_kev_present": 1,
        "critical_cve_count": 2,
        "high_cve_count": 2,
        "medium_cve_count": 1,
        "low_cve_count": 0,
        # Repo features
        "repo_maturity_score": 0.75,
        "mean_sec_close_days_norm": 0.08,
        "days_since_release_norm": 0.12,
        "commit_count_90d": 180,
        "contributor_count_90d": 22,
        "days_since_release": 14,
        "has_security_policy": 1,
        # Incident features
        "operational_risk_score": 0.30,
        "major_incident_count_12m": 2,
        "total_incident_hours_12m": 3.5,
        # NLP features
        "doc_quality_score": 0.45,
        "security_guidance_score": 0.55,
        "trust_coverage_score": 0.80,
        "incident_sentiment_score": 0.35,
        # Governance composite
        "governance_composite": 0.30,
        # Engineered features
        "security_posture_index": 0.78,
        "operational_maturity_index": 0.72,
        "reliability_index": 0.30,
        "governance_index": 0.30,
        "kev_severity_index": 0.76,
        "patch_velocity_index": 0.85,
        # Confidence
        "data_confidence": "full_data",
    }


@pytest.fixture()
def insufficient_record(full_etl_record):
    rec = dict(full_etl_record)
    rec["service_name"] = "unknown-svc"
    rec["data_confidence"] = "insufficient_data"
    return rec


# ===========================================================================
# OSPC validation tests
# ===========================================================================

class TestOSPCValidation:

    def test_valid_ospc_passes(self, base_ospc, tmp_path):
        p = tmp_path / "ospc.json"
        p.write_text(json.dumps(base_ospc))
        result = scoring.load_ospc(str(p))
        assert result["org_name"] == "Acme Corp"

    def test_missing_required_field_raises(self, tmp_path):
        bad = {"regulatory_frameworks": [], "compensating_controls": []}  # missing org_name
        p = tmp_path / "ospc.json"
        p.write_text(json.dumps(bad))
        with pytest.raises(jsonschema.ValidationError):
            scoring.load_ospc(str(p))

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            scoring.load_ospc(str(tmp_path / "nonexistent.json"))

    def test_empty_org_name_raises(self, tmp_path):
        bad = {"org_name": "", "regulatory_frameworks": [], "compensating_controls": []}
        p = tmp_path / "ospc.json"
        p.write_text(json.dumps(bad))
        with pytest.raises(jsonschema.ValidationError):
            scoring.load_ospc(str(p))


# ===========================================================================
# Weight composition tests
# ===========================================================================

class TestComposeWeights:

    def test_default_weights_no_frameworks(self, base_ospc):
        w = scoring.compose_weights(base_ospc)
        assert abs(sum(w.values()) - 1.0) < 1e-5
        assert abs(w["security_posture"] - 0.40) < 0.01

    def test_weights_sum_to_one_with_frameworks(self, ospc_with_soc2):
        w = scoring.compose_weights(ospc_with_soc2)
        assert abs(sum(w.values()) - 1.0) < 1e-5

    def test_soc2_increases_governance_weight(self, base_ospc, ospc_with_soc2):
        w_base = scoring.compose_weights(base_ospc)
        w_soc2 = scoring.compose_weights(ospc_with_soc2)
        assert w_soc2["governance"] > w_base["governance"]

    def test_pcidss_increases_security_weight(self, base_ospc):
        ospc = dict(base_ospc)
        ospc["regulatory_frameworks"] = ["PCI-DSS"]
        w_base = scoring.compose_weights(base_ospc)
        w_pci = scoring.compose_weights(ospc)
        assert w_pci["security_posture"] > w_base["security_posture"]

    def test_weight_override_applied(self, base_ospc):
        ospc = dict(base_ospc)
        ospc["dimension_weight_overrides"] = {"security_posture": 0.60}
        w = scoring.compose_weights(ospc)
        assert abs(sum(w.values()) - 1.0) < 1e-5
        # Override sets security_posture=0.60; remaining three weights also sum to 0.60,
        # so after re-normalisation security_posture = 0.60/1.20 = exactly 0.50.
        assert w["security_posture"] >= 0.50

    def test_multiple_frameworks_still_normalize(self, base_ospc):
        ospc = dict(base_ospc)
        ospc["regulatory_frameworks"] = ["SOC2", "PCI-DSS", "HIPAA"]
        w = scoring.compose_weights(ospc)
        assert abs(sum(w.values()) - 1.0) < 1e-5
        for v in w.values():
            assert v >= 0.0

    def test_all_weight_values_non_negative(self, base_ospc):
        for fw in scoring.FRAMEWORK_WEIGHT_ADJUSTMENTS:
            ospc = dict(base_ospc)
            ospc["regulatory_frameworks"] = [fw]
            w = scoring.compose_weights(ospc)
            for dim, val in w.items():
                assert val >= 0.0, f"{fw}: {dim} weight is negative"


# ===========================================================================
# Raw score computation tests
# ===========================================================================

class TestComputeRawScore:

    def test_zero_indices_zero_score(self, base_ospc):
        record = {k: 0.0 for k in
                  ["security_posture_index", "operational_maturity_index",
                   "reliability_index", "governance_index"]}
        w = scoring.compose_weights(base_ospc)
        assert scoring.compute_raw_score(record, w) == 0.0

    def test_all_ones_score_is_100(self, base_ospc):
        record = {
            "security_posture_index": 1.0,
            "operational_maturity_index": 1.0,
            "reliability_index": 1.0,
            "governance_index": 1.0,
        }
        w = scoring.compose_weights(base_ospc)
        assert abs(scoring.compute_raw_score(record, w) - 100.0) < 0.1

    def test_score_in_range(self, full_etl_record, base_ospc):
        w = scoring.compose_weights(base_ospc)
        score = scoring.compute_raw_score(full_etl_record, w)
        assert 0.0 <= score <= 100.0

    def test_higher_indices_higher_score(self, base_ospc):
        w = scoring.compose_weights(base_ospc)
        low = scoring.compute_raw_score(
            {"security_posture_index": 0.1, "operational_maturity_index": 0.1,
             "reliability_index": 0.1, "governance_index": 0.1}, w
        )
        high = scoring.compute_raw_score(
            {"security_posture_index": 0.9, "operational_maturity_index": 0.9,
             "reliability_index": 0.9, "governance_index": 0.9}, w
        )
        assert high > low


# ===========================================================================
# Dimension scores tests
# ===========================================================================

class TestDimensionScores:

    def test_all_four_keys_present(self, full_etl_record, base_ospc):
        w = scoring.compose_weights(base_ospc)
        d = scoring.compute_dimension_scores(full_etl_record, w)
        assert set(d.keys()) == {
            "security_posture_score", "operational_maturity_score",
            "service_reliability_score", "governance_score"
        }

    def test_sub_scores_sum_near_raw(self, full_etl_record, base_ospc):
        w = scoring.compose_weights(base_ospc)
        d = scoring.compute_dimension_scores(full_etl_record, w)
        raw = scoring.compute_raw_score(full_etl_record, w)
        assert abs(sum(d.values()) - raw) < 0.5  # rounding tolerance

    def test_zero_index_zero_sub_score(self, base_ospc):
        record = {k: 0.0 for k in
                  ["security_posture_index", "operational_maturity_index",
                   "reliability_index", "governance_index"]}
        w = scoring.compose_weights(base_ospc)
        d = scoring.compute_dimension_scores(record, w)
        assert all(v == 0.0 for v in d.values())


# ===========================================================================
# Compensating control discount tests
# ===========================================================================

class TestCompensatingControls:

    def test_no_controls_no_change(self):
        assert scoring.apply_compensating_controls(60.0, []) == 60.0

    def test_single_control_reduces_score(self):
        result = scoring.apply_compensating_controls(60.0, ["mfa_enforced"])
        expected = 60.0 * (1 - 0.05)
        assert abs(result - expected) < 0.1

    def test_multiple_controls_compound(self):
        result = scoring.apply_compensating_controls(60.0, ["mfa_enforced", "network_segmentation"])
        expected = 60.0 * (1 - 0.05) * (1 - 0.03)
        assert abs(result - expected) < 0.1

    def test_unknown_control_skipped(self):
        # Should not raise and should not change score
        result = scoring.apply_compensating_controls(60.0, ["nonexistent_control"])
        assert result == 60.0

    def test_all_controls_reduce_score(self):
        raw = 80.0
        all_controls = list(scoring.CONTROL_DISCOUNTS.keys())
        result = scoring.apply_compensating_controls(raw, all_controls)
        assert result < raw

    def test_score_never_goes_negative(self):
        result = scoring.apply_compensating_controls(1.0, list(scoring.CONTROL_DISCOUNTS.keys()))
        assert result >= 0.0


# ===========================================================================
# Confidence penalty tests
# ===========================================================================

class TestConfidencePenalty:

    def test_full_data_no_penalty(self):
        assert scoring.apply_confidence_penalty(80.0, "full_data") == 80.0

    def test_partial_data_no_penalty(self):
        assert scoring.apply_confidence_penalty(80.0, "partial_data") == 80.0

    def test_insufficient_data_penalty(self):
        result = scoring.apply_confidence_penalty(80.0, "insufficient_data")
        assert abs(result - 80.0 * scoring.CONFIDENCE_PENALTY) < 0.1

    def test_penalty_multiplier_is_0_75(self):
        assert scoring.CONFIDENCE_PENALTY == 0.75


# ===========================================================================
# score_record end-to-end tests
# ===========================================================================

class TestScoreRecord:

    def test_all_schema_columns_present(self, full_etl_record, base_ospc):
        w = scoring.compose_weights(base_ospc)
        result = scoring.score_record(full_etl_record, w, base_ospc)
        for col in scoring._SCORES_TABLE_COLUMNS:
            assert col in result, f"Missing column: {col}"

    def test_final_score_in_range(self, full_etl_record, base_ospc):
        w = scoring.compose_weights(base_ospc)
        result = scoring.score_record(full_etl_record, w, base_ospc)
        assert 0.0 <= result["final_risk_score"] <= 100.0

    def test_final_score_lte_raw_score_with_controls(self, full_etl_record, ospc_with_controls):
        w = scoring.compose_weights(ospc_with_controls)
        result = scoring.score_record(full_etl_record, w, ospc_with_controls)
        assert result["final_risk_score"] <= result["raw_score"]

    def test_insufficient_data_final_less_than_raw(self, insufficient_record, base_ospc):
        w = scoring.compose_weights(base_ospc)
        result = scoring.score_record(insufficient_record, w, base_ospc)
        assert result["final_risk_score"] < result["raw_score"]

    def test_active_controls_serialized(self, full_etl_record, ospc_with_controls):
        w = scoring.compose_weights(ospc_with_controls)
        result = scoring.score_record(full_etl_record, w, ospc_with_controls)
        assert "mfa_enforced" in result["active_controls"]
        assert "network_segmentation" in result["active_controls"]

    def test_no_controls_empty_string(self, full_etl_record, base_ospc):
        w = scoring.compose_weights(base_ospc)
        result = scoring.score_record(full_etl_record, w, base_ospc)
        assert result["active_controls"] == ""

    def test_ospc_org_name_propagated(self, full_etl_record, base_ospc):
        w = scoring.compose_weights(base_ospc)
        result = scoring.score_record(full_etl_record, w, base_ospc)
        assert result["ospc_org_name"] == "Acme Corp"

    def test_kev_flag_preserved(self, full_etl_record, base_ospc):
        w = scoring.compose_weights(base_ospc)
        result = scoring.score_record(full_etl_record, w, base_ospc)
        assert result["is_kev_present"] == 1


# ===========================================================================
# MySQL write tests
# ===========================================================================

class TestWriteScoresToMySQL:

    def test_empty_records_returns_zero(self):
        engine = MagicMock()
        assert scoring.write_scores_to_mysql(engine, []) == 0

    def test_insert_called_with_correct_columns(self, full_etl_record, base_ospc):
        w = scoring.compose_weights(base_ospc)
        scored = scoring.score_record(full_etl_record, w, base_ospc)

        mock_conn = MagicMock()
        mock_conn.__enter__ = MagicMock(return_value=mock_conn)
        mock_conn.__exit__ = MagicMock(return_value=False)
        mock_result = MagicMock()
        mock_result.rowcount = 1
        mock_conn.execute = MagicMock(return_value=mock_result)

        mock_engine = MagicMock()
        mock_engine.begin = MagicMock(return_value=mock_conn)

        inserted = scoring.write_scores_to_mysql(mock_engine, [scored])
        assert inserted == 1
        mock_conn.execute.assert_called_once()


# ===========================================================================
# Integration — run_scoring() with mocked I/O
# ===========================================================================

class TestRunScoringIntegration:

    @pytest.fixture()
    def etl_ndjson(self, tmp_path, full_etl_record, insufficient_record):
        """Create a fake ETL output directory with 3 service records."""
        third_record = dict(full_etl_record)
        third_record["service_name"] = "requests"
        third_record["data_confidence"] = "partial_data"
        third_record["is_kev_present"] = 0

        run_id = "integration-run-001"
        etl_dir = tmp_path / "etl" / run_id
        etl_dir.mkdir(parents=True)
        ndjson = etl_dir / "features.ndjson"
        with ndjson.open("w") as f:
            for rec in [full_etl_record, insufficient_record, third_record]:
                rec_copy = dict(rec)
                rec_copy["run_id"] = run_id
                f.write(json.dumps(rec_copy) + "\n")

        return tmp_path, run_id

    @pytest.fixture()
    def ospc_file(self, tmp_path, base_ospc):
        ospc = dict(base_ospc)
        ospc["regulatory_frameworks"] = ["SOC2"]
        ospc["compensating_controls"] = ["mfa_enforced"]
        p = tmp_path / "ospc.json"
        p.write_text(json.dumps(ospc))
        return str(p)

    def test_run_scoring_returns_correct_count(self, etl_ndjson, ospc_file, monkeypatch):
        tmp_path, run_id = etl_ndjson
        monkeypatch.setattr(scoring, "ETL_OUTPUT_BASE", tmp_path / "etl")
        monkeypatch.setattr(scoring, "SCORES_OUTPUT_BASE", tmp_path / "scores")

        with patch("scoring.get_engine") as mock_eng, \
             patch("scoring.write_scores_to_mysql", return_value=3):
            results = scoring.run_scoring(run_id=run_id, ospc_path=ospc_file)

        assert len(results) == 3

    def test_score_json_files_written(self, etl_ndjson, ospc_file, monkeypatch):
        tmp_path, run_id = etl_ndjson
        monkeypatch.setattr(scoring, "ETL_OUTPUT_BASE", tmp_path / "etl")
        monkeypatch.setattr(scoring, "SCORES_OUTPUT_BASE", tmp_path / "scores")

        with patch("scoring.get_engine"), \
             patch("scoring.write_scores_to_mysql", return_value=3):
            scoring.run_scoring(run_id=run_id, ospc_path=ospc_file)

        score_dir = tmp_path / "scores" / run_id
        json_files = list(score_dir.glob("*_score.json"))
        assert len(json_files) == 3

    def test_score_json_content_valid(self, etl_ndjson, ospc_file, monkeypatch):
        tmp_path, run_id = etl_ndjson
        monkeypatch.setattr(scoring, "ETL_OUTPUT_BASE", tmp_path / "etl")
        monkeypatch.setattr(scoring, "SCORES_OUTPUT_BASE", tmp_path / "scores")

        with patch("scoring.get_engine"), \
             patch("scoring.write_scores_to_mysql", return_value=3):
            scoring.run_scoring(run_id=run_id, ospc_path=ospc_file)

        score_dir = tmp_path / "scores" / run_id
        for f in score_dir.glob("*_score.json"):
            data = json.loads(f.read_text())
            assert "final_risk_score" in data
            assert 0.0 <= data["final_risk_score"] <= 100.0

    def test_mysql_write_called_once(self, etl_ndjson, ospc_file, monkeypatch):
        tmp_path, run_id = etl_ndjson
        monkeypatch.setattr(scoring, "ETL_OUTPUT_BASE", tmp_path / "etl")
        monkeypatch.setattr(scoring, "SCORES_OUTPUT_BASE", tmp_path / "scores")

        with patch("scoring.get_engine"), \
             patch("scoring.write_scores_to_mysql", return_value=3) as mock_write:
            scoring.run_scoring(run_id=run_id, ospc_path=ospc_file)

        mock_write.assert_called_once()
        # Verify all 3 records were passed in one batch
        args = mock_write.call_args[0]
        assert len(args[1]) == 3

    def test_missing_etl_output_raises(self, tmp_path, ospc_file, monkeypatch):
        monkeypatch.setattr(scoring, "ETL_OUTPUT_BASE", tmp_path / "etl")
        monkeypatch.setattr(scoring, "SCORES_OUTPUT_BASE", tmp_path / "scores")

        with pytest.raises(FileNotFoundError, match="ETL output not found"):
            scoring.run_scoring(run_id="nonexistent-run", ospc_path=ospc_file)

    def test_insufficient_data_scores_lower(self, etl_ndjson, ospc_file, monkeypatch):
        tmp_path, run_id = etl_ndjson
        monkeypatch.setattr(scoring, "ETL_OUTPUT_BASE", tmp_path / "etl")
        monkeypatch.setattr(scoring, "SCORES_OUTPUT_BASE", tmp_path / "scores")

        with patch("scoring.get_engine"), \
             patch("scoring.write_scores_to_mysql", return_value=3):
            results = scoring.run_scoring(run_id=run_id, ospc_path=ospc_file)

        by_name = {r["service_name"]: r for r in results}
        # unknown-svc is insufficient_data; stripe is full_data — same raw indices
        # so insufficient must have lower final score
        assert by_name["unknown-svc"]["final_risk_score"] < by_name["stripe"]["final_risk_score"]
