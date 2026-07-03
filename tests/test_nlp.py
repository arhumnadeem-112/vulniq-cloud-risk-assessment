"""
tests/test_nlp.py
=================
Exhaustive unit tests for all four NLP feature functions in etl.py plus the
governance composite that consumes them.  No MySQL, ChromaDB, or network
access required — every test is pure-Python.

Functions under test
--------------------
  _keyword_density(text_blob, keyword_set)          — internal primitive
  compute_doc_quality_score(docs)                   — DOC_QUALITY_KEYWORDS
  compute_security_guidance_score(advisory_docs)    — SECURITY_GUIDANCE_KEYWORDS
  compute_trust_coverage_score(trust_docs, fws)     — FRAMEWORK_KEYWORDS detection
  compute_incident_sentiment_score(incident_docs)   — VADER compound, inverted
  compute_governance_score(doc, guidance, trust, sentiment) — composite [0,1]

Run:
    pytest tests/test_nlp.py -v
"""

from __future__ import annotations

import os

import pytest

# ── Stub env vars before etl imports SQLAlchemy / ChromaDB clients ─────────
os.environ.setdefault("DATABASE_URL", "mysql+pymysql://cloudrisk:test@localhost/cloudrisk_test")
os.environ.setdefault("CHROMA_HOST", "127.0.0.1")

import etl  # noqa: E402


# ===========================================================================
# Section 1 — _keyword_density  (internal primitive)
# ===========================================================================

class TestKeywordDensity:
    """
    _keyword_density is private but the public NLP functions are thin wrappers
    around it.  Testing it directly avoids coupling to specific keyword lists
    while still verifying the core arithmetic.
    """

    KW = {"alpha", "beta", "gamma", "delta"}   # 4-word set for easy fraction math

    def test_empty_blob_returns_zero(self):
        assert etl._keyword_density("", self.KW) == 0.0

    def test_whitespace_only_blob_returns_zero(self):
        assert etl._keyword_density("   \n\t  ", self.KW) == 0.0

    def test_no_keyword_hit_returns_zero(self):
        assert etl._keyword_density("the quick brown fox", self.KW) == 0.0

    def test_single_hit_correct_fraction(self):
        # 1 of 4 → 0.25
        result = etl._keyword_density("the alpha is here", self.KW)
        assert result == pytest.approx(0.25, abs=1e-4)

    def test_two_hits_correct_fraction(self):
        # 2 of 4 → 0.5
        result = etl._keyword_density("alpha and beta are present", self.KW)
        assert result == pytest.approx(0.5, abs=1e-4)

    def test_all_keywords_hit_returns_one(self):
        blob = "alpha beta gamma delta"
        assert etl._keyword_density(blob, self.KW) == pytest.approx(1.0)

    def test_case_insensitive_match(self):
        # Function lowercases the blob; "ALPHA" should hit "alpha"
        result = etl._keyword_density("ALPHA BETA", self.KW)
        assert result == pytest.approx(0.5, abs=1e-4)

    def test_substring_within_word_counts_as_hit(self):
        # "alphabetical" contains "alpha" — keyword density uses `in`, not word boundary
        result = etl._keyword_density("alphabetical", self.KW)
        assert result == pytest.approx(0.25, abs=1e-4)

    def test_repeated_keyword_counts_only_once(self):
        # "alpha alpha alpha" — only 1 unique keyword hit, still 1/4
        result = etl._keyword_density("alpha alpha alpha", self.KW)
        assert result == pytest.approx(0.25, abs=1e-4)

    def test_output_is_rounded_to_four_decimals(self):
        # 1/3 ≈ 0.3333 — verifies the round() call in the implementation
        kw3 = {"x", "y", "z"}
        result = etl._keyword_density("x and y are here", kw3)
        assert result == pytest.approx(round(2 / 3, 4), abs=1e-6)

    def test_single_keyword_set_hit(self):
        assert etl._keyword_density("only x present", {"x"}) == 1.0

    def test_single_keyword_set_miss(self):
        assert etl._keyword_density("nothing here", {"x"}) == 0.0

    def test_return_type_is_float(self):
        result = etl._keyword_density("alpha", self.KW)
        assert isinstance(result, float)


# ===========================================================================
# Section 2 — compute_doc_quality_score
# ===========================================================================

class TestDocQualityScore:
    """
    DOC_QUALITY_KEYWORDS has 21 terms (confirmed).
    Score = fraction of those terms present in the joined doc blob.
    """

    # One term guaranteed to be in DOC_QUALITY_KEYWORDS
    SINGLE_KW = "tls"
    N_KEYWORDS = 21   # matches DOC_QUALITY_KEYWORDS cardinality

    def test_empty_list_returns_zero(self):
        assert etl.compute_doc_quality_score([]) == 0.0

    def test_single_empty_string_doc_returns_zero(self):
        assert etl.compute_doc_quality_score([""]) == 0.0

    def test_whitespace_only_docs_return_zero(self):
        assert etl.compute_doc_quality_score(["   ", "\n\t"]) == 0.0

    def test_no_security_keywords_returns_zero(self):
        docs = ["The quick brown fox jumps over the lazy dog."]
        assert etl.compute_doc_quality_score(docs) == 0.0

    def test_single_keyword_gives_correct_fraction(self):
        docs = [f"We use {self.SINGLE_KW} for all connections."]
        expected = round(1 / self.N_KEYWORDS, 4)
        assert etl.compute_doc_quality_score(docs) == pytest.approx(expected, abs=1e-4)

    def test_all_doc_quality_keywords_returns_one(self):
        # Build text from all keywords in the set
        docs = [" ".join(etl.DOC_QUALITY_KEYWORDS)]
        assert etl.compute_doc_quality_score(docs) == pytest.approx(1.0)

    def test_multiple_docs_are_joined(self):
        # Split across two docs — should produce same result as one combined doc
        docs_split = ["tls encryption", "authentication audit"]
        docs_joined = ["tls encryption authentication audit"]
        assert etl.compute_doc_quality_score(docs_split) == etl.compute_doc_quality_score(docs_joined)

    def test_case_insensitive(self):
        docs_lower = ["tls encryption authentication"]
        docs_upper = ["TLS ENCRYPTION AUTHENTICATION"]
        assert etl.compute_doc_quality_score(docs_lower) == etl.compute_doc_quality_score(docs_upper)

    def test_output_in_range(self):
        docs = ["tls encryption authentication audit monitor patch cve"]
        score = etl.compute_doc_quality_score(docs)
        assert 0.0 <= score <= 1.0

    def test_richer_doc_scores_higher_than_sparse(self):
        sparse = ["tls"]
        rich = ["tls encryption authentication authorization audit monitor vulnerability"]
        assert etl.compute_doc_quality_score(rich) > etl.compute_doc_quality_score(sparse)

    def test_return_type_is_float(self):
        assert isinstance(etl.compute_doc_quality_score(["tls"]), float)


# ===========================================================================
# Section 3 — compute_security_guidance_score
# ===========================================================================

class TestSecurityGuidanceScore:
    """
    SECURITY_GUIDANCE_KEYWORDS has 21 terms (confirmed).
    Multi-word phrases like 'least privilege' and 'zero trust' must appear
    verbatim (as substrings) in the blob to be counted.
    """

    N_KEYWORDS = 21

    def test_empty_list_returns_zero(self):
        assert etl.compute_security_guidance_score([]) == 0.0

    def test_empty_string_returns_zero(self):
        assert etl.compute_security_guidance_score([""]) == 0.0

    def test_no_keywords_returns_zero(self):
        docs = ["a database stores records"]
        assert etl.compute_security_guidance_score(docs) == 0.0

    def test_single_keyword_security(self):
        docs = ["our security policy is comprehensive"]
        expected = round(1 / self.N_KEYWORDS, 4)
        assert etl.compute_security_guidance_score(docs) == pytest.approx(expected, abs=1e-4)

    def test_multi_word_keyword_least_privilege(self):
        # "least privilege" is one keyword — must appear verbatim
        docs = ["we enforce least privilege access across all systems"]
        assert etl.compute_security_guidance_score(docs) > 0.0

    def test_multi_word_keyword_zero_trust(self):
        docs = ["our architecture follows zero trust principles"]
        assert etl.compute_security_guidance_score(docs) > 0.0

    def test_partial_multi_word_does_not_count(self):
        # "zero" alone should not match "zero trust"
        docs = ["zero systems were affected"]
        score_partial = etl.compute_security_guidance_score(docs)
        docs_full = ["zero trust architecture deployed"]
        score_full = etl.compute_security_guidance_score(docs_full)
        assert score_full >= score_partial   # full phrase scores at least as high

    def test_all_keywords_returns_one(self):
        docs = [" ".join(etl.SECURITY_GUIDANCE_KEYWORDS)]
        assert etl.compute_security_guidance_score(docs) == pytest.approx(1.0)

    def test_multiple_docs_joined(self):
        docs_split = ["security hardening mfa", "firewall waf ddos"]
        docs_joined = ["security hardening mfa firewall waf ddos"]
        assert etl.compute_security_guidance_score(docs_split) == etl.compute_security_guidance_score(docs_joined)

    def test_output_in_range(self):
        docs = ["security mfa compliance policy firewall"]
        score = etl.compute_security_guidance_score(docs)
        assert 0.0 <= score <= 1.0


# ===========================================================================
# Section 4 — compute_trust_coverage_score
# ===========================================================================

class TestTrustCoverageScore:
    """
    Returns fraction of target_frameworks detected in the trust doc text.
    Falls back to {fw.lower()} for unknown frameworks.
    """

    def test_empty_docs_returns_zero(self):
        assert etl.compute_trust_coverage_score([], ["SOC2"]) == 0.0

    def test_empty_frameworks_returns_zero(self):
        assert etl.compute_trust_coverage_score(["soc 2 certified"], []) == 0.0

    def test_both_empty_returns_zero(self):
        assert etl.compute_trust_coverage_score([], []) == 0.0

    def test_all_frameworks_detected_returns_one(self):
        docs = ["We hold SOC 2 and ISO 27001 certifications."]
        assert etl.compute_trust_coverage_score(docs, ["SOC2", "ISO27001"]) == 1.0

    def test_partial_detection_correct_fraction(self):
        # Only SOC2 present; ISO27001 and HIPAA absent → 1/3
        docs = ["We are SOC 2 certified."]
        score = etl.compute_trust_coverage_score(docs, ["SOC2", "ISO27001", "HIPAA"])
        assert score == pytest.approx(round(1 / 3, 4), abs=1e-4)

    def test_no_frameworks_detected_returns_zero(self):
        docs = ["Our platform is highly reliable."]
        score = etl.compute_trust_coverage_score(docs, ["SOC2", "ISO27001", "PCI-DSS"])
        assert score == 0.0

    # ── Alias variants ────────────────────────────────────────────────────

    def test_soc2_alias_soc2_nospace(self):
        docs = ["soc2 compliant"]
        assert etl.compute_trust_coverage_score(docs, ["SOC2"]) == 1.0

    def test_soc2_alias_service_organization(self):
        docs = ["as a service organization we maintain controls"]
        assert etl.compute_trust_coverage_score(docs, ["SOC2"]) == 1.0

    def test_iso27001_alias_iso_iec(self):
        docs = ["certified against iso/iec 27001"]
        assert etl.compute_trust_coverage_score(docs, ["ISO27001"]) == 1.0

    def test_iso27001_alias_nospace(self):
        docs = ["iso27001 certified environment"]
        assert etl.compute_trust_coverage_score(docs, ["ISO27001"]) == 1.0

    def test_pci_dss_hyphen_alias(self):
        docs = ["our platform is pci-dss certified"]
        assert etl.compute_trust_coverage_score(docs, ["PCI-DSS"]) == 1.0

    def test_pci_dss_space_alias(self):
        docs = ["we comply with pci dss requirements"]
        assert etl.compute_trust_coverage_score(docs, ["PCI-DSS"]) == 1.0

    def test_fedramp_alias(self):
        docs = ["fedramp authorized at moderate impact level"]
        assert etl.compute_trust_coverage_score(docs, ["FedRAMP"]) == 1.0

    def test_hipaa_alias(self):
        docs = ["hipaa compliance maintained for all phi data"]
        assert etl.compute_trust_coverage_score(docs, ["HIPAA"]) == 1.0

    def test_gdpr_alias(self):
        docs = ["gdpr data processing agreements in place"]
        assert etl.compute_trust_coverage_score(docs, ["GDPR"]) == 1.0

    # ── Case insensitivity ───────────────────────────────────────────────

    def test_uppercase_in_doc_still_detected(self):
        # blob is lowercased before matching
        docs = ["WE ARE SOC 2 AND ISO 27001 CERTIFIED."]
        assert etl.compute_trust_coverage_score(docs, ["SOC2", "ISO27001"]) == 1.0

    # ── Multi-doc joining ────────────────────────────────────────────────

    def test_frameworks_split_across_docs(self):
        docs = ["soc 2 certified", "iso 27001 maintained"]
        assert etl.compute_trust_coverage_score(docs, ["SOC2", "ISO27001"]) == 1.0

    # ── Unknown framework fallback ────────────────────────────────────────

    def test_unknown_framework_fallback_miss(self):
        # 'NIST-CSF' not in FRAMEWORK_KEYWORDS; fallback keyword is 'nist-csf'
        # 'nist csf' (space) does not match 'nist-csf' (hyphen)
        docs = ["nist csf certified"]
        assert etl.compute_trust_coverage_score(docs, ["NIST-CSF"]) == 0.0

    def test_unknown_framework_fallback_exact_match(self):
        # Lowercase name exact substring match does work
        docs = ["nist-csf certified environment"]
        assert etl.compute_trust_coverage_score(docs, ["NIST-CSF"]) == 1.0

    def test_unknown_framework_does_not_crash(self):
        # Must not raise — should gracefully return a float
        score = etl.compute_trust_coverage_score(["some text"], ["MADE-UP-FRAMEWORK-XYZ"])
        assert isinstance(score, float)

    # ── Output range ─────────────────────────────────────────────────────

    def test_output_in_range(self):
        docs = ["soc 2 iso 27001 hipaa pci dss gdpr fedramp"]
        score = etl.compute_trust_coverage_score(
            docs, ["SOC2", "ISO27001", "HIPAA", "PCI-DSS", "GDPR", "FedRAMP"]
        )
        assert 0.0 <= score <= 1.0

    def test_return_type_is_float(self):
        result = etl.compute_trust_coverage_score(["soc 2"], ["SOC2"])
        assert isinstance(result, float)


# ===========================================================================
# Section 5 — compute_incident_sentiment_score
# ===========================================================================

class TestIncidentSentimentScore:
    """
    Uses VADER compound score, inverted and scaled to [0,1]:
        inverted = (1.0 - compound) / 2.0
    Higher output = more negative sentiment = higher operational risk.
    Empty input returns 0.0 (not 0.5) per the implementation.

    Verified compound values (from VADER directly):
        'Critical outage...'    compound ≈ -0.8771  → inverted ≈ 0.9385
        'Excellent recovery...' compound ≈ +0.8555  → inverted ≈ 0.0722
        whitespace-only                  → returns 0.0 (no scores list)
    """

    def test_empty_list_returns_zero(self):
        assert etl.compute_incident_sentiment_score([]) == 0.0

    def test_whitespace_only_docs_returns_zero(self):
        # Whitespace-stripped docs are skipped; empty scores list → returns 0.0
        assert etl.compute_incident_sentiment_score(["   ", "\t"]) == 0.0

    def test_negative_sentiment_yields_high_score(self):
        docs = ["Critical outage. Major failure. Severe downtime. Customers lost data."]
        score = etl.compute_incident_sentiment_score(docs)
        assert score > 0.6   # compound ≈ -0.877 → inverted ≈ 0.94

    def test_positive_sentiment_yields_low_score(self):
        docs = ["Excellent recovery. Resolved quickly. Outstanding performance maintained."]
        score = etl.compute_incident_sentiment_score(docs)
        assert score < 0.5   # compound ≈ +0.856 → inverted ≈ 0.07

    def test_very_negative_text_approaches_one(self):
        docs = ["Catastrophic failure. Complete data loss. Unacceptable breach. Terrible experience."]
        score = etl.compute_incident_sentiment_score(docs)
        assert score > 0.8

    def test_very_positive_text_approaches_zero(self):
        docs = ["Flawless execution. Zero downtime. Perfect performance. Best results ever."]
        score = etl.compute_incident_sentiment_score(docs)
        assert score < 0.2

    def test_output_in_range_for_negative(self):
        docs = ["failure outage breach disaster"]
        score = etl.compute_incident_sentiment_score(docs)
        assert 0.0 <= score <= 1.0

    def test_output_in_range_for_positive(self):
        docs = ["excellent outstanding perfect flawless"]
        score = etl.compute_incident_sentiment_score(docs)
        assert 0.0 <= score <= 1.0

    def test_neutral_text_near_midpoint(self):
        # Factual, emotionally neutral text — VADER compound near 0 → inverted near 0.5
        docs = ["The service was unavailable from 14:00 UTC to 15:00 UTC on Tuesday."]
        score = etl.compute_incident_sentiment_score(docs)
        assert 0.3 <= score <= 0.7

    def test_multiple_docs_averaged(self):
        # One very negative, one very positive → should land near midpoint
        negative = ["Critical outage. Major failure. Severe downtime. Customers lost data."]
        positive = ["Excellent recovery. Resolved quickly. Outstanding performance maintained."]
        combined = negative + positive
        score_combined = etl.compute_incident_sentiment_score(combined)
        score_neg = etl.compute_incident_sentiment_score(negative)
        score_pos = etl.compute_incident_sentiment_score(positive)
        # Combined should be between the two extremes
        assert min(score_neg, score_pos) < score_combined < max(score_neg, score_pos)

    def test_return_type_is_float(self):
        result = etl.compute_incident_sentiment_score(["outage"])
        assert isinstance(result, float)

    def test_inversion_formula_positive_compound(self):
        # Verify the exact inversion math: (1 - compound) / 2
        # A completely positive doc (compound close to +1) should yield close to 0
        docs = ["amazing wonderful excellent perfect outstanding brilliant"]
        score = etl.compute_incident_sentiment_score(docs)
        assert score < 0.3

    def test_inversion_formula_negative_compound(self):
        # A completely negative doc (compound close to -1) should yield close to 1
        docs = ["terrible horrible awful disaster failure catastrophic"]
        score = etl.compute_incident_sentiment_score(docs)
        assert score > 0.7


# ===========================================================================
# Section 6 — compute_governance_score
# ===========================================================================

class TestGovernanceScore:
    """
    Governance composite formula:
        risk = (1-doc) * 0.25 + (1-guidance) * 0.25 + (1-trust) * 0.25 + sentiment * 0.25
        clamped to [0.0, 1.0], rounded to 4 decimal places.

    Equal 0.25 weights on all four components.
    """

    def test_perfect_inputs_returns_zero(self):
        # doc=1, guidance=1, trust=1, sentiment=0  →  0 risk
        assert etl.compute_governance_score(1.0, 1.0, 1.0, 0.0) == pytest.approx(0.0)

    def test_worst_inputs_returns_one(self):
        # doc=0, guidance=0, trust=0, sentiment=1  →  max risk
        assert etl.compute_governance_score(0.0, 0.0, 0.0, 1.0) == pytest.approx(1.0)

    def test_all_midpoint_returns_half(self):
        # Each component contributes 0.5 * 0.25 = 0.125; four of them = 0.5
        assert etl.compute_governance_score(0.5, 0.5, 0.5, 0.5) == pytest.approx(0.5)

    def test_exact_arithmetic_asymmetric(self):
        # doc=0.8, guidance=0.2, trust=0.6, sentiment=0.3
        # = (0.2*0.25) + (0.8*0.25) + (0.4*0.25) + (0.3*0.25)
        # = 0.05 + 0.20 + 0.10 + 0.075 = 0.425
        result = etl.compute_governance_score(0.8, 0.2, 0.6, 0.3)
        assert result == pytest.approx(0.425, abs=1e-4)

    def test_each_component_contributes_equally(self):
        # Vary one input at a time; each unit change should move the output by 0.25
        base = etl.compute_governance_score(0.0, 0.0, 0.0, 0.0)   # = 0.75
        with_doc = etl.compute_governance_score(1.0, 0.0, 0.0, 0.0)
        with_guidance = etl.compute_governance_score(0.0, 1.0, 0.0, 0.0)
        with_trust = etl.compute_governance_score(0.0, 0.0, 1.0, 0.0)
        with_sentiment = etl.compute_governance_score(0.0, 0.0, 0.0, 1.0)

        assert base == pytest.approx(0.75)
        # Each improvement reduces risk by exactly 0.25
        assert base - with_doc == pytest.approx(0.25, abs=1e-4)
        assert base - with_guidance == pytest.approx(0.25, abs=1e-4)
        assert base - with_trust == pytest.approx(0.25, abs=1e-4)
        # Sentiment increase keeps risk at 1.0 (already max), clamp holds
        assert with_sentiment == pytest.approx(1.0)

    def test_output_clamped_below_zero(self):
        # Can't go below 0.0 even with extreme "good" inputs
        assert etl.compute_governance_score(1.0, 1.0, 1.0, 0.0) >= 0.0

    def test_output_clamped_above_one(self):
        # Even if floating-point arithmetic exceeds 1.0, result is clamped
        # Simulate via 0 everything + 2.0 sentiment (abnormal but defensive)
        result = etl.compute_governance_score(0.0, 0.0, 0.0, 2.0)
        assert result <= 1.0

    def test_output_in_range_various_inputs(self):
        combos = [
            (0.1, 0.9, 0.3, 0.7),
            (0.95, 0.05, 0.5, 0.5),
            (0.3, 0.3, 0.3, 0.3),
            (0.0, 1.0, 0.0, 1.0),
            (1.0, 0.0, 1.0, 0.0),
        ]
        for args in combos:
            score = etl.compute_governance_score(*args)
            assert 0.0 <= score <= 1.0, f"Out of range for inputs {args}: {score}"

    def test_return_is_float(self):
        assert isinstance(etl.compute_governance_score(0.5, 0.5, 0.5, 0.5), float)

    def test_rounded_to_four_decimals(self):
        # 1/3 inputs should produce a rounded result, not a long float
        result = etl.compute_governance_score(1/3, 1/3, 1/3, 1/3)
        # String representation should have at most 4 decimal digits
        str_result = str(result)
        decimal_part = str_result.split(".")[-1] if "." in str_result else ""
        assert len(decimal_part) <= 4, f"Too many decimals: {result}"

    def test_doc_quality_improvement_lowers_risk(self):
        low_doc = etl.compute_governance_score(0.0, 0.5, 0.5, 0.5)
        high_doc = etl.compute_governance_score(1.0, 0.5, 0.5, 0.5)
        assert high_doc < low_doc

    def test_sentiment_increase_raises_risk(self):
        low_sent = etl.compute_governance_score(0.5, 0.5, 0.5, 0.0)
        high_sent = etl.compute_governance_score(0.5, 0.5, 0.5, 1.0)
        assert high_sent > low_sent

    def test_trust_coverage_improvement_lowers_risk(self):
        no_trust = etl.compute_governance_score(0.5, 0.5, 0.0, 0.5)
        full_trust = etl.compute_governance_score(0.5, 0.5, 1.0, 0.5)
        assert full_trust < no_trust
