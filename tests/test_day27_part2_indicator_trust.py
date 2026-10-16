"""
ACTIS Day 27 — Part 2: Indicator Trust & Provenance Invariant Tests.
Validates the trust principles established in Part 1 audit:
1. Local 'SUSPICIOUS' indicators must not trigger the is_known_malicious fast-track override.
2. Authoritative 'CONFIRMED' intelligence from external providers/analysts retains fast-track protection.
3. Provider unavailability and unknown status must remain explicitly distinct from clean/benign verdicts.
4. Machine learning inference outputs remain typed as ML evidence and are distinguishable from TI.
"""

import tempfile
import pathlib
import pytest

import config.config as cfg
import reports.threat_database as tdb
from detection_engine.threat_detector import ThreatDetector
from scanners.url_scanner import normalize_url
from threat_intelligence.threat_lookup import (
    ThreatLookup,
    OUTCOME_FOUND_MALICIOUS,
    OUTCOME_FOUND_SUSPICIOUS,
    OUTCOME_FOUND_BENIGN,
    OUTCOME_NOT_FOUND,
    OUTCOME_PROVIDER_UNAVAILABLE,
)
from detection_engine.threat_intel_contract import ThreatIntelVerdict, IndicatorType


@pytest.fixture
def isolated_ti_db():
    """Provides an isolated, temporary SQLite database for threat intelligence."""
    with tempfile.TemporaryDirectory() as tmpdir:
        test_db = pathlib.Path(tmpdir) / "test_part2_trust.db"
        orig_db = tdb.DATABASE_PATH
        tdb.DATABASE_PATH = test_db
        tdb.initialize_database()
        try:
            yield test_db
        finally:
            tdb.DATABASE_PATH = orig_db


class TestDay27Part2IndicatorTrustInvariants:
    """Invariant tests ensuring unverified predictions cannot escalate to authoritative TI."""

    def test_suspicious_indicator_does_not_trigger_fast_track_critical_override(self, isolated_ti_db):
        """
        Trust Principle:
        A 'SUSPICIOUS' indicator represents an uncorroborated alert.
        On subsequent scans, it must produce outcome_state=FOUND_SUSPICIOUS and
        must NOT trigger is_known_malicious=True or the 100.0 CRITICAL fast-track override.
        """
        test_url = "https://unverified-alert-target.example.org/verify"
        norm_url = normalize_url(test_url)

        # Pre-seed as SUSPICIOUS
        tdb.register_indicator(
            indicator_type="url",
            indicator_value=norm_url,
            source="actis_url_scanner",
            confidence=0.75,
            status="SUSPICIOUS",
            threat_type="Phishing",
            threat_name="Unverified Phishing Alert"
        )

        lookup = ThreatLookup()
        lookup_res = lookup.lookup_url(test_url)

        assert lookup_res["is_known_threat"] is True
        assert lookup_res["outcome_state"] == OUTCOME_FOUND_SUSPICIOUS
        # Primary evidence verdict is SUSPICIOUS, not MALICIOUS
        assert lookup_res["primary_evidence"].verdict == ThreatIntelVerdict.SUSPICIOUS
        assert lookup_res["primary_evidence"].is_confirmed_threat is False

    def test_confirmed_authoritative_intelligence_retains_fast_track(self, isolated_ti_db):
        """
        Trust Principle:
        Authoritative external intelligence (e.g. VirusTotal, CERT advisory) with status='CONFIRMED'
        correctly produces outcome_state=FOUND_MALICIOUS and is_confirmed_threat=True.
        """
        test_url = "https://known-c2-malware.example.com/payload.exe"
        norm_url = normalize_url(test_url)

        tdb.register_indicator(
            indicator_type="url",
            indicator_value=norm_url,
            source="VirusTotal",
            confidence=0.99,
            status="CONFIRMED",
            threat_type="Malware C2",
            threat_name="Emotet C2"
        )

        lookup = ThreatLookup()
        lookup_res = lookup.lookup_url(test_url)

        assert lookup_res["is_known_threat"] is True
        assert lookup_res["outcome_state"] == OUTCOME_FOUND_MALICIOUS
        assert lookup_res["primary_evidence"].verdict == ThreatIntelVerdict.MALICIOUS
        assert lookup_res["primary_evidence"].is_confirmed_threat is True

    def test_missing_or_unavailable_intelligence_does_not_imply_benign(self, isolated_ti_db):
        """
        Trust Principle:
        A query that is not found or where the provider is unavailable must NEVER
        be represented as CLEAN/benign. Missing evidence != evidence of absence.
        """
        lookup = ThreatLookup()

        # 1. Not Found
        res_not_found = lookup.lookup_indicator("https://unknown-domain-test.example.net/page", IndicatorType.URL)
        assert res_not_found["outcome_state"] == OUTCOME_NOT_FOUND
        assert res_not_found["primary_evidence"].verdict == ThreatIntelVerdict.UNKNOWN
        assert res_not_found["primary_evidence"].verdict != ThreatIntelVerdict.CLEAN

        # 2. Unavailable Provider
        unavail_ev = lookup.lookup_indicator_multi_provider("https://any-url.com", IndicatorType.URL, provider_names=["NonExistentProvider"])
        assert unavail_ev["outcome_state"] in (OUTCOME_NOT_FOUND, OUTCOME_PROVIDER_UNAVAILABLE, "QUERY_SKIPPED")
        assert unavail_ev["aggregated_evidence"].verdict != ThreatIntelVerdict.CLEAN

    def test_ml_evidence_distinguishable_from_threat_intelligence(self):
        """
        Trust Principle:
        Machine learning predictions must remain structured as probabilistic ML evidence
        and must not be masqueraded as deterministic threat intelligence indicators.
        """
        detector = ThreatDetector()
        res = detector.analyze_url("https://suspicious-test-phish-domain.org/login")

        # Result dictionary clearly segregates layers
        assert "ml_result" in res
        assert "threat_intel" in res
        assert "heuristic_result" in res

        # ML result contains float probability, not a TI status
        assert "probability" in res["ml_result"]
        assert isinstance(res["ml_result"]["probability"], float)

        # Threat intel outcome is distinct from ML
        ti = res["threat_intel"]
        assert "outcome_state" in ti
        assert ti["outcome_state"] in (OUTCOME_NOT_FOUND, OUTCOME_FOUND_BENIGN, OUTCOME_FOUND_SUSPICIOUS, OUTCOME_FOUND_MALICIOUS)
