"""
ACTIS Day 27 — Part 1: Indicator Trust, Provenance & Cache Consistency Tests.
Reproduces and documents:
1. Cache invalidation key mismatch in ThreatDetector.invalidate_url().
2. Unverified ML / heuristic prediction escalation to "CONFIRMED" Threat Intelligence.
3. Fast-track bypass on subsequent scans triggered by self-persisted indicators.
4. Collapsed provenance in indicators table persistence.
"""

import tempfile
import pathlib
import pytest
from unittest.mock import patch

import config.config as cfg
import reports.threat_database as tdb
from detection_engine.threat_detector import ThreatDetector
from scanners.url_scanner import normalize_url
from detection_engine.risk_engine import RiskEngine


@pytest.fixture
def isolated_ti_db():
    """Provides an isolated, temporary SQLite database for threat intelligence."""
    with tempfile.TemporaryDirectory() as tmpdir:
        test_db = pathlib.Path(tmpdir) / "test_threat_intel.db"
        orig_db = tdb.DATABASE_PATH
        tdb.DATABASE_PATH = test_db
        tdb.initialize_database()
        try:
            yield test_db
        finally:
            tdb.DATABASE_PATH = orig_db


class TestDay27IndicatorTrustAndCacheConsistency:
    """Deterministic regression tests capturing baseline indicator trust and cache behavior."""

    def test_cache_invalidation_key_mismatch_reproduction(self, isolated_ti_db):
        """
        Defect Reproduction:
        ThreatDetector.invalidate_url() canonicalizes the URL via ThreatLookup._canonicalize_url(url),
        which produces 'https://example-test.com/login'.
        However, ThreatDetector.analyze_url() stores the entry under:
        f"{canonical_url}__redir_{follow_redirects}" (e.g. 'https://example-test.com/login__redir_False').
        
        As a result, invalidate_url() fails to match the key, returns False, and the stale cache
        entry remains active in memory.
        """
        detector = ThreatDetector()
        test_url = "https://example-test.com/login"
        canonical_key = normalize_url(test_url)
        expected_cache_key = f"{canonical_key}__redir_False"

        # 1. Warm cache
        result1 = detector.analyze_url(test_url, follow_redirects=False)
        assert result1 is not None
        assert detector._url_cache.size >= 1

        # Confirm the entry is stored with the __redir_False suffix
        assert detector._url_cache.get(expected_cache_key) is not None
        # Confirm lookup without suffix returns None
        assert detector._url_cache.get(canonical_key) is None

        # 2. Invalidate using fixed implementation
        invalidation_result = detector.invalidate_url(test_url)

        # 3. VERIFY DEFECT FIX: Invalidation returns True and successfully evicts the entry
        assert invalidation_result is True, (
            "Expected invalidate_url to return True upon invalidating redirect-aware key variants"
        )

        # 4. Confirm the entry was evicted
        cached_entry = detector._url_cache.get(expected_cache_key)
        assert cached_entry is None, "Cache entry should be evicted after invalidate_url()"

    def test_unverified_heuristic_ml_escalates_to_confirmed_ti(self, isolated_ti_db):
        """
        Defect Reproduction:
        When a high-scoring synthetic URL (e.g., raw IP address with multiple banking/phishing keywords)
        is analyzed by ThreatDetector.analyze_url(), RiskEngine assigns CRITICAL risk (100.0).
        
        ThreatDetector.analyze_url() lines 517-530 then automatically registers the indicator in SQLite
        with status='CONFIRMED' because risk_level == 'CRITICAL':
            status = 'SUSPICIOUS' if risk_res['risk_level'] != 'CRITICAL' else 'CONFIRMED'
            register_indicator(canonical_url, status=status, source='actis_url_scanner', ...)
            
        This promotes an unverified statistical / heuristic prediction to authoritative CONFIRMED TI
        without human review or external threat provider corroboration.
        """
        detector = ThreatDetector()
        high_risk_url = "http://198.51.100.10:8080/login/verify/account/update/secure/banking/signin/webscr?token=xyz"
        norm_url = normalize_url(high_risk_url)

        # Ensure database is clean initially
        pre_ind = tdb.lookup_indicator("url", norm_url)
        assert pre_ind["found"] is False

        # Run analysis (offline)
        res = detector.analyze_url(high_risk_url)

        assert res["risk_level"] == "CRITICAL"
        assert res["score"] == 100.0

        # Query SQLite to inspect persisted indicator status
        post_ind = tdb.lookup_indicator("url", norm_url)
        assert post_ind["found"] is True
        
        # VERIFY DEFECT FIX: Indicator is registered as SUSPICIOUS, NOT promoted to CONFIRMED
        assert post_ind["status"] == "SUSPICIOUS", (
            f"Expected status 'SUSPICIOUS' reflecting unverified engine alert, got {post_ind['status']}"
        )
        assert post_ind["source"] == "actis_url_scanner"

    def test_escalated_indicator_bypasses_multi_attribute_scoring_on_rescan(self, isolated_ti_db):
        """
        Validates that authoritative intelligence with status='CONFIRMED' (e.g. from an authoritative provider)
        retrieves is_known_malicious=True and triggers the fast-track override, whereas
        engine-generated detections remain 'SUSPICIOUS'.
        """
        # Step 1: Pre-populate authoritative intelligence in database
        test_url = "http://198.51.100.10:8080/login/verify/account/update/secure/banking/signin/webscr?token=xyz"
        norm_url = normalize_url(test_url)

        tdb.register_indicator(
            indicator_type="url",
            indicator_value=norm_url,
            source="Authoritative_CERT",
            confidence=1.0,
            status="CONFIRMED",
            threat_type="Phishing",
            threat_name="Authoritative Confirmed Phish"
        )

        # Verify indicator exists in DB as CONFIRMED
        ind = tdb.lookup_indicator("url", norm_url)
        assert ind["found"] is True
        assert ind["status"] == "CONFIRMED"

        # Step 2: Fresh detector instance (no in-memory cache)
        detector2 = ThreatDetector()
        assert detector2._url_cache.size == 0

        # Lookup directly through ThreatLookup to verify contract state
        from threat_intelligence.threat_lookup import ThreatLookup
        lookup_res = ThreatLookup().lookup_url(test_url)
        assert lookup_res["is_known_threat"] is True
        assert lookup_res["outcome_state"] == "FOUND_MALICIOUS"
        assert lookup_res["local_intel"]["status"] == "CONFIRMED"

        # Scan with fresh detector
        res2 = detector2.analyze_url(test_url)

        # VERIFY: Fast-track bypass for authoritative CONFIRMED threat
        assert res2["score"] == 100.0
        assert res2["risk_level"] == "CRITICAL"
        assert res2["is_threat"] is True
        assert res2["threat_intel"]["is_known_threat"] is True
        assert res2["threat_intel"]["local_intel"]["status"] == "CONFIRMED"

    def test_ti_provenance_collapse_in_sqlite_persistence(self, isolated_ti_db):
        """
        Audits provenance preservation in the indicators table schema.
        Verifies that:
        1. Model architecture (RandomForest) and model version are NOT recorded in indicators table.
        2. Threat engine heuristic source is collapsed into generic string 'ACTIS_DETECTION_ENGINE'.
        3. No distinction exists in the schema between external authoritative threat intel
           and internal heuristic detections.
        """
        norm_val = "https://phishing-lure-bank.example.com/login"
        tdb.register_indicator(
            indicator_type="url",
            indicator_value=norm_val,
            source="ACTIS_DETECTION_ENGINE",
            confidence=0.85,
            status="SUSPICIOUS",
            threat_type="Phishing",
            threat_name="URL_Phishing_Heuristic"
        )

        ind = tdb.lookup_indicator("url", norm_val)
        assert ind["found"] is True
        # Check available fields in the returned row
        assert "source" in ind
        assert ind["source"] == "ACTIS_DETECTION_ENGINE"
        # Schema does not maintain model_name, model_version, or verification_authority
        assert "model_name" not in ind
        assert "model_version" not in ind
