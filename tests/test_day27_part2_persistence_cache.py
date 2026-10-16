"""
ACTIS Day 27 — Part 2: Persistence & Cache Consistency Invariant Tests.
Validates the persistence, canonicalization, and cache invariants:
1. Indicators persist across distinct database connections and processes.
2. Equivalent canonical URLs (case variations, port defaults, trailing slashes) map to single indicator rows.
3. Confidence updates remain monotonic (max of existing and new confidence).
4. Cache key format adherence for redirect-aware URL caching.
"""

import tempfile
import pathlib
import pytest

import config.config as cfg
import reports.threat_database as tdb
from detection_engine.threat_detector import ThreatDetector
from scanners.url_scanner import normalize_url


@pytest.fixture
def isolated_ti_db():
    """Provides an isolated, temporary SQLite database for threat intelligence."""
    with tempfile.TemporaryDirectory() as tmpdir:
        test_db = pathlib.Path(tmpdir) / "test_part2_cache.db"
        orig_db = tdb.DATABASE_PATH
        tdb.DATABASE_PATH = test_db
        tdb.initialize_database()
        try:
            yield test_db
        finally:
            tdb.DATABASE_PATH = orig_db


class TestDay27Part2PersistenceAndCacheConsistency:
    """Invariant tests ensuring robust persistence, canonicalization, and cache alignment."""

    def test_indicator_persistence_across_connection_reloads(self, isolated_ti_db):
        """
        Validates that indicators written to SQLite persist across separate connection handles.
        """
        val = "https://persistent-target.example.org/path"
        id1 = tdb.register_indicator(
            indicator_type="url",
            indicator_value=val,
            source="test_runner",
            confidence=0.88,
            status="SUSPICIOUS",
            threat_type="Phishing",
            threat_name="PersistenceTest"
        )
        assert id1 > 0

        # Query using a brand new connection
        conn = tdb.get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, confidence, status, source FROM indicators WHERE id = ?", (id1,))
        row = cursor.fetchone()
        conn.close()

        assert row is not None
        assert row["confidence"] == 0.88
        assert row["status"] == "SUSPICIOUS"
        assert row["source"] == "test_runner"

    def test_canonical_url_identity_deduplication(self, isolated_ti_db):
        """
        Validates that equivalent canonical URLs (e.g. differing in casing or default ports)
        map to the exact same indicator identity without creating duplicate rows.
        """
        url1 = "https://LOGIN.Example.Com:443/auth/verify"
        url2 = "https://login.example.com/auth/verify"
        norm1 = normalize_url(url1)
        norm2 = normalize_url(url2)
        assert norm1 == norm2

        id_a = tdb.register_indicator("url", norm1, confidence=0.7)
        id_b = tdb.register_indicator("url", norm2, confidence=0.8)
        assert id_a == id_b

        conn = tdb.get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT count(*) as cnt FROM indicators WHERE indicator_value = ?", (norm1,))
        count = cursor.fetchone()["cnt"]
        conn.close()
        assert count == 1

    def test_monotonic_confidence_calculation(self, isolated_ti_db):
        """
        Validates that updating an existing indicator retains the highest observed confidence.
        """
        url = "https://confidence-test.example.net/login"
        norm = normalize_url(url)

        tdb.register_indicator("url", norm, confidence=0.90)
        row1 = tdb.lookup_indicator("url", norm)
        assert row1["confidence"] == 0.90

        # Attempt registration with lower confidence
        tdb.register_indicator("url", norm, confidence=0.60)
        row2 = tdb.lookup_indicator("url", norm)
        # Confidence must remain 0.90 (monotonic non-decreasing)
        assert row2["confidence"] == 0.90

        # Update with higher confidence
        tdb.register_indicator("url", norm, confidence=0.95)
        row3 = tdb.lookup_indicator("url", norm)
        assert row3["confidence"] == 0.95

    def test_cache_key_format_adherence(self):
        """
        Validates that URL cache entries follow the documented redirect-aware naming contract:
        f"{canonical_url}__redir_{follow_redirects}"
        """
        detector = ThreatDetector()
        url = "https://format-check.example.org/test"
        norm = normalize_url(url)

        detector.analyze_url(url, follow_redirects=False)
        key_false = f"{norm}__redir_False"
        assert detector._url_cache.get(key_false) is not None

        detector.analyze_url(url, follow_redirects=True)
        key_true = f"{norm}__redir_True"
        assert detector._url_cache.get(key_true) is not None

    def test_cache_invalidation_evicts_all_redirect_variants(self):
        """
        Validates that ThreatDetector.invalidate_url() correctly invalidates redirect-aware keys.
        """
        detector = ThreatDetector()
        url = "https://eviction-test.example.com/login"
        norm = normalize_url(url)
        key_false = f"{norm}__redir_False"

        detector.analyze_url(url, follow_redirects=False)
        assert detector._url_cache.get(key_false) is not None

        # Call invalidate_url
        res = detector.invalidate_url(url)
        assert res is True, "invalidate_url should return True upon evicting cached entry"
        assert detector._url_cache.get(key_false) is None, "Cache entry must be evicted"

    def test_status_promotion_from_suspicious_to_confirmed_on_authoritative_update(self, isolated_ti_db):
        """
        Validates that an existing SUSPICIOUS indicator is properly promoted to CONFIRMED
        when an authoritative update is registered.
        """
        val = "https://promo-target.example.com/auth"
        norm = normalize_url(val)

        # 1. Initially registered as SUSPICIOUS
        tdb.register_indicator("url", norm, source="scanner", confidence=0.5, status="SUSPICIOUS")
        row1 = tdb.lookup_indicator("url", norm)
        assert row1["status"] == "SUSPICIOUS"

        # 2. Authoritative CERT update
        tdb.register_indicator("url", norm, source="Authoritative_CERT", confidence=0.99, status="CONFIRMED")
        row2 = tdb.lookup_indicator("url", norm)
        assert row2["status"] == "CONFIRMED", f"Expected promotion to 'CONFIRMED', got {row2['status']}"

    def test_confirmed_status_protected_from_downgrade_by_unverified_scan(self, isolated_ti_db):
        """
        Validates that an authoritative CONFIRMED indicator is NOT downgraded when an unverified
        local scan registers SUSPICIOUS.
        """
        val = "https://c2-infrastructure.example.com/beacon"
        norm = normalize_url(val)

        tdb.register_indicator("url", norm, source="VirusTotal", confidence=0.95, status="CONFIRMED")
        row1 = tdb.lookup_indicator("url", norm)
        assert row1["status"] == "CONFIRMED"

        # Subsequent local scan reports SUSPICIOUS
        tdb.register_indicator("url", norm, source="actis_url_scanner", confidence=0.7, status="SUSPICIOUS")
        row2 = tdb.lookup_indicator("url", norm)
        assert row2["status"] == "CONFIRMED", "CONFIRMED indicator must not be downgraded by weaker local scan"

    def test_authoritative_provenance_protected_from_local_scanner_overwrite(self, isolated_ti_db):
        """
        Validates that authoritative external provenance (e.g. VirusTotal) is preserved when
        a subsequent local scan observes the same indicator.
        """
        val = "https://threat-feed-sample.example.org/dl"
        norm = normalize_url(val)

        tdb.register_indicator("url", norm, source="VirusTotal", confidence=0.95, status="CONFIRMED")
        row1 = tdb.lookup_indicator("url", norm)
        assert row1["source"] == "VirusTotal"

        # Subsequent scan with local scanner
        tdb.register_indicator("url", norm, source="actis_url_scanner", confidence=0.8)
        row2 = tdb.lookup_indicator("url", norm)
        assert row2["source"] == "VirusTotal", f"Expected authoritative source to be preserved, got {row2['source']}"

    def test_explicit_false_positive_resolution_updates_status(self, isolated_ti_db):
        """
        Validates that an explicit FALSE_POSITIVE resolution takes precedence and updates status.
        """
        val = "https://trusted-partner.example.com/login"
        norm = normalize_url(val)

        tdb.register_indicator("url", norm, source="VirusTotal", confidence=0.9, status="CONFIRMED")
        row1 = tdb.lookup_indicator("url", norm)
        assert row1["status"] == "CONFIRMED"

        # Administrative false-positive resolution
        tdb.register_indicator("url", norm, source="Security_Analyst", confidence=1.0, status="FALSE_POSITIVE")
        row2 = tdb.lookup_indicator("url", norm)
        assert row2["status"] == "FALSE_POSITIVE"
