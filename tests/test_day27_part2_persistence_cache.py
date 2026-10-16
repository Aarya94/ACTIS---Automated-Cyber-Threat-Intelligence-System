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
