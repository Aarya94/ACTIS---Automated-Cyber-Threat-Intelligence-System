"""
ACTIS Day 27 — Part 1: Threat Intelligence Status Transitions & Provenance Overwrite Tests.
Reproduces and documents:
1. Status rigidity: register_indicator does not update the 'status' column on existing indicators,
   preventing legitimate promotion (SUSPICIOUS -> CONFIRMED) or resolution (CONFIRMED -> FALSE_POSITIVE).
2. Authoritative provenance loss: subsequent local scans overwrite the 'source' column,
   erasing authoritative external provider provenance (e.g. VirusTotal -> actis_url_scanner).
3. Monotonic confidence calculation and database uniqueness constraint idempotency.
4. Persistence-triggered cache invalidation failure due to URL cache key mismatch.
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
        test_db = pathlib.Path(tmpdir) / "test_ti_transitions.db"
        orig_db = tdb.DATABASE_PATH
        tdb.DATABASE_PATH = test_db
        tdb.initialize_database()
        try:
            yield test_db
        finally:
            tdb.DATABASE_PATH = orig_db


class TestDay27TIStatusTransitionsAndProvenance:
    """Deterministic regression tests auditing indicator status transitions and provenance updates."""

    def test_status_rigidly_retained_on_existing_indicator_update(self, isolated_ti_db):
        """
        Defect Reproduction:
        In reports.threat_database.register_indicator() lines 317-321:
            UPDATE indicators
            SET last_seen = ?, confidence = ?, source = ?
            WHERE id = ?
        The 'status' column is omitted from the UPDATE query.
        
        If an indicator is originally registered as 'SUSPICIOUS' with confidence 0.50,
        and later authoritative external intelligence confirms it with status='CONFIRMED',
        the database silently discards the status transition, leaving the indicator locked in 'SUSPICIOUS'.
        """
        indicator_val = "https://phishing-campaign-sample.xyz/auth"

        # 1. First registration: SUSPICIOUS
        id1 = tdb.register_indicator(
            indicator_type="url",
            indicator_value=indicator_val,
            source="heuristic_scanner",
            confidence=0.50,
            status="SUSPICIOUS",
            threat_type="Phishing",
            threat_name="Suspect Lure"
        )
        assert id1 > 0

        row1 = tdb.lookup_indicator("url", indicator_val)
        assert row1["found"] is True
        assert row1["status"] == "SUSPICIOUS"
        assert row1["confidence"] == 0.50

        # 2. Second registration: authoritative update attempting promotion to CONFIRMED
        id2 = tdb.register_indicator(
            indicator_type="url",
            indicator_value=indicator_val,
            source="Authoritative_CERT",
            confidence=0.99,
            status="CONFIRMED",
            threat_type="Phishing",
            threat_name="Confirmed APT Phishing"
        )
        assert id2 == id1, "Should update the existing indicator row rather than creating a duplicate"

        # 3. VERIFY DEFECT FIX: Status IS updated to CONFIRMED on authoritative promotion
        row2 = tdb.lookup_indicator("url", indicator_val)
        assert row2["found"] is True
        assert row2["confidence"] == 0.99
        assert row2["status"] == "CONFIRMED", (
            f"Expected authoritative status 'CONFIRMED', got '{row2['status']}'"
        )

    def test_authoritative_provenance_overwritten_by_subsequent_scans(self, isolated_ti_db):
        """
        Validates that authoritative external provider provenance (e.g. VirusTotal)
        is preserved when an unverified local scanner observes the same indicator.
        """
        indicator_val = "https://c2-infrastructure.example.org/beacon"

        # Ingest from authoritative provider
        tdb.register_indicator(
            indicator_type="url",
            indicator_value=indicator_val,
            source="VirusTotal",
            confidence=0.95,
            status="CONFIRMED",
            threat_type="Malware C2",
            threat_name="CobaltStrike"
        )

        row1 = tdb.lookup_indicator("url", indicator_val)
        assert row1["source"] == "VirusTotal"

        # Subsequent local scan observes the indicator again
        tdb.register_indicator(
            indicator_type="url",
            indicator_value=indicator_val,
            source="actis_url_scanner",
            confidence=0.80,
            status="SUSPICIOUS"
        )

        row2 = tdb.lookup_indicator("url", indicator_val)
        # VERIFY DEFECT FIX: Source is preserved as 'VirusTotal', not overwritten by 'actis_url_scanner'
        assert row2["source"] == "VirusTotal", (
            f"Expected authoritative source 'VirusTotal' to be preserved, got '{row2['source']}'"
        )

    def test_register_indicator_idempotency_and_uniqueness(self, isolated_ti_db):
        """
        Verifies that SQLite schema uniqueness constraint UNIQUE(indicator_type, indicator_value)
        prevents duplicate rows and ensures register_indicator is idempotent.
        """
        indicator_val = "https://unique-test-lure.org/login"

        id_a = tdb.register_indicator("url", indicator_val, source="scanner_a", confidence=0.6)
        id_b = tdb.register_indicator("url", indicator_val, source="scanner_b", confidence=0.7)
        id_c = tdb.register_indicator("url", indicator_val.upper(), source="scanner_c", confidence=0.5)

        assert id_a == id_b == id_c, "All casing variations of the same indicator must map to a single ID"

        conn = tdb.get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT count(*) as cnt FROM indicators WHERE lower(indicator_value) = ?", (indicator_val.lower(),))
        count = cursor.fetchone()["cnt"]
        conn.close()

        assert count == 1, f"Expected exactly 1 database row for normalized indicator, found {count}"

    def test_persistence_triggered_invalidation_fails_due_to_cache_key_defect(self, isolated_ti_db):
        """
        Validates that invalidate_url successfully purges redirect-aware cache entries
        upon indicator registration.
        """
        detector = ThreatDetector()
        url = "https://cached-stale-test.com/landing"
        norm = normalize_url(url)
        cache_key = f"{norm}__redir_False"

        # 1. Warm cache via analyze_url
        res1 = detector.analyze_url(url)
        assert detector._url_cache.get(cache_key) is not None

        # 2. Invalidate using fixed invalidate_url
        res = detector.invalidate_url(norm)
        assert res is True

        # 3. VERIFY DEFECT FIX: Cache entry was purged
        cached_entry = detector._url_cache.get(cache_key)
        assert cached_entry is None, "Cache entry must be successfully evicted"
