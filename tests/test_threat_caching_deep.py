"""
ACTIS Day 21 Deep Integration Tests: Threat Intelligence Caching Subsystem
Comprehensive validation of bounded LRU capacity, TTL expiration, deterministic clock injection,
indicator type collision prevention, provider failure isolation, cache invalidation,
thread safety, offline resilience, and ThreatDetector scan cache integration.
"""

import time
import threading
import pytest
from unittest.mock import MagicMock, patch
from pathlib import Path
from typing import Optional, Dict, Any, List

from detection_engine.threat_intel_contract import (
    ThreatIntelEvidence,
    ThreatIntelVerdict,
    IndicatorType,
)
from threat_intelligence.threat_cache import (
    ThreatIntelligenceCache,
    LRUTTLCache,
    CacheEntry,
)
from threat_intelligence.provider_base import BaseThreatClient
from threat_intelligence.threat_lookup import (
    ThreatLookup,
    OUTCOME_FOUND_MALICIOUS,
    OUTCOME_FOUND_SUSPICIOUS,
    OUTCOME_FOUND_BENIGN,
    OUTCOME_NOT_FOUND,
    OUTCOME_PROVIDER_UNAVAILABLE,
    OUTCOME_REQUEST_TIMEOUT,
    OUTCOME_INVALID_RESPONSE,
    OUTCOME_QUERY_SKIPPED,
)
from detection_engine.threat_detector import ThreatDetector
from reports.threat_database import (
    register_indicator,
    lookup_indicator,
)


class MockClock:
    """Deterministic injectable clock for sub-millisecond TTL testing."""

    def __init__(self, start_time: float = 1000.0):
        self._current_time = float(start_time)

    def __call__(self) -> float:
        return self._current_time

    def advance(self, seconds: float):
        self._current_time += float(seconds)


class DummyMockProvider(BaseThreatClient):
    """Deterministic configurable provider adapter for testing."""

    def __init__(self, name: str = "TestProvider", verdict: ThreatIntelVerdict = ThreatIntelVerdict.MALICIOUS, confidence: float = 0.9):
        super().__init__(
            provider_name=name,
            supported_types={IndicatorType.SHA256, IndicatorType.MD5, IndicatorType.URL, IndicatorType.DOMAIN, IndicatorType.IP_ADDRESS},
            timeout=2.0
        )
        self.mock_verdict = verdict
        self.mock_confidence = confidence
        self.lookup_call_count = 0

    def is_configured(self) -> bool:
        return True

    def lookup(self, indicator: str, indicator_type: IndicatorType, timeout: Optional[float] = None) -> ThreatIntelEvidence:
        self.lookup_call_count += 1
        if self.mock_verdict == ThreatIntelVerdict.UNAVAILABLE:
            return ThreatIntelEvidence.unavailable(
                indicator=indicator,
                reason="Simulated connection timeout",
                indicator_type=indicator_type,
                provider=self.provider_name
            )
        return ThreatIntelEvidence(
            indicator=indicator,
            indicator_type=indicator_type,
            verdict=self.mock_verdict,
            confidence=self.mock_confidence,
            threat_type="Test Threat",
            provider=self.provider_name,
            is_confirmed_threat=(self.mock_verdict == ThreatIntelVerdict.MALICIOUS),
            raw_data={"call_id": self.lookup_call_count}
        )


# =====================================================================
# 1. LRUTTLCache Generic Unit Tests
# =====================================================================

class TestLRUTTLCache:
    """Verifies bounded capacity, LRU eviction, TTL expiration, and thread safety."""

    def test_lru_eviction_when_capacity_reached(self):
        clock = MockClock(100.0)
        cache = LRUTTLCache(max_size=3, default_ttl_seconds=60.0, clock=clock)

        cache.set("k1", "v1")
        cache.set("k2", "v2")
        cache.set("k3", "v3")
        assert cache.size == 3
        assert cache.get("k1") == "v1"

        # Access k1 so k2 becomes the least recently used
        assert cache.get("k1") == "v1"

        # Add k4 -> should evict k2
        cache.set("k4", "v4")
        assert cache.size == 3
        assert cache.get("k2") is None
        assert cache.get("k1") == "v1"
        assert cache.get("k3") == "v3"
        assert cache.get("k4") == "v4"

        stats = cache.get_stats()
        assert stats["evictions_lru"] == 1
        assert stats["max_size"] == 3

    def test_ttl_expiration_with_injected_clock(self):
        clock = MockClock(500.0)
        cache = LRUTTLCache(max_size=10, default_ttl_seconds=30.0, clock=clock)

        cache.set("alpha", "data_a")
        assert cache.get("alpha") == "data_a"

        # Advance 29s -> still valid
        clock.advance(29.0)
        assert cache.get("alpha") == "data_a"

        # Advance 2s (total 31s) -> expired
        clock.advance(2.0)
        assert cache.get("alpha") is None
        assert "alpha" not in cache

        stats = cache.get_stats()
        assert stats["evictions_ttl"] >= 1

    def test_dict_interface_compatibility(self):
        cache = LRUTTLCache(max_size=5, default_ttl_seconds=60.0)
        cache["key1"] = {"status": "ok"}
        assert "key1" in cache
        assert cache["key1"]["status"] == "ok"
        assert len(cache) == 1

        del cache["key1"]
        assert "key1" not in cache

    def test_invalidate_and_clear(self):
        cache = LRUTTLCache(max_size=10, default_ttl_seconds=60.0)
        cache.set("target_a", 100)
        cache.set("target_b", 200)

        assert cache.invalidate("target_a") is True
        assert cache.invalidate("target_nonexistent") is False
        assert cache.get("target_a") is None
        assert cache.get("target_b") == 200

        cache.clear()
        assert cache.size == 0
        assert cache.get("target_b") is None


# =====================================================================
# 2. ThreatIntelligenceCache Core Behaviors
# =====================================================================

class TestThreatIntelligenceCache:
    """Verifies typed caching, indicator type collision prevention, and failure semantics."""

    def test_cache_hit_avoids_repeated_lookup(self):
        clock = MockClock(100.0)
        cache = ThreatIntelligenceCache(default_ttl_seconds=60.0, max_entries=100, clock=clock)
        provider = DummyMockProvider()
        lookup = ThreatLookup(external_client=provider, cache=cache)
        lookup.available_providers = [provider]

        with patch("threat_intelligence.threat_lookup.db_lookup_indicator", return_value={"found": False}):
            res1 = lookup.lookup_indicator("http://example-test.com", IndicatorType.URL, query_external=True)
            assert provider.lookup_call_count == 1
            assert res1["outcome_state"] == OUTCOME_FOUND_MALICIOUS

            res2 = lookup.lookup_indicator("http://example-test.com", IndicatorType.URL, query_external=True)
            assert provider.lookup_call_count == 1  # No second call!
            assert res2["external_intel"].get("from_cache") is True

    def test_indicator_type_prevents_key_collisions(self):
        """Identical string value across different IndicatorTypes must NOT collide in cache."""
        cache = ThreatIntelligenceCache(default_ttl_seconds=60.0)

        # Same string 'bad-asset' used as DOMAIN and URL
        ev_domain = ThreatIntelEvidence(
            indicator="bad-asset",
            indicator_type=IndicatorType.DOMAIN,
            verdict=ThreatIntelVerdict.MALICIOUS,
            confidence=0.9,
            provider="TestProvider"
        )
        ev_url = ThreatIntelEvidence(
            indicator="bad-asset",
            indicator_type=IndicatorType.URL,
            verdict=ThreatIntelVerdict.CLEAN,
            confidence=0.8,
            provider="TestProvider"
        )

        cache.set(ev_domain)
        cache.set(ev_url)

        cached_dom = cache.get("TestProvider", IndicatorType.DOMAIN, "bad-asset")
        cached_url = cache.get("TestProvider", IndicatorType.URL, "bad-asset")

        assert cached_dom is not None
        assert cached_url is not None
        assert cached_dom.verdict == ThreatIntelVerdict.MALICIOUS
        assert cached_url.verdict == ThreatIntelVerdict.CLEAN
        assert cached_dom.indicator_type == IndicatorType.DOMAIN
        assert cached_url.indicator_type == IndicatorType.URL

    def test_normalization_produces_consistent_keys(self):
        """Case variations and leading/trailing whitespace must map to identical cache keys."""
        cache = ThreatIntelligenceCache()
        sha = "ED01EBFBC9EB5BBEA545AF4D01BF5F1071661840480439C6E5BABE8E080E41AA"
        ev = ThreatIntelEvidence(
            indicator=sha.lower(),
            indicator_type=IndicatorType.SHA256,
            verdict=ThreatIntelVerdict.MALICIOUS,
            confidence=1.0,
            provider="VT"
        )
        cache.set(ev)

        # Retrieve with uppercase and whitespace
        retrieved = cache.get("VT", IndicatorType.SHA256, f"  {sha}  ")
        assert retrieved is not None
        assert retrieved.verdict == ThreatIntelVerdict.MALICIOUS

    def test_expired_entries_follow_defined_policy(self):
        """Expired entries must return None and be pruned on lookup."""
        clock = MockClock(1000.0)
        cache = ThreatIntelligenceCache(default_ttl_seconds=30.0, clock=clock)

        ev = ThreatIntelEvidence(
            indicator="http://expiring-indicator.com",
            indicator_type=IndicatorType.URL,
            verdict=ThreatIntelVerdict.SUSPICIOUS,
            confidence=0.7,
            provider="URLhaus"
        )
        cache.set(ev, ttl_seconds=20.0)

        # Before expiry
        clock.advance(19.0)
        assert cache.get("URLhaus", IndicatorType.URL, "http://expiring-indicator.com") is not None

        # After expiry
        clock.advance(2.0)  # 21s elapsed
        assert cache.get("URLhaus", IndicatorType.URL, "http://expiring-indicator.com") is None
        assert cache.size == 0

    def test_provider_failures_are_never_cached(self):
        """UNAVAILABLE verdicts (timeouts, outages, 5xx) must NEVER be cached."""
        cache = ThreatIntelligenceCache()
        ev_unavail = ThreatIntelEvidence.unavailable(
            indicator="http://timeout-target.com",
            reason="Gateway Timeout 504",
            indicator_type=IndicatorType.URL,
            provider="VirusTotal"
        )

        assert cache.set(ev_unavail) is False
        assert cache.size == 0
        assert cache.get("VirusTotal", IndicatorType.URL, "http://timeout-target.com") is None

    def test_cache_write_failure_isolation(self):
        """A cache write failure or exception must not crash detection."""
        failing_cache = ThreatIntelligenceCache()
        # Simulate unexpected exception inside set
        failing_cache.set = MagicMock(side_effect=RuntimeError("Simulated memory error"))

        provider = DummyMockProvider()
        lookup = ThreatLookup(external_client=provider, cache=failing_cache)
        lookup.available_providers = [provider]

        with patch("threat_intelligence.threat_lookup.db_lookup_indicator", return_value={"found": False}):
            # Must run cleanly without raising RuntimeError
            res = lookup.lookup_indicator("http://test-safe.com", IndicatorType.URL, query_external=True)
            assert res["outcome_state"] == OUTCOME_FOUND_MALICIOUS
            assert res["is_known_threat"] is True

    def test_indicator_invalidation(self):
        """Invalidating an indicator purges all matching entries across providers."""
        cache = ThreatIntelligenceCache()
        ind = "compromised-domain.xyz"

        ev1 = ThreatIntelEvidence(indicator=ind, indicator_type=IndicatorType.DOMAIN, verdict=ThreatIntelVerdict.MALICIOUS, provider="P1")
        ev2 = ThreatIntelEvidence(indicator=ind, indicator_type=IndicatorType.DOMAIN, verdict=ThreatIntelVerdict.SUSPICIOUS, provider="P2")
        ev3 = ThreatIntelEvidence(indicator="other-domain.xyz", indicator_type=IndicatorType.DOMAIN, verdict=ThreatIntelVerdict.CLEAN, provider="P1")

        cache.set(ev1)
        cache.set(ev2)
        cache.set(ev3)
        assert cache.size == 3

        invalidated_count = cache.invalidate(ind)
        assert invalidated_count == 2
        assert cache.size == 1
        assert cache.get("P1", IndicatorType.DOMAIN, ind) is None
        assert cache.get("P2", IndicatorType.DOMAIN, ind) is None
        assert cache.get("P1", IndicatorType.DOMAIN, "other-domain.xyz") is not None

    def test_cache_capacity_lru_retention(self):
        """When max_entries is exceeded, LRU entry is evicted."""
        clock = MockClock(10.0)
        cache = ThreatIntelligenceCache(max_entries=3, default_ttl_seconds=100.0, clock=clock)

        for i in range(1, 4):
            cache.set(ThreatIntelEvidence(indicator=f"ind-{i}", indicator_type=IndicatorType.GENERIC, verdict=ThreatIntelVerdict.CLEAN, provider="Prov"))

        assert cache.size == 3

        # Access ind-1 so ind-2 is the LRU
        cache.get("Prov", IndicatorType.GENERIC, "ind-1")

        # Insert ind-4 -> ind-2 must be evicted
        cache.set(ThreatIntelEvidence(indicator="ind-4", indicator_type=IndicatorType.GENERIC, verdict=ThreatIntelVerdict.CLEAN, provider="Prov"))
        assert cache.size == 3
        assert cache.get("Prov", IndicatorType.GENERIC, "ind-2") is None
        assert cache.get("Prov", IndicatorType.GENERIC, "ind-1") is not None
        assert cache.get("Prov", IndicatorType.GENERIC, "ind-3") is not None
        assert cache.get("Prov", IndicatorType.GENERIC, "ind-4") is not None

        stats = cache.get_stats()
        assert stats["evictions_lru"] == 1


# =====================================================================
# 3. Thread Safety and Concurrency
# =====================================================================

class TestCacheConcurrency:
    """Verifies non-blocking, deadlock-free concurrent read/write access."""

    def test_concurrent_read_write_under_load(self):
        cache = ThreatIntelligenceCache(max_entries=50, default_ttl_seconds=10.0)
        errors = []

        def worker(worker_id: int):
            try:
                for i in range(100):
                    ind = f"indicator-{i % 20}"
                    ev = ThreatIntelEvidence(
                        indicator=ind,
                        indicator_type=IndicatorType.SHA256,
                        verdict=ThreatIntelVerdict.MALICIOUS if i % 2 == 0 else ThreatIntelVerdict.CLEAN,
                        provider=f"Worker-{worker_id}"
                    )
                    cache.set(ev)
                    cache.get(f"Worker-{worker_id}", IndicatorType.SHA256, ind)
                    if i % 15 == 0:
                        cache.invalidate(ind)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert cache.size <= 50


# =====================================================================
# 4. ThreatDetector Scan Cache Integration
# =====================================================================

class TestThreatDetectorScanCache:
    """Verifies file hash and URL scan caching in ThreatDetector."""

    def test_threat_detector_hash_cache_hit_bypasses_deep_analysis(self, tmp_path):
        detector = ThreatDetector(max_cache_entries=100, cache_ttl_seconds=60.0)
        target_file = tmp_path / "test_executable.txt"
        target_file.write_text("Hello benign content for caching test", encoding="utf-8")

        # First scan: cache miss
        res1 = detector.analyze_file(target_file)
        assert "error" not in res1
        assert res1.get("from_cache") is False
        sha = res1.get("sha256")
        assert sha != ""

        # Second scan: cache hit
        res2 = detector.analyze_file(target_file)
        assert "error" not in res2
        assert res2.get("from_cache") is True
        assert res2.get("sha256") == sha

        stats = detector.get_cache_stats()
        assert stats["hash_cache"]["hits"] >= 1

    def test_threat_detector_url_cache_hit(self):
        detector = ThreatDetector(max_cache_entries=100, cache_ttl_seconds=60.0)
        url = "http://cached-url-test.org/path"

        res1 = detector.analyze_url(url)
        assert res1["from_cache"] is False

        res2 = detector.analyze_url(url)
        assert res2["from_cache"] is True

        stats = detector.get_cache_stats()
        assert stats["url_cache"]["hits"] == 1

    def test_threat_detector_invalidate_and_clear(self, tmp_path):
        detector = ThreatDetector(max_cache_entries=100, cache_ttl_seconds=60.0)
        target_file = tmp_path / "inval_test.txt"
        target_file.write_text("Some arbitrary payload text", encoding="utf-8")

        res1 = detector.analyze_file(target_file)
        sha = res1["sha256"]

        # Invalidate specific hash
        assert detector.invalidate_hash(sha) is True
        res_after = detector.analyze_file(target_file)
        assert res_after["from_cache"] is False  # Re-analyzed!

        # Clear entire cache
        detector.clear_cache()
        stats = detector.get_cache_stats()
        assert stats["hash_cache"]["size"] == 0
        assert stats["url_cache"]["size"] == 0


# =====================================================================
# 5. Offline and Provider Outage Resilience
# =====================================================================

class TestOfflineOutageResilience:
    """Verifies local analysis and SQLite lookups survive provider outages without false negatives."""

    def test_outage_does_not_falsely_declare_clean(self):
        failing_provider = DummyMockProvider(verdict=ThreatIntelVerdict.UNAVAILABLE)
        lookup = ThreatLookup(external_client=failing_provider)
        lookup.available_providers = [failing_provider]

        with patch("threat_intelligence.threat_lookup.db_lookup_indicator", return_value={"found": False}):
            res = lookup.lookup_indicator("http://outage-sample.com", IndicatorType.URL, query_external=True)
            # Must be request timeout or provider unavailable, NEVER benign/clean!
            assert res["outcome_state"] in (OUTCOME_REQUEST_TIMEOUT, OUTCOME_PROVIDER_UNAVAILABLE)
            assert res["outcome_state"] != OUTCOME_FOUND_BENIGN
            assert res["external_evidence"].verdict == ThreatIntelVerdict.UNAVAILABLE

    def test_database_registration_invalidates_cache(self):
        """When an indicator is registered in SQLite, memory caches are invalidated."""
        from detection_engine.threat_detector import threat_detector

        test_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        threat_detector._hash_cache.set(test_hash, {"score": 0.0, "is_threat": False})
        assert test_hash in threat_detector._hash_cache

        # Register in database
        ind_id = register_indicator(
            indicator_type="sha256",
            indicator_value=test_hash,
            source="test_day21",
            confidence=0.95,
            status="CONFIRMED",
            threat_type="Malware"
        )
        assert ind_id > 0

        # Memory cache must have been invalidated
        assert test_hash not in threat_detector._hash_cache
