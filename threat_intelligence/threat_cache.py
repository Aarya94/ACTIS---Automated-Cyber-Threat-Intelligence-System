"""
ACTIS Threat Intelligence Cache
Provides thread-safe in-memory caching with configurable TTL, provider-awareness,
and indicator-type indexing for external threat intelligence lookups.
Strictly avoids caching transient errors or request timeouts.
"""

import time
import threading
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass

from detection_engine.threat_intel_contract import (
    ThreatIntelEvidence,
    ThreatIntelVerdict,
    IndicatorType,
)
from config.config import TI_CACHE_TTL_SECONDS, get_logger

logger = get_logger("ThreatCache")


@dataclass(frozen=True)
class CacheEntry:
    evidence: ThreatIntelEvidence
    inserted_at: float
    ttl_seconds: float

    @property
    def is_expired(self) -> bool:
        return (time.time() - self.inserted_at) > self.ttl_seconds


class ThreatIntelligenceCache:
    """
    Thread-safe, TTL-based threat intelligence cache.
    Ensures transient errors (timeouts, rate limits, 5xx) are never cached.
    """

    def __init__(self, default_ttl_seconds: Optional[int] = None):
        self.default_ttl = max(60.0, float(default_ttl_seconds or TI_CACHE_TTL_SECONDS))
        self._cache: Dict[str, CacheEntry] = {}
        self._lock = threading.RLock()
        self._hits: int = 0
        self._misses: int = 0

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._cache)

    def __len__(self) -> int:
        return self.size


    @staticmethod
    def build_cache_key(provider: str, indicator_type: IndicatorType, indicator: str) -> str:
        """Constructs canonical, safe, secret-free cache key."""
        type_str = indicator_type.value.lower() if isinstance(indicator_type, IndicatorType) else str(indicator_type).lower()
        clean_ind = indicator.strip().lower()
        clean_prov = provider.strip().lower()
        return f"{clean_prov}::{type_str}::{clean_ind}"

    def get(
        self,
        provider: str,
        indicator_type: IndicatorType,
        indicator: str
    ) -> Optional[ThreatIntelEvidence]:
        """
        Retrieves unexpired ThreatIntelEvidence from cache.
        Returns None if missing or expired.
        """
        key = self.build_cache_key(provider, indicator_type, indicator)
        with self._lock:
            entry = self._cache.get(key)
            if not entry:
                self._misses += 1
                return None

            if entry.is_expired:
                del self._cache[key]
                self._misses += 1
                return None

            self._hits += 1
            # Return evidence with cached marker
            ev = entry.evidence
            raw = dict(ev.raw_data or {})
            raw["from_cache"] = True
            return ThreatIntelEvidence(
                indicator=ev.indicator,
                indicator_type=ev.indicator_type,
                verdict=ev.verdict,
                confidence=ev.confidence,
                threat_type=ev.threat_type,
                provider=ev.provider,
                is_confirmed_threat=ev.is_confirmed_threat,
                is_whitelisted=ev.is_whitelisted,
                raw_data=raw,
                timestamp=ev.timestamp
            )

    def set(
        self,
        evidence: ThreatIntelEvidence,
        ttl_seconds: Optional[float] = None
    ) -> bool:
        """
        Stores ThreatIntelEvidence in cache if verdict is a durable finding.
        Never caches UNAVAILABLE states (e.g. timeout, rate limit, outage).
        """
        if not evidence or not evidence.indicator:
            return False

        # Strictly never cache unavailable/transient errors
        if evidence.verdict == ThreatIntelVerdict.UNAVAILABLE:
            return False

        ttl = max(10.0, float(ttl_seconds if ttl_seconds is not None else self.default_ttl))
        key = self.build_cache_key(evidence.provider, evidence.indicator_type, evidence.indicator)
        entry = CacheEntry(
            evidence=evidence,
            inserted_at=time.time(),
            ttl_seconds=ttl
        )

        with self._lock:
            self._cache[key] = entry
            return True

    def evict_expired(self) -> int:
        """Prunes all expired cache entries and returns count of evicted entries."""
        now = time.time()
        evicted = 0
        with self._lock:
            expired_keys = [k for k, v in self._cache.items() if (now - v.inserted_at) > v.ttl_seconds]
            for k in expired_keys:
                del self._cache[k]
                evicted += 1
        return evicted

    def clear(self) -> None:
        """Clears all entries from the cache."""
        with self._lock:
            self._cache.clear()
            self._hits = 0
            self._misses = 0

    def get_stats(self) -> Dict[str, Any]:
        """Returns cache telemetry statistics."""
        with self._lock:
            total_queries = self._hits + self._misses
            hit_ratio = round(self._hits / total_queries, 4) if total_queries > 0 else 0.0
            return {
                "size": len(self._cache),
                "hits": self._hits,
                "misses": self._misses,
                "total_queries": total_queries,
                "hit_ratio": hit_ratio,
                "default_ttl_seconds": self.default_ttl
            }


# Global cache instance
threat_cache = ThreatIntelligenceCache()
