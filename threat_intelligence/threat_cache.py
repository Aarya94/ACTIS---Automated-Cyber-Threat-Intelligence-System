"""
ACTIS Threat Intelligence Cache & Bounded High-Throughput LRU Subsystem
Provides thread-safe in-memory caching with configurable TTL, bounded capacity,
LRU eviction, provider-awareness, indicator-type indexing, and clock injection.
Strictly avoids caching transient errors or request timeouts (UNAVAILABLE).
"""

import time
import threading
from collections import OrderedDict
from typing import Dict, Any, Optional, Tuple, Callable, Union
from dataclasses import dataclass, field

from detection_engine.threat_intel_contract import (
    ThreatIntelEvidence,
    ThreatIntelVerdict,
    IndicatorType,
)
from config.config import TI_CACHE_TTL_SECONDS, get_logger

logger = get_logger("ThreatCache")


@dataclass
class CacheEntry:
    """Represents a cached threat intelligence evidence record with provenance and expiry."""
    evidence: ThreatIntelEvidence
    inserted_at: float
    ttl_seconds: float
    hit_count: int = 0
    last_accessed_at: float = 0.0

    @property
    def expires_at(self) -> float:
        return self.inserted_at + self.ttl_seconds

    @property
    def is_expired(self) -> bool:
        return (time.time() - self.inserted_at) > self.ttl_seconds

    def is_expired_at(self, current_time: float) -> bool:
        return (current_time - self.inserted_at) > self.ttl_seconds


class LRUTTLCache:
    """
    Thread-safe, bounded, Least-Recently-Used (LRU) in-memory cache
    with configurable time-to-live (TTL) expiration per entry.
    Supports injectable clocks for deterministic testing and error isolation.
    """

    def __init__(
        self,
        max_size: int = 5000,
        default_ttl_seconds: float = 300.0,
        clock: Optional[Callable[[], float]] = None,
    ):
        self.max_size = max(1, int(max_size))
        self.default_ttl = max(1.0, float(default_ttl_seconds))
        self.clock = clock or time.time
        self._cache: OrderedDict[str, Tuple[Any, float, float]] = OrderedDict()  # key -> (value, inserted_at, ttl)
        self._lock = threading.RLock()
        self._hits: int = 0
        self._misses: int = 0
        self._evictions_lru: int = 0
        self._evictions_ttl: int = 0

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._cache)

    def __len__(self) -> int:
        return self.size

    def get(self, key: str, default: Any = None) -> Any:
        """Retrieves unexpired value for key, returning default if missing or expired."""
        clean_key = str(key).strip().lower()
        try:
            with self._lock:
                item = self._cache.get(clean_key)
                if item is None:
                    self._misses += 1
                    return default

                val, inserted_at, ttl = item
                now = self.clock()
                if (now - inserted_at) > ttl:
                    del self._cache[clean_key]
                    self._evictions_ttl += 1
                    self._misses += 1
                    return default

                self._cache.move_to_end(clean_key)
                self._hits += 1
                return val
        except Exception as e:
            logger.warning(f"LRUTTLCache get error: {e}")
            return default

    def set(self, key: str, value: Any, ttl_seconds: Optional[float] = None) -> bool:
        """Stores a key-value pair with TTL and LRU eviction."""
        if key is None:
            return False
        clean_key = str(key).strip().lower()
        ttl = max(1.0, float(ttl_seconds if ttl_seconds is not None else self.default_ttl))

        try:
            with self._lock:
                now = self.clock()
                if clean_key in self._cache:
                    del self._cache[clean_key]

                # Evict expired entries if capacity reached
                if len(self._cache) >= self.max_size:
                    self._evict_expired_locked(now)

                # If still at capacity, pop LRU item
                while len(self._cache) >= self.max_size:
                    self._cache.popitem(last=False)
                    self._evictions_lru += 1

                self._cache[clean_key] = (value, now, ttl)
                self._cache.move_to_end(clean_key)
                return True
        except Exception as e:
            logger.warning(f"LRUTTLCache set error: {e}")
            return False

    def invalidate(self, key: str) -> bool:
        """Removes a key from cache, returning True if key was present."""
        clean_key = str(key).strip().lower()
        try:
            with self._lock:
                if clean_key in self._cache:
                    del self._cache[clean_key]
                    return True
                return False
        except Exception as e:
            logger.warning(f"LRUTTLCache invalidate error: {e}")
            return False

    def clear(self) -> None:
        """Clears all entries and resets statistics."""
        with self._lock:
            self._cache.clear()
            self._hits = 0
            self._misses = 0
            self._evictions_lru = 0
            self._evictions_ttl = 0

    def _evict_expired_locked(self, now: float) -> int:
        evicted = 0
        expired_keys = [k for k, (_, ins, ttl) in self._cache.items() if (now - ins) > ttl]
        for k in expired_keys:
            del self._cache[k]
            evicted += 1
            self._evictions_ttl += 1
        return evicted

    def evict_expired(self) -> int:
        """Prunes all expired entries and returns the count pruned."""
        with self._lock:
            return self._evict_expired_locked(self.clock())

    def __contains__(self, key: str) -> bool:
        clean_key = str(key).strip().lower()
        try:
            with self._lock:
                item = self._cache.get(clean_key)
                if item is None:
                    return False
                _, ins, ttl = item
                if (self.clock() - ins) > ttl:
                    del self._cache[clean_key]
                    self._evictions_ttl += 1
                    return False
                return True
        except Exception:
            return False

    def __getitem__(self, key: str) -> Any:
        res = self.get(key)
        if res is None and key not in self:
            raise KeyError(key)
        return res

    def __setitem__(self, key: str, value: Any) -> None:
        self.set(key, value)

    def __delitem__(self, key: str) -> None:
        if not self.invalidate(key):
            raise KeyError(key)

    def get_stats(self) -> Dict[str, Any]:
        """Returns cache telemetry."""
        with self._lock:
            total = self._hits + self._misses
            ratio = round(self._hits / total, 4) if total > 0 else 0.0
            return {
                "size": len(self._cache),
                "max_size": self.max_size,
                "hits": self._hits,
                "misses": self._misses,
                "total_queries": total,
                "hit_ratio": ratio,
                "evictions_lru": self._evictions_lru,
                "evictions_ttl": self._evictions_ttl,
                "default_ttl_seconds": self.default_ttl,
            }


class ThreatIntelligenceCache:
    """
    Thread-safe, bounded, TTL-based threat intelligence cache.
    Provides LRU capacity eviction, configurable default TTL, provider-awareness,
    indicator-type indexing, clock injection for deterministic testing, and safe error bounds.
    Strictly avoids caching transient errors or request timeouts (UNAVAILABLE).
    """

    def __init__(
        self,
        default_ttl_seconds: Optional[int] = None,
        max_entries: int = 10000,
        clock: Optional[Callable[[], float]] = None,
    ):
        self.default_ttl = max(10.0, float(default_ttl_seconds or TI_CACHE_TTL_SECONDS))
        self.max_entries = max(1, int(max_entries))
        self.clock = clock or time.time
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._lock = threading.RLock()
        self._hits: int = 0
        self._misses: int = 0
        self._evictions_lru: int = 0
        self._evictions_ttl: int = 0

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._cache)

    def __len__(self) -> int:
        return self.size

    @staticmethod
    def build_cache_key(provider: str, indicator_type: Union[str, IndicatorType], indicator: str) -> str:
        """Constructs canonical, safe, secret-free cache key."""
        type_str = indicator_type.value.lower() if isinstance(indicator_type, IndicatorType) else str(indicator_type).lower()
        clean_ind = str(indicator).strip().lower()
        clean_prov = str(provider).strip().lower()
        return f"{clean_prov}::{type_str}::{clean_ind}"

    def get(
        self,
        provider: str,
        indicator_type: Union[str, IndicatorType],
        indicator: str
    ) -> Optional[ThreatIntelEvidence]:
        """
        Retrieves unexpired ThreatIntelEvidence from cache.
        Returns None if missing or expired.
        Fails safely on unexpected errors without crashing detection.
        """
        try:
            key = self.build_cache_key(provider, indicator_type, indicator)
            with self._lock:
                entry = self._cache.get(key)
                if not entry:
                    self._misses += 1
                    return None

                now = self.clock()
                if entry.is_expired_at(now):
                    del self._cache[key]
                    self._evictions_ttl += 1
                    self._misses += 1
                    return None

                self._cache.move_to_end(key)
                self._hits += 1
                entry.hit_count += 1
                entry.last_accessed_at = now

                # Return evidence with cached marker and provenance
                ev = entry.evidence
                raw = dict(ev.raw_data or {})
                raw["from_cache"] = True
                raw["cached_at"] = entry.inserted_at
                raw["ttl_seconds"] = entry.ttl_seconds
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
        except Exception as e:
            logger.warning(f"ThreatIntelligenceCache get error: {e}")
            return None

    def set(
        self,
        evidence: ThreatIntelEvidence,
        ttl_seconds: Optional[float] = None
    ) -> bool:
        """
        Stores ThreatIntelEvidence in cache if verdict is a durable finding.
        Never caches UNAVAILABLE states (e.g. timeout, rate limit, outage).
        Applies LRU eviction if max_entries capacity is reached.
        """
        if not evidence or not evidence.indicator:
            return False

        # Strictly never cache unavailable/transient errors
        if evidence.verdict == ThreatIntelVerdict.UNAVAILABLE:
            return False

        try:
            ttl = max(5.0, float(ttl_seconds if ttl_seconds is not None else self.default_ttl))
            key = self.build_cache_key(evidence.provider, evidence.indicator_type, evidence.indicator)
            now = self.clock()
            entry = CacheEntry(
                evidence=evidence,
                inserted_at=now,
                ttl_seconds=ttl,
                last_accessed_at=now
            )

            with self._lock:
                if key in self._cache:
                    del self._cache[key]

                # Evict expired entries first when approaching limit
                if len(self._cache) >= self.max_entries:
                    self._evict_expired_locked(now)

                # If still at limit, evict LRU entry
                while len(self._cache) >= self.max_entries:
                    self._cache.popitem(last=False)
                    self._evictions_lru += 1

                self._cache[key] = entry
                self._cache.move_to_end(key)
                return True
        except Exception as e:
            logger.warning(f"ThreatIntelligenceCache set error: {e}")
            return False

    def invalidate(
        self,
        indicator: str,
        indicator_type: Optional[Union[str, IndicatorType]] = None,
        provider: Optional[str] = None
    ) -> int:
        """
        Invalidates cached entries matching indicator, and optionally indicator_type/provider.
        Returns the number of invalidated entries.
        """
        try:
            clean_ind = str(indicator).strip().lower()
            type_filter = (
                indicator_type.value.lower()
                if isinstance(indicator_type, IndicatorType)
                else str(indicator_type).lower()
            ) if indicator_type else None
            prov_filter = str(provider).strip().lower() if provider else None

            invalidated = 0
            with self._lock:
                keys_to_delete = []
                for k in list(self._cache.keys()):
                    parts = k.split("::")
                    if len(parts) == 3:
                        k_prov, k_type, k_ind = parts
                        if k_ind == clean_ind:
                            if type_filter and k_type != type_filter:
                                continue
                            if prov_filter and k_prov != prov_filter:
                                continue
                            keys_to_delete.append(k)
                    elif clean_ind in k:
                        keys_to_delete.append(k)

                for k in keys_to_delete:
                    del self._cache[k]
                    invalidated += 1

            return invalidated
        except Exception as e:
            logger.warning(f"ThreatIntelligenceCache invalidate error: {e}")
            return 0

    def _evict_expired_locked(self, now: float) -> int:
        evicted = 0
        expired_keys = [k for k, v in self._cache.items() if (now - v.inserted_at) > v.ttl_seconds]
        for k in expired_keys:
            del self._cache[k]
            evicted += 1
            self._evictions_ttl += 1
        return evicted

    def evict_expired(self) -> int:
        """Prunes all expired cache entries and returns count of evicted entries."""
        with self._lock:
            return self._evict_expired_locked(self.clock())

    def clear(self) -> None:
        """Clears all entries from the cache and resets telemetry."""
        with self._lock:
            self._cache.clear()
            self._hits = 0
            self._misses = 0
            self._evictions_lru = 0
            self._evictions_ttl = 0

    def get_stats(self) -> Dict[str, Any]:
        """Returns cache telemetry statistics."""
        with self._lock:
            total_queries = self._hits + self._misses
            hit_ratio = round(self._hits / total_queries, 4) if total_queries > 0 else 0.0
            return {
                "size": len(self._cache),
                "max_entries": self.max_entries,
                "hits": self._hits,
                "misses": self._misses,
                "evictions_lru": self._evictions_lru,
                "evictions_ttl": self._evictions_ttl,
                "total_queries": total_queries,
                "hit_ratio": hit_ratio,
                "default_ttl_seconds": self.default_ttl
            }


# Global threat cache singleton
threat_cache = ThreatIntelligenceCache()
