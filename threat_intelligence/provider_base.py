"""
ACTIS Threat Intelligence Provider Abstraction
Defines common interface, rate-limit tracking, and contract translation for
external threat intelligence providers.
"""

import time
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, Set

from detection_engine.threat_intel_contract import (
    ThreatIntelEvidence,
    ThreatIntelVerdict,
    IndicatorType,
)
from config.config import get_logger

logger = get_logger("ThreatProviderBase")


class BaseThreatClient(ABC):
    """
    Abstract base class for threat intelligence providers.
    Provides uniform lookup method, indicator capability reporting,
    bounded timeouts, rate-limit tracking, and normalized ThreatIntelEvidence translation.
    """

    def __init__(
        self,
        provider_name: str,
        supported_types: Optional[Set[IndicatorType]] = None,
        timeout: float = 5.0,
        rate_limit_rpm: Optional[int] = None,
        max_retries: int = 1,
    ):
        self.provider_name = provider_name
        self.supported_types = supported_types or set()
        self.timeout = max(1.0, float(timeout))
        self.rate_limit_rpm = rate_limit_rpm
        self.max_retries = max(0, min(5, int(max_retries)))
        self._last_request_time: float = 0.0
        self._request_count_window: int = 0
        self._window_start_time: float = time.time()

    def supports_indicator_type(self, indicator_type: IndicatorType) -> bool:
        """Returns True if this provider supports the given indicator type."""
        return indicator_type in self.supported_types

    @abstractmethod
    def is_configured(self) -> bool:
        """Returns True if the provider has necessary API credentials and configuration."""
        pass

    @abstractmethod
    def lookup(
        self,
        indicator: str,
        indicator_type: IndicatorType,
        timeout: Optional[float] = None
    ) -> ThreatIntelEvidence:
        """
        Queries the provider for the specified indicator and returns normalized ThreatIntelEvidence.
        """
        pass

    # Backward compatibility helper methods
    def lookup_hash(self, file_hash: str) -> Dict[str, Any]:
        """Convenience method returning legacy dict format for backward compatibility."""
        ev = self.lookup(file_hash, IndicatorType.SHA256)
        return self._evidence_to_legacy_dict(ev)

    def lookup_url(self, url: str) -> Dict[str, Any]:
        """Convenience method returning legacy dict format for backward compatibility."""
        ev = self.lookup(url, IndicatorType.URL)
        return self._evidence_to_legacy_dict(ev)

    def lookup_domain(self, domain: str) -> Dict[str, Any]:
        """Convenience method returning legacy dict format for backward compatibility."""
        ev = self.lookup(domain, IndicatorType.DOMAIN)
        return self._evidence_to_legacy_dict(ev)

    def lookup_ip(self, ip_address: str) -> Dict[str, Any]:
        """Convenience method returning legacy dict format for backward compatibility."""
        ev = self.lookup(ip_address, IndicatorType.IP_ADDRESS)
        return self._evidence_to_legacy_dict(ev)

    def _evidence_to_legacy_dict(self, ev: ThreatIntelEvidence) -> Dict[str, Any]:
        """Translates ThreatIntelEvidence into the legacy dictionary format expected by older callers."""
        raw = ev.raw_data or {}
        is_available = (ev.verdict != ThreatIntelVerdict.UNAVAILABLE)
        is_mal = (ev.verdict == ThreatIntelVerdict.MALICIOUS)
        return {
            "source": ev.provider,
            "available": is_available,
            "indicator": ev.indicator,
            "indicator_type": ev.indicator_type.value.lower() if isinstance(ev.indicator_type, IndicatorType) else str(ev.indicator_type),
            "malicious": is_mal,
            "positives": raw.get("positives", 1 if is_mal else 0),
            "total": raw.get("total", 1 if is_available else 0),
            "confidence": ev.confidence,
            "details": raw.get("details", {}),
            "reason": raw.get("reason", "") if not is_available else ""
        }
