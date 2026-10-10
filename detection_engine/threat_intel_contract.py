"""
ACTIS Threat Intelligence Evidence Contract
Standardized abstraction for local and external threat intelligence indicators and verdicts.
Provides typed verdicts, confidence scores, provider provenance, and seamless EvidenceSignal conversion.
"""

from enum import Enum
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional

from detection_engine.evidence_model import EvidenceSignal, EvidenceSource, EvidenceSeverity


class ThreatIntelVerdict(str, Enum):
    """Categorical threat intelligence verdict."""
    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    UNKNOWN = "UNKNOWN"
    UNAVAILABLE = "UNAVAILABLE"


class IndicatorType(str, Enum):
    """Supported threat intelligence indicator types."""
    SHA256 = "SHA256"
    MD5 = "MD5"
    SHA1 = "SHA1"
    URL = "URL"
    DOMAIN = "DOMAIN"
    IP_ADDRESS = "IP_ADDRESS"
    GENERIC = "GENERIC"


@dataclass(frozen=True)
class ThreatIntelEvidence:
    """
    Immutable representation of threat intelligence lookup results.
    Captures verdict, reputation, source provider, and confidence.
    """
    indicator: str
    indicator_type: IndicatorType
    verdict: ThreatIntelVerdict
    confidence: float = 1.0
    threat_type: Optional[str] = None
    provider: str = "LOCAL_DATABASE"
    is_confirmed_threat: bool = False
    is_whitelisted: bool = False
    raw_data: Optional[Dict[str, Any]] = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __post_init__(self):
        clamped_conf = max(0.0, min(1.0, float(self.confidence)))
        if clamped_conf != self.confidence:
            object.__setattr__(self, "confidence", clamped_conf)

    @classmethod
    def unknown(cls, indicator: str, indicator_type: IndicatorType = IndicatorType.GENERIC, provider: str = "LOCAL_DATABASE") -> "ThreatIntelEvidence":
        return cls(
            indicator=indicator,
            indicator_type=indicator_type,
            verdict=ThreatIntelVerdict.UNKNOWN,
            confidence=0.0,
            provider=provider
        )

    @classmethod
    def unavailable(cls, indicator: str, reason: str = "TI service unavailable", indicator_type: IndicatorType = IndicatorType.GENERIC, provider: str = "LOCAL_DATABASE") -> "ThreatIntelEvidence":
        return cls(
            indicator=indicator,
            indicator_type=indicator_type,
            verdict=ThreatIntelVerdict.UNAVAILABLE,
            confidence=0.0,
            provider=provider,
            raw_data={"reason": reason}
        )

    @classmethod
    def from_external_intel(
        cls,
        intel: Optional[Dict[str, Any]],
        indicator: str,
        indicator_type: IndicatorType = IndicatorType.GENERIC,
        provider: str = "EXTERNAL_PROVIDER"
    ) -> "ThreatIntelEvidence":
        """
        Translates normalized external provider results dictionary into typed ThreatIntelEvidence.
        Preserves provider provenance, detection counts, confidence, and raw provider payloads.
        """
        if not intel:
            return cls.unavailable(indicator, reason="No external response received", indicator_type=indicator_type, provider=provider)

        src = intel.get("source") or provider
        if not intel.get("available", True):
            reason = intel.get("reason") or "External service unavailable"
            return cls.unavailable(indicator, reason=reason, indicator_type=indicator_type, provider=src)

        is_mal = bool(intel.get("malicious", False))
        positives = int(intel.get("positives", 0))
        total = int(intel.get("total", 0))
        conf = float(intel.get("confidence", 0.0))

        if is_mal:
            confirmed = positives >= 3 or conf >= 0.20
            threat_type = intel.get("threat_type") or ("Malware" if indicator_type == IndicatorType.SHA256 else "Phishing / Malicious")
            return cls(
                indicator=indicator,
                indicator_type=indicator_type,
                verdict=ThreatIntelVerdict.MALICIOUS,
                confidence=max(0.4, conf),
                threat_type=threat_type,
                provider=src,
                is_confirmed_threat=confirmed,
                raw_data=intel
            )
        elif total > 0 and positives == 0:
            return cls(
                indicator=indicator,
                indicator_type=indicator_type,
                verdict=ThreatIntelVerdict.CLEAN,
                confidence=round(min(1.0, max(0.5, total / 70.0)), 2),
                provider=src,
                is_whitelisted=False,
                raw_data=intel
            )
        else:
            return cls.unknown(indicator, indicator_type=indicator_type, provider=src)

    @classmethod
    def from_local_intel(cls, intel: Optional[Dict[str, Any]], indicator: str, indicator_type: IndicatorType = IndicatorType.GENERIC) -> "ThreatIntelEvidence":
        """Translates existing ACTIS local database lookup dictionaries into typed ThreatIntelEvidence."""
        if not intel or not intel.get("found", False):
            return cls.unknown(indicator, indicator_type)

        raw_status = str(intel.get("status", "")).upper()
        threat_type = intel.get("threat_type") or intel.get("type", "Malicious")
        confidence = float(intel.get("confidence", 1.0))

        if raw_status in ("CONFIRMED", "MALICIOUS"):
            return cls(
                indicator=indicator,
                indicator_type=indicator_type,
                verdict=ThreatIntelVerdict.MALICIOUS,
                confidence=confidence,
                threat_type=threat_type,
                provider="LOCAL_DATABASE",
                is_confirmed_threat=True,
                raw_data=intel
            )
        elif raw_status == "SUSPICIOUS":
            return cls(
                indicator=indicator,
                indicator_type=indicator_type,
                verdict=ThreatIntelVerdict.SUSPICIOUS,
                confidence=confidence,
                threat_type=threat_type,
                provider="LOCAL_DATABASE",
                is_confirmed_threat=False,
                raw_data=intel
            )
        elif raw_status == "FALSE_POSITIVE":
            return cls(
                indicator=indicator,
                indicator_type=indicator_type,
                verdict=ThreatIntelVerdict.FALSE_POSITIVE,
                confidence=confidence,
                threat_type="False Positive Whitelist",
                provider="LOCAL_DATABASE",
                is_whitelisted=True,
                raw_data=intel
            )
        elif raw_status == "CLEAN":
            return cls(
                indicator=indicator,
                indicator_type=indicator_type,
                verdict=ThreatIntelVerdict.CLEAN,
                confidence=confidence,
                provider="LOCAL_DATABASE",
                is_whitelisted=True,
                raw_data=intel
            )
        else:
            return cls.unknown(indicator, indicator_type)

    def to_evidence_signal(self) -> Optional[EvidenceSignal]:
        """Converts TI record into an EvidenceSignal for multi-layer risk fusion."""
        if self.verdict in (ThreatIntelVerdict.UNKNOWN, ThreatIntelVerdict.UNAVAILABLE):
            return None

        if self.verdict == ThreatIntelVerdict.MALICIOUS:
            severity = EvidenceSeverity.CRITICAL if self.is_confirmed_threat else EvidenceSeverity.HIGH
            score_contrib = 100.0 * self.confidence
            desc = f"Known MALICIOUS indicator '{self.indicator}' identified by {self.provider} ({self.threat_type or 'General Threat'})."
        elif self.verdict == ThreatIntelVerdict.SUSPICIOUS:
            severity = EvidenceSeverity.MEDIUM
            score_contrib = 65.0 * self.confidence
            desc = f"Recorded as SUSPICIOUS indicator in {self.provider} (Confidence: {int(self.confidence * 100)}%)."
        elif self.verdict == ThreatIntelVerdict.FALSE_POSITIVE:
            severity = EvidenceSeverity.INFO
            score_contrib = 0.0
            desc = f"Indicator is explicitly flagged as a verified FALSE POSITIVE in {self.provider}."
        elif self.verdict == ThreatIntelVerdict.CLEAN:
            severity = EvidenceSeverity.INFO
            score_contrib = 0.0
            desc = f"Indicator is verified CLEAN by {self.provider}."
        else:
            return None

        return EvidenceSignal(
            source=EvidenceSource.THREAT_INTELLIGENCE,
            signal_id=f"TI_{self.verdict.value}_{self.indicator_type.value}",
            name=f"Threat Intelligence: {self.verdict.value}",
            description=desc,
            severity=severity,
            score_contribution=score_contrib,
            weight=self.confidence if self.confidence > 0.0 else 1.0,
            raw_data=self.raw_data
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "indicator": self.indicator,
            "indicator_type": self.indicator_type.value if isinstance(self.indicator_type, IndicatorType) else str(self.indicator_type),
            "verdict": self.verdict.value if isinstance(self.verdict, ThreatIntelVerdict) else str(self.verdict),
            "confidence": round(self.confidence, 4),
            "threat_type": self.threat_type,
            "provider": self.provider,
            "is_confirmed_threat": self.is_confirmed_threat,
            "is_whitelisted": self.is_whitelisted,
            "timestamp": self.timestamp
        }
