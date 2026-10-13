"""
ACTIS Detection Result Contract
Formal structured representation for detection decisions across all ACTIS scanners.
Defines typed classifications, risk levels, confidence scores, and serialization contracts.
"""

from enum import Enum
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional


class InputType(str, Enum):
    """Supported input modalities for detection analysis."""
    FILE = "FILE"
    PE_BINARY = "PE_BINARY"
    URL = "URL"
    DOMAIN = "DOMAIN"
    IP_ADDRESS = "IP_ADDRESS"
    HASH = "HASH"
    IOC = "IOC"
    GENERIC = "GENERIC"
    MESSAGE = "MESSAGE"


class DetectionStatus(str, Enum):
    """Categorical threat verdict for an analyzed target."""
    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    UNKNOWN = "UNKNOWN"
    ERROR = "ERROR"


class RiskLevel(str, Enum):
    """Standardized five-tier ACTIS risk level."""
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class DetectionResult:
    """
    Immutable, structured detection result contract.
    Encapsulates final classification, risk scoring, confidence, and audit trail.
    """
    target_identifier: str
    input_type: InputType
    detection_status: DetectionStatus
    risk_level: RiskLevel
    risk_score: float
    confidence: float
    primary_reason: str
    reasons: List[str] = field(default_factory=list)
    contributing_signals: List[Dict[str, Any]] = field(default_factory=list)
    analysis_metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __post_init__(self):
        clamped_score = max(0.0, min(100.0, float(self.risk_score)))
        if clamped_score != self.risk_score:
            object.__setattr__(self, "risk_score", clamped_score)
        
        clamped_conf = max(0.0, min(1.0, float(self.confidence)))
        if clamped_conf != self.confidence:
            object.__setattr__(self, "confidence", clamped_conf)

    @property
    def is_threat(self) -> bool:
        """Returns True if the verdict indicates a potential or confirmed threat."""
        return (
            self.detection_status in (DetectionStatus.SUSPICIOUS, DetectionStatus.MALICIOUS)
            or self.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        )

    @property
    def explainability_tree(self) -> Optional[Dict[str, Any]]:
        """Returns the serialized hierarchical explainability tree if present in analysis_metadata."""
        return self.analysis_metadata.get("explainability_tree")

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the detection result to a clean dictionary representation."""
        return {
            "target_identifier": self.target_identifier,
            "input_type": self.input_type.value if isinstance(self.input_type, InputType) else str(self.input_type),
            "detection_status": self.detection_status.value if isinstance(self.detection_status, DetectionStatus) else str(self.detection_status),
            "risk_level": self.risk_level.value if isinstance(self.risk_level, RiskLevel) else str(self.risk_level),
            "risk_score": round(self.risk_score, 2),
            "confidence": round(self.confidence, 4),
            "is_threat": self.is_threat,
            "primary_reason": self.primary_reason,
            "reasons": list(self.reasons),
            "contributing_signals": list(self.contributing_signals),
            "analysis_metadata": dict(self.analysis_metadata),
            "timestamp": self.timestamp
        }
