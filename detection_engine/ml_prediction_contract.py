"""
ACTIS Machine Learning Prediction Contract
Standardized interface for ML model inference results across phishing and malware classifiers.
Encapsulates prediction probabilities, decision status, feature contracts, and evidence conversion.
"""

from enum import Enum
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional

from detection_engine.evidence_model import EvidenceSignal, EvidenceSource, EvidenceSeverity


class MLModelType(str, Enum):
    """Model classification domain."""
    PHISHING_URL = "PHISHING_URL"
    WINDOWS_PE_MALWARE = "WINDOWS_PE_MALWARE"
    GENERIC_CLASSIFIER = "GENERIC_CLASSIFIER"


class MLPredictionStatus(str, Enum):
    """Execution status of the ML inference attempt."""
    AVAILABLE = "AVAILABLE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    MODEL_UNAVAILABLE = "MODEL_UNAVAILABLE"
    INFERENCE_ERROR = "INFERENCE_ERROR"
    SCHEMA_MISMATCH = "SCHEMA_MISMATCH"


@dataclass(frozen=True)
class MLPredictionResult:
    """
    Immutable representation of machine learning model prediction output.
    Bridges ML runtime inference with the ACTIS risk scoring and explanation pipeline.
    """
    model_name: str
    model_version: str
    model_type: MLModelType
    status: MLPredictionStatus
    is_threat: bool = False
    probability: float = 0.0
    confidence: float = 0.0
    prediction_label: str = "BENIGN"
    features_used: List[str] = field(default_factory=list)
    error_message: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __post_init__(self):
        clamped_prob = max(0.0, min(1.0, float(self.probability)))
        if clamped_prob != self.probability:
            object.__setattr__(self, "probability", clamped_prob)
        
        clamped_conf = max(0.0, min(1.0, float(self.confidence)))
        if clamped_conf != self.confidence:
            object.__setattr__(self, "confidence", clamped_conf)

    @classmethod
    def unavailable(cls, model_name: str, model_type: MLModelType, reason: str) -> "MLPredictionResult":
        """Factory for unavailable model states."""
        return cls(
            model_name=model_name,
            model_version="unknown",
            model_type=model_type,
            status=MLPredictionStatus.MODEL_UNAVAILABLE,
            error_message=reason
        )

    @classmethod
    def not_applicable(cls, model_name: str, model_type: MLModelType, reason: str = "Target type not supported") -> "MLPredictionResult":
        """Factory for skipped inference when target modality does not apply."""
        return cls(
            model_name=model_name,
            model_version="unknown",
            model_type=model_type,
            status=MLPredictionStatus.NOT_APPLICABLE,
            error_message=reason
        )

    @classmethod
    def from_error(cls, model_name: str, model_type: MLModelType, error: Exception) -> "MLPredictionResult":
        """Factory for safe error handling during inference."""
        return cls(
            model_name=model_name,
            model_version="unknown",
            model_type=model_type,
            status=MLPredictionStatus.INFERENCE_ERROR,
            error_message=str(error)
        )

    def to_evidence_signal(self) -> Optional[EvidenceSignal]:
        """
        Converts available prediction result into an EvidenceSignal for risk aggregation.
        Returns None if model is unavailable or target not applicable.
        """
        if self.status != MLPredictionStatus.AVAILABLE:
            return None

        # Severity determined by predicted probability
        if self.probability >= 0.85:
            severity = EvidenceSeverity.CRITICAL if self.is_threat else EvidenceSeverity.INFO
        elif self.probability >= 0.70:
            severity = EvidenceSeverity.HIGH if self.is_threat else EvidenceSeverity.INFO
        elif self.probability >= 0.50:
            severity = EvidenceSeverity.MEDIUM if self.is_threat else EvidenceSeverity.LOW
        else:
            severity = EvidenceSeverity.LOW

        score_contrib = round(self.probability * 100.0, 2)
        desc = (
            f"{self.model_name} classified target as {self.prediction_label} "
            f"(Probability: {int(self.probability * 100)}%, Confidence: {int(self.confidence * 100)}%)."
        )

        return EvidenceSignal(
            source=EvidenceSource.MACHINE_LEARNING,
            signal_id=f"ML_{self.model_type.value}_{self.prediction_label}",
            name=f"ML {self.model_name} Prediction",
            description=desc,
            severity=severity,
            score_contribution=score_contrib,
            weight=self.confidence if self.confidence > 0.0 else 0.8,
            raw_data={
                "model_name": self.model_name,
                "model_version": self.model_version,
                "probability": self.probability,
                "confidence": self.confidence,
                "features_count": len(self.features_used)
            }
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "model_name": self.model_name,
            "model_version": self.model_version,
            "model_type": self.model_type.value if isinstance(self.model_type, MLModelType) else str(self.model_type),
            "status": self.status.value if isinstance(self.status, MLPredictionStatus) else str(self.status),
            "is_threat": self.is_threat,
            "probability": round(self.probability, 4),
            "confidence": round(self.confidence, 4),
            "prediction_label": self.prediction_label,
            "features_used": list(self.features_used),
            "error_message": self.error_message,
            "timestamp": self.timestamp
        }
