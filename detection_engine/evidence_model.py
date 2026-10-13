"""
ACTIS Structured Detection Evidence Model
Standardized evidence representation across intelligence sources (ML, Rules, TI, Static Analysis).
Provides provenance tracking, severity grading, score weighting, and human-readable explanation formatting.
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional


class EvidenceSource(str, Enum):
    """Source provenance for a security evidence signal."""
    THREAT_INTELLIGENCE = "THREAT_INTELLIGENCE"
    MACHINE_LEARNING = "MACHINE_LEARNING"
    HEURISTIC_RULES = "HEURISTIC_RULES"
    STATIC_PE = "STATIC_PE"
    REPUTATION = "REPUTATION"
    ANOMALY = "ANOMALY"
    USER_OVERRIDE = "USER_OVERRIDE"


class EvidenceSeverity(str, Enum):
    """Severity classification for an individual evidence signal."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class EvidenceSignal:
    """
    Immutable individual evidence finding.
    Retains source, identifier, explanation, severity, and score contribution.
    """
    source: EvidenceSource
    signal_id: str
    name: str
    description: str
    severity: EvidenceSeverity
    score_contribution: float
    weight: float = 1.0
    raw_data: Optional[Dict[str, Any]] = None

    def __post_init__(self):
        clamped_score = max(0.0, min(100.0, float(self.score_contribution)))
        if clamped_score != self.score_contribution:
            object.__setattr__(self, "score_contribution", clamped_score)
        
        clamped_weight = max(0.0, min(1.0, float(self.weight)))
        if clamped_weight != self.weight:
            object.__setattr__(self, "weight", clamped_weight)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source.value if isinstance(self.source, EvidenceSource) else str(self.source),
            "signal_id": self.signal_id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity.value if isinstance(self.severity, EvidenceSeverity) else str(self.severity),
            "score_contribution": round(self.score_contribution, 2),
            "weight": round(self.weight, 4),
            "raw_data": dict(self.raw_data) if self.raw_data else None
        }


@dataclass
class DetectionEvidence:
    """
    Mutable container aggregating evidence signals from multiple security layers.
    Provides filtering, severity ranking, and explanation aggregation.
    """
    signals: List[EvidenceSignal] = field(default_factory=list)
    discarded_duplicates: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self):
        if self.signals:
            raw_signals = list(self.signals)
            self.signals = []
            for s in raw_signals:
                self.add_signal(s)

    def add_signal(self, signal: EvidenceSignal) -> None:
        """
        Appends an evidence signal to the collection with automatic deduplication.
        If an exact duplicate signal (same source and signal_id) is added,
        preserves the signal with the higher weighted contribution and
        records the dropped duplicate in discarded_duplicates to prevent artificial score inflation.
        """
        if not isinstance(signal, EvidenceSignal):
            return

        for idx, existing in enumerate(self.signals):
            if existing.source == signal.source and existing.signal_id == signal.signal_id:
                # Duplicate finding identified
                if (signal.score_contribution * signal.weight) > (existing.score_contribution * existing.weight):
                    dropped = existing
                    self.signals[idx] = signal
                else:
                    dropped = signal

                self.discarded_duplicates.append({
                    "source": dropped.source.value if hasattr(dropped.source, "value") else str(dropped.source),
                    "signal_id": dropped.signal_id,
                    "name": dropped.name,
                    "score_contribution": dropped.score_contribution,
                    "reason": "Duplicate finding from identical source and identifier suppressed to prevent score inflation."
                })
                return

        self.signals.append(signal)

    @property
    def discarded_duplicates_count(self) -> int:
        """Returns the count of suppressed duplicate signals."""
        return len(self.discarded_duplicates)

    def get_signals_by_source(self, source: EvidenceSource) -> List[EvidenceSignal]:
        """Filters signals by provenance source."""
        return [s for s in self.signals if s.source == source]

    def get_signals_by_severity(self, severity: EvidenceSeverity) -> List[EvidenceSignal]:
        """Filters signals by severity grade."""
        return [s for s in self.signals if s.severity == severity]

    def has_critical_evidence(self) -> bool:
        """Returns True if any signal has CRITICAL severity."""
        return any(s.severity == EvidenceSeverity.CRITICAL for s in self.signals)

    def get_max_severity(self) -> EvidenceSeverity:
        """Calculates the highest severity among all recorded signals."""
        if not self.signals:
            return EvidenceSeverity.INFO
        order = [
            EvidenceSeverity.INFO,
            EvidenceSeverity.LOW,
            EvidenceSeverity.MEDIUM,
            EvidenceSeverity.HIGH,
            EvidenceSeverity.CRITICAL
        ]
        severities = [s.severity for s in self.signals]
        for s in reversed(order):
            if s in severities:
                return s
        return EvidenceSeverity.INFO

    def get_total_weighted_score(self) -> float:
        """Computes sum of weighted score contributions."""
        if not self.signals:
            return 0.0
        return sum(s.score_contribution * s.weight for s in self.signals)

    def format_explanations(self) -> List[str]:
        """Generates ordered human-readable reason strings from evidence."""
        # Sort by score contribution descending
        sorted_signals = sorted(self.signals, key=lambda s: s.score_contribution, reverse=True)
        return [f"[{s.source.value}] {s.name}: {s.description}" for s in sorted_signals]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "signal_count": len(self.signals),
            "max_severity": self.get_max_severity().value,
            "has_critical": self.has_critical_evidence(),
            "signals": [s.to_dict() for s in self.signals],
            "explanations": self.format_explanations(),
            "discarded_duplicates_count": len(self.discarded_duplicates),
            "discarded_duplicates": list(self.discarded_duplicates)
        }
