"""
ACTIS Detection Decision Engine
Central intelligence layer that fuses multi-source evidence (Threat Intel, ML, Rules, Static Analysis)
into a unified, deterministic, strongly-typed DetectionResult.
"""

from typing import Dict, Any, List, Optional

from detection_engine.detection_contract import (
    DetectionResult,
    DetectionStatus,
    RiskLevel,
    InputType,
)
from detection_engine.evidence_model import (
    DetectionEvidence,
    EvidenceSignal,
    EvidenceSource,
    EvidenceSeverity,
)
from detection_engine.ml_prediction_contract import (
    MLPredictionResult,
    MLPredictionStatus,
)
from detection_engine.rule_engine import RuleEvaluationResult
from detection_engine.threat_intel_contract import (
    ThreatIntelEvidence,
    ThreatIntelVerdict,
)
from detection_engine.risk_engine import (
    RiskScoringEngine,
    RiskScoringWeights,
    ScoreBreakdown,
    RiskThresholdConfig,
    RiskClassifier,
)
from detection_engine.explanation_generator import (
    ConfidenceEngine,
    ExplanationGenerator,
)


class DetectionDecisionEngine:
    """
    Central decision fusion pipeline.
    Synthesizes diverse, asynchronous intelligence signals into structured security decisions.
    """

    @classmethod
    def evaluate(
        cls,
        target_identifier: str,
        input_type: InputType,
        ti_evidence: Optional[ThreatIntelEvidence] = None,
        ml_prediction: Optional[MLPredictionResult] = None,
        rule_result: Optional[RuleEvaluationResult] = None,
        static_signals: Optional[List[EvidenceSignal]] = None,
        custom_weights: Optional[RiskScoringWeights] = None,
        custom_thresholds: Optional[RiskThresholdConfig] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> DetectionResult:
        """
        Fuses all available intelligence signals for a target into a unified DetectionResult.
        Guarantees deterministic output and safe handling of missing or incomplete evidence.
        """
        evidence = DetectionEvidence()

        # 1. Threat Intelligence Evidence
        is_confirmed = False
        is_whitelisted = False
        if ti_evidence:
            is_confirmed = ti_evidence.is_confirmed_threat
            is_whitelisted = ti_evidence.is_whitelisted
            sig = ti_evidence.to_evidence_signal()
            if sig:
                evidence.add_signal(sig)

        # 2. Machine Learning Prediction Evidence
        if ml_prediction:
            sig = ml_prediction.to_evidence_signal()
            if sig:
                evidence.add_signal(sig)

        # 3. Rule Heuristic Evaluation Evidence
        if rule_result:
            for sig in rule_result.to_evidence_signals():
                evidence.add_signal(sig)

        # 4. Static PE / Anomaly Evidence Signals
        if static_signals:
            for sig in static_signals:
                evidence.add_signal(sig)

        # 5. Risk Scoring Fusion
        score, breakdown = RiskScoringEngine.score_evidence(evidence, weights=custom_weights)

        # 6. Risk Level & Status Classification
        risk_level, status, action = RiskClassifier.classify(
            score=score,
            is_confirmed_threat=is_confirmed,
            is_whitelisted=is_whitelisted,
            has_critical_evidence=evidence.has_critical_evidence(),
            thresholds=custom_thresholds
        )

        # 7. Internal Decision Confidence Calculation
        confidence = ConfidenceEngine.calculate_confidence(evidence, breakdown)

        # 8. Human-Readable Explanation Generation
        primary_reason, reasons = ExplanationGenerator.generate_explanation(
            risk_level=risk_level,
            status=status,
            score=score,
            evidence=evidence,
            breakdown=breakdown
        )

        # Combine analysis metadata
        meta = dict(metadata or {})
        meta["recommended_action"] = action
        meta["score_breakdown"] = breakdown.to_dict()
        meta["evidence_summary"] = evidence.to_dict()

        return DetectionResult(
            target_identifier=target_identifier,
            input_type=input_type,
            detection_status=status,
            risk_level=risk_level,
            risk_score=score,
            confidence=confidence,
            primary_reason=primary_reason,
            reasons=reasons,
            contributing_signals=[s.to_dict() for s in evidence.signals],
            analysis_metadata=meta
        )
