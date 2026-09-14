"""
ACTIS Explanation and Decision Confidence Engine
Generates human-readable, evidence-grounded security explanations and calculates internal decision confidence.
Strictly distinguishes internal decision confidence (evidence corroboration) from threat risk scores.
"""

from dataclasses import dataclass
from typing import Dict, Any, List, Optional, Tuple

from detection_engine.detection_contract import RiskLevel, DetectionStatus
from detection_engine.evidence_model import DetectionEvidence, EvidenceSource, EvidenceSeverity
from detection_engine.risk_engine import ScoreBreakdown


class ConfidenceEngine:
    """
    Computes internal decision confidence (0.0 - 1.0).
    Note: Decision confidence measures the diversity, agreement, and quality of observed evidence;
    it is fundamentally distinct from the threat risk score.
    """

    @classmethod
    def calculate_confidence(
        cls,
        evidence: DetectionEvidence,
        score_breakdown: ScoreBreakdown
    ) -> float:
        """
        Calculates internal decision confidence based on:
        1. Number of active corroborating layers (breadth of evidence).
        2. Signal weights and quality.
        3. Agreement / conflict between independent security layers.
        """
        if not evidence.signals:
            return 0.20  # Baseline confidence for zero evidence (informative uncertainty)

        active_count = len(score_breakdown.active_layers)
        
        # Breadth component: 1 layer -> 0.60, 2 layers -> 0.80, 3+ layers -> 0.95
        if active_count >= 3:
            breadth_conf = 0.95
        elif active_count == 2:
            breadth_conf = 0.80
        elif active_count == 1:
            breadth_conf = 0.60
        else:
            breadth_conf = 0.30

        # Agreement component: check for conflict between ML and TI
        has_conflict = False
        ti_score = score_breakdown.threat_intel_score
        ml_score = score_breakdown.ml_score

        if "THREAT_INTELLIGENCE" in score_breakdown.active_layers and "MACHINE_LEARNING" in score_breakdown.active_layers:
            # Significant divergence (e.g. TI says 100% malicious but ML says < 10% threat, or vice versa)
            if abs(ti_score - ml_score) > 60.0:
                has_conflict = True

        penalty = 0.20 if has_conflict else 0.0

        # Average weights of recorded signals
        avg_weight = sum(s.weight for s in evidence.signals) / max(1, len(evidence.signals))

        confidence = (breadth_conf * 0.70 + avg_weight * 0.30) - penalty
        return max(0.10, min(1.0, round(confidence, 4)))


class ExplanationGenerator:
    """Produces grounded, non-hallucinatory explanations strictly from observed evidence."""

    @classmethod
    def generate_explanation(
        cls,
        risk_level: RiskLevel,
        status: DetectionStatus,
        score: float,
        evidence: DetectionEvidence,
        breakdown: ScoreBreakdown
    ) -> Tuple[str, List[str]]:
        """
        Generates (primary_headline, detailed_reasons_list).
        Only mentions evidence signals that actually exist in the record.
        """
        reasons: List[str] = []

        # 1. Primary Headline
        if risk_level == RiskLevel.CRITICAL:
            if breakdown.threat_intel_score >= 85.0:
                primary = f"CRITICAL threat: Known malicious indicator verified by threat intelligence (Score: {score:.1f}/100)."
            elif breakdown.mutual_confirmation_boost:
                primary = f"CRITICAL threat: Machine learning and heuristic rules independently confirm high risk (Score: {score:.1f}/100)."
            else:
                primary = f"CRITICAL security threat identified with high confidence (Score: {score:.1f}/100)."
        elif risk_level == RiskLevel.HIGH:
            primary = f"HIGH risk security threat detected with multiple corroborating indicators (Score: {score:.1f}/100)."
        elif risk_level == RiskLevel.MEDIUM:
            primary = f"SUSPICIOUS activity: Target exhibits anomalous characteristics warranting caution (Score: {score:.1f}/100)."
        elif risk_level == RiskLevel.LOW:
            primary = f"LOW risk: Minor or benign signals observed; no active malicious behavior found (Score: {score:.1f}/100)."
        else:
            primary = f"INFORMATIONAL / BENIGN: Target matches safe operational baseline (Score: {score:.1f}/100)."

        # 2. Detailed Rationale
        if not evidence.signals:
            reasons.append("No suspicious indicators or anomalous features were discovered during static inspection.")
        else:
            # Sort signals by score contribution descending
            sorted_signals = sorted(evidence.signals, key=lambda s: s.score_contribution, reverse=True)
            for sig in sorted_signals:
                reasons.append(f"[{sig.source.value}] {sig.name}: {sig.description}")

        # Layer audit trail summary
        layer_summary = f"Active analysis layers evaluated: {', '.join(breakdown.active_layers) if breakdown.active_layers else 'None'}."
        reasons.append(layer_summary)

        return primary, reasons
