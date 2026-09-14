"""
Unit Tests for ACTIS Risk Engine Edge Cases (Day 6)
Validates deterministic mathematical scoring, weight configurations, threshold boundaries,
conflicting signals, whitelist overrides, missing layers, and decision repeatability.
"""

import pytest
from detection_engine.detection_contract import RiskLevel, DetectionStatus, InputType
from detection_engine.evidence_model import (
    DetectionEvidence,
    EvidenceSignal,
    EvidenceSource,
    EvidenceSeverity,
)
from detection_engine.risk_engine import (
    RiskScoringEngine,
    RiskScoringWeights,
    ScoreBreakdown,
    RiskThresholdConfig,
    RiskClassifier,
)
from detection_engine.decision_engine import DetectionDecisionEngine


class TestRiskScoringEdgeCases:
    """Rigorous edge-case validation for the risk scoring engine."""

    def test_zero_signals_scoring(self):
        evidence = DetectionEvidence()
        score, breakdown = RiskScoringEngine.score_evidence(evidence)
        assert score == 0.0
        assert breakdown.active_layers == []
        assert breakdown.raw_composite == 0.0

    def test_single_active_layer_dynamic_renormalization(self):
        evidence = DetectionEvidence()
        sig = EvidenceSignal(
            source=EvidenceSource.HEURISTIC_RULES,
            signal_id="RULE_01",
            name="Test Rule",
            description="Rule finding",
            severity=EvidenceSeverity.HIGH,
            score_contribution=60.0
        )
        evidence.add_signal(sig)
        score, breakdown = RiskScoringEngine.score_evidence(evidence)
        # Because only heuristic rules are active, dynamic normalization divides by rule weight
        # resulting in the layer score (60.0) being accurately represented without arbitrary suppression
        assert score == 60.0
        assert breakdown.active_layers == ["HEURISTIC_RULES"]

    def test_custom_weights_and_zero_weight_layers(self):
        custom = RiskScoringWeights(
            threat_intel=0.80,
            ml_probability=0.20,
            heuristic_rules=0.0,
            static_pe=0.0
        )
        evidence = DetectionEvidence()
        # High rule score (should contribute 0 due to 0 weight)
        evidence.add_signal(EvidenceSignal(
            source=EvidenceSource.HEURISTIC_RULES,
            signal_id="R1",
            name="Rule",
            description="Ignored",
            severity=EvidenceSeverity.HIGH,
            score_contribution=100.0
        ))
        # Moderate TI score
        evidence.add_signal(EvidenceSignal(
            source=EvidenceSource.THREAT_INTELLIGENCE,
            signal_id="TI1",
            name="TI",
            description="Moderate",
            severity=EvidenceSeverity.MEDIUM,
            score_contribution=50.0
        ))
        score, breakdown = RiskScoringEngine.score_evidence(evidence, weights=custom)
        assert score == 50.0

    def test_reputation_mitigation_subtraction(self):
        evidence = DetectionEvidence()
        # Malicious heuristic finding
        evidence.add_signal(EvidenceSignal(
            source=EvidenceSource.HEURISTIC_RULES,
            signal_id="R1",
            name="Rule",
            description="Suspicious",
            severity=EvidenceSeverity.HIGH,
            score_contribution=70.0
        ))
        # Verified benign whitelist reputation mitigation (30.0 discount)
        evidence.add_signal(EvidenceSignal(
            source=EvidenceSource.REPUTATION,
            signal_id="REP_WHITELIST",
            name="Trusted Vendor",
            description="Known good",
            severity=EvidenceSeverity.INFO,
            score_contribution=30.0
        ))
        score, breakdown = RiskScoringEngine.score_evidence(evidence)
        assert breakdown.mitigation_adjustment == 30.0
        assert score == 40.0  # 70 - 30


class TestRiskClassificationThresholdBoundaries:
    """Tests boundary conditions and overrides in RiskClassifier."""

    def test_exact_threshold_transitions(self):
        cfg = RiskThresholdConfig(
            informational_max=20.0,
            low_max=35.0,
            medium_max=70.0,
            high_max=85.0,
            critical_min=85.0
        )
        # Below informational
        lvl, stat, _ = RiskClassifier.classify(15.0, thresholds=cfg)
        assert lvl == RiskLevel.INFORMATIONAL
        assert stat == DetectionStatus.BENIGN

        # At low boundary
        lvl, stat, _ = RiskClassifier.classify(20.0, thresholds=cfg)
        assert lvl == RiskLevel.LOW
        assert stat == DetectionStatus.BENIGN

        # At medium boundary
        lvl, stat, _ = RiskClassifier.classify(35.0, thresholds=cfg)
        assert lvl == RiskLevel.MEDIUM
        assert stat == DetectionStatus.SUSPICIOUS

        # At high boundary
        lvl, stat, _ = RiskClassifier.classify(70.0, thresholds=cfg)
        assert lvl == RiskLevel.HIGH
        assert stat == DetectionStatus.MALICIOUS

        # At critical boundary
        lvl, stat, _ = RiskClassifier.classify(85.0, thresholds=cfg)
        assert lvl == RiskLevel.CRITICAL
        assert stat == DetectionStatus.MALICIOUS

    def test_whitelist_safety_override(self):
        # Even with maximum risk score 100.0, whitelist flag forces INFORMATIONAL/BENIGN
        lvl, stat, action = RiskClassifier.classify(100.0, is_whitelisted=True)
        assert lvl == RiskLevel.INFORMATIONAL
        assert stat == DetectionStatus.BENIGN
        assert "whitelist" in action.lower()

    def test_confirmed_threat_override(self):
        # Even with low score 10.0, confirmed threat flag guarantees CRITICAL/MALICIOUS
        lvl, stat, action = RiskClassifier.classify(10.0, is_confirmed_threat=True)
        assert lvl == RiskLevel.CRITICAL
        assert stat == DetectionStatus.MALICIOUS
        assert "CRITICAL" in action

    def test_deterministic_repeatability(self):
        """Validates that identical evidence inputs always produce byte-for-byte identical decisions."""
        ev1 = DetectionEvidence()
        ev1.add_signal(EvidenceSignal(
            source=EvidenceSource.HEURISTIC_RULES,
            signal_id="R_REP",
            name="Test",
            description="Desc",
            severity=EvidenceSeverity.MEDIUM,
            score_contribution=45.0
        ))
        res1 = DetectionDecisionEngine.evaluate("repeatable_target", InputType.HASH, static_signals=ev1.signals)
        res2 = DetectionDecisionEngine.evaluate("repeatable_target", InputType.HASH, static_signals=ev1.signals)
        assert res1.risk_score == res2.risk_score
        assert res1.risk_level == res2.risk_level
        assert res1.detection_status == res2.detection_status
        assert res1.confidence == res2.confidence
        assert res1.primary_reason == res2.primary_reason
