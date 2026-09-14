"""
Unit Tests for ACTIS Detection Engine Foundation (Day 6)
Validates detection result contracts, evidence models, rule evaluations,
ML prediction representations, threat intelligence integration, and deterministic decision fusion.
"""

import pytest
from detection_engine.detection_contract import (
    DetectionResult,
    DetectionStatus,
    RiskLevel,
    InputType,
)
from detection_engine.evidence_model import (
    EvidenceSource,
    EvidenceSeverity,
    EvidenceSignal,
    DetectionEvidence,
)
from detection_engine.ml_prediction_contract import (
    MLModelType,
    MLPredictionStatus,
    MLPredictionResult,
)
from detection_engine.rule_engine import (
    RuleEngine,
    RuleSeverity,
    RuleTargetType,
    RuleMatch,
    RuleEvaluationResult,
    RuleDefinition,
    GenericRuleRegistry,
)
from detection_engine.threat_intel_contract import (
    ThreatIntelVerdict,
    IndicatorType,
    ThreatIntelEvidence,
)
from detection_engine.risk_engine import (
    RiskEngine,
    RiskScoringWeights,
    ScoreBreakdown,
    RiskScoringEngine,
    RiskThresholdConfig,
    RiskClassifier,
)
from detection_engine.explanation_generator import (
    ConfidenceEngine,
    ExplanationGenerator,
)
from detection_engine.model_manager import model_manager, ModelManager
from detection_engine.decision_engine import DetectionDecisionEngine


class TestDetectionContractsAndEvidence:
    """Tests for Day 6 contract dataclasses and evidence serialization."""

    def test_detection_result_clamping_and_properties(self):
        result = DetectionResult(
            target_identifier="abc123hash",
            input_type=InputType.HASH,
            detection_status=DetectionStatus.MALICIOUS,
            risk_level=RiskLevel.CRITICAL,
            risk_score=150.0,  # Should clamp to 100.0
            confidence=1.5,    # Should clamp to 1.0
            primary_reason="Known malicious sample"
        )
        assert result.risk_score == 100.0
        assert result.confidence == 1.0
        assert result.is_threat is True
        d = result.to_dict()
        assert d["is_threat"] is True
        assert d["risk_level"] == "CRITICAL"
        assert d["risk_score"] == 100.0

    def test_detection_evidence_aggregation_and_filtering(self):
        evidence = DetectionEvidence()
        sig1 = EvidenceSignal(
            source=EvidenceSource.THREAT_INTELLIGENCE,
            signal_id="TI_01",
            name="Confirmed Threat",
            description="Found in database",
            severity=EvidenceSeverity.CRITICAL,
            score_contribution=100.0,
            weight=1.0
        )
        sig2 = EvidenceSignal(
            source=EvidenceSource.HEURISTIC_RULES,
            signal_id="RULE_01",
            name="Suspicious Section",
            description="Packed header",
            severity=EvidenceSeverity.MEDIUM,
            score_contribution=30.0,
            weight=0.8
        )
        evidence.add_signal(sig1)
        evidence.add_signal(sig2)

        assert evidence.has_critical_evidence() is True
        assert evidence.get_max_severity() == EvidenceSeverity.CRITICAL
        ti_signals = evidence.get_signals_by_source(EvidenceSource.THREAT_INTELLIGENCE)
        assert len(ti_signals) == 1
        assert ti_signals[0].signal_id == "TI_01"
        assert evidence.get_total_weighted_score() == 100.0 * 1.0 + 30.0 * 0.8
        explanations = evidence.format_explanations()
        assert len(explanations) == 2
        assert "[THREAT_INTELLIGENCE]" in explanations[0]


class TestRuleEngineContractsAndEvaluation:
    """Tests for rule evaluation results, matches, and generic registry."""

    def test_rule_match_to_evidence_signal(self):
        match = RuleMatch(
            rule_id="RULE_PE_TEST",
            rule_name="Test WX Section",
            severity=RuleSeverity.CRITICAL,
            score_contribution=40.0,
            explanation="Section is both writable and executable."
        )
        sig = match.to_evidence_signal()
        assert sig.source == EvidenceSource.HEURISTIC_RULES
        assert sig.severity == EvidenceSeverity.CRITICAL
        assert sig.score_contribution == 40.0
        assert sig.description == "Section is both writable and executable."

    def test_generic_rule_registry_execution(self):
        registry = GenericRuleRegistry()
        rule1 = RuleDefinition(
            rule_id="CUSTOM_RULE_1",
            name="Length Check",
            description="Identifier length too long",
            severity=RuleSeverity.LOW,
            target_type=RuleTargetType.GENERIC,
            base_score=15.0,
            condition=lambda t: (len(str(t)) > 10, "Target length exceeds 10 chars", {"length": len(str(t))})
        )
        registry.register(rule1)

        res = registry.evaluate("short", "short", RuleTargetType.GENERIC)
        assert res.matched_count == 0
        assert res.total_score == 0.0

        res2 = registry.evaluate("a_very_long_string_target", "target2", RuleTargetType.GENERIC)
        assert res2.matched_count == 1
        assert res2.total_score == 15.0
        assert res2.max_severity == RuleSeverity.LOW


class TestMLAndThreatIntelContracts:
    """Tests for ML prediction and threat intelligence evidence contracts."""

    def test_ml_prediction_result_conversion(self):
        pred = MLPredictionResult(
            model_name="phishing_rf",
            model_version="1.0.0",
            model_type=MLModelType.PHISHING_URL,
            status=MLPredictionStatus.AVAILABLE,
            is_threat=True,
            probability=0.92,
            confidence=0.84,
            prediction_label="PHISHING"
        )
        sig = pred.to_evidence_signal()
        assert sig is not None
        assert sig.source == EvidenceSource.MACHINE_LEARNING
        assert sig.severity == EvidenceSeverity.CRITICAL
        assert sig.score_contribution == 92.0

    def test_ml_prediction_unavailable_and_error(self):
        unavail = MLPredictionResult.unavailable("malware_rf", MLModelType.WINDOWS_PE_MALWARE, "File missing")
        assert unavail.status == MLPredictionStatus.MODEL_UNAVAILABLE
        assert unavail.to_evidence_signal() is None

        err = MLPredictionResult.from_error("malware_rf", MLModelType.WINDOWS_PE_MALWARE, RuntimeError("Crash"))
        assert err.status == MLPredictionStatus.INFERENCE_ERROR
        assert "Crash" in (err.error_message or "")
        assert err.to_evidence_signal() is None

    def test_threat_intel_evidence_from_local_intel(self):
        # 1. Confirmed malicious
        intel_mal = {"found": True, "status": "CONFIRMED", "confidence": 0.95, "threat_type": "Trojan"}
        ti_mal = ThreatIntelEvidence.from_local_intel(intel_mal, "hash123", IndicatorType.SHA256)
        assert ti_mal.verdict == ThreatIntelVerdict.MALICIOUS
        assert ti_mal.is_confirmed_threat is True
        sig_mal = ti_mal.to_evidence_signal()
        assert sig_mal is not None
        assert sig_mal.severity == EvidenceSeverity.CRITICAL
        assert sig_mal.score_contribution == 95.0

        # 2. False positive
        intel_fp = {"found": True, "status": "FALSE_POSITIVE", "confidence": 1.0}
        ti_fp = ThreatIntelEvidence.from_local_intel(intel_fp, "hash_clean", IndicatorType.SHA256)
        assert ti_fp.verdict == ThreatIntelVerdict.FALSE_POSITIVE
        assert ti_fp.is_whitelisted is True

        # 3. Unknown
        ti_unk = ThreatIntelEvidence.unknown("hash_unknown", IndicatorType.SHA256)
        assert ti_unk.verdict == ThreatIntelVerdict.UNKNOWN
        assert ti_unk.to_evidence_signal() is None


class TestDetectionDecisionEngineEndToEnd:
    """End-to-end integration tests for DetectionDecisionEngine."""

    def test_decision_engine_with_confirmed_malicious_ti(self):
        ti = ThreatIntelEvidence(
            indicator="test_malware_hash",
            indicator_type=IndicatorType.SHA256,
            verdict=ThreatIntelVerdict.MALICIOUS,
            confidence=1.0,
            threat_type="Ransomware",
            is_confirmed_threat=True
        )
        res = DetectionDecisionEngine.evaluate(
            target_identifier="test_malware_hash",
            input_type=InputType.HASH,
            ti_evidence=ti
        )
        assert res.risk_level == RiskLevel.CRITICAL
        assert res.detection_status == DetectionStatus.MALICIOUS
        assert res.risk_score >= 90.0
        assert res.is_threat is True
        assert "CRITICAL" in res.primary_reason

    def test_decision_engine_with_benign_evidence(self):
        ti = ThreatIntelEvidence(
            indicator="safe_domain.com",
            indicator_type=IndicatorType.DOMAIN,
            verdict=ThreatIntelVerdict.CLEAN,
            confidence=1.0,
            is_whitelisted=True
        )
        res = DetectionDecisionEngine.evaluate(
            target_identifier="safe_domain.com",
            input_type=InputType.DOMAIN,
            ti_evidence=ti
        )
        assert res.risk_level == RiskLevel.INFORMATIONAL
        assert res.detection_status == DetectionStatus.BENIGN
        assert res.is_threat is False

    def test_decision_engine_empty_evidence_safe_fallback(self):
        res = DetectionDecisionEngine.evaluate(
            target_identifier="unknown_target",
            input_type=InputType.GENERIC
        )
        assert res.risk_level == RiskLevel.INFORMATIONAL
        assert res.detection_status == DetectionStatus.BENIGN
        assert res.risk_score == 0.0
        assert res.confidence <= 0.30
        assert len(res.reasons) >= 1

    def test_decision_engine_combined_ml_and_rules(self):
        ml = MLPredictionResult(
            model_name="phishing_rf",
            model_version="1.0.0",
            model_type=MLModelType.PHISHING_URL,
            status=MLPredictionStatus.AVAILABLE,
            is_threat=True,
            probability=0.88,
            confidence=0.85,
            prediction_label="PHISHING"
        )
        match = RuleMatch(
            rule_id="RULE_URL_IP_HOST",
            rule_name="IP Hostname",
            severity=RuleSeverity.HIGH,
            score_contribution=35.0,
            explanation="URL uses raw IP hostname"
        )
        rule_res = RuleEvaluationResult(
            target_identifier="http://1.2.3.4/login",
            target_type=RuleTargetType.URL,
            matches=[match]
        )
        res = DetectionDecisionEngine.evaluate(
            target_identifier="http://1.2.3.4/login",
            input_type=InputType.URL,
            ml_prediction=ml,
            rule_result=rule_res
        )
        assert res.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        assert res.detection_status == DetectionStatus.MALICIOUS
        assert res.risk_score >= 60.0
        assert res.confidence >= 0.70
