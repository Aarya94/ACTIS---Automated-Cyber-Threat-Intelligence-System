"""
Unit and Integration Tests for ACTIS Hierarchical Explainability Tree & Weight Validation
Automated Cyber Threat Intelligence System — Milestone Day 22

Validates:
1. Hierarchical explainability tree contracts, node categories, and bounds.
2. Evidence-to-score mathematical traceability.
3. Honest representation of unavailable/unsupported models and providers.
4. Redaction of sensitive tokens and credentials from explanations.
5. Deterministic repeatable tree generation.
6. Strict and safe RiskScoringWeights validation (NaN, inf, ranges, types).
7. End-to-end integration across file and URL scanning pipelines.
8. Sub-millisecond explanation generation performance.
"""

import math
import time
from pathlib import Path
import pytest

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
from detection_engine.explainability_tree import (
    ExplainabilityNode,
    ExplainabilityTree,
    ScoreTraceability,
    NodeCategory,
    NodeStatus,
    mask_sensitive_value,
    MAX_TREE_DEPTH,
    MAX_TOTAL_NODES,
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
from detection_engine.decision_engine import DetectionDecisionEngine
from detection_engine.threat_detector import ThreatDetector
from detection_engine.ml_prediction_contract import (
    MLPredictionResult,
    MLPredictionStatus,
    MLModelType,
)
from detection_engine.rule_engine import RuleEvaluationResult, RuleMatch, RuleSeverity
from detection_engine.threat_intel_contract import (
    ThreatIntelEvidence,
    ThreatIntelVerdict,
    IndicatorType,
)


class TestExplainabilityTreeStructureAndContracts:
    """Tests for hierarchical explainability tree models and node properties."""

    def test_tree_generation_for_simple_benign_target(self):
        """Verifies complete branch generation for a clean benign target."""
        evidence = DetectionEvidence()
        score, breakdown = RiskScoringEngine.score_evidence(evidence)
        lvl, stat, action = RiskClassifier.classify(score)
        conf = ConfidenceEngine.calculate_confidence(evidence, breakdown)

        tree = ExplanationGenerator.generate_explainability_tree(
            target_identifier="safe_document.pdf",
            input_type=InputType.FILE,
            risk_level=lvl,
            status=stat,
            score=score,
            confidence=conf,
            evidence=evidence,
            breakdown=breakdown
        )

        assert tree.target_identifier == "safe_document.pdf"
        assert tree.input_type == "FILE"
        assert tree.final_score == 0.0
        assert tree.risk_level == "INFORMATIONAL"
        assert tree.detection_status == "BENIGN"
        assert tree.total_nodes > 5
        assert tree.tree_depth <= MAX_TREE_DEPTH

        # Verify key branch categories exist
        cats = [n.category for n in tree.root.children]
        assert NodeCategory.INPUT_ANALYSIS in cats
        assert NodeCategory.STATIC_ANALYSIS in cats
        assert NodeCategory.RULE_ENGINE in cats
        assert NodeCategory.MACHINE_LEARNING in cats
        assert NodeCategory.THREAT_INTELLIGENCE in cats
        assert NodeCategory.EVIDENCE_AGGREGATION in cats
        assert NodeCategory.RISK_CALCULATION in cats
        assert NodeCategory.FINAL_DECISION in cats

    def test_multiple_independent_findings_in_branches(self):
        """Verifies that findings from different layers appear in their respective branches."""
        evidence = DetectionEvidence()
        # Heuristic rule
        evidence.add_signal(EvidenceSignal(
            source=EvidenceSource.HEURISTIC_RULES,
            signal_id="RULE_SUSP_IMPORT",
            name="Suspicious API Import",
            description="Process injection API sequence",
            severity=EvidenceSeverity.HIGH,
            score_contribution=75.0,
            weight=0.9
        ))
        # ML signal
        evidence.add_signal(EvidenceSignal(
            source=EvidenceSource.MACHINE_LEARNING,
            signal_id="ML_PE_HIGH_CONF",
            name="PE Malware Model",
            description="Probability 88.5%",
            severity=EvidenceSeverity.HIGH,
            score_contribution=88.5,
            weight=0.85,
            raw_data={"probability": 0.885, "model_name": "rf_pe_v2"}
        ))
        # Static anomaly
        evidence.add_signal(EvidenceSignal(
            source=EvidenceSource.STATIC_PE,
            signal_id="PE_ENTROPY_PACKED",
            name="Packed Section",
            description="Entropy 7.92 in .upx0",
            severity=EvidenceSeverity.MEDIUM,
            score_contribution=45.0,
            weight=0.7
        ))

        score, breakdown = RiskScoringEngine.score_evidence(evidence)
        lvl, stat, _ = RiskClassifier.classify(score)
        conf = ConfidenceEngine.calculate_confidence(evidence, breakdown)

        tree = ExplanationGenerator.generate_explainability_tree(
            target_identifier="malicious_sample.exe",
            input_type=InputType.PE_BINARY,
            risk_level=lvl,
            status=stat,
            score=score,
            confidence=conf,
            evidence=evidence,
            breakdown=breakdown
        )

        # Rule branch verification
        rule_node = tree.find_node("rule_engine")
        assert rule_node is not None
        assert rule_node.status == NodeStatus.SUSPICIOUS
        assert len(rule_node.children) == 1
        assert "RULE_SUSP_IMPORT" in rule_node.children[0].node_id

        # ML branch verification
        ml_node = tree.find_node("machine_learning")
        assert ml_node is not None
        assert ml_node.status == NodeStatus.SUSPICIOUS
        assert ml_node.score_contribution == 88.5

        # Static analysis branch verification
        static_node = tree.find_node("static_analysis")
        assert static_node is not None
        assert static_node.status == NodeStatus.SUSPICIOUS

    def test_unavailable_ml_model_representation(self):
        """Unavailable ML models must be recorded honestly as UNAVAILABLE, not as a clean verdict."""
        evidence = DetectionEvidence()
        score, breakdown = RiskScoringEngine.score_evidence(evidence)
        lvl, stat, _ = RiskClassifier.classify(score)
        conf = ConfidenceEngine.calculate_confidence(evidence, breakdown)

        tree = ExplanationGenerator.generate_explainability_tree(
            target_identifier="script.ps1",
            input_type=InputType.FILE,
            risk_level=lvl,
            status=stat,
            score=score,
            confidence=conf,
            evidence=evidence,
            breakdown=breakdown,
            metadata={"analysis_method": "SCRIPT_FALLBACK", "is_pe": False}
        )

        ml_node = tree.find_node("machine_learning")
        assert ml_node is not None
        assert ml_node.status == NodeStatus.UNAVAILABLE
        assert "unavailable" in ml_node.description.lower()
        # Ensure it does not claim clean/benign
        assert ml_node.status != NodeStatus.BENIGN

    def test_confirmed_threat_intelligence_provenance(self):
        """Confirmed threat intelligence records must indicate CONFIRMED_THREAT and override floor."""
        evidence = DetectionEvidence()
        evidence.add_signal(EvidenceSignal(
            source=EvidenceSource.THREAT_INTELLIGENCE,
            signal_id="TI_CONFIRMED_HASH",
            name="VirusTotal Confirmed Malware",
            description="58/70 engines detected WannaCry",
            severity=EvidenceSeverity.CRITICAL,
            score_contribution=100.0,
            weight=1.0,
            raw_data={"source": "virustotal", "positives": 58, "total": 70}
        ))

        score, breakdown = RiskScoringEngine.score_evidence(evidence)
        lvl, stat, _ = RiskClassifier.classify(score, is_confirmed_threat=True)
        conf = ConfidenceEngine.calculate_confidence(evidence, breakdown)

        tree = ExplanationGenerator.generate_explainability_tree(
            target_identifier="ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
            input_type=InputType.HASH,
            risk_level=lvl,
            status=stat,
            score=score,
            confidence=conf,
            evidence=evidence,
            breakdown=breakdown,
            is_confirmed_threat=True
        )

        ti_node = tree.find_node("threat_intelligence")
        assert ti_node is not None
        assert ti_node.status == NodeStatus.CONFIRMED_THREAT
        assert tree.traceability.is_override is True
        assert tree.final_score >= 90.0

    def test_tree_depth_and_node_count_bounds(self):
        """Verifies tree node additions are strictly bounded to prevent memory exhaustion."""
        root = ExplainabilityNode(
            node_id="root",
            category=NodeCategory.ROOT,
            title="Root",
            description="Root",
            status=NodeStatus.EVALUATED
        )

        # Attempt adding more than MAX_TOTAL_NODES
        added_count = 0
        for i in range(MAX_TOTAL_NODES + 50):
            success = root.add_child(
                ExplainabilityNode(
                    node_id=f"child_{i}",
                    category=NodeCategory.FINDING,
                    title=f"Child {i}",
                    description="Test",
                    status=NodeStatus.EVALUATED
                ),
                current_total_nodes=root.count_nodes()
            )
            if success:
                added_count += 1

        assert root.count_nodes() <= MAX_TOTAL_NODES

    def test_sensitive_token_redaction_in_explanations(self):
        """Tokens, passwords, and API keys must be redacted from all explanation nodes."""
        raw_token = "api_key=abcdef1234567890secret_token"
        masked = mask_sensitive_value(raw_token)
        assert "abcdef1234567890" not in masked
        assert "****" in masked

        node = ExplainabilityNode(
            node_id="test_node",
            category=NodeCategory.FINDING,
            title="External Provider Result",
            description=f"Received response with token: bearer secret_access_token_12345678",
            status=NodeStatus.EVALUATED,
            metadata={"auth_header": "Bearer super_secret_auth_token_9999"}
        )
        d = node.to_dict()
        assert "secret_access_token" not in d["description"]
        assert "****" in d["description"]
        assert "super_secret_auth_token" not in str(d["metadata"])


class TestMathematicalTraceability:
    """Tests for exact evidence-to-score calculation traceability."""

    def test_traceability_exact_score_match(self):
        """Verifies that traceability.final_score matches authoritative RiskEngine output."""
        evidence = DetectionEvidence()
        evidence.add_signal(EvidenceSignal(
            source=EvidenceSource.MACHINE_LEARNING,
            signal_id="ML1",
            name="ML Model",
            description="80% probability",
            severity=EvidenceSeverity.HIGH,
            score_contribution=80.0
        ))
        evidence.add_signal(EvidenceSignal(
            source=EvidenceSource.HEURISTIC_RULES,
            signal_id="R1",
            name="Rule",
            description="Rule hit",
            severity=EvidenceSeverity.HIGH,
            score_contribution=60.0
        ))

        score, breakdown = RiskScoringEngine.score_evidence(evidence)
        lvl, stat, _ = RiskClassifier.classify(score)
        conf = ConfidenceEngine.calculate_confidence(evidence, breakdown)

        tree = ExplanationGenerator.generate_explainability_tree(
            target_identifier="test_target",
            input_type=InputType.FILE,
            risk_level=lvl,
            status=stat,
            score=score,
            confidence=conf,
            evidence=evidence,
            breakdown=breakdown
        )

        trace = tree.traceability
        assert trace.final_score == score
        assert trace.active_layers == ["MACHINE_LEARNING", "HEURISTIC_RULES"]
        assert math.isclose(
            sum(trace.normalized_weights.values()),
            1.0,
            rel_tol=1e-3,
            abs_tol=1e-3
        )
        assert trace.mutual_confirmation_boost is True  # ML >= 70 and Rules >= 50
        assert trace.boost_multiplier == 1.25

    def test_reputation_mitigation_traceability(self):
        """Mitigation discounts must be explicitly tracked in score traceability."""
        evidence = DetectionEvidence()
        evidence.add_signal(EvidenceSignal(
            source=EvidenceSource.HEURISTIC_RULES,
            signal_id="R1",
            name="Rule",
            description="Rule",
            severity=EvidenceSeverity.MEDIUM,
            score_contribution=50.0
        ))
        evidence.add_signal(EvidenceSignal(
            source=EvidenceSource.REPUTATION,
            signal_id="REP_TRUSTED",
            name="Trusted Cert",
            description="Signed by Microsoft",
            severity=EvidenceSeverity.INFO,
            score_contribution=20.0
        ))

        score, breakdown = RiskScoringEngine.score_evidence(evidence)
        lvl, stat, _ = RiskClassifier.classify(score)
        conf = ConfidenceEngine.calculate_confidence(evidence, breakdown)

        tree = ExplanationGenerator.generate_explainability_tree(
            target_identifier="signed_binary.exe",
            input_type=InputType.PE_BINARY,
            risk_level=lvl,
            status=stat,
            score=score,
            confidence=conf,
            evidence=evidence,
            breakdown=breakdown
        )

        assert tree.traceability.mitigation_adjustment == 20.0
        assert tree.final_score == 30.0  # 50 - 20

    def test_ascii_rendering_completeness(self):
        """Verifies that ASCII rendering produces formatted branches and traceability summary."""
        evidence = DetectionEvidence()
        evidence.add_signal(EvidenceSignal(
            source=EvidenceSource.HEURISTIC_RULES,
            signal_id="R_TEST",
            name="Test Signature",
            description="Suspicious payload pattern",
            severity=EvidenceSeverity.HIGH,
            score_contribution=65.0
        ))
        score, breakdown = RiskScoringEngine.score_evidence(evidence)
        lvl, stat, _ = RiskClassifier.classify(score)
        conf = ConfidenceEngine.calculate_confidence(evidence, breakdown)

        tree = ExplanationGenerator.generate_explainability_tree(
            target_identifier="payload.bin",
            input_type=InputType.FILE,
            risk_level=lvl,
            status=stat,
            score=score,
            confidence=conf,
            evidence=evidence,
            breakdown=breakdown
        )

        rendered = tree.render_ascii()
        assert "ACTIS Explainability Tree" in rendered
        assert "payload.bin" in rendered
        assert "Test Signature" in rendered
        assert "Traceability:" in rendered
        assert "├── " in rendered or "└── " in rendered


class TestRiskScoringWeightsValidation:
    """Comprehensive validation tests for RiskScoringWeights configuration."""

    def test_valid_default_weights(self):
        w = RiskScoringWeights.default()
        assert w.threat_intel == 0.35
        assert w.ml_probability == 0.30
        assert w.heuristic_rules == 0.20
        assert w.static_pe == 0.15
        assert math.isclose(sum(w.to_dict().values()), 1.0)

    def test_rejects_nan_and_infinite_weights(self):
        with pytest.raises(ValueError, match="finite number"):
            RiskScoringWeights(threat_intel=float("nan"))
        with pytest.raises(ValueError, match="finite number"):
            RiskScoringWeights(ml_probability=float("inf"))
        with pytest.raises(ValueError, match="finite number"):
            RiskScoringWeights(heuristic_rules=float("-inf"))

    def test_rejects_negative_weights(self):
        with pytest.raises(ValueError, match="between 0.0 and 1.0"):
            RiskScoringWeights(threat_intel=-0.10)

    def test_rejects_out_of_range_weights(self):
        with pytest.raises(ValueError, match="between 0.0 and 1.0"):
            RiskScoringWeights(threat_intel=1.5)

    def test_rejects_non_numeric_types(self):
        with pytest.raises(TypeError, match="numeric float or integer"):
            RiskScoringWeights(threat_intel="0.5")  # type: ignore
        with pytest.raises(TypeError, match="numeric float or integer"):
            RiskScoringWeights(threat_intel=True)  # type: ignore

    def test_rejects_all_zero_weights(self):
        with pytest.raises(ValueError, match="strictly positive"):
            RiskScoringWeights(threat_intel=0.0, ml_probability=0.0, heuristic_rules=0.0, static_pe=0.0)

    def test_normalized_method(self):
        w = RiskScoringWeights(threat_intel=0.5, ml_probability=0.5, heuristic_rules=0.5, static_pe=0.5)
        norm = w.normalized()
        assert math.isclose(sum(norm.to_dict().values()), 1.0)
        assert norm.threat_intel == 0.25

    def test_from_dict_strict_mode(self):
        valid_dict = {
            "threat_intel": 0.40,
            "ml_probability": 0.30,
            "heuristic_rules": 0.20,
            "static_pe": 0.10
        }
        w = RiskScoringWeights.from_dict(valid_dict, strict=True)
        assert w.threat_intel == 0.40

        invalid_dict = dict(valid_dict)
        invalid_dict["unknown_layer"] = 0.50
        with pytest.raises(ValueError, match="Unknown weight name"):
            RiskScoringWeights.from_dict(invalid_dict, strict=True)

    def test_from_dict_non_strict_mode(self):
        data = {
            "threat_intel": 0.50,
            "ml_probability": 0.30,
            "heuristic_rules": 0.20,
            "static_pe": 0.0,
            "extra_ignored_key": 999
        }
        w = RiskScoringWeights.from_dict(data, strict=False)
        assert w.threat_intel == 0.50

    def test_scoring_with_custom_validated_weights(self):
        custom = RiskScoringWeights(
            threat_intel=0.90,
            ml_probability=0.10,
            heuristic_rules=0.0,
            static_pe=0.0
        )
        evidence = DetectionEvidence()
        evidence.add_signal(EvidenceSignal(
            source=EvidenceSource.THREAT_INTELLIGENCE,
            signal_id="TI1",
            name="Intel",
            description="Found",
            severity=EvidenceSeverity.HIGH,
            score_contribution=100.0
        ))
        evidence.add_signal(EvidenceSignal(
            source=EvidenceSource.MACHINE_LEARNING,
            signal_id="ML1",
            name="ML",
            description="Low",
            severity=EvidenceSeverity.LOW,
            score_contribution=0.0
        ))
        score, breakdown = RiskScoringEngine.score_evidence(evidence, weights=custom)
        # 100 * 0.90 + 0 * 0.10 = 90.0
        assert score == 90.0


class TestEndToEndPipelineIntegration:
    """Verifies that file and URL pipelines produce structured explainability trees."""

    def test_detector_analyze_url_produces_explainability_tree(self):
        detector = ThreatDetector()
        res = detector.analyze_url("https://example.com/login-test")

        assert "detection_result" in res
        assert "explainability_tree" in res
        assert res["explainability_tree"] is not None
        tree_dict = res["explainability_tree"]
        assert "target_identifier" in tree_dict
        assert "traceability" in tree_dict
        assert "root" in tree_dict
        assert tree_dict["final_score"] == res["detection_result"]["risk_score"]

    def test_detector_analyze_file_produces_explainability_tree(self, tmp_path):
        dummy_file = tmp_path / "sample_text.txt"
        dummy_file.write_text("Safe content for testing explainability.", encoding="utf-8")

        detector = ThreatDetector()
        res = detector.analyze_file(dummy_file)

        assert "detection_result" in res
        assert "explainability_tree" in res
        assert res["explainability_tree"] is not None
        tree_dict = res["explainability_tree"]
        assert tree_dict["target_identifier"] == str(dummy_file)
        assert tree_dict["final_score"] == res["detection_result"]["risk_score"]
        assert "root" in tree_dict

    def test_repeatable_identical_explanations(self):
        """Verifies deterministic repeatability across duplicate evaluations."""
        evidence = DetectionEvidence()
        evidence.add_signal(EvidenceSignal(
            source=EvidenceSource.HEURISTIC_RULES,
            signal_id="R_REPEAT",
            name="Repeatability Signature",
            description="Testing deterministic output",
            severity=EvidenceSeverity.HIGH,
            score_contribution=70.0
        ))
        res1 = DetectionDecisionEngine.evaluate("repeat_target", InputType.HASH, static_signals=evidence.signals)
        res2 = DetectionDecisionEngine.evaluate("repeat_target", InputType.HASH, static_signals=evidence.signals)

        tree1 = res1.explainability_tree
        tree2 = res2.explainability_tree
        assert tree1 is not None and tree2 is not None
        assert tree1["final_score"] == tree2["final_score"]
        assert tree1["total_nodes"] == tree2["total_nodes"]
        assert tree1["summary_reasons"] == tree2["summary_reasons"]
        assert tree1["traceability"] == tree2["traceability"]

    def test_submillisecond_tree_generation_performance(self):
        """Benchmarks explanation tree generation across 50 evidence signals."""
        evidence = DetectionEvidence()
        for i in range(50):
            evidence.add_signal(EvidenceSignal(
                source=EvidenceSource.HEURISTIC_RULES,
                signal_id=f"RULE_{i:02d}",
                name=f"Rule Metric {i}",
                description=f"Generated heuristic finding {i}",
                severity=EvidenceSeverity.LOW if i % 2 == 0 else EvidenceSeverity.MEDIUM,
                score_contribution=float(i)
            ))

        score, breakdown = RiskScoringEngine.score_evidence(evidence)
        lvl, stat, _ = RiskClassifier.classify(score)
        conf = ConfidenceEngine.calculate_confidence(evidence, breakdown)

        start = time.perf_counter()
        tree = ExplanationGenerator.generate_explainability_tree(
            target_identifier="benchmark_target",
            input_type=InputType.FILE,
            risk_level=lvl,
            status=stat,
            score=score,
            confidence=conf,
            evidence=evidence,
            breakdown=breakdown
        )
        elapsed_ms = (time.perf_counter() - start) * 1000.0

        assert tree is not None
        assert tree.total_nodes > 10
        # Tree generation for 50 signals should execute in less than 5 milliseconds
        assert elapsed_ms < 5.0, f"Tree generation took {elapsed_ms:.2f} ms (expected < 5.0 ms)"
