"""
ACTIS Evidence Fusion Edge-Case Audit & Detection Reliability Test Suite
Day 23 — Month 2, Week 6, Day 42

Systematic, test-backed verification across:
1. Contradictory evidence (ML high vs TI absent, ML low vs TI confirmed, Whitelist vs Confirmed TI).
2. Missing and unavailable evidence (TI timeouts, rate limits, missing ML models, unsupported formats).
3. Duplicate and correlated evidence (Exact signal deduplication, audit trail, score inflation prevention).
4. Risk-scoring boundaries (0, 100, epsilons around 20, 35, 60, 80, NaN/Inf rejection).
5. Safety override precedence (Whitelist priority over Confirmed TI, pre-override traceability).
6. Explainability consistency (Tree score == Authoritative score, redaction, bounded nodes).
7. Offline analysis and failure recovery (External TI outage resilience).
"""

import math
import pytest
from pathlib import Path
from typing import Dict, Any

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
    MLModelType,
)
from detection_engine.rule_engine import (
    RuleEvaluationResult,
    RuleMatch,
    RuleSeverity,
    RuleTargetType,
)
from detection_engine.threat_intel_contract import (
    ThreatIntelEvidence,
    ThreatIntelVerdict,
    IndicatorType,
)
from detection_engine.risk_engine import (
    RiskScoringEngine,
    RiskScoringWeights,
    RiskClassifier,
    RiskThresholdConfig,
    ScoreBreakdown,
)
from detection_engine.decision_engine import DetectionDecisionEngine
from detection_engine.explanation_generator import (
    ConfidenceEngine,
    ExplanationGenerator,
)
from detection_engine.explainability_tree import (
    ExplainabilityTree,
    NodeCategory,
    NodeStatus,
    MAX_TOTAL_NODES,
)


# ==============================================================================
# PHASE 2: CONTRADICTORY EVIDENCE TESTS
# ==============================================================================

class TestContradictoryEvidence:
    """Verifies pipeline behavior under conflicting intelligence signals."""

    def test_case_a_ml_high_threat_intel_absent(self):
        """
        CASE A: ML reports high probability (0.85 -> 85.0), while TI has no matching indicator.
        Absence of TI indicator is neutral; ML finding is preserved without suppression.
        """
        ml = MLPredictionResult(
            model_name="actis_windows_pe_malware_rf",
            model_version="1.0.0",
            model_type=MLModelType.WINDOWS_PE_MALWARE,
            status=MLPredictionStatus.AVAILABLE,
            is_threat=True,
            probability=0.85,
            prediction_label="Malware",
            confidence=0.85
        )
        ti = ThreatIntelEvidence.unknown(
            indicator="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            indicator_type=IndicatorType.SHA256,
            provider="LOCAL_DB"
        )

        res = DetectionDecisionEngine.evaluate(
            target_identifier="sample_ml_threat.exe",
            input_type=InputType.PE_BINARY,
            ti_evidence=ti,
            ml_prediction=ml
        )

        assert res.risk_score == 85.0
        assert res.risk_level == RiskLevel.CRITICAL
        assert res.detection_status == DetectionStatus.MALICIOUS
        assert "MACHINE_LEARNING" in res.analysis_metadata["score_breakdown"]["active_layers"]
        assert "THREAT_INTELLIGENCE" not in res.analysis_metadata["score_breakdown"]["active_layers"]

    def test_case_b_ml_low_threat_intel_confirmed_critical(self):
        """
        CASE B: ML reports low probability (0.05), but TI reports a confirmed malicious indicator.
        Confirmed TI guarantees CRITICAL floor (score >= 90.0, MALICIOUS status).
        """
        ml = MLPredictionResult(
            model_name="actis_windows_pe_malware_rf",
            model_version="1.0.0",
            model_type=MLModelType.WINDOWS_PE_MALWARE,
            status=MLPredictionStatus.AVAILABLE,
            is_threat=False,
            probability=0.05,
            prediction_label="Benign",
            confidence=0.95
        )
        ti = ThreatIntelEvidence(
            indicator="44d88612fea8a8f36de82e1278abb02f",
            indicator_type=IndicatorType.MD5,
            verdict=ThreatIntelVerdict.MALICIOUS,
            confidence=1.0,
            is_confirmed_threat=True,
            threat_type="Ransomware",
            provider="LOCAL_DB"
        )

        res = DetectionDecisionEngine.evaluate(
            target_identifier="wannacry_sample.exe",
            input_type=InputType.PE_BINARY,
            ti_evidence=ti,
            ml_prediction=ml
        )

        assert res.risk_score >= 90.0
        assert res.risk_level == RiskLevel.CRITICAL
        assert res.detection_status == DetectionStatus.MALICIOUS
        # Significant conflict penalizes internal decision confidence
        assert res.confidence < 0.80

    def test_case_c_static_structural_findings_rules_clean(self):
        """
        CASE C: Static analysis reports high section entropy, but rule engine triggers 0 rules.
        Static PE layer contributes its finding without being discarded.
        """
        static_signals = [
            EvidenceSignal(
                source=EvidenceSource.STATIC_PE,
                signal_id="STATIC_ENTROPY_HIGH",
                name="PackedSectionEntropy",
                description="High section entropy suggests packed executable.",
                severity=EvidenceSeverity.HIGH,
                score_contribution=65.0,
                weight=1.0
            )
        ]

        res = DetectionDecisionEngine.evaluate(
            target_identifier="packed_clean_rules.exe",
            input_type=InputType.PE_BINARY,
            static_signals=static_signals
        )

        assert res.risk_score == 65.0
        assert res.risk_level == RiskLevel.HIGH
        assert res.detection_status == DetectionStatus.MALICIOUS
        tree_dict = res.explainability_tree
        static_node = next(c for c in tree_dict["root"]["children"] if c["node_id"] == "static_analysis")
        assert static_node["status"] == "SUSPICIOUS"

    def test_case_d_rules_suspicious_ml_unavailable(self):
        """
        CASE D: Rules identify suspicious behavior (70.0), but ML model is unavailable.
        Rule finding is evaluated at full dynamic weight; missing ML does not dilute score.
        """
        rule = RuleEvaluationResult(
            target_identifier="http://suspicious-target.xyz/login",
            target_type=RuleTargetType.URL,
            total_score=70.0,
            matches=[
                RuleMatch(
                    rule_id="RULE_URL_SUSPICIOUS_TLD",
                    rule_name="SuspiciousTLD",
                    severity=RuleSeverity.MEDIUM,
                    score_contribution=35.0,
                    explanation="Suspicious top-level domain."
                ),
                RuleMatch(
                    rule_id="RULE_URL_CREDENTIAL_KEYWORD",
                    rule_name="CredentialKeyword",
                    severity=RuleSeverity.MEDIUM,
                    score_contribution=35.0,
                    explanation="Contains sensitive credential keyword."
                )
            ]
        )
        ml_unavail = MLPredictionResult.unavailable(
            model_name="actis_phishing_rf",
            model_type=MLModelType.PHISHING_URL,
            reason="Phishing model weights not loaded."
        )

        res = DetectionDecisionEngine.evaluate(
            target_identifier="http://suspicious-target.xyz/login",
            input_type=InputType.URL,
            ml_prediction=ml_unavail,
            rule_result=rule
        )

        assert res.risk_score == 70.0
        assert res.risk_level == RiskLevel.HIGH
        assert res.detection_status == DetectionStatus.MALICIOUS
        tree_dict = res.explainability_tree
        ml_node = next(c for c in tree_dict["root"]["children"] if c["node_id"] == "machine_learning")
        assert ml_node["status"] == "UNAVAILABLE"

    def test_case_e_reputation_mitigation_conflicts_with_suspicious_static(self):
        """
        CASE E: Suspicious static anomaly (60.0) conflicts with verified reputation mitigation (-30.0).
        Mitigation discount is subtracted from composite risk score.
        """
        static_signals = [
            EvidenceSignal(
                source=EvidenceSource.STATIC_PE,
                signal_id="STATIC_ANOMALOUS_SECTION",
                name="AnomalousSection",
                description="Suspicious section characteristics.",
                severity=EvidenceSeverity.HIGH,
                score_contribution=60.0
            ),
            EvidenceSignal(
                source=EvidenceSource.REPUTATION,
                signal_id="REP_TRUSTED_INTERNAL_SIGNER",
                name="InternalTrustedCert",
                description="Signed by verified enterprise certificate authority.",
                severity=EvidenceSeverity.INFO,
                score_contribution=30.0
            )
        ]

        res = DetectionDecisionEngine.evaluate(
            target_identifier="internal_tool.exe",
            input_type=InputType.PE_BINARY,
            static_signals=static_signals
        )

        # 60.0 static - 30.0 reputation mitigation = 30.0 (LOW tier)
        assert res.risk_score == 30.0
        assert res.risk_level == RiskLevel.LOW
        assert res.detection_status == DetectionStatus.BENIGN
        assert res.analysis_metadata["score_breakdown"]["mitigation_adjustment"] == 30.0

    def test_case_f_whitelist_override_precedence_over_confirmed_malicious(self):
        """
        CASE F: Verified Whitelist conflicts with Confirmed Malicious TI.
        Administrative whitelist takes precedence:
        Score is forced to 0.0, status BENIGN, level INFORMATIONAL, with pre-override score preserved.
        """
        # Target has high ML probability (90.0) but administrative whitelist is applied
        ml = MLPredictionResult(
            model_name="actis_windows_pe_malware_rf",
            model_version="1.0.0",
            model_type=MLModelType.WINDOWS_PE_MALWARE,
            status=MLPredictionStatus.AVAILABLE,
            is_threat=True,
            probability=0.90,
            prediction_label="Malware",
            confidence=0.90
        )
        ti = ThreatIntelEvidence(
            indicator="known_internal_utility.exe",
            indicator_type=IndicatorType.GENERIC,
            verdict=ThreatIntelVerdict.FALSE_POSITIVE,
            confidence=1.0,
            provider="LOCAL_DB",
            threat_type="Utility",
            is_confirmed_threat=True,
            is_whitelisted=True
        )

        res = DetectionDecisionEngine.evaluate(
            target_identifier="known_internal_utility.exe",
            input_type=InputType.PE_BINARY,
            ti_evidence=ti,
            ml_prediction=ml
        )

        assert res.risk_score == 0.0
        assert res.risk_level == RiskLevel.INFORMATIONAL
        assert res.detection_status == DetectionStatus.BENIGN
        assert res.analysis_metadata["pre_override_score"] == 41.5
        assert res.analysis_metadata["override_applied"] == "WHITELIST_SAFETY_OVERRIDE"

        # Tree consistency
        tree_dict = res.explainability_tree
        assert tree_dict["final_score"] == 0.0
        assert tree_dict["risk_level"] == "INFORMATIONAL"
        assert tree_dict["detection_status"] == "BENIGN"
        assert tree_dict["traceability"]["is_override"] is True
        assert tree_dict["traceability"]["pre_override_score"] == 41.5
        assert "safety override replaced pre-override score of 41.5 with 0.0" in tree_dict["traceability"]["override_reason"]


# ==============================================================================
# PHASE 3: MISSING AND UNAVAILABLE EVIDENCE TESTS
# ==============================================================================

class TestMissingAndUnavailableEvidence:
    """Verifies that missing or failed evidence components fail safely without producing false benign verdicts."""

    def test_ti_provider_timeout_not_treated_as_clean(self):
        """A threat intelligence timeout must produce an UNAVAILABLE verdict, not a clean verdict."""
        ti_timeout = ThreatIntelEvidence.unavailable(
            indicator="evil-domain.com",
            indicator_type=IndicatorType.DOMAIN,
            provider="EXTERNAL_VIRUSTOTAL",
            reason="HTTP request timed out after 5.0 seconds."
        )

        assert ti_timeout.verdict == ThreatIntelVerdict.UNAVAILABLE
        assert ti_timeout.is_confirmed_threat is False
        assert ti_timeout.is_whitelisted is False
        assert ti_timeout.to_evidence_signal() is None

        # Evaluated alone produces 0 score with LOW/INFO, but with informative low confidence
        res = DetectionDecisionEngine.evaluate(
            target_identifier="evil-domain.com",
            input_type=InputType.URL,
            ti_evidence=ti_timeout
        )
        assert res.confidence <= 0.30  # Low confidence reflecting missing evidence

    def test_ti_rate_limiting_handled_safely(self):
        """TI provider 429 rate limit produces UNAVAILABLE verdict without crashing."""
        ti_rate_limit = ThreatIntelEvidence.unavailable(
            indicator="sample_hash",
            indicator_type=IndicatorType.SHA256,
            provider="EXTERNAL_ABUSE_IPDB",
            reason="HTTP 429: Rate limit exceeded."
        )
        assert ti_rate_limit.verdict == ThreatIntelVerdict.UNAVAILABLE
        assert ti_rate_limit.to_evidence_signal() is None

    def test_ml_model_missing_omitted_without_penalty(self):
        """When ML model is missing, the layer is omitted without acting as a 0% threat indicator."""
        ml_missing = MLPredictionResult.unavailable(
            model_name="actis_windows_pe_malware_rf",
            model_type=MLModelType.WINDOWS_PE_MALWARE,
            reason="Model artifact file not found on disk."
        )
        assert ml_missing.status == MLPredictionStatus.MODEL_UNAVAILABLE
        assert ml_missing.to_evidence_signal() is None

        # Only Heuristic Rules active (score 50.0)
        rule = RuleEvaluationResult(
            target_identifier="test.exe",
            target_type=RuleTargetType.PE_FILE,
            total_score=50.0,
            matches=[
                RuleMatch(
                    rule_id="R1",
                    rule_name="AnomalousExport",
                    severity=RuleSeverity.MEDIUM,
                    score_contribution=50.0,
                    explanation="Anomalous export table"
                )
            ]
        )
        res = DetectionDecisionEngine.evaluate(
            target_identifier="test.exe",
            input_type=InputType.PE_BINARY,
            ml_prediction=ml_missing,
            rule_result=rule
        )
        # Score is 50.0 (dynamic normalization active on heuristic rules only)
        assert res.risk_score == 50.0
        assert res.analysis_metadata["score_breakdown"]["active_layers"] == ["HEURISTIC_RULES"]

    def test_empty_evidence_collection_produces_informative_uncertainty(self):
        """Zero evidence discovered results in score 0.0 with baseline confidence 0.20."""
        res = DetectionDecisionEngine.evaluate(
            target_identifier="clean_text.txt",
            input_type=InputType.FILE
        )
        assert res.risk_score == 0.0
        assert res.risk_level == RiskLevel.INFORMATIONAL
        assert res.detection_status == DetectionStatus.BENIGN
        assert res.confidence == 0.20
        assert len(res.contributing_signals) == 0


# ==============================================================================
# PHASE 4: DUPLICATE AND CORRELATED EVIDENCE TESTS
# ==============================================================================

class TestDuplicateAndCorrelatedEvidence:
    """Verifies evidence deduplication prevents score inflation and false corroboration."""

    def test_duplicate_rule_signals_suppressed_to_prevent_score_inflation(self):
        """
        Duplicate ingestion of the exact same rule finding (e.g. 3x 30.0)
        must NOT inflate score to 90.0 (CRITICAL).
        """
        evidence = DetectionEvidence()
        sig = EvidenceSignal(
            source=EvidenceSource.HEURISTIC_RULES,
            signal_id="RULE_URL_SUSPICIOUS_TLD",
            name="SuspiciousTLD",
            description="Suspicious TLD match",
            severity=EvidenceSeverity.MEDIUM,
            score_contribution=30.0
        )

        # Ingest the same signal 3 times
        evidence.add_signal(sig)
        evidence.add_signal(sig)
        evidence.add_signal(sig)

        assert len(evidence.signals) == 1
        assert len(evidence.discarded_duplicates) == 2
        assert evidence.to_dict()["discarded_duplicates_count"] == 2

        score, breakdown = RiskScoringEngine.score_evidence(evidence)
        assert score == 30.0  # NOT 90.0!
        assert breakdown.rules_score == 30.0

    def test_duplicate_signal_retains_stronger_finding_on_conflict(self):
        """When an updated signal with higher score contribution is added, the stronger signal is retained."""
        evidence = DetectionEvidence()
        sig_weak = EvidenceSignal(
            source=EvidenceSource.STATIC_PE,
            signal_id="STATIC_SUSP_SECTION",
            name="SuspiciousSection",
            description="Initial observation",
            severity=EvidenceSeverity.LOW,
            score_contribution=20.0
        )
        sig_strong = EvidenceSignal(
            source=EvidenceSource.STATIC_PE,
            signal_id="STATIC_SUSP_SECTION",
            name="SuspiciousSection",
            description="Refined observation with higher entropy",
            severity=EvidenceSeverity.HIGH,
            score_contribution=50.0
        )

        evidence.add_signal(sig_weak)
        evidence.add_signal(sig_strong)

        assert len(evidence.signals) == 1
        assert evidence.signals[0].score_contribution == 50.0
        assert len(evidence.discarded_duplicates) == 1
        assert evidence.discarded_duplicates[0]["score_contribution"] == 20.0

    def test_distinct_rules_accumulate_legitimately(self):
        """Distinct heuristic rules legitimately accumulate score contributions up to the 100 cap."""
        evidence = DetectionEvidence()
        evidence.add_signal(EvidenceSignal(
            source=EvidenceSource.HEURISTIC_RULES,
            signal_id="R1",
            name="Rule 1",
            description="Distinct 1",
            severity=EvidenceSeverity.MEDIUM,
            score_contribution=30.0
        ))
        evidence.add_signal(EvidenceSignal(
            source=EvidenceSource.HEURISTIC_RULES,
            signal_id="R2",
            name="Rule 2",
            description="Distinct 2",
            severity=EvidenceSeverity.MEDIUM,
            score_contribution=30.0
        ))
        evidence.add_signal(EvidenceSignal(
            source=EvidenceSource.HEURISTIC_RULES,
            signal_id="R3",
            name="Rule 3",
            description="Distinct 3",
            severity=EvidenceSeverity.HIGH,
            score_contribution=30.0
        ))

        assert len(evidence.signals) == 3
        score, breakdown = RiskScoringEngine.score_evidence(evidence)
        assert score == 90.0
        assert breakdown.rules_score == 90.0


# ==============================================================================
# PHASE 5: RISK-SCORING BOUNDARY AUDIT TESTS
# ==============================================================================

class TestRiskScoringBoundaries:
    """Verifies mathematical boundaries, weight invariants, and classification thresholds."""

    def test_numeric_boundaries_clamping(self):
        """Signals with negative or >100 contributions are safely clamped."""
        sig_neg = EvidenceSignal(
            source=EvidenceSource.HEURISTIC_RULES,
            signal_id="R_NEG",
            name="NegativeRule",
            description="Negative contribution",
            severity=EvidenceSeverity.LOW,
            score_contribution=-25.0
        )
        assert sig_neg.score_contribution == 0.0

        sig_high = EvidenceSignal(
            source=EvidenceSource.HEURISTIC_RULES,
            signal_id="R_HIGH",
            name="ExcessiveRule",
            description="Excessive contribution",
            severity=EvidenceSeverity.CRITICAL,
            score_contribution=250.0
        )
        assert sig_high.score_contribution == 100.0

    def test_weights_safety_and_rejections(self):
        """Invalid weights (NaN, Inf, strings, negatives, total == 0) raise explicit exceptions."""
        with pytest.raises(ValueError):
            RiskScoringWeights(threat_intel=float("nan"))

        with pytest.raises(ValueError):
            RiskScoringWeights(ml_probability=float("inf"))

        with pytest.raises(TypeError):
            RiskScoringWeights(heuristic_rules="not_a_number")

        with pytest.raises(ValueError):
            RiskScoringWeights(threat_intel=-0.1)

        with pytest.raises(ValueError):
            RiskScoringWeights(threat_intel=0.0, ml_probability=0.0, heuristic_rules=0.0, static_pe=0.0)

    @pytest.mark.parametrize("score,expected_level,expected_status", [
        (0.0, RiskLevel.INFORMATIONAL, DetectionStatus.BENIGN),
        (19.999, RiskLevel.INFORMATIONAL, DetectionStatus.BENIGN),
        (20.0, RiskLevel.LOW, DetectionStatus.BENIGN),
        (20.001, RiskLevel.LOW, DetectionStatus.BENIGN),
        (34.999, RiskLevel.LOW, DetectionStatus.BENIGN),
        (35.0, RiskLevel.MEDIUM, DetectionStatus.SUSPICIOUS),
        (35.001, RiskLevel.MEDIUM, DetectionStatus.SUSPICIOUS),
        (59.999, RiskLevel.MEDIUM, DetectionStatus.SUSPICIOUS),
        (60.0, RiskLevel.HIGH, DetectionStatus.MALICIOUS),
        (60.001, RiskLevel.HIGH, DetectionStatus.MALICIOUS),
        (79.999, RiskLevel.HIGH, DetectionStatus.MALICIOUS),
        (80.0, RiskLevel.CRITICAL, DetectionStatus.MALICIOUS),
        (80.001, RiskLevel.CRITICAL, DetectionStatus.MALICIOUS),
        (100.0, RiskLevel.CRITICAL, DetectionStatus.MALICIOUS),
    ])
    def test_classification_threshold_boundaries(self, score, expected_level, expected_status):
        """Verifies exact epsilon transitions around all canonical ACTIS thresholds (20, 35, 60, 80)."""
        level, status, _ = RiskClassifier.classify(score)
        assert level == expected_level
        assert status == expected_status

    def test_mutual_confirmation_boost_trigger_and_cap(self):
        """Mutual confirmation (+25% boost) triggers when ML >= 70 and Rules >= 50, capped at 100.0."""
        evidence = DetectionEvidence()
        evidence.add_signal(EvidenceSignal(
            source=EvidenceSource.MACHINE_LEARNING,
            signal_id="ML1",
            name="ML High",
            description="ML threat",
            severity=EvidenceSeverity.HIGH,
            score_contribution=80.0
        ))
        evidence.add_signal(EvidenceSignal(
            source=EvidenceSource.HEURISTIC_RULES,
            signal_id="R1",
            name="Rule High",
            description="Rule threat",
            severity=EvidenceSeverity.HIGH,
            score_contribution=60.0
        ))

        # Weights: ML (0.30) + Rules (0.20) = 0.50
        # Weighted sum: (80*0.30 + 60*0.20) / 0.50 = 36 / 0.50 = 72.0
        # Boosted by 1.25x: 72.0 * 1.25 = 90.0
        score, breakdown = RiskScoringEngine.score_evidence(evidence)
        assert score == 90.0
        assert breakdown.mutual_confirmation_boost is True

    def test_mitigation_adjustment_clamped_at_zero(self):
        """Mitigation discount larger than the raw score clamps final score cleanly to 0.0."""
        evidence = DetectionEvidence()
        evidence.add_signal(EvidenceSignal(
            source=EvidenceSource.STATIC_PE,
            signal_id="S1",
            name="Minor anomaly",
            description="Score 20",
            severity=EvidenceSeverity.LOW,
            score_contribution=20.0
        ))
        evidence.add_signal(EvidenceSignal(
            source=EvidenceSource.REPUTATION,
            signal_id="R1",
            name="Heavy whitelist discount",
            description="Score -50",
            severity=EvidenceSeverity.INFO,
            score_contribution=50.0
        ))

        score, breakdown = RiskScoringEngine.score_evidence(evidence)
        assert score == 0.0
        assert breakdown.final_score == 0.0


# ==============================================================================
# PHASE 7: EXPLAINABILITY CONSISTENCY TESTS
# ==============================================================================

class TestExplainabilityConsistency:
    """Verifies that the ExplainabilityTree strictly matches authoritative detection decisions."""

    def test_tree_score_and_classification_strictly_equal_detection_result(self):
        """Tree final_score and classifications must strictly match DetectionResult."""
        evidence = DetectionEvidence()
        evidence.add_signal(EvidenceSignal(
            source=EvidenceSource.MACHINE_LEARNING,
            signal_id="ML_TEST",
            name="ML Score",
            description="ML finding",
            severity=EvidenceSeverity.HIGH,
            score_contribution=75.0
        ))

        res = DetectionDecisionEngine.evaluate(
            target_identifier="https://test-consistency.com",
            input_type=InputType.URL,
            static_signals=evidence.signals
        )

        tree_dict = res.explainability_tree
        assert tree_dict is not None
        assert tree_dict["final_score"] == res.risk_score
        assert tree_dict["risk_level"] == res.risk_level.value
        assert tree_dict["detection_status"] == res.detection_status.value
        assert tree_dict["root"]["score_contribution"] == res.risk_score

    def test_sensitive_credential_redaction_in_explainability_nodes(self):
        """Explainability tree recursively redacts API keys, tokens, and credentials."""
        metadata_with_secret = {
            "api_key": "secret_abc123456789xyz",
            "url": "https://example.com/api?token=SUPERSECRETTOKEN12345"
        }

        res = DetectionDecisionEngine.evaluate(
            target_identifier="sensitive_target",
            input_type=InputType.URL,
            metadata=metadata_with_secret
        )

        tree_dict = res.explainability_tree
        input_meta = tree_dict["root"]["children"][0]["metadata"]

        # Ensure raw secret is not present in serialized dict or rendered text
        assert "secret_abc123456789xyz" not in str(tree_dict)
        assert "SUPERSECRETTOKEN12345" not in str(tree_dict)

    def test_explainability_tree_node_count_strictly_bounded(self):
        """Tree node count is strictly bounded <= MAX_TOTAL_NODES (100) even with large evidence inputs."""
        large_signals = []
        for i in range(120):
            large_signals.append(EvidenceSignal(
                source=EvidenceSource.STATIC_PE,
                signal_id=f"STATIC_SIG_{i:03d}",
                name=f"Feature {i}",
                description=f"Detail {i}",
                severity=EvidenceSeverity.LOW,
                score_contribution=1.0
            ))

        res = DetectionDecisionEngine.evaluate(
            target_identifier="large_file.exe",
            input_type=InputType.PE_BINARY,
            static_signals=large_signals
        )

        def count_nodes(node: Dict[str, Any]) -> int:
            return 1 + sum(count_nodes(child) for child in node.get("children", []))

        node_count = count_nodes(res.explainability_tree["root"])
        assert node_count <= MAX_TOTAL_NODES


# ==============================================================================
# PHASE 8: OFFLINE AND FAILURE-RECOVERY TESTS
# ==============================================================================

class TestOfflineAndFailureRecovery:
    """Verifies local detection engine resilience during external network outages."""

    def test_local_pe_analysis_completes_when_external_ti_offline(self, monkeypatch):
        """PE analysis succeeds and detects threats locally when external lookup fails or times out."""
        from threat_intelligence.threat_lookup import ThreatLookup
        from detection_engine.threat_detector import ThreatDetector

        # Simulate external provider timeout
        def mock_lookup_hash(self, sha256: str, query_external: bool = False):
            return {
                "hash": sha256,
                "local_intel": None,
                "external_intel": None,
                "primary_evidence": ThreatIntelEvidence.unavailable(
                    indicator=sha256,
                    indicator_type=IndicatorType.SHA256,
                    provider="EXTERNAL_PROVIDER",
                    reason="Network offline"
                ),
                "is_malicious": False,
                "confidence": 0.0
            }

        monkeypatch.setattr(ThreatLookup, "lookup_hash", mock_lookup_hash)

        detector = ThreatDetector()
        res = detector.analyze_file(Path("scanners/pe_feature_contract.py"), check_external=True)

        assert "file_path" in res
        assert "sha256" in res
        assert res["from_cache"] is False
        assert "detection_result" in res
        assert res["detection_result"]["confidence"] <= 0.60
