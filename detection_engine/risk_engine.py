"""
ACTIS Risk Scoring Engine
Combines multi-layer security evidence from threat intelligence, machine learning,
heuristic rule engines, and static PE metadata into a deterministic, explainable risk score (0-100).
Implements dynamic weight re-normalization across active evidence layers and mutual confirmation boosts.
"""

from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple

from config.config import (
    RISK_CRITICAL_THRESHOLD,
    RISK_HIGH_THRESHOLD,
    RISK_MEDIUM_THRESHOLD,
    WEIGHT_KNOWN_INTEL,
    WEIGHT_ML_PROBABILITY,
    WEIGHT_HEURISTIC_RULES,
    WEIGHT_EXTERNAL_INTEL,
    get_logger
)
from detection_engine.evidence_model import (
    DetectionEvidence,
    EvidenceSignal,
    EvidenceSource,
    EvidenceSeverity,
)

logger = get_logger("RiskEngine")


@dataclass(frozen=True)
class RiskScoringWeights:
    """
    Normalized weight configurations for security evidence layers.
    ACTIS project-defined heuristic weights balancing threat intelligence, ML, rules, and anomalies.
    """
    threat_intel: float = WEIGHT_KNOWN_INTEL
    ml_probability: float = WEIGHT_ML_PROBABILITY
    heuristic_rules: float = WEIGHT_HEURISTIC_RULES
    static_pe: float = WEIGHT_EXTERNAL_INTEL

    def __post_init__(self):
        total = self.threat_intel + self.ml_probability + self.heuristic_rules + self.static_pe
        if total <= 0:
            raise ValueError("Total weights must be strictly positive.")


@dataclass(frozen=True)
class ScoreBreakdown:
    """Detailed score audit trail showing exact contribution per layer."""
    threat_intel_score: float
    ml_score: float
    rules_score: float
    static_pe_score: float
    active_layers: List[str]
    mutual_confirmation_boost: bool
    mitigation_adjustment: float
    raw_composite: float
    final_score: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "threat_intel_score": round(self.threat_intel_score, 2),
            "ml_score": round(self.ml_score, 2),
            "rules_score": round(self.rules_score, 2),
            "static_pe_score": round(self.static_pe_score, 2),
            "active_layers": list(self.active_layers),
            "mutual_confirmation_boost": self.mutual_confirmation_boost,
            "mitigation_adjustment": round(self.mitigation_adjustment, 2),
            "raw_composite": round(self.raw_composite, 2),
            "final_score": round(self.final_score, 2)
        }


class RiskScoringEngine:
    """
    Deterministic mathematical risk scoring engine.
    Applies multi-attribute utility theory across heterogenous security findings.
    """

    DEFAULT_WEIGHTS = RiskScoringWeights(
        threat_intel=WEIGHT_KNOWN_INTEL,
        ml_probability=WEIGHT_ML_PROBABILITY,
        heuristic_rules=WEIGHT_HEURISTIC_RULES,
        static_pe=WEIGHT_EXTERNAL_INTEL
    )

    @classmethod
    def score_evidence(
        cls,
        evidence: DetectionEvidence,
        weights: Optional[RiskScoringWeights] = None
    ) -> Tuple[float, ScoreBreakdown]:
        """
        Computes composite 0.0 to 100.0 risk score from structured DetectionEvidence.
        Dynamically renormalizes across active evidence layers to prevent missing-evidence bias.
        """
        w = weights or cls.DEFAULT_WEIGHTS

        # Layer 1: Threat Intelligence
        ti_signals = evidence.get_signals_by_source(EvidenceSource.THREAT_INTELLIGENCE)
        ti_score = 0.0
        ti_active = False
        is_known_malicious = False
        if ti_signals:
            ti_active = True
            ti_score = max(s.score_contribution for s in ti_signals)
            is_known_malicious = any(s.severity == EvidenceSeverity.CRITICAL for s in ti_signals)

        # Layer 2: Machine Learning
        ml_signals = evidence.get_signals_by_source(EvidenceSource.MACHINE_LEARNING)
        ml_score = 0.0
        ml_active = False
        if ml_signals:
            ml_active = True
            ml_score = max(s.score_contribution for s in ml_signals)

        # Layer 3: Heuristic Rules
        rule_signals = evidence.get_signals_by_source(EvidenceSource.HEURISTIC_RULES)
        rule_score = 0.0
        rule_active = False
        if rule_signals:
            rule_active = True
            rule_score = min(100.0, sum(s.score_contribution for s in rule_signals))

        # Layer 4: Static PE / Anomaly Findings
        static_signals = evidence.get_signals_by_source(EvidenceSource.STATIC_PE) + evidence.get_signals_by_source(EvidenceSource.ANOMALY)
        static_score = 0.0
        static_active = False
        if static_signals:
            static_active = True
            static_score = min(100.0, sum(s.score_contribution for s in static_signals))

        # Fast-track: Confirmed malicious threat intelligence guarantees critical floor
        mutual_boost = False
        if is_known_malicious:
            final_score = max(90.0, ti_score)
            raw_composite = final_score
            active_layers = ["THREAT_INTELLIGENCE"]
            mitigation_adj = 0.0
        else:
            numerator = 0.0
            denominator = 0.0
            active_layers = []

            if ti_active:
                numerator += ti_score * w.threat_intel
                denominator += w.threat_intel
                active_layers.append("THREAT_INTELLIGENCE")

            if ml_active:
                numerator += ml_score * w.ml_probability
                denominator += w.ml_probability
                active_layers.append("MACHINE_LEARNING")

            if rule_active:
                numerator += rule_score * w.heuristic_rules
                denominator += w.heuristic_rules
                active_layers.append("HEURISTIC_RULES")

            if static_active:
                numerator += static_score * w.static_pe
                denominator += w.static_pe
                active_layers.append("STATIC_PE")

            if denominator > 0.0:
                raw_composite = numerator / denominator
            else:
                raw_composite = 0.0

            # Mutual confirmation escalation: when ML and heuristics both indicate high risk
            if ml_score >= 70.0 and rule_score >= 50.0:
                raw_composite = min(100.0, raw_composite * 1.25)
                mutual_boost = True

            # Mitigations (e.g. Whitelist / False positive signals)
            mitigation_adj = 0.0
            reputation_signals = evidence.get_signals_by_source(EvidenceSource.REPUTATION) + evidence.get_signals_by_source(EvidenceSource.USER_OVERRIDE)
            for rep in reputation_signals:
                if rep.score_contribution < 0:
                    mitigation_adj += abs(rep.score_contribution)

            final_score = max(0.0, min(100.0, raw_composite - mitigation_adj))

        breakdown = ScoreBreakdown(
            threat_intel_score=ti_score,
            ml_score=ml_score,
            rules_score=rule_score,
            static_pe_score=static_score,
            active_layers=active_layers,
            mutual_confirmation_boost=mutual_boost,
            mitigation_adjustment=mitigation_adj,
            raw_composite=raw_composite,
            final_score=round(final_score, 1)
        )

        return round(final_score, 1), breakdown


class RiskEngine:
    """Multi-criteria risk evaluation and explainability engine."""

    @classmethod
    def calculate_risk(
        cls,
        target_type: str,
        target_value: str,
        known_intel: Optional[Dict[str, Any]] = None,
        ml_result: Optional[Dict[str, Any]] = None,
        heuristic_result: Optional[Dict[str, Any]] = None,
        external_intel: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Fuses multiple evidence layers into a standardized risk evaluation.
        Maintains complete backward compatibility with existing tests and modules.
        """
        reasons: List[str] = []
        is_known_malicious = False
        known_score = 0.0
        ml_score = 0.0
        rule_score = 0.0
        ext_score = 0.0

        # Layer 1: Local Threat Intelligence Database
        if known_intel and known_intel.get("found", False):
            intel_status = known_intel.get("status", "").upper()
            confidence = float(known_intel.get("confidence", 1.0))
            
            if intel_status in ["CONFIRMED", "MALICIOUS"]:
                is_known_malicious = True
                known_score = 100.0 * confidence
                reasons.append(
                    f"Identified in local threat intelligence database as CONFIRMED threat: "
                    f"'{known_intel.get('threat_type', 'Malicious')}' (Confidence: {int(confidence*100)}%)."
                )
            elif intel_status == "SUSPICIOUS":
                known_score = 70.0 * confidence
                reasons.append(f"Recorded in threat database as SUSPICIOUS indicator (Confidence: {int(confidence*100)}%).")
            elif intel_status == "FALSE_POSITIVE":
                known_score = -50.0
                reasons.append("Indicator is flagged as a verified FALSE POSITIVE in threat database.")

        # Layer 2: Machine Learning Model
        if ml_result and ml_result.get("available", False):
            prob = float(ml_result.get("probability", 0.0))
            is_positive = bool(ml_result.get("is_phishing") or ml_result.get("is_malware"))
            ml_score = prob * 100.0
            
            if is_positive:
                reasons.append(
                    f"Machine learning model ({ml_result.get('model_name')}) flagged as malicious "
                    f"with {round(prob * 100, 1)}% probability."
                )
            else:
                if prob > 0.25:
                    reasons.append(f"Machine learning model calculated minor anomalous probability of {round(prob * 100, 1)}%.")
                else:
                    reasons.append(f"Machine learning model classified as benign (confidence: {round((1 - prob) * 100, 1)}%).")

        # Layer 3: Rule-Based Heuristics
        if heuristic_result:
            rule_score = float(heuristic_result.get("heuristic_score", 0.0))
            rule_reasons = heuristic_result.get("reasons", [])
            for r in rule_reasons:
                reasons.append(f"Heuristic Rule: {r}")

        # Layer 4: External Threat Intelligence
        if external_intel and external_intel.get("available", False):
            ext_malicious = external_intel.get("malicious", False)
            ext_positives = external_intel.get("positives", 0)
            ext_total = external_intel.get("total", 0)
            
            if ext_malicious and ext_positives > 0:
                ext_score = min(100.0, (ext_positives / max(1, ext_total)) * 150.0)
                reasons.append(
                    f"External threat intelligence ({external_intel.get('source')}): "
                    f"{ext_positives}/{ext_total} security vendors flagged this indicator as malicious."
                )
            elif ext_total > 0:
                reasons.append(f"External threat intelligence ({external_intel.get('source')}): 0/{ext_total} security vendors reported issues.")

        # Fast-track: Confirmed malicious indicator in database guarantees CRITICAL
        if is_known_malicious:
            final_score = max(90.0, known_score)
        else:
            active_weights = {}
            if known_intel and known_intel.get("found"):
                active_weights["known"] = WEIGHT_KNOWN_INTEL
            if ml_result and ml_result.get("available"):
                active_weights["ml"] = WEIGHT_ML_PROBABILITY
            if heuristic_result:
                active_weights["rule"] = WEIGHT_HEURISTIC_RULES
            if external_intel and external_intel.get("available"):
                active_weights["ext"] = WEIGHT_EXTERNAL_INTEL

            total_weight = sum(active_weights.values())
            if total_weight > 0:
                weighted_sum = (
                    (known_score * active_weights.get("known", 0.0)) +
                    (ml_score * active_weights.get("ml", 0.0)) +
                    (rule_score * active_weights.get("rule", 0.0)) +
                    (ext_score * active_weights.get("ext", 0.0))
                ) / total_weight
            else:
                weighted_sum = 0.0

            if ml_score >= 70.0 and rule_score >= 50.0:
                weighted_sum = min(100.0, weighted_sum * 1.25)
                reasons.append("High correlation detected: Machine learning inference and rule heuristics independently confirm threat.")

            final_score = max(0.0, min(100.0, round(weighted_sum, 1)))

        if final_score >= RISK_CRITICAL_THRESHOLD:
            risk_level = "CRITICAL"
            recommended_action = (
                "IMMEDIATE ACTION: Do not open, execute, or interact with this target. "
                "Quarantine or remove from network if applicable."
            )
        elif final_score >= RISK_HIGH_THRESHOLD:
            risk_level = "HIGH"
            recommended_action = (
                "CAUTION: High probability of cyber threat. Do not execute or enter credentials. "
                "Verify origin before taking any further action."
            )
        elif final_score >= RISK_MEDIUM_THRESHOLD:
            risk_level = "MEDIUM"
            recommended_action = (
                "ATTENTION: Target shows suspicious or anomalous characteristics. Exercise caution "
                "and verify authenticity with the sender or source."
            )
        else:
            risk_level = "LOW"
            recommended_action = "No significant threats or anomalies detected. Standard security hygiene recommended."

        return {
            "target_type": target_type,
            "target": target_value,
            "score": round(final_score, 1),
            "risk_level": risk_level,
            "is_threat": (final_score >= RISK_MEDIUM_THRESHOLD),
            "reasons": reasons,
            "recommended_action": recommended_action,
            "evidence_breakdown": {
                "known_intel_score": round(known_score, 1),
                "ml_score": round(ml_score, 1),
                "heuristic_score": round(rule_score, 1),
                "external_intel_score": round(ext_score, 1),
                "is_known_malicious": is_known_malicious
            }
        }


from detection_engine.detection_contract import RiskLevel, DetectionStatus


@dataclass(frozen=True)
class RiskThresholdConfig:
    """Configurable boundaries for risk tier classification."""
    informational_max: float = 20.0
    low_max: float = 35.0
    medium_max: float = 70.0
    high_max: float = 85.0
    critical_min: float = 85.0

    def validate(self) -> None:
        if not (0.0 <= self.informational_max <= self.low_max <= self.medium_max <= self.high_max <= 100.0):
            raise ValueError("Thresholds must be strictly monotonic non-decreasing between 0.0 and 100.0.")


class RiskClassifier:
    """
    Deterministic risk classification engine with safety overrides.
    Maps continuous numeric scores (0-100) to standard RiskLevel and DetectionStatus tiers.
    """

    DEFAULT_THRESHOLDS = RiskThresholdConfig(
        informational_max=20.0,
        low_max=float(RISK_MEDIUM_THRESHOLD),
        medium_max=float(RISK_HIGH_THRESHOLD),
        high_max=float(RISK_CRITICAL_THRESHOLD),
        critical_min=float(RISK_CRITICAL_THRESHOLD)
    )

    RECOMMENDED_ACTIONS = {
        RiskLevel.CRITICAL: (
            "CRITICAL THREAT DETECTED: Immediate containment required. Do not execute or open this target. "
            "Isolate the host or remove the malicious artifact immediately."
        ),
        RiskLevel.HIGH: (
            "HIGH RISK DETECTED: Strong malicious indicators present. Do not execute or supply credentials. "
            "Manual security analyst verification strongly recommended."
        ),
        RiskLevel.MEDIUM: (
            "SUSPICIOUS ACTIVITY: Target exhibits anomalous or potentially deceptive characteristics. "
            "Exercise caution and independently verify the source."
        ),
        RiskLevel.LOW: (
            "LOW RISK: Minor or routine security indicators observed. "
            "Standard operational security hygiene applies."
        ),
        RiskLevel.INFORMATIONAL: (
            "BENIGN / INFORMATIONAL: No malicious indicators detected. Target conforms to expected safe profiles."
        )
    }

    @classmethod
    def classify(
        cls,
        score: float,
        is_confirmed_threat: bool = False,
        is_whitelisted: bool = False,
        has_critical_evidence: bool = False,
        thresholds: Optional[RiskThresholdConfig] = None
    ) -> Tuple[RiskLevel, DetectionStatus, str]:
        """
        Classifies risk score into standardized tiers with deterministic security overrides.
        Returns (RiskLevel, DetectionStatus, recommended_action).
        """
        cfg = thresholds or cls.DEFAULT_THRESHOLDS

        # Override 1: Verified Whitelist / False Positive
        if is_whitelisted:
            level = RiskLevel.INFORMATIONAL
            status = DetectionStatus.BENIGN
            action = "Target is verified as a trusted whitelist entity or confirmed false positive."
            return level, status, action

        # Override 2: Confirmed Malicious Threat Intelligence
        if is_confirmed_threat:
            level = RiskLevel.CRITICAL
            status = DetectionStatus.MALICIOUS
            action = cls.RECOMMENDED_ACTIONS[RiskLevel.CRITICAL]
            return level, status, action

        # Override 3: Critical Evidence Escalation
        if has_critical_evidence and score >= cfg.low_max:
            level = RiskLevel.CRITICAL
            status = DetectionStatus.MALICIOUS
            action = cls.RECOMMENDED_ACTIONS[RiskLevel.CRITICAL]
            return level, status, action

        # Continuous Threshold Mapping
        if score >= cfg.critical_min:
            level = RiskLevel.CRITICAL
            status = DetectionStatus.MALICIOUS
        elif score >= cfg.medium_max:
            level = RiskLevel.HIGH
            status = DetectionStatus.MALICIOUS
        elif score >= cfg.low_max:
            level = RiskLevel.MEDIUM
            status = DetectionStatus.SUSPICIOUS
        elif score >= cfg.informational_max:
            level = RiskLevel.LOW
            status = DetectionStatus.BENIGN
        else:
            level = RiskLevel.INFORMATIONAL
            status = DetectionStatus.BENIGN

        action = cls.RECOMMENDED_ACTIONS[level]
        return level, status, action
