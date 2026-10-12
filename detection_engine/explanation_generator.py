"""
ACTIS Explanation and Decision Confidence Engine
Generates human-readable, evidence-grounded security explanations and calculates internal decision confidence.
Strictly distinguishes internal decision confidence (evidence corroboration) from threat risk scores.
Provides hierarchical explainability trees and exact score calculation traceability.
"""

from dataclasses import dataclass
from typing import Dict, Any, List, Optional, Tuple

from detection_engine.detection_contract import RiskLevel, DetectionStatus, InputType
from detection_engine.evidence_model import DetectionEvidence, EvidenceSource, EvidenceSeverity
from detection_engine.risk_engine import ScoreBreakdown, RiskScoringWeights
from detection_engine.explainability_tree import (
    ExplainabilityNode,
    ExplainabilityTree,
    ScoreTraceability,
    NodeCategory,
    NodeStatus,
    mask_sensitive_value,
    MAX_TOTAL_NODES,
)


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
    """Produces grounded, non-hallucinatory explanations and hierarchical trees strictly from observed evidence."""

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
        Generates legacy (primary_headline, detailed_reasons_list).
        Only mentions evidence signals that actually exist in the record.
        Maintains 100% backward compatibility for all existing callers.
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

    @classmethod
    def generate_explainability_tree(
        cls,
        target_identifier: str,
        input_type: Any,
        risk_level: RiskLevel,
        status: DetectionStatus,
        score: float,
        confidence: float,
        evidence: DetectionEvidence,
        breakdown: ScoreBreakdown,
        weights: Optional[RiskScoringWeights] = None,
        is_whitelisted: bool = False,
        is_confirmed_threat: bool = False,
        metadata: Optional[Dict[str, Any]] = None
    ) -> ExplainabilityTree:
        """
        Builds the authoritative hierarchical explainability tree for a detection result.
        Maps all inputs, analytical layers, evidence signals, calculation steps, and provenance.
        """
        w = weights or RiskScoringWeights.default()
        meta = metadata or {}
        input_type_str = input_type.value if hasattr(input_type, "value") else str(input_type)
        risk_level_str = risk_level.value if hasattr(risk_level, "value") else str(risk_level)
        status_str = status.value if hasattr(status, "value") else str(status)

        # 1. Compute exact mathematical traceability
        configured_weights = w.to_dict()
        layer_scores = {
            "threat_intel": breakdown.threat_intel_score,
            "ml_probability": breakdown.ml_score,
            "heuristic_rules": breakdown.rules_score,
            "static_pe": breakdown.static_pe_score
        }

        # Calculate normalized active weights
        active_weight_sum = 0.0
        normalized_weights = {}
        layer_contributions = {}

        layer_key_map = {
            "THREAT_INTELLIGENCE": "threat_intel",
            "MACHINE_LEARNING": "ml_probability",
            "HEURISTIC_RULES": "heuristic_rules",
            "STATIC_PE": "static_pe"
        }

        for layer_enum, weight_key in layer_key_map.items():
            if layer_enum in breakdown.active_layers:
                active_weight_sum += configured_weights.get(weight_key, 0.0)

        weighted_sum = 0.0
        for layer_enum, weight_key in layer_key_map.items():
            if layer_enum in breakdown.active_layers and active_weight_sum > 0:
                norm_w = configured_weights[weight_key] / active_weight_sum
                contrib = layer_scores[weight_key] * norm_w
                normalized_weights[weight_key] = norm_w
                layer_contributions[weight_key] = contrib
                weighted_sum += contrib
            else:
                normalized_weights[weight_key] = 0.0
                layer_contributions[weight_key] = 0.0

        is_override = is_whitelisted or is_confirmed_threat
        override_reason = None
        if is_whitelisted:
            override_reason = "Entity is in trusted whitelist or verified false positive; forces INFORMATIONAL / BENIGN verdict."
        elif is_confirmed_threat:
            override_reason = "Entity confirmed malicious in threat intelligence; guarantees CRITICAL floor (min 90.0)."

        traceability = ScoreTraceability(
            active_layers=list(breakdown.active_layers),
            configured_weights=configured_weights,
            normalized_weights=normalized_weights,
            layer_scores=layer_scores,
            layer_contributions=layer_contributions,
            weighted_sum=weighted_sum,
            mutual_confirmation_boost=breakdown.mutual_confirmation_boost,
            boost_multiplier=1.25 if breakdown.mutual_confirmation_boost else 1.0,
            mitigation_adjustment=breakdown.mitigation_adjustment,
            raw_composite=breakdown.raw_composite,
            final_score=score,
            is_override=is_override,
            override_reason=override_reason
        )

        # 2. Build Root Node
        root_status = NodeStatus.CONFIRMED_THREAT if is_confirmed_threat else (
            NodeStatus.OVERRIDDEN if is_whitelisted else (
                NodeStatus.SUSPICIOUS if status == DetectionStatus.SUSPICIOUS or risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL) else NodeStatus.EVALUATED
            )
        )
        root = ExplainabilityNode(
            node_id="root",
            category=NodeCategory.ROOT,
            title=f"ACTIS Threat Evaluation: {risk_level_str}",
            description=f"Detection decision for target '{target_identifier}' ({input_type_str}) with composite score {score:.1f}/100.",
            status=root_status,
            score_contribution=score,
            metadata={
                "target": target_identifier,
                "input_type": input_type_str,
                "risk_level": risk_level_str,
                "detection_status": status_str,
                "confidence": confidence,
            }
        )

        # 3. Branch: Input Analysis
        input_node = ExplainabilityNode(
            node_id="input_analysis",
            category=NodeCategory.INPUT_ANALYSIS,
            title="Input Target Analysis",
            description=f"Normalized input specification: {input_type_str}.",
            status=NodeStatus.EVALUATED,
            metadata={
                "target_identifier": target_identifier,
                "input_type": input_type_str,
                "detected_format": meta.get("detected_format", "UNKNOWN"),
                "file_size": meta.get("file_size"),
                "analysis_method": meta.get("analysis_method", "UNKNOWN"),
                "sha256": meta.get("sha256", ""),
                "domain": meta.get("domain", "")
            }
        )
        root.add_child(input_node)

        # 4. Branch: Static Analysis
        static_signals = evidence.get_signals_by_source(EvidenceSource.STATIC_PE) + evidence.get_signals_by_source(EvidenceSource.ANOMALY)
        static_status = NodeStatus.SUSPICIOUS if static_signals else (
            NodeStatus.EVALUATED if meta.get("is_pe") or meta.get("detected_format") else NodeStatus.NO_FINDINGS
        )
        static_node = ExplainabilityNode(
            node_id="static_analysis",
            category=NodeCategory.STATIC_ANALYSIS,
            title="Static Analysis & Structural Inspection",
            description="Inspection of file structures, PE headers, entropy, archives, or script patterns without execution.",
            status=static_status,
            score_contribution=breakdown.static_pe_score,
            source="STATIC_ANALYSIS",
            metadata={
                "is_pe": meta.get("is_pe", False),
                "entropy": meta.get("entropy", 0.0),
                "is_signed": meta.get("is_signed", False),
                "signal_count": len(static_signals)
            }
        )
        for idx, sig in enumerate(static_signals):
            static_node.add_child(ExplainabilityNode(
                node_id=f"static_sig_{idx}_{sig.signal_id}",
                category=NodeCategory.FINDING,
                title=sig.name,
                description=sig.description,
                status=NodeStatus.SUSPICIOUS if sig.severity in (EvidenceSeverity.HIGH, EvidenceSeverity.CRITICAL) else NodeStatus.EVALUATED,
                score_contribution=sig.score_contribution,
                weight=sig.weight,
                source=sig.source.value,
                metadata=sig.raw_data or {}
            ))
        root.add_child(static_node)

        # 5. Branch: Heuristic Rule Engine
        rule_signals = evidence.get_signals_by_source(EvidenceSource.HEURISTIC_RULES)
        rule_status = NodeStatus.SUSPICIOUS if rule_signals else NodeStatus.NO_FINDINGS
        rule_node = ExplainabilityNode(
            node_id="rule_engine",
            category=NodeCategory.RULE_ENGINE,
            title="Deterministic Heuristic Rules",
            description=f"Evaluation against deterministic heuristic rules. Triggered {len(rule_signals)} rule(s).",
            status=rule_status,
            score_contribution=breakdown.rules_score,
            source="HEURISTIC_RULES",
            metadata={"rules_triggered_count": len(rule_signals)}
        )
        if rule_signals:
            for idx, r_sig in enumerate(rule_signals):
                rule_node.add_child(ExplainabilityNode(
                    node_id=f"rule_sig_{idx}_{r_sig.signal_id}",
                    category=NodeCategory.FINDING,
                    title=f"Rule {r_sig.signal_id}: {r_sig.name}",
                    description=r_sig.description,
                    status=NodeStatus.SUSPICIOUS,
                    score_contribution=r_sig.score_contribution,
                    weight=r_sig.weight,
                    source="RULE_ENGINE",
                    metadata=r_sig.raw_data or {}
                ))
        else:
            rule_node.add_child(ExplainabilityNode(
                node_id="rule_none",
                category=NodeCategory.METRIC,
                title="No Rules Triggered",
                description="Target did not match any suspicious heuristic rules.",
                status=NodeStatus.NO_FINDINGS
            ))
        root.add_child(rule_node)

        # 6. Branch: Machine Learning Models
        ml_signals = evidence.get_signals_by_source(EvidenceSource.MACHINE_LEARNING)
        if ml_signals:
            sig = ml_signals[0]
            ml_status = NodeStatus.SUSPICIOUS if sig.score_contribution >= 50.0 else NodeStatus.BENIGN
            ml_node = ExplainabilityNode(
                node_id="machine_learning",
                category=NodeCategory.MACHINE_LEARNING,
                title="Machine Learning Inference",
                description=f"Statistical inference via supervised Random Forest model ({sig.name}).",
                status=ml_status,
                score_contribution=breakdown.ml_score,
                source="MACHINE_LEARNING",
                metadata=sig.raw_data or {}
            )
            ml_node.add_child(ExplainabilityNode(
                node_id="ml_finding",
                category=NodeCategory.FINDING,
                title=sig.name,
                description=sig.description,
                status=ml_status,
                score_contribution=sig.score_contribution,
                weight=sig.weight,
                metadata=sig.raw_data or {}
            ))
            ml_node.add_child(ExplainabilityNode(
                node_id="ml_limitation",
                category=NodeCategory.LIMITATION,
                title="Model Uncertainty Notice",
                description="ML outputs represent statistical probability estimates based on trained morphological patterns and require corroborating evidence.",
                status=NodeStatus.EVALUATED
            ))
        else:
            ml_node = ExplainabilityNode(
                node_id="machine_learning",
                category=NodeCategory.MACHINE_LEARNING,
                title="Machine Learning Inference",
                description="Model prediction was unavailable or not applicable for this target type (omitted without penalty).",
                status=NodeStatus.UNAVAILABLE,
                score_contribution=0.0,
                source="MACHINE_LEARNING",
                metadata={"reason": "Model unavailable or unsupported input format"}
            )
        root.add_child(ml_node)

        # 7. Branch: Threat Intelligence
        ti_signals = evidence.get_signals_by_source(EvidenceSource.THREAT_INTELLIGENCE)
        ti_status = NodeStatus.CONFIRMED_THREAT if is_confirmed_threat else (
            NodeStatus.SUSPICIOUS if ti_signals else NodeStatus.NO_FINDINGS
        )
        ti_node = ExplainabilityNode(
            node_id="threat_intelligence",
            category=NodeCategory.THREAT_INTELLIGENCE,
            title="Threat Intelligence & Reputation",
            description="Correlation against local threat intelligence database and external reputation feeds.",
            status=ti_status,
            score_contribution=breakdown.threat_intel_score,
            source="THREAT_INTELLIGENCE",
            metadata={
                "is_confirmed_threat": is_confirmed_threat,
                "is_whitelisted": is_whitelisted,
                "signals_found": len(ti_signals)
            }
        )
        if ti_signals:
            for idx, ti_sig in enumerate(ti_signals):
                ti_node.add_child(ExplainabilityNode(
                    node_id=f"ti_sig_{idx}_{ti_sig.signal_id}",
                    category=NodeCategory.FINDING,
                    title=ti_sig.name,
                    description=ti_sig.description,
                    status=NodeStatus.CONFIRMED_THREAT if ti_sig.severity == EvidenceSeverity.CRITICAL else NodeStatus.SUSPICIOUS,
                    score_contribution=ti_sig.score_contribution,
                    weight=ti_sig.weight,
                    source="THREAT_INTELLIGENCE",
                    metadata=ti_sig.raw_data or {}
                ))
        else:
            ti_node.add_child(ExplainabilityNode(
                node_id="ti_not_found",
                category=NodeCategory.METRIC,
                title="No Threat Intelligence Records",
                description="Indicator not found in threat database (absence of record is neutral, not verified safe).",
                status=NodeStatus.NO_FINDINGS
            ))
        root.add_child(ti_node)

        # 8. Branch: Evidence Aggregation & Trust
        agg_node = ExplainabilityNode(
            node_id="evidence_aggregation",
            category=NodeCategory.EVIDENCE_AGGREGATION,
            title="Multi-Criteria Evidence Aggregation",
            description=f"Aggregated {len(evidence.signals)} evidence signal(s) across {len(breakdown.active_layers)} active layer(s).",
            status=NodeStatus.EVALUATED,
            metadata={
                "active_layers": list(breakdown.active_layers),
                "total_signals": len(evidence.signals),
                "max_severity": evidence.get_max_severity().value
            }
        )
        if breakdown.mitigation_adjustment > 0:
            agg_node.add_child(ExplainabilityNode(
                node_id="mitigation_discount",
                category=NodeCategory.FINDING,
                title="Mitigation & Reputation Discount",
                description=f"Verified whitelist or reputation signals discounted -{breakdown.mitigation_adjustment:.1f} points from composite risk.",
                status=NodeStatus.MITIGATED,
                score_contribution=-breakdown.mitigation_adjustment
            ))
        root.add_child(agg_node)

        # 9. Branch: Risk Calculation & Traceability
        calc_status = NodeStatus.OVERRIDDEN if is_override else (
            NodeStatus.MUTUAL_CONFIRMATION if breakdown.mutual_confirmation_boost else NodeStatus.EVALUATED
        )
        calc_node = ExplainabilityNode(
            node_id="risk_calculation",
            category=NodeCategory.RISK_CALCULATION,
            title="Mathematical Risk Score Derivation",
            description=f"Multi-attribute utility calculation: raw composite {breakdown.raw_composite:.1f} -> final score {score:.1f}/100.",
            status=calc_status,
            score_contribution=score,
            metadata=traceability.to_dict()
        )
        for layer_enum, weight_key in layer_key_map.items():
            if layer_enum in breakdown.active_layers:
                norm_w = normalized_weights.get(weight_key, 0.0)
                l_score = layer_scores.get(weight_key, 0.0)
                contrib = layer_contributions.get(weight_key, 0.0)
                calc_node.add_child(ExplainabilityNode(
                    node_id=f"calc_layer_{weight_key}",
                    category=NodeCategory.METRIC,
                    title=f"Layer {layer_enum}",
                    description=f"Score: {l_score:.1f} × Normalized Weight: {norm_w:.4f} = Contribution: +{contrib:.2f}",
                    status=NodeStatus.EVALUATED,
                    score_contribution=contrib,
                    weight=norm_w
                ))
        if breakdown.mutual_confirmation_boost:
            calc_node.add_child(ExplainabilityNode(
                node_id="calc_mutual_boost",
                category=NodeCategory.FINDING,
                title="Mutual Corroboration Escalation",
                description="Machine Learning and Rule Engine independently confirmed high risk (+25% multiplier applied).",
                status=NodeStatus.MUTUAL_CONFIRMATION,
                score_contribution=round(breakdown.raw_composite - weighted_sum, 2)
            ))
        if is_override:
            calc_node.add_child(ExplainabilityNode(
                node_id="calc_override",
                category=NodeCategory.FINDING,
                title="Security Override Applied",
                description=override_reason or "Safety boundary override modified classification.",
                status=NodeStatus.OVERRIDDEN
            ))
        root.add_child(calc_node)

        # 10. Branch: Final Decision
        primary_reason, summary_reasons = cls.generate_explanation(
            risk_level=risk_level,
            status=status,
            score=score,
            evidence=evidence,
            breakdown=breakdown
        )

        decision_node = ExplainabilityNode(
            node_id="final_decision",
            category=NodeCategory.FINAL_DECISION,
            title=f"Final Verdict: {status_str} ({risk_level_str})",
            description=primary_reason,
            status=root_status,
            score_contribution=score,
            metadata={
                "risk_score": score,
                "confidence": confidence,
                "risk_level": risk_level_str,
                "detection_status": status_str,
            }
        )
        decision_node.add_child(ExplainabilityNode(
            node_id="decision_confidence",
            category=NodeCategory.METRIC,
            title="Internal Decision Confidence",
            description=f"Calculated confidence {confidence:.2f} based on evidence diversity across {len(breakdown.active_layers)} active layer(s).",
            status=NodeStatus.EVALUATED,
            metadata={"confidence": confidence}
        ))
        root.add_child(decision_node)

        return ExplainabilityTree(
            target_identifier=target_identifier,
            input_type=input_type_str,
            final_score=score,
            risk_level=risk_level_str,
            detection_status=status_str,
            confidence=confidence,
            root=root,
            traceability=traceability,
            summary_reasons=summary_reasons
        )
