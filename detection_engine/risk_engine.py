"""
ACTIS Risk Engine Module
Combines evidence from local threat intelligence, machine learning inference,
rule-based heuristics, and external threat feeds into an explainable 0-100 risk score.
"""

from typing import Dict, Any, List, Optional
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

logger = get_logger("RiskEngine")


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
        
        Args:
            target_type: 'url', 'domain', 'hash', 'file'
            target_value: The target string or file path
            known_intel: Result from local SQLite threat database lookup
            ml_result: Output from ModelManager
            heuristic_result: Output from RuleEngine
            external_intel: Output from external API providers (e.g. VirusTotal)
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
            # Dynamically normalize weights across active/available evidence layers
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

            # Boost score if ML and Heuristics mutually confirm suspicion
            if ml_score >= 70.0 and rule_score >= 50.0:
                weighted_sum = min(100.0, weighted_sum * 1.25)
                reasons.append("High correlation detected: Machine learning inference and rule heuristics independently confirm threat.")

            final_score = max(0.0, min(100.0, round(weighted_sum, 1)))

        # Categorical Risk Level
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
