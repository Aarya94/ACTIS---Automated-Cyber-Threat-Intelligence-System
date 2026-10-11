"""
ACTIS Threat Detector Module
Central intelligence orchestrator that unifies feature extraction, threat lookup,
machine learning inference, rule-based heuristics, risk scoring, and detection logging.
"""

from pathlib import Path
from urllib.parse import urlparse
from typing import Dict, Any, Optional

from detection_engine.model_manager import model_manager
from detection_engine.rule_engine import RuleEngine
from detection_engine.risk_engine import RiskEngine
from reports.threat_database import record_detection, register_indicator
from config.config import get_logger

logger = get_logger("ThreatDetector")


def _get_threat_lookup():
    """Lazily resolves threat_lookup singleton to avoid circular import cycles."""
    from threat_intelligence.threat_lookup import threat_lookup
    return threat_lookup


class ThreatDetector:
    """Central detection pipeline orchestrator."""

    def __init__(self):
        # In-memory scan caches
        self._hash_cache: Dict[str, Dict[str, Any]] = {}
        self._url_cache: Dict[str, Dict[str, Any]] = {}

    def clear_cache(self):
        """Clears both the in-memory file hash and URL scan caches."""
        self._hash_cache.clear()
        self._url_cache.clear()

    def analyze_file(
        self,
        file_path: Path,
        scan_id: Optional[int] = None,
        check_external: bool = False
    ) -> Dict[str, Any]:
        """
        Executes complete multi-layer security analysis on a local file.
        Operates strictly in READ-ONLY mode.
        """
        if not file_path or not isinstance(file_path, (str, Path)):
            return {
                "error": "Target file path is None or invalid.",
                "is_valid": False,
                "target": "",
                "score": 0.0,
                "risk_level": "LOW",
                "is_threat": False
            }
        path = Path(file_path)
        if not path.exists():
            return {
                "error": f"File not found: {path}",
                "is_valid": False,
                "target": str(path),
                "score": 0.0,
                "risk_level": "LOW",
                "is_threat": False
            }
        if path.is_dir():
            return {
                "error": f"Path is a directory, not a regular file: {path}",
                "is_valid": False,
                "target": str(path),
                "score": 0.0,
                "risk_level": "LOW",
                "is_threat": False
            }

        # Step 1: Extract Static Metadata & Hashes
        from scanners.file_feature_extractor import FileFeatureExtractor
        static_info = FileFeatureExtractor.extract_features(path)
        if not static_info.get("is_valid", False):
            return static_info

        sha256 = static_info.get("sha256", "")
        
        # Check in-memory hash cache to avoid redundant expensive processing
        if sha256 and sha256 in self._hash_cache:
            cached_result = dict(self._hash_cache[sha256])
            cached_result["from_cache"] = True
            return cached_result

        # Step 2: Local & External Threat Intelligence Lookup
        intel_result = _get_threat_lookup().lookup_hash(sha256, query_external=check_external)
        known_intel = intel_result.get("local_intel")
        external_intel = intel_result.get("external_intel")

        # Step 3: Heuristic Rule Engine
        heuristic_res = RuleEngine.evaluate_pe_file(static_info)

        # Step 4: Machine Learning Inference (both structured & legacy format)
        from detection_engine.decision_engine import DetectionDecisionEngine
        from detection_engine.detection_contract import InputType
        from detection_engine.ml_prediction_contract import MLPredictionResult, MLModelType
        from detection_engine.threat_intel_contract import ThreatIntelEvidence, IndicatorType

        ml_structured = MLPredictionResult.unavailable(
            model_name="windows_pe_malware_rf",
            model_type=MLModelType.WINDOWS_PE_MALWARE,
            reason="Not a PE executable or missing feature vector."
        )
        ml_res = {"available": False, "probability": 0.0, "is_malware": False}
        if static_info.get("is_pe", False) and static_info.get("ml_feature_vector"):
            ml_structured = model_manager.predict_malware_structured(static_info["ml_feature_vector"])
            ml_res = model_manager.predict_malware(static_info["ml_feature_vector"])

        rule_eval = heuristic_res.get("structured_result")
        ti_evidence = intel_result.get("primary_evidence") or ThreatIntelEvidence.from_local_intel(
            intel=known_intel,
            indicator=sha256,
            indicator_type=IndicatorType.SHA256
        )

        # Step 5: Multi-Criteria Risk Evaluation & Decision Fusion
        risk_res = RiskEngine.calculate_risk(
            target_type="file",
            target_value=str(path),
            known_intel=known_intel,
            ml_result=ml_res,
            heuristic_result=heuristic_res,
            external_intel=external_intel
        )

        decision_result = DetectionDecisionEngine.evaluate(
            target_identifier=str(path),
            input_type=InputType.PE_BINARY if static_info.get("is_pe", False) else InputType.FILE,
            ti_evidence=ti_evidence,
            ml_prediction=ml_structured,
            rule_result=rule_eval,
            metadata={
                "sha256": sha256,
                "file_name": path.name,
                "file_size": static_info.get("file_size", 0),
                "is_pe": static_info.get("is_pe", False),
                "threat_intel": intel_result,
            }
        )

        # Step 6: Log Detection Event if Threat Identified
        if risk_res.get("is_threat", False):
            indicator_id = None
            if known_intel and known_intel.get("found"):
                indicator_id = known_intel.get("id")
            elif sha256:
                # Register new suspicious candidate indicator locally
                indicator_id = register_indicator(
                    indicator_type="sha256",
                    indicator_value=sha256,
                    source="actis_file_scanner",
                    confidence=round(risk_res["score"] / 100.0, 2),
                    status="SUSPICIOUS" if risk_res["risk_level"] != "CRITICAL" else "CONFIRMED",
                    threat_type="Malware",
                    threat_name=path.name
                )

            record_detection(
                target=str(path),
                target_type="file",
                final_score=risk_res["score"],
                risk_level=risk_res["risk_level"],
                model_name=ml_res.get("model_name", "N/A"),
                model_score=ml_res.get("probability", 0.0) * 100.0,
                rule_score=heuristic_res.get("heuristic_score", 0.0),
                intel_score=risk_res["evidence_breakdown"]["known_intel_score"],
                explanation_list=risk_res["reasons"],
                scan_id=scan_id,
                indicator_id=indicator_id
            )

        # Assemble unified response
        final_result = {
            "target_type": "file",
            "file_path": str(path),
            "file_name": path.name,
            "sha256": sha256,
            "md5": static_info.get("md5", ""),
            "file_size": static_info.get("file_size", 0),
            "is_pe": static_info.get("is_pe", False),
            "entropy": static_info.get("entropy", 0.0),
            "is_signed": static_info.get("is_signed", False),
            "score": risk_res["score"],
            "risk_level": risk_res["risk_level"],
            "is_threat": risk_res["is_threat"],
            "reasons": risk_res["reasons"],
            "recommended_action": risk_res["recommended_action"],
            "confidence": decision_result.confidence,
            "ml_result": ml_res,
            "ml_prediction": ml_structured.to_dict(),
            "heuristic_result": heuristic_res,
            "threat_intel": intel_result,
            "detection_result": decision_result.to_dict(),
            "static_info": static_info,
            "from_cache": False
        }

        # Cache result
        if sha256:
            self._hash_cache[sha256] = final_result

        return final_result

    def analyze_message(
        self,
        text: str,
        check_external: bool = False
    ) -> Dict[str, Any]:
        """
        Executes security analysis on message text, extracting embedded links,
        evaluating social engineering cues, and delegating each link to URL analysis.
        """
        from scanners.text_analyzer import TextAnalyzer
        return TextAnalyzer.analyze_message(text, check_external=check_external)

    def analyze_url(
        self,
        url: Any,
        scan_id: Optional[int] = None,
        check_external: bool = False
    ) -> Dict[str, Any]:
        """
        Executes complete multi-layer security analysis on a URL.
        Validates input, applies canonical normalization, inspects local TI,
        evaluates morphological features and heuristics, and fuses decisions
        via the DetectionDecisionEngine. Operates strictly in READ-ONLY mode.
        """
        from scanners.url_scanner import validate_url, normalize_url, extract_domain, extract_url_features
        from detection_engine.decision_engine import DetectionDecisionEngine
        from detection_engine.detection_contract import InputType
        from detection_engine.threat_intel_contract import ThreatIntelEvidence, IndicatorType

        # Step 1: Input Validation
        is_valid, validation_error = validate_url(url)
        if not is_valid:
            return {
                "target_type": "url",
                "url": str(url or ""),
                "domain": "",
                "score": 0.0,
                "risk_level": "INFORMATIONAL",
                "is_threat": False,
                "reasons": [f"Invalid URL: {validation_error}"],
                "recommended_action": "Provide a syntactically valid HTTP or HTTPS URL.",
                "ml_result": {"available": False, "probability": 0.0, "is_phishing": False},
                "heuristic_result": {"score": 0, "heuristic_score": 0, "rules_triggered": [], "reasons": []},
                "threat_intel": {"found": False, "is_known_threat": False},
                "detection_result": None,
                "confidence": 0.0,
                "is_valid": False,
                "error": validation_error,
                "from_cache": False
            }

        # Step 2: Canonical Normalization & In-Memory Cache Lookup
        canonical_url = normalize_url(url)
        domain = extract_domain(canonical_url)

        if canonical_url in self._url_cache:
            cached_result = dict(self._url_cache[canonical_url])
            cached_result["from_cache"] = True
            return cached_result

        # Step 3: Local & External Threat Intelligence Lookup
        intel_result = _get_threat_lookup().lookup_url(canonical_url, domain, query_external=check_external)
        known_intel = intel_result.get("local_intel")
        external_intel = intel_result.get("external_intel")
        ti_evidence = intel_result.get("primary_evidence") or ThreatIntelEvidence.from_local_intel(
            intel=known_intel,
            indicator=canonical_url,
            indicator_type=IndicatorType.URL
        )

        # Step 4: Extract Morphological Features (19 features)
        features = extract_url_features(canonical_url)

        # Step 5: Machine Learning Inference (both structured & legacy format)
        ml_structured = model_manager.predict_phishing_structured(features)
        ml_res = model_manager.predict_phishing(features)

        # Step 6: Heuristic Rule Engine
        heuristic_res = RuleEngine.evaluate_url(canonical_url)
        rule_eval = heuristic_res.get("structured_result")

        # Step 7: Multi-Criteria Risk Evaluation & Decision Fusion
        risk_res = RiskEngine.calculate_risk(
            target_type="url",
            target_value=canonical_url,
            known_intel=known_intel,
            ml_result=ml_res,
            heuristic_result=heuristic_res,
            external_intel=external_intel
        )

        decision_result = DetectionDecisionEngine.evaluate(
            target_identifier=canonical_url,
            input_type=InputType.URL,
            ti_evidence=ti_evidence,
            ml_prediction=ml_structured,
            rule_result=rule_eval,
            metadata={
                "domain": domain,
                "raw_url": str(url),
                "threat_intel": intel_result,
                "features": features
            }
        )

        # Step 8: Record Detection Event if Threat Identified
        if risk_res.get("is_threat", False):
            indicator_id = None
            if known_intel and known_intel.get("found"):
                indicator_id = known_intel.get("id")
            else:
                indicator_id = register_indicator(
                    indicator_type="url",
                    indicator_value=canonical_url,
                    source="actis_url_scanner",
                    confidence=round(risk_res["score"] / 100.0, 2),
                    status="SUSPICIOUS" if risk_res["risk_level"] != "CRITICAL" else "CONFIRMED",
                    threat_type="Phishing",
                    threat_name=domain
                )

            record_detection(
                target=canonical_url,
                target_type="url",
                final_score=risk_res["score"],
                risk_level=risk_res["risk_level"],
                model_name=ml_res.get("model_name", "N/A"),
                model_score=ml_res.get("probability", 0.0) * 100.0,
                rule_score=heuristic_res.get("heuristic_score", 0.0),
                intel_score=risk_res["evidence_breakdown"]["known_intel_score"],
                explanation_list=risk_res["reasons"],
                scan_id=scan_id,
                indicator_id=indicator_id
            )

        final_result = {
            "target_type": "url",
            "url": canonical_url,
            "domain": domain,
            "score": risk_res["score"],
            "risk_level": risk_res["risk_level"],
            "is_threat": risk_res["is_threat"],
            "reasons": risk_res["reasons"],
            "recommended_action": risk_res["recommended_action"],
            "confidence": decision_result.confidence,
            "ml_result": ml_res,
            "ml_prediction": ml_structured.to_dict(),
            "heuristic_result": heuristic_res,
            "threat_intel": intel_result,
            "detection_result": decision_result.to_dict(),
            "is_valid": True,
            "from_cache": False
        }

        # Cache canonical result in memory
        self._url_cache[canonical_url] = final_result
        return final_result



# Global detector singleton
threat_detector = ThreatDetector()
