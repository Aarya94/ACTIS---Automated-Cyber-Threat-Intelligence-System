"""
ACTIS Threat Detector Module
Central intelligence orchestrator that unifies feature extraction, threat lookup,
machine learning inference, rule-based heuristics, risk scoring, and detection logging.
"""

from pathlib import Path
from urllib.parse import urlparse
from typing import Dict, Any, Optional

from scanners.file_feature_extractor import FileFeatureExtractor
from detection_engine.model_manager import model_manager
from detection_engine.rule_engine import RuleEngine
from detection_engine.risk_engine import RiskEngine
from threat_intelligence.threat_lookup import threat_lookup
from reports.threat_database import record_detection, register_indicator
from config.config import get_logger

logger = get_logger("ThreatDetector")


class ThreatDetector:
    """Central detection pipeline orchestrator."""

    def __init__(self):
        # In-memory scan cache: hash -> analysis_result
        self._hash_cache: Dict[str, Dict[str, Any]] = {}

    def clear_cache(self):
        """Clears the in-memory scan hash cache."""
        self._hash_cache.clear()

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
        path = Path(file_path)
        if not path.exists():
            return {"error": f"File not found: {path}", "is_valid": False}

        # Step 1: Extract Static Metadata & Hashes
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
        intel_result = threat_lookup.lookup_hash(sha256, query_external=check_external)
        known_intel = intel_result.get("local_intel")
        external_intel = intel_result.get("external_intel")

        # Step 3: Heuristic Rule Engine
        heuristic_res = RuleEngine.evaluate_pe_file(static_info)

        # Step 4: Machine Learning Inference (if PE binary)
        ml_res = {"available": False, "probability": 0.0, "is_malware": False}
        if static_info.get("is_pe", False) and static_info.get("ml_feature_vector"):
            ml_res = model_manager.predict_malware(static_info["ml_feature_vector"])

        # Step 5: Multi-Criteria Risk Evaluation
        risk_res = RiskEngine.calculate_risk(
            target_type="file",
            target_value=str(path),
            known_intel=known_intel,
            ml_result=ml_res,
            heuristic_result=heuristic_res,
            external_intel=external_intel
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
            "ml_result": ml_res,
            "heuristic_result": heuristic_res,
            "threat_intel": intel_result,
            "static_info": static_info,
            "from_cache": False
        }

        # Cache result
        if sha256:
            self._hash_cache[sha256] = final_result

        return final_result

    def analyze_url(
        self,
        url: str,
        scan_id: Optional[int] = None,
        check_external: bool = False
    ) -> Dict[str, Any]:
        """
        Executes complete multi-layer security analysis on a URL.
        """
        # Step 1: Normalize URL & Extract Domain
        clean_url = url.strip()
        if not clean_url.startswith(("http://", "https://")):
            clean_url = "http://" + clean_url

        parsed = urlparse(clean_url)
        domain = (parsed.netloc or "").lower()
        if domain.startswith("www."):
            domain = domain[4:]

        # Step 2: Threat Intelligence Lookup
        intel_result = threat_lookup.lookup_url(clean_url, domain, query_external=check_external)
        known_intel = intel_result.get("local_intel")
        external_intel = intel_result.get("external_intel")

        # Step 3: Extract Morphological Features (19 features)
        from scanners.url_scanner import extract_url_features
        features = extract_url_features(clean_url)

        # Step 4: ML Inference
        ml_res = model_manager.predict_phishing(features)

        # Step 5: Heuristic Rule Engine
        heuristic_res = RuleEngine.evaluate_url(clean_url)

        # Step 6: Multi-Criteria Risk Evaluation
        risk_res = RiskEngine.calculate_risk(
            target_type="url",
            target_value=clean_url,
            known_intel=known_intel,
            ml_result=ml_res,
            heuristic_result=heuristic_res,
            external_intel=external_intel
        )

        # Step 7: Record Detection
        if risk_res.get("is_threat", False):
            indicator_id = None
            if known_intel and known_intel.get("found"):
                indicator_id = known_intel.get("id")
            else:
                indicator_id = register_indicator(
                    indicator_type="url",
                    indicator_value=clean_url,
                    source="actis_url_scanner",
                    confidence=round(risk_res["score"] / 100.0, 2),
                    status="SUSPICIOUS" if risk_res["risk_level"] != "CRITICAL" else "CONFIRMED",
                    threat_type="Phishing",
                    threat_name=domain
                )

            record_detection(
                target=clean_url,
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

        return {
            "target_type": "url",
            "url": clean_url,
            "domain": domain,
            "score": risk_res["score"],
            "risk_level": risk_res["risk_level"],
            "is_threat": risk_res["is_threat"],
            "reasons": risk_res["reasons"],
            "recommended_action": risk_res["recommended_action"],
            "ml_result": ml_res,
            "heuristic_result": heuristic_res,
            "threat_intel": intel_result
        }


# Global detector singleton
threat_detector = ThreatDetector()
