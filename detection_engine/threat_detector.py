"""
ACTIS Threat Detector Module
Central intelligence orchestrator that unifies feature extraction, threat lookup,
machine learning inference, rule-based heuristics, risk scoring, and detection logging.
"""

from pathlib import Path
from urllib.parse import urlparse
from typing import Dict, Any, Optional, Callable

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

    def __init__(
        self,
        max_cache_entries: int = 5000,
        cache_ttl_seconds: float = 300.0,
        clock: Optional[Callable[[], float]] = None
    ):
        # Bounded thread-safe LRU scan caches with TTL
        from threat_intelligence.threat_cache import LRUTTLCache
        self._hash_cache = LRUTTLCache(
            max_size=max_cache_entries,
            default_ttl_seconds=cache_ttl_seconds,
            clock=clock
        )
        self._url_cache = LRUTTLCache(
            max_size=max_cache_entries,
            default_ttl_seconds=cache_ttl_seconds,
            clock=clock
        )

    def clear_cache(self):
        """Clears both the in-memory file hash and URL scan caches."""
        self._hash_cache.clear()
        self._url_cache.clear()

    def invalidate_hash(self, sha256: str) -> bool:
        """Invalidates a specific file hash from the in-memory scan cache."""
        return self._hash_cache.invalidate(sha256)

    def invalidate_url(self, url: str) -> bool:
        """Invalidates a specific URL from the in-memory scan cache across all redirect variants."""
        from scanners.url_scanner import normalize_url
        try:
            norm = normalize_url(url)
        except Exception:
            norm = str(url).strip()
        inv_false = self._url_cache.invalidate(f"{norm}__redir_False")
        inv_true = self._url_cache.invalidate(f"{norm}__redir_True")
        inv_base = self._url_cache.invalidate(norm)
        return bool(inv_false or inv_true or inv_base)

    def get_cache_stats(self) -> Dict[str, Any]:
        """Returns cache telemetry for both file hash and URL caches."""
        return {
            "hash_cache": self._hash_cache.get_stats(),
            "url_cache": self._url_cache.get_stats()
        }

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
        if sha256:
            cached_result = self._hash_cache.get(sha256)
            if cached_result is not None:
                res = dict(cached_result)
                res["from_cache"] = True
                return res

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
                "detected_format": static_info.get("detected_format", "UNKNOWN"),
                "analysis_method": static_info.get("analysis_method", "UNKNOWN"),
                "non_pe_features": static_info.get("non_pe_features", {}),
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
                    # Trust Invariant (Day 27 Part 2): Internal heuristic/ML detections are unverified alerts
                    # and must NEVER be auto-promoted to CONFIRMED without authoritative review.
                    status="SUSPICIOUS",
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
            "detected_format": static_info.get("detected_format", "UNKNOWN"),
            "analysis_method": static_info.get("analysis_method", "UNKNOWN"),
            "non_pe_features": static_info.get("non_pe_features", {}),
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
            "explainability_tree": decision_result.explainability_tree,
            "static_info": static_info,
            "from_cache": False
        }

        # Cache result
        if sha256:
            self._hash_cache.set(sha256, final_result)

        return final_result

    def analyze_message(
        self,
        text_or_message: Any = None,
        check_external: bool = False,
        scan_id: Optional[int] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Executes security analysis on message text or MIME message, extracting embedded links,
        evaluating social engineering cues, MIME structure, attachments, display mismatches,
        and fusing evidence into the ACTIS detection decision engine.
        """
        if text_or_message is None and "text" in kwargs:
            text_or_message = kwargs["text"]

        from scanners.text_analyzer import TextAnalyzer
        from detection_engine.decision_engine import DetectionDecisionEngine
        from detection_engine.detection_contract import InputType, RiskLevel
        from detection_engine.evidence_model import EvidenceSignal, EvidenceSource, EvidenceSeverity
        from detection_engine.threat_intel_contract import ThreatIntelEvidence, IndicatorType

        # Step 1: Structured Message & MIME Analysis
        scan_result = TextAnalyzer.analyze_message_structured(
            text_or_message,
            check_external=check_external
        )
        scan_dict = scan_result.to_dict()

        if not scan_result.is_valid:
            res = dict(scan_dict)
            res.update({
                "target_type": "message",
                "score": 0.0,
                "risk_level": "LOW",
                "is_threat": False,
                "reasons": scan_result.explanation_summary,
                "recommended_action": scan_result.recommended_action,
                "confidence": 0.0,
                "detection_result": None,
                "explainability_tree": None,
                "from_cache": False,
            })
            return res

        # Step 2: Heuristic Rule Engine (Message & Social Engineering Rules)
        heuristic_res = RuleEngine.evaluate_message(scan_result)
        rule_eval = heuristic_res.get("structured_result")

        # Step 3: Extract Threat Signals from Embedded URLs
        static_signals = []
        ti_evidence = None
        for u_res in scan_result.url_results:
            u_score = float(u_res.get("score", 0.0) or 0.0)
            u_threat = bool(u_res.get("is_threat", False))
            u_canonical = u_res.get("url", "")
            u_domain = u_res.get("domain", "")

            # Check if URL matched CONFIRMED threat intelligence
            u_ti = u_res.get("threat_intel", {})
            local_status = str(u_ti.get("local_intel", {}).get("status", "")).upper()
            if u_ti.get("is_known_threat") or local_status in ("CONFIRMED", "MALICIOUS"):
                if ti_evidence is None:
                    ti_evidence = ThreatIntelEvidence.from_local_intel(
                        intel=u_ti.get("local_intel"),
                        indicator=u_canonical,
                        indicator_type=IndicatorType.URL
                    )

            if u_threat and u_score >= 60.0:
                sev = EvidenceSeverity.CRITICAL if u_score >= 80.0 else EvidenceSeverity.HIGH
                static_signals.append(
                    EvidenceSignal(
                        source=EvidenceSource.ANOMALY,
                        signal_id=f"MSG_URL_RISK_{u_canonical}",
                        name=f"High-Risk URL in Message: {u_domain}",
                        description=f"Message contains link '{u_canonical}' with risk score {u_score:.1f}.",
                        severity=sev,
                        score_contribution=min(100.0, u_score),
                        raw_data={"url": u_canonical, "domain": u_domain, "score": u_score}
                    )
                )

        # Step 4: Decision Fusion & Explainability Tree
        subj = scan_result.mime_headers.get("Subject") if scan_result.mime_headers else None
        target_id = subj or (scan_result.urls_found[0] if scan_result.urls_found else "message_payload")

        decision_result = DetectionDecisionEngine.evaluate(
            target_identifier=target_id,
            input_type=InputType.MESSAGE,
            ti_evidence=ti_evidence,
            ml_prediction=None,
            rule_result=rule_eval,
            static_signals=static_signals,
            metadata={
                "message_analysis": scan_dict,
                "message_structure": scan_dict,
                "url_results": scan_result.url_results,
                "total_urls": scan_result.total_url_count,
                "threat_urls": scan_result.threat_urls_count,
                "is_mime": scan_result.is_mime,
                "display_mismatches": scan_result.display_mismatches_count,
            }
        )

        is_threat = (
            decision_result.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
            or scan_result.threat_urls_count > 0
            or scan_result.suspicious_attachments_count > 0
            or scan_result.is_suspicious_message
        )

        # Step 5: Optional Record Detection if Threat Identified
        if is_threat:
            try:
                record_detection(
                    target=target_id,
                    target_type="message",
                    final_score=decision_result.risk_score,
                    risk_level=decision_result.risk_level.value if hasattr(decision_result.risk_level, "value") else str(decision_result.risk_level),
                    model_name="N/A",
                    model_score=0.0,
                    rule_score=heuristic_res.get("heuristic_score", 0.0),
                    intel_score=decision_result.analysis_metadata.get("score_breakdown", {}).get("threat_intel_score", 0.0),
                    explanation_list=decision_result.reasons,
                    scan_id=scan_id,
                    indicator_id=None
                )
            except Exception as e:
                logger.warning(f"Failed to record message detection log: {e}")

        # Assemble unified response preserving all legacy TextAnalyzer keys
        final_dict = dict(scan_dict)
        final_dict.update({
            "target_type": "message",
            "score": decision_result.risk_score,
            "risk_level": decision_result.risk_level.value if hasattr(decision_result.risk_level, "value") else str(decision_result.risk_level),
            "is_threat": is_threat,
            "reasons": decision_result.reasons,
            "recommended_action": decision_result.analysis_metadata.get("recommended_action", scan_result.recommended_action),
            "confidence": decision_result.confidence,
            "heuristic_result": heuristic_res,
            "detection_result": decision_result.to_dict(),
            "explainability_tree": decision_result.explainability_tree,
            "from_cache": False
        })
        return final_dict


    def analyze_url(
        self,
        url: Any,
        scan_id: Optional[int] = None,
        check_external: bool = False,
        follow_redirects: bool = False,
        http_fetcher: Optional[Callable] = None,
        dns_resolver: Optional[Callable] = None
    ) -> Dict[str, Any]:
        """
        Executes complete multi-layer security analysis on a URL.
        Validates input, applies advanced de-obfuscation and canonical normalization,
        evaluates morphological features, heuristic rules, machine learning models,
        local & external threat intelligence, and optional safe redirect hops.
        Operates strictly in READ-ONLY mode.
        """
        from scanners.url_scanner import (
            validate_url,
            normalize_url,
            extract_domain,
            extract_url_features,
            deobfuscate_and_analyze_url
        )
        from detection_engine.decision_engine import DetectionDecisionEngine
        from detection_engine.detection_contract import InputType
        from detection_engine.threat_intel_contract import ThreatIntelEvidence, IndicatorType

        # Step 1: Input Validation
        is_valid, validation_error = validate_url(url)
        if not is_valid:
            return {
                "target_type": "url",
                "url": str(url or ""),
                "original_url": str(url or ""),
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

        # Step 2: Advanced De-obfuscation & Analysis
        url_analysis = deobfuscate_and_analyze_url(
            url,
            follow_redirects=follow_redirects,
            http_fetcher=http_fetcher,
            dns_resolver=dns_resolver
        )
        canonical_url = url_analysis.normalized_url
        domain = extract_domain(canonical_url)

        # In-Memory Cache Lookup (keyed by canonical URL and follow_redirects flag)
        cache_key = f"{canonical_url}__redir_{follow_redirects}"
        cached_result = self._url_cache.get(cache_key)
        if cached_result is not None:
            res = dict(cached_result)
            res["from_cache"] = True
            return res

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

        # Step 6: Heuristic Rule Engine (evaluates both URL string and structured URL analysis)
        heuristic_res = RuleEngine.evaluate_url(canonical_url, analysis_result=url_analysis)
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
                "features": features,
                "url_analysis": url_analysis.to_dict()
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
                    # Defect Fix (Day 27 Part 2): Internal heuristic/ML detections are unverified alerts
                    # and must NEVER be auto-promoted to CONFIRMED without authoritative review.
                    status="SUSPICIOUS",
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
            "original_url": str(url),
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
            "explainability_tree": decision_result.explainability_tree,
            "url_analysis": url_analysis.to_dict(),
            "redirect_hops": url_analysis.redirect_hops,
            "final_destination": url_analysis.final_destination,
            "is_valid": True,
            "from_cache": False
        }

        # Cache canonical result in memory
        self._url_cache.set(cache_key, final_result)
        return final_result



# Global detector singleton
threat_detector = ThreatDetector()
