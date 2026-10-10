"""
ACTIS Analysis Orchestrator
Authoritative central analytical coordinator unifying input normalization handoffs,
feature extraction, ML inference, rule evaluation, threat intelligence queries,
and decision fusion across all supported input modalities.
Implements IAnalysisOrchestrationBoundary for seamless Windows Protection Service integration.
"""

from pathlib import Path
from typing import Dict, Any, Optional, Union

from detection_engine.threat_detector import ThreatDetector
from service.dispatcher import IAnalysisOrchestrationBoundary
from service.events import SecurityEvent, SecurityEventType
from config.config import get_logger

logger = get_logger("AnalysisOrchestrator")


class AnalysisOrchestrator(ThreatDetector, IAnalysisOrchestrationBoundary):
    """
    Unified ACTIS Analysis Orchestrator.
    Serves as the single authoritative analytical engine for:
    1. Local Files & PE Binaries (`analyze_file`)
    2. Web URLs & Domains (`analyze_url`)
    3. Messages & Emails (`analyze_message`)
    4. Resident Windows Security Events (`handle_security_event`)
    """

    def __init__(self, name: str = "UnifiedAnalysisOrchestrator"):
        super().__init__()
        self.name = name

    def handle_security_event(self, event: SecurityEvent) -> Dict[str, Any]:
        """
        Consumes a validated SecurityEvent from the Windows Protection Service
        and routes it to the authoritative detection pipeline.
        """
        event.validate()
        event_type = event.event_type
        meta = event.metadata or {}

        logger.info(
            f"Analysis Orchestrator [{self.name}] processing security event "
            f"'{event.event_id}' ({event_type.value} from {event.source})"
        )

        # 1. Filesystem Events (File creation or modification)
        if event_type in (SecurityEventType.FILE_CREATED, SecurityEventType.FILE_MODIFIED):
            file_path_str = event.target or meta.get("canonical_path") or meta.get("file_path")
            if not file_path_str:
                return {
                    "status": "SKIPPED",
                    "event_id": event.event_id,
                    "reason": "SecurityEvent missing target file_path."
                }

            path = Path(file_path_str)
            if not path.exists():
                return {
                    "status": "DISAPPEARED",
                    "event_id": event.event_id,
                    "target": str(path),
                    "reason": "File disappeared before analysis could execute."
                }

            analysis_result = self.analyze_file(path)
            return {
                "status": "ANALYZED",
                "event_id": event.event_id,
                "target": str(path),
                "is_threat": analysis_result.get("is_threat", False),
                "score": analysis_result.get("score", 0.0),
                "risk_level": analysis_result.get("risk_level", "LOW"),
                "analysis": analysis_result
            }

        # 2. URL Ingest / Clipboard URL Events
        elif event_type == SecurityEventType.URL_DETECTED:
            url_str = event.target or meta.get("url")
            if not url_str:
                return {
                    "status": "SKIPPED",
                    "event_id": event.event_id,
                    "reason": "SecurityEvent missing target URL."
                }

            analysis_result = self.analyze_url(url_str)
            return {
                "status": "ANALYZED",
                "event_id": event.event_id,
                "target": url_str,
                "is_threat": analysis_result.get("is_threat", False),
                "score": analysis_result.get("score", 0.0),
                "risk_level": analysis_result.get("risk_level", "LOW"),
                "analysis": analysis_result
            }

        # 3. Message / Email Ingest Events
        elif event_type == SecurityEventType.MESSAGE_RECEIVED:
            msg_text = event.target or meta.get("text") or meta.get("message") or ""
            analysis_result = self.analyze_message(msg_text)
            return {
                "status": "ANALYZED",
                "event_id": event.event_id,
                "is_threat": analysis_result.get("is_suspicious_message", False),
                "score": analysis_result.get("overall_score", 0.0),
                "risk_level": analysis_result.get("overall_risk_level", "LOW"),
                "analysis": analysis_result
            }


        # 4. Other events (Service lifecycle, status telemetry)
        return {
            "status": "ACCEPTED",
            "event_id": event.event_id,
            "event_type": event_type.value,
            "message": "Event recorded; no static threat analysis required."
        }


# Global Analysis Orchestrator singleton
analysis_orchestrator = AnalysisOrchestrator()
