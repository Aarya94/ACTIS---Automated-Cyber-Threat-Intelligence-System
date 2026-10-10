"""
ACTIS Unified Architecture Validation Tests
Verifies adherence to the Core + Extensions unified architecture:
- Authoritative Analysis Orchestrator multi-modal ingestion (File, URL, Message, SecurityEvent)
- Contract symmetry between file and URL detection pipelines
- Scanner delegation without competing detection engines
- Failure isolation and defensive boundaries
"""

import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

from detection_engine.orchestrator import AnalysisOrchestrator, analysis_orchestrator
from detection_engine.threat_detector import ThreatDetector, threat_detector
from detection_engine.detection_contract import DetectionResult, DetectionStatus, RiskLevel, InputType
from scanners.file_scanner import scan_file
from scanners.url_scanner import scan_url_logic
from scanners.text_analyzer import TextAnalyzer
from service.events import SecurityEvent, SecurityEventType


@pytest.fixture
def orchestrator():
    return AnalysisOrchestrator(name="TestArchitectureOrchestrator")


# ============================================================================
# 1. MULTI-MODAL INGESTION & CONTRACT SYMMETRY
# ============================================================================

def test_file_analysis_contract_symmetry(orchestrator, tmp_path):
    """File analysis must return structured DetectionResult and confidence identical to URL analysis."""
    dummy_file = tmp_path / "test_sample.txt"
    dummy_file.write_text("Hello ACTIS Unified Architecture", encoding="utf-8")

    result = orchestrator.analyze_file(dummy_file)

    assert result["target_type"] == "file"
    assert result["file_path"] == str(dummy_file)
    assert "score" in result
    assert "risk_level" in result
    assert "confidence" in result
    assert "detection_result" in result

    det_res = result["detection_result"]
    assert "target_identifier" in det_res
    assert det_res["input_type"] in (InputType.FILE.value, InputType.PE_BINARY.value)
    assert "detection_status" in det_res
    assert "risk_score" in det_res
    assert "confidence" in det_res


def test_url_analysis_contract_symmetry(orchestrator):
    """URL analysis must return structured DetectionResult and confidence."""
    result = orchestrator.analyze_url("https://example.com/safe-path")

    assert result["target_type"] == "url"
    assert result["url"] == "https://example.com/safe-path"
    assert "score" in result
    assert "risk_level" in result
    assert "confidence" in result
    assert "detection_result" in result

    det_res = result["detection_result"]
    assert det_res["input_type"] == InputType.URL.value
    assert "detection_status" in det_res
    assert "risk_score" in det_res
    assert "confidence" in det_res


def test_message_analysis_ingestion(orchestrator):
    """Message analysis extracts links and social engineering cues through the orchestrator."""
    sample_text = "URGENT: Verify your credentials at https://secure-bank.example.com immediately!"
    result = orchestrator.analyze_message(sample_text)

    assert "total_url_count" in result
    assert result["total_url_count"] >= 1
    assert "social_engineering" in result
    assert result["social_engineering"]["has_urgency"] is True
    assert "url_results" in result


# ============================================================================
# 2. WINDOWS PROTECTION SERVICE EVENT HANDOFF BOUNDARY
# ============================================================================

def test_handle_security_event_file_created(orchestrator, tmp_path):
    """AnalysisOrchestrator consumes FILE_CREATED security events and executes analysis."""
    test_file = tmp_path / "created_binary.bin"
    test_file.write_bytes(b"\x90\x90\x90\x90")

    event = SecurityEvent(
        event_type=SecurityEventType.FILE_CREATED,
        source="WindowsFileWatcher",
        target=str(test_file)
    )
    receipt = orchestrator.handle_security_event(event)

    assert receipt["status"] == "ANALYZED"
    assert receipt["event_id"] == event.event_id
    assert "analysis" in receipt
    assert receipt["analysis"]["target_type"] == "file"
    assert "detection_result" in receipt["analysis"]


def test_handle_security_event_url_accessed(orchestrator):
    """AnalysisOrchestrator consumes URL_DETECTED security events and executes analysis."""
    event = SecurityEvent(
        event_type=SecurityEventType.URL_DETECTED,
        source="BrowserClipboardMonitor",
        target="https://suspicious-domain.xyz/login"
    )
    receipt = orchestrator.handle_security_event(event)

    assert receipt["status"] == "ANALYZED"
    assert receipt["target"] == "https://suspicious-domain.xyz/login"
    assert "analysis" in receipt
    assert receipt["analysis"]["target_type"] == "url"


def test_handle_security_event_message_received(orchestrator):
    """AnalysisOrchestrator consumes MESSAGE_RECEIVED security events and executes analysis."""
    event = SecurityEvent(
        event_type=SecurityEventType.MESSAGE_RECEIVED,
        source="EmailClientPlugin",
        target="Check this update: http://example-patch.org"
    )
    receipt = orchestrator.handle_security_event(event)

    assert receipt["status"] == "ANALYZED"
    assert "analysis" in receipt
    assert "total_url_count" in receipt["analysis"]


def test_handle_security_event_disappeared_file(orchestrator, tmp_path):
    """Orchestrator safely handles file deletion races between event and inspection."""
    ghost_file = tmp_path / "vanished.exe"
    event = SecurityEvent(
        event_type=SecurityEventType.FILE_CREATED,
        source="TestRace",
        target=str(ghost_file)
    )
    receipt = orchestrator.handle_security_event(event)

    assert receipt["status"] == "DISAPPEARED"
    assert "vanished.exe" in receipt["target"]



# ============================================================================
# 3. SCANNER DELEGATION (SINGLE DETECTION PIPELINE RULE)
# ============================================================================

def test_single_file_scanner_delegation(tmp_path):
    """scanners.file_scanner.scan_file must delegate directly to the central analysis engine."""
    sample = tmp_path / "scanner_test.exe"
    sample.write_bytes(b"MZ\x90\x00")

    result = scan_file(sample)
    assert result["target_type"] == "file"
    assert "detection_result" in result
    assert "score" in result


def test_url_scanner_logic_delegation():
    """scanners.url_scanner.scan_url_logic must delegate directly to the central analysis engine."""
    result = scan_url_logic("https://actis-secure.local")
    assert result["target_type"] == "url"
    assert "detection_result" in result
    assert "score" in result


def test_text_analyzer_delegates_urls_to_scanner():
    """TextAnalyzer must delegate all extracted URLs to the central scanner path."""
    res = TextAnalyzer.analyze_message("Please review https://test-link.com and alert security.")
    assert res["total_url_count"] == 1
    assert len(res["url_results"]) == 1
    assert "detection_result" in res["url_results"][0]


# ============================================================================
# 4. FAILURE ISOLATION & DEFENSIVE BOUNDARIES
# ============================================================================

def test_orchestrator_invalid_url_isolation(orchestrator):
    """Malformed or invalid URLs must be handled gracefully without raising unhandled exceptions."""
    result = orchestrator.analyze_url("not a url at all :::")
    assert result["is_valid"] is False
    assert result["risk_level"] == "INFORMATIONAL"
    assert result["score"] == 0.0


def test_orchestrator_nonexistent_file_isolation(orchestrator):
    """Non-existent files return a structured error response without crashing."""
    result = orchestrator.analyze_file(Path("D:/nonexistent/path/to/missing_file.exe"))
    assert result["is_valid"] is False
    assert "File not found" in result["error"]
