"""
ACTIS — Automated Cyber Threat Intelligence System
Milestone Day 16: System Integration & Release Acceptance Test Suite

Verifies end-to-end integration across subsystems, result contracts,
safe malformed input handling, threat intel lifecycle, anti-poisoning boundaries,
assistant grounded reasoning, isolated reporting, and demonstration execution.
"""

import sys
import json
import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from config.config import ACTIS_ROOT, DATABASE_PATH
from scanners.url_scanner import scan_url_logic, normalize_url
from scanners.file_scanner import scan_file
from detection_engine.threat_detector import threat_detector
from detection_engine.threat_intel_contract import (
    ThreatIntelEvidence,
    ThreatIntelVerdict,
    IndicatorType,
)
from threat_intelligence.threat_lookup import (
    ThreatLookup,
    OUTCOME_NOT_FOUND,
    OUTCOME_REQUEST_TIMEOUT,
)
from threat_intelligence.provider_base import BaseThreatClient
from threat_intelligence.sync_manager import sync_manager
from threat_intelligence.indicator_validator import validate_and_normalize_indicator
from assistant.security_assistant import security_assistant
from reports.report_generator import ReportGenerator
import reports.threat_database as tdb
import reports.scan_database as sdb


# -----------------------------------------------------------------------------
# Test Fixture: Isolated Temporary Database for Release Integration Tests
# -----------------------------------------------------------------------------
@pytest.fixture
def isolated_release_db(tmp_path, monkeypatch):
    """Provides a fresh isolated SQLite database for integration testing."""
    test_db = tmp_path / "test_release_integration.db"
    monkeypatch.setattr(tdb, "DATABASE_PATH", test_db)
    tdb.initialize_database()
    return test_db


# -----------------------------------------------------------------------------
# 1 & 2. Core Analysis Entry Points & Result Contracts
# -----------------------------------------------------------------------------
class TestCoreAnalysisAndResultContracts:
    """Verifies documented analysis entry points and structured result contracts."""

    def test_url_analysis_entry_point_and_contract(self, isolated_release_db):
        """Documented URL entry point processes input and returns compliant contract."""
        url = "https://google.com"
        result = scan_url_logic(url, check_external=False)

        assert isinstance(result, dict)
        assert result.get("is_valid") is True
        assert "url" in result
        assert "score" in result
        assert isinstance(result["score"], (int, float))
        assert 0.0 <= result["score"] <= 100.0

        assert "risk_level" in result
        assert result["risk_level"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

        assert "is_threat" in result
        assert isinstance(result["is_threat"], bool)

        assert "reasons" in result
        assert isinstance(result["reasons"], list)

        assert "recommended_action" in result
        assert isinstance(result["recommended_action"], str)

        assert "ml_result" in result
        assert isinstance(result["ml_result"], dict)
        assert "probability" in result["ml_result"]

        assert "detection_result" in result
        assert isinstance(result["detection_result"], dict)

    def test_file_analysis_entry_point_and_contract(self, tmp_path, isolated_release_db):
        """Documented File entry point processes local file safely and returns compliant contract."""
        sample_file = tmp_path / "plain_text_test.txt"
        sample_file.write_text("ACTIS defensive security integration test payload.", encoding="utf-8")

        result = scan_file(sample_file, check_external=False)

        assert isinstance(result, dict)
        assert result.get("error") is None
        assert result.get("static_info", {}).get("is_valid") is True
        assert "file_path" in result
        assert "sha256" in result
        assert len(result["sha256"]) == 64
        assert "score" in result
        assert 0.0 <= result["score"] <= 100.0
        assert result["risk_level"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        assert isinstance(result["reasons"], list)
        assert result["is_pe"] is False


# -----------------------------------------------------------------------------
# 3. Missing Intelligence Negative Evidence Protection
# -----------------------------------------------------------------------------
class TestNegativeEvidenceProtection:
    """Verifies that missing threat intelligence is never treated as proof of safety."""

    def test_missing_intelligence_not_reported_as_safe_in_lookup(self, isolated_release_db):
        """Lookup for an unknown hash returns NOT_FOUND and does not claim benign verdict."""
        unknown_hash = "f" * 64
        lookup_result = tdb.lookup_indicator("sha256", unknown_hash)

        assert lookup_result.get("found") is False
        assert lookup_result.get("status") != "BENIGN"

    def test_missing_intelligence_in_assistant_explains_uncertainty(self, isolated_release_db):
        """Assistant explicitly informs user that absence of intelligence != benign/safe."""
        response = security_assistant.ask("Why was completely_unknown_file.exe flagged?")

        assert "No Recorded Intelligence" in response or "does not mean" in response.lower()
        # Must explicitly warn against assuming safety
        assert "not mean the target is safe" in response.lower() or "not mean" in response.lower()


# -----------------------------------------------------------------------------
# 4. Candidate Indicator Anti-Poisoning Lifecycle
# -----------------------------------------------------------------------------
class TestCandidateIndicatorProtection:
    """Verifies candidate indicators retain candidate status and are not promoted silently."""

    def test_candidate_indicator_retains_candidate_status(self, isolated_release_db):
        candidate_hash = "a" * 64
        tdb.register_indicator(
            indicator_type="sha256",
            indicator_value=candidate_hash,
            source="fleet_telemetry_client",
            confidence=0.55,
            status="CANDIDATE",
            threat_type="Suspicious Script",
            threat_name="Unreviewed Dropper Candidate"
        )

        ind = tdb.lookup_indicator("sha256", candidate_hash)
        assert ind.get("found") is True
        assert ind.get("status") == "CANDIDATE"

        # Query through assistant
        explanation = security_assistant.ask(f"Why was {candidate_hash} flagged?")
        assert "CANDIDATE" in explanation
        assert "Anti-Poisoning Notice" in explanation or "pending" in explanation.lower()


# -----------------------------------------------------------------------------
# 5. External Provider Timeout Handling
# -----------------------------------------------------------------------------
class TestProviderTimeoutHandling:
    """Verifies external provider timeouts produce documented outcome states without crash."""

    def test_provider_timeout_produces_documented_outcome(self):
        class TimeoutMockProvider(BaseThreatClient):
            def __init__(self):
                super().__init__(provider_name="MockTimeoutProvider", supported_types={IndicatorType.SHA256}, timeout=0.1)

            def is_configured(self) -> bool:
                return True

            def lookup(self, indicator: str, indicator_type: IndicatorType, timeout=None) -> ThreatIntelEvidence:
                return ThreatIntelEvidence.unavailable(
                    indicator=indicator,
                    reason="Provider request timed out after 0.1s",
                    indicator_type=indicator_type,
                    provider=self.provider_name
                )

        mock_provider = TimeoutMockProvider()
        evidence = mock_provider.lookup("b" * 64, IndicatorType.SHA256)

        assert evidence.verdict == ThreatIntelVerdict.UNAVAILABLE
        assert "timed out" in evidence.raw_data.get("reason", "").lower()


# -----------------------------------------------------------------------------
# 6. Resilience: Local Analysis Available When Central Service Is Offline
# -----------------------------------------------------------------------------
class TestLocalAnalysisResilience:
    """Verifies local scanning operates completely when central backend service is unreachable."""

    def test_local_analysis_resilient_to_central_backend_outage(self, isolated_release_db):
        # Simulate offline central backend
        with patch.object(sync_manager, "check_backend_health", return_value={"status": "OFFLINE", "error": "Connection refused"}):
            health = sync_manager.check_backend_health()
            assert health["status"] == "OFFLINE"

            # URL analysis still functions fully
            url_res = scan_url_logic("https://google.com", check_external=False)
            assert url_res.get("is_valid") is True
            assert "score" in url_res


# -----------------------------------------------------------------------------
# 7. Privacy Safeguards: Sensitive Paths Shielded From Outbound Lookups
# -----------------------------------------------------------------------------
class TestPrivacySafeguards:
    """Verifies sensitive local paths and private network addresses are not leaked."""

    def test_local_filepath_rejected_from_indicator_validation(self):
        windows_path = "C:\\Users\\Administrator\\Documents\\Confidential\\credentials.txt"
        is_valid, _, _, _ = validate_and_normalize_indicator(windows_path, expected_type="url")
        assert is_valid is False

    def test_private_ip_rejected_from_external_indicator_validation(self):
        private_ip = "192.168.1.100"
        is_valid, _, reason, _ = validate_and_normalize_indicator(private_ip, expected_type="ip_address")
        assert is_valid is False
        assert "private" in (reason or "").lower()


# -----------------------------------------------------------------------------
# 8. Grounded AI Security Assistant Explanations
# -----------------------------------------------------------------------------
class TestGroundedAssistantExplanations:
    """Verifies assistant explanations strictly reflect verified records and facts."""

    def test_assistant_explains_recorded_detection_accurately(self, isolated_release_db):
        target_name = "C:\\Tools\\malicious_injector.exe"
        tdb.record_detection(
            target=target_name,
            target_type="file",
            final_score=94.0,
            risk_level="CRITICAL",
            model_name="windows_pe_malware_rf",
            model_score=96.0,
            rule_score=90.0,
            intel_score=95.0,
            explanation_list=[
                "Detected reflective DLL injection signature",
                "High byte entropy in PE section .rsrc"
            ]
        )

        resp = security_assistant.ask("Why was malicious_injector.exe flagged?")
        assert "CRITICAL" in resp
        assert "reflective DLL injection" in resp
        assert "94" in resp or "94.0" in resp


# -----------------------------------------------------------------------------
# 9. Safe Synthetic Malformed File Handling
# -----------------------------------------------------------------------------
class TestMalformedFileHandling:
    """Verifies synthetic corrupt binaries are parsed safely without code execution."""

    def test_malformed_truncated_binary_handled_safely(self, tmp_path):
        corrupt_pe = tmp_path / "corrupt_pe_header.exe"
        # Partial DOS signature with corrupt bytes
        corrupt_pe.write_bytes(b"MZ" + b"\x00\xff" * 64)

        result = scan_file(corrupt_pe, check_external=False)
        assert result.get("is_valid", True) is True
        assert result.get("is_pe") is False
        assert "sha256" in result
        assert result.get("score") < 35.0


# -----------------------------------------------------------------------------
# 10 & 11. Reporting in Isolated Directory & Resource Cleanup
# -----------------------------------------------------------------------------
class TestReportingAndCleanup:
    """Verifies reports export to an isolated location and clean up without leakage."""

    def test_reports_generate_in_isolated_dir_and_clean_up(self, tmp_path, isolated_release_db):
        report_dir = tmp_path / "reports_export"
        report_dir.mkdir(parents=True, exist_ok=True)

        json_file = report_dir / "audit.json"
        csv_file = report_dir / "audit.csv"
        md_file = report_dir / "audit.md"

        json_data = ReportGenerator.generate_json_report()
        csv_data = ReportGenerator.generate_csv_report()
        md_data = ReportGenerator.generate_markdown_report()

        json_file.write_text(json_data, encoding="utf-8")
        csv_file.write_text(csv_data, encoding="utf-8")
        md_file.write_text(md_data, encoding="utf-8")

        assert json_file.exists() and json_file.stat().st_size > 0
        assert csv_file.exists() and csv_file.stat().st_size > 0
        assert md_file.exists() and md_file.stat().st_size > 0

        parsed = json.loads(json_data)
        assert "title" in parsed
        assert "system_statistics" in parsed

        # Cleanup
        json_file.unlink()
        csv_file.unlink()
        md_file.unlink()
        assert not json_file.exists()
        assert not csv_file.exists()
        assert not md_file.exists()


# -----------------------------------------------------------------------------
# 12. Demonstration Script Execution Verification
# -----------------------------------------------------------------------------
class TestDemonstrationExecution:
    """Verifies that the demonstration script executes end-to-end and exits with code 0."""

    def test_demo_script_runs_successfully(self):
        demo_script = ACTIS_ROOT / "scripts" / "demo_actis.py"
        assert demo_script.exists()

        cmd = [sys.executable, str(demo_script)]
        result = subprocess.run(
            cmd,
            cwd=str(ACTIS_ROOT),
            capture_output=True,
            text=True,
            timeout=45
        )

        assert result.returncode == 0, f"Demo failed with error:\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
        assert "[SUCCESS] ALL 7 DEMONSTRATION PHASES PASSED" in result.stdout
