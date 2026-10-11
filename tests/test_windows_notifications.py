"""
Unit and Integration Tests for ACTIS Windows Native Toast Notifications
Validates async non-blocking dispatch, secret redaction, rate limiting,
crash resilience, silent test mode, and integration with NotificationManager and FileProtectionPipeline.
"""

import time
import pytest
from unittest.mock import MagicMock, patch
from pathlib import Path

from notifications.windows_toast import (
    WindowsToastNotifier,
    sanitize_notification_text,
    get_powershell_executable,
)
from notifications.notifier import NotificationManager, notifier
from service.file_pipeline import FileProtectionPipeline, EventProcessingStatus
from service.events import SecurityEvent, SecurityEventType


class TestNotificationSanitization:
    """Tests secret redaction, length bounds, and XML escaping in toast notifications."""

    def test_sanitize_empty_text(self):
        assert sanitize_notification_text("") == ""
        assert sanitize_notification_text(None) == ""

    def test_sanitize_xml_special_characters(self):
        raw = "Threat detected: <script>alert('xss')</script> & \"quotes\""
        sanitized = sanitize_notification_text(raw)
        assert "<" not in sanitized
        assert ">" not in sanitized
        assert "&lt;" in sanitized
        assert "&gt;" in sanitized
        assert "&amp;" in sanitized
        assert "&quot;" in sanitized

    def test_sanitize_redacts_api_keys_and_tokens(self):
        # API key prefixed token
        fake_api_key = "a" * 64
        raw = f"Scanner error with api_key: {fake_api_key} on target"
        sanitized = sanitize_notification_text(raw)
        assert fake_api_key not in sanitized
        assert "****" in sanitized

    def test_sanitize_bounds_length(self):
        long_text = "A" * 500
        sanitized = sanitize_notification_text(long_text, max_length=100)
        assert len(sanitized) <= 100
        assert sanitized.endswith("...")


class TestWindowsToastNotifier:
    """Tests core WindowsToastNotifier lifecycle, non-blocking execution, and flood protection."""

    @pytest.fixture
    def test_notifier(self):
        n = WindowsToastNotifier(
            cooldown_seconds=1.0,
            test_mode=True,  # Test mode strictly prevents OS popups
        )
        yield n
        n.shutdown(wait=False)

    def test_toast_dispatch_is_non_blocking(self, test_notifier):
        """Verifies send_toast returns immediately (< 50ms) via async executor."""
        start = time.perf_counter()
        accepted = test_notifier.send_toast(
            title="Fast Alert",
            message="Testing async dispatch",
            risk_level="HIGH",
            target="C:\\test\\malware.exe",
        )
        duration = time.perf_counter() - start
        assert accepted is True
        assert duration < 0.05, f"Dispatch took too long: {duration:.4f}s"

    def test_test_mode_records_history(self, test_notifier):
        test_notifier.send_toast(
            title="Recorded Toast",
            message="Should appear in history",
            risk_level="CRITICAL",
            target="C:\\path\\evil.dll",
            synchronous=True,
        )
        history = test_notifier.get_history()
        assert len(history) == 1
        assert history[0]["title"] == "Recorded Toast"
        assert history[0]["risk_level"] == "CRITICAL"
        assert history[0]["test_mode"] is True

        telemetry = test_notifier.get_telemetry()
        assert telemetry["total_dispatched"] == 1
        assert telemetry["total_suppressed"] == 0

    def test_rate_limiting_suppresses_rapid_duplicate_toasts(self, test_notifier):
        target = "C:\\Windows\\Temp\\repeated_payload.exe"
        # First toast should succeed
        assert test_notifier.send_toast("Alert 1", "Msg 1", target=target, synchronous=True) is True
        # Second toast for the same target within 1.0s should be suppressed
        assert test_notifier.send_toast("Alert 2", "Msg 2", target=target, synchronous=True) is False

        telemetry = test_notifier.get_telemetry()
        assert telemetry["total_dispatched"] == 1
        assert telemetry["total_suppressed"] == 1

        # Clear history resets rate limit
        test_notifier.clear_history()
        assert test_notifier.send_toast("Alert 3", "Msg 3", target=target, synchronous=True) is True

    def test_notify_threat_event_labeling(self, test_notifier):
        # High confidence alert
        high_alert = {
            "target": "C:\\malware\\ransomware.exe",
            "risk_level": "HIGH",
            "score": 88.0,
            "reasons": ["Dangerous API combination", "High entropy section"],
            "recommended_action": "Quarantine candidate indicator immediately.",
        }
        test_notifier.notify_threat_event(high_alert, synchronous=True)
        rec = test_notifier.get_history()[-1]
        assert "ACTIS Security Alert: HIGH Risk" in rec["title"]
        assert "ransomware.exe" in rec["message"]

        # Medium / Suspicious activity
        med_alert = {
            "target": "C:\\suspicious\\script.bat",
            "risk_level": "MEDIUM",
            "score": 45.0,
            "reasons": ["Unusual batch commands"],
            "recommended_action": "Inspect script manually.",
        }
        test_notifier.notify_threat_event(med_alert, synchronous=True)
        rec = test_notifier.get_history()[-1]
        assert "ACTIS Notice: MEDIUM Risk" in rec["title"]

    def test_powershell_failure_isolated_safely(self, test_notifier):
        """Validates that underlying OS or PowerShell exceptions do not crash dispatch."""
        test_notifier.test_mode = False  # Enable real execution path
        with patch.object(test_notifier, "_show_windows_toast_native", side_effect=RuntimeError("Simulated OS failure")):
            # Must not raise RuntimeError
            result = test_notifier.send_toast("Crash Test", "Should catch error", synchronous=True)
            assert result is False

        telemetry = test_notifier.get_telemetry()
        assert telemetry["total_failed"] == 1


class TestNotificationManagerIntegration:
    """Tests integration between NotificationManager and WindowsToastNotifier."""

    def test_notification_manager_triggers_toast_for_high_risk(self):
        custom_toast = WindowsToastNotifier(test_mode=True, cooldown_seconds=0.0)
        mgr = NotificationManager(toast_notifier=custom_toast)
        mgr.set_toast_notifier(custom_toast)

        # Notify high risk threat
        alert = mgr.notify_threat(
            target="C:\\evil\\trojan.exe",
            target_type="file",
            risk_level="HIGH",
            score=95.0,
            reasons=["Known trojan signature"],
            recommended_action="Do not execute.",
        )
        assert alert["id"] > 0
        time.sleep(0.05)  # Allow async executor worker to complete
        history = custom_toast.get_history()
        assert len(history) >= 1
        assert "HIGH Risk" in history[-1]["title"]
        custom_toast.shutdown(wait=False)

    def test_notification_manager_skips_toast_for_low_risk(self):
        custom_toast = WindowsToastNotifier(test_mode=True, cooldown_seconds=0.0)
        mgr = NotificationManager(toast_notifier=custom_toast)
        mgr.set_toast_notifier(custom_toast)
        custom_toast.clear_history()

        mgr.notify_threat(
            target="C:\\clean\\notepad.exe",
            target_type="file",
            risk_level="LOW",
            score=10.0,
            reasons=["Clean PE"],
            recommended_action="No action needed.",
        )
        time.sleep(0.05)
        assert len(custom_toast.get_history()) == 0
        custom_toast.shutdown(wait=False)


class TestFileProtectionPipelineNotificationHandoff:
    """Tests that FileProtectionPipeline dispatches threat alerts when threats are found."""

    def test_pipeline_dispatches_notification_on_threat(self, tmp_path):
        mock_notifier = MagicMock()
        target_file = tmp_path / "threat_sample.exe"
        target_file.write_bytes(b"MZ" + b"\x00" * 200)

        fake_analysis = {
            "is_threat": True,
            "score": 90.0,
            "risk_level": "CRITICAL",
            "reasons": ["Simulated ransomware behavior"],
            "recommended_action": "Isolate file.",
            "sha256": "abcdef1234567890",
        }

        pipeline = FileProtectionPipeline(
            analysis_fn=lambda p: fake_analysis,
            notifier=mock_notifier,
        )

        event = SecurityEvent(
            event_type=SecurityEventType.FILE_CREATED,
            source="FileSystemWatcher",
            target=str(target_file),
        )

        result = pipeline.process_file_event(event)
        assert result.status == EventProcessingStatus.ANALYZED
        assert result.is_threat is True

        mock_notifier.notify_threat.assert_called_once_with(
            target=str(target_file.resolve()),
            target_type="file",
            risk_level="CRITICAL",
            score=90.0,
            reasons=["Simulated ransomware behavior"],
            recommended_action="Isolate file.",
        )
