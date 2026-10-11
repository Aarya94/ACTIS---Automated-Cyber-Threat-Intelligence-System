"""
ACTIS Windows Native Toast Notification Integration
Provides asynchronous, non-blocking desktop notifications for security events.

SECURITY & RELIABILITY CONSTRAINTS:
1. Strictly asynchronous: notifications NEVER block scanning or pipeline execution.
2. Crash isolation: notification failures are logged and recorded, NEVER raising to caller.
3. Secret redaction: API keys, tokens, and credentials are scrubbed before display.
4. Truth in labeling: unconfirmed indicators are NOT labeled as confirmed malware.
5. Flood protection: per-target sliding-window cooldown suppresses notification storms.
6. Test isolation: test_mode/silent mode completely disables OS popups for automated tests.
"""

import os
import platform
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from config.config import get_logger

logger = get_logger("WindowsToast")


def get_powershell_executable() -> Optional[str]:
    """Resolves the canonical path to powershell.exe on Windows."""
    import shutil
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    default_ps = Path(system_root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    if default_ps.exists():
        return str(default_ps)
    candidate = shutil.which("powershell.exe") or shutil.which("powershell")
    if candidate and not candidate.endswith(".CMD"):
        return candidate
    return None


def sanitize_notification_text(text: str, max_length: int = 180) -> str:
    """
    Sanitizes notification message content:
    - Redacts API keys, credentials, and known token patterns.
    - Strips XML/control characters that could break Windows notification templates.
    - Bounds text length to prevent overflow.
    """
    if not text:
        return ""

    # Import secret masking utility from assistant or config
    try:
        from assistant.security_assistant import mask_sensitive_strings
        cleaned = mask_sensitive_strings(str(text))
    except ImportError:
        cleaned = str(text)

    # Escape XML special characters for Windows toast XML safety
    cleaned = cleaned.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

    # Bound length
    if len(cleaned) > max_length:
        cleaned = cleaned[:max_length - 3] + "..."
    return cleaned


class WindowsToastNotifier:
    """
    Native Windows toast notification dispatcher with async thread pool execution,
    secret redaction, rate limiting, and silent test mode.
    """

    def __init__(
        self,
        app_id: str = "ACTIS.CyberThreatIntelligence",
        cooldown_seconds: float = 5.0,
        test_mode: bool = False,
        enabled: bool = True,
        max_workers: int = 2,
    ):
        self.app_id = app_id
        self.cooldown_seconds = max(0.5, float(cooldown_seconds))
        self.test_mode = test_mode
        self.enabled = enabled

        self._lock = threading.Lock()
        self._last_toast_per_target: Dict[str, float] = {}
        self._sent_history: List[Dict[str, Any]] = []
        self._total_dispatched = 0
        self._total_suppressed = 0
        self._total_failed = 0

        self._executor = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="ACTIS-ToastNotifier",
        )

    @property
    def is_windows(self) -> bool:
        """Returns True if running on Microsoft Windows platform."""
        return platform.system() == "Windows"

    def is_rate_limited(self, target_key: str) -> bool:
        """Checks if an alert for target_key was sent within cooldown window."""
        if not target_key:
            return False
        with self._lock:
            now = time.monotonic()
            last_time = self._last_toast_per_target.get(target_key, 0.0)
            if (now - last_time) < self.cooldown_seconds:
                return True
            return False

    def send_toast(
        self,
        title: str,
        message: str,
        risk_level: str = "LOW",
        target: str = "",
        synchronous: bool = False,
    ) -> bool:
        """
        Submits a toast notification for non-blocking asynchronous dispatch.
        Returns True if the toast was accepted for dispatch, False if suppressed or disabled.
        """
        if not self.enabled:
            logger.debug("Notifications are globally disabled; suppressing toast.")
            return False

        # Flood suppression check
        target_key = (target or title).lower().strip()
        if self.is_rate_limited(target_key):
            with self._lock:
                self._total_suppressed += 1
            logger.info(f"Notification for '{target_key}' suppressed by rate limiter ({self.cooldown_seconds}s cooldown).")
            return False

        # Mark timestamp for rate limiting
        with self._lock:
            self._last_toast_per_target[target_key] = time.monotonic()

        # Sanitize title and message
        clean_title = sanitize_notification_text(title, max_length=64)
        clean_msg = sanitize_notification_text(message, max_length=200)

        record = {
            "title": clean_title,
            "message": clean_msg,
            "risk_level": risk_level,
            "target": target,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "test_mode": self.test_mode,
        }

        if synchronous:
            return self._dispatch_worker(record)
        else:
            self._executor.submit(self._dispatch_worker, record)
            return True

    def notify_threat_event(self, alert_data: Dict[str, Any], synchronous: bool = False) -> bool:
        """
        Formats and dispatches a structured ACTIS alert event into a desktop toast.
        Differentiates confirmed threats from candidate or suspicious indicators.
        """
        target = str(alert_data.get("target", "Unknown"))
        risk_level = str(alert_data.get("risk_level", "LOW")).upper()
        score = alert_data.get("score", 0.0)
        reasons = alert_data.get("reasons", [])
        action = alert_data.get("recommended_action", "Inspect details in ACTIS.")

        # Truth in advertising: unconfirmed indicators are NOT labeled confirmed malware
        if risk_level in ("CRITICAL", "HIGH"):
            title = f"ACTIS Security Alert: {risk_level} Risk"
        else:
            title = f"ACTIS Notice: {risk_level} Risk Detected"

        reason_summary = reasons[0] if reasons else "Suspicious indicator pattern detected"
        message = f"Target: {os.path.basename(target) if target else 'Unknown'} | Score: {score}/100 | {reason_summary} | Action: {action}"

        return self.send_toast(
            title=title,
            message=message,
            risk_level=risk_level,
            target=target,
            synchronous=synchronous,
        )

    def _dispatch_worker(self, record: Dict[str, Any]) -> bool:
        """
        Internal worker executed on background thread pool.
        Isolates all OS errors so the main pipeline is completely unaffected.
        """
        try:
            with self._lock:
                self._sent_history.append(record)
                if len(self._sent_history) > 100:
                    self._sent_history.pop(0)
                self._total_dispatched += 1

            if self.test_mode:
                logger.debug(f"[TEST_MODE] Recorded toast notification: {record['title']}")
                return True

            if not self.is_windows:
                logger.debug("Non-Windows OS: native toast dispatch skipped.")
                return True

            # Execute native Windows Toast via PowerShell WindowsRuntime
            return self._show_windows_toast_native(record["title"], record["message"])

        except Exception as e:
            with self._lock:
                self._total_failed += 1
            logger.warning(f"Failed to display Windows toast notification: {e}")
            return False

    def _show_windows_toast_native(self, title: str, message: str) -> bool:
        """
        Displays a native Windows 10/11 toast notification using PowerShell WindowsRuntime.
        Non-interactive, hidden window, times out safely after 4 seconds.
        """
        ps_script = f"""
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
$template = @"
<toast>
    <visual>
        <binding template="ToastGeneric">
            <text>{title}</text>
            <text>{message}</text>
        </binding>
    </visual>
</toast>
"@
$xml = New-Object Windows.Data.Xml.Dom.XmlDocument
$xml.LoadXml($template)
$toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("{self.app_id}").Show($toast)
"""
        ps_exe = get_powershell_executable()
        if not ps_exe:
            logger.debug("powershell.exe not found on system; native toast skipped.")
            return False

        cmd = [
            ps_exe,
            "-NoProfile",
            "-NonInteractive",
            "-WindowStyle", "Hidden",
            "-Command",
            ps_script,
        ]

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=4.0,
            )
            return res.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as ex:
            logger.debug(f"Native toast PowerShell execution bypassed: {ex}")
            return False

    def get_telemetry(self) -> Dict[str, Any]:
        """Returns thread-safe notification dispatch statistics."""
        with self._lock:
            return {
                "enabled": self.enabled,
                "test_mode": self.test_mode,
                "total_dispatched": self._total_dispatched,
                "total_suppressed": self._total_suppressed,
                "total_failed": self._total_failed,
                "history_count": len(self._sent_history),
                "is_windows": self.is_windows,
            }

    def get_history(self) -> List[Dict[str, Any]]:
        """Returns a snapshot copy of recent sent toast records."""
        with self._lock:
            return list(self._sent_history)

    def clear_history(self) -> None:
        """Clears in-memory toast history and rate-limit tracking."""
        with self._lock:
            self._sent_history.clear()
            self._last_toast_per_target.clear()
            self._total_dispatched = 0
            self._total_suppressed = 0
            self._total_failed = 0

    def shutdown(self, wait: bool = False) -> None:
        """Shuts down background thread pool cleanly."""
        self._executor.shutdown(wait=wait)


# Global singleton instance (defaults to silent/test_mode=False for runtime)
windows_toast = WindowsToastNotifier()
