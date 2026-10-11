"""
ACTIS Notification System
Manages cybersecurity alerts, formatters, and dispatching to desktop UI and logs.
Follows safe principles: alerts user with explanations and safe recommendations;
never performs automated destructive actions.
"""

from datetime import datetime
from typing import Dict, Any, List, Optional
from config.config import get_logger

logger = get_logger("Notifier")


class NotificationManager:
    """Manages active threat notifications, alert history, and native desktop toasts."""

    _instance = None

    def __new__(cls, toast_notifier: Optional[Any] = None):
        if cls._instance is None:
            cls._instance = super(NotificationManager, cls).__new__(cls)
            cls._instance.alerts = []
            from notifications.windows_toast import windows_toast
            cls._instance.toast_notifier = toast_notifier or windows_toast
        return cls._instance

    def set_toast_notifier(self, toast_notifier: Any) -> None:
        """Configures or replaces the active toast notification provider."""
        self.toast_notifier = toast_notifier

    def get_toast_notifier(self) -> Any:
        """Returns the active toast notification provider."""
        return getattr(self, "toast_notifier", None)

    def notify_threat(
        self,
        target: str,
        target_type: str,
        risk_level: str,
        score: float,
        reasons: List[str],
        recommended_action: str
    ) -> Dict[str, Any]:
        """Creates, formats, logs, stores, and dispatches a security notification."""
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        alert = {
            "id": len(self.alerts) + 1,
            "timestamp": now_str,
            "target": target,
            "target_type": target_type,
            "risk_level": risk_level,
            "score": score,
            "reasons": reasons,
            "recommended_action": recommended_action,
            "read": False
        }

        self.alerts.append(alert)
        if len(self.alerts) > 100:
            self.alerts.pop(0)

        # Log formatted alert
        logger.warning(
            f"SECURITY ALERT [{risk_level} - {score}/100] on {target_type.upper()}: {target} | "
            f"Action: {recommended_action}"
        )

        # Dispatch native toast for HIGH and CRITICAL security events asynchronously
        if self.toast_notifier is not None and str(risk_level).upper() in ("HIGH", "CRITICAL"):
            try:
                self.toast_notifier.notify_threat_event(alert)
            except Exception as e:
                logger.warning(f"Failed to dispatch desktop toast notification: {e}")

        return alert

    def get_unread_alerts(self) -> List[Dict[str, Any]]:
        """Returns list of unread alerts."""
        return [a for a in self.alerts if not a["read"]]

    def mark_all_read(self):
        """Marks all alerts as read."""
        for a in self.alerts:
            a["read"] = True

    def get_all_alerts(self) -> List[Dict[str, Any]]:
        """Returns all recorded alerts in reverse chronological order."""
        return list(reversed(self.alerts))


notifier = NotificationManager()
