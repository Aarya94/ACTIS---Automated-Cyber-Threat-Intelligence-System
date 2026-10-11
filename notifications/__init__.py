"""
ACTIS Notification System Package
Desktop threat alerts and Windows native toast notification dispatching.
"""

from notifications.notifier import NotificationManager, notifier
from notifications.windows_toast import WindowsToastNotifier, windows_toast

__all__ = [
    "NotificationManager",
    "notifier",
    "WindowsToastNotifier",
    "windows_toast",
]
