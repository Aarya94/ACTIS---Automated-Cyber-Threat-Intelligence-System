"""
ACTIS Windows Service Host & Service Control Manager (SCM) Boundary
Provides the Windows Service hosting adapter, Service Control Manager handler hooks,
and safe standalone/interactive execution for the ACTIS Protection Service.

SECURITY & PERSISTENCE NOTICE:
1. ACTIS uses only legitimate Windows Service infrastructure.
2. NO registry run keys, scheduled tasks, or stealth persistence mechanisms are used.
3. Actual Windows Service registration (SCM registration via sc.exe or pywin32) is a
   controlled deployment action requiring administrative privileges.
4. When pywin32 is not installed or when running in development/user mode, this module
   provides full lifecycle execution via standalone interactive hosting.
"""

import os
import signal
import sys
import threading
import time
from typing import Any, Dict, List, Optional

from service.lifecycle import ServiceState
from service.config import ServiceConfig, get_default_service_config
from service.protection_service import ProtectionService
from config.config import get_logger

logger = get_logger("WindowsServiceHost")

# Optional pywin32 detection
try:
    import win32service
    import win32serviceutil
    import win32event
    import servicemanager
    PYWIN32_AVAILABLE = True
except ImportError:
    PYWIN32_AVAILABLE = False
    win32service = None
    win32serviceutil = None
    win32event = None
    servicemanager = None


class WindowsServiceHost:
    """
    Host manager and SCM control bridge for the ACTIS Protection Service.
    Translates Windows SCM control codes into ProtectionService lifecycle calls.
    """

    def __init__(
        self,
        service: Optional[ProtectionService] = None,
        config: Optional[ServiceConfig] = None,
    ):
        self.config = config or get_default_service_config()
        self.service = service or ProtectionService(config=self.config)
        self._stop_requested = threading.Event()

    @property
    def is_pywin32_available(self) -> bool:
        """Returns True if pywin32 Windows Service modules are available."""
        return PYWIN32_AVAILABLE

    def handle_scm_control_stop(self) -> bool:
        """Called by Windows SCM when SERVICE_CONTROL_STOP is signaled."""
        logger.info("SCM control: SERVICE_CONTROL_STOP received.")
        self._stop_requested.set()
        return self.service.stop()

    def handle_scm_control_pause(self) -> bool:
        """Called by Windows SCM when SERVICE_CONTROL_PAUSE is signaled."""
        logger.info("SCM control: SERVICE_CONTROL_PAUSE received.")
        return self.service.pause()

    def handle_scm_control_continue(self) -> bool:
        """Called by Windows SCM when SERVICE_CONTROL_CONTINUE is signaled."""
        logger.info("SCM control: SERVICE_CONTROL_CONTINUE received.")
        return self.service.resume()

    def handle_scm_control_interrogate(self) -> Dict[str, Any]:
        """Called by Windows SCM or diagnostics to query current service health."""
        return self.service.get_health().to_dict()

    def run_standalone(self, poll_interval: float = 0.5) -> int:
        """
        Runs the protection service interactively in console / non-SCM mode.
        Captures SIGINT (Ctrl+C) and SIGTERM for graceful shutdown.
        Returns process exit code (0 for clean stop, 1 for failure).
        """
        logger.info(
            f"Starting ACTIS Protection Service in standalone host mode "
            f"[PID: {os.getpid()}]..."
        )

        def _signal_handler(signum, frame):
            sig_name = "SIGINT" if signum == signal.SIGINT else f"Signal {signum}"
            logger.info(f"Received {sig_name}. Initiating graceful shutdown...")
            self._stop_requested.set()

        # Register signals where supported
        try:
            signal.signal(signal.SIGINT, _signal_handler)
            if hasattr(signal, "SIGTERM"):
                signal.signal(signal.SIGTERM, _signal_handler)
        except (ValueError, AttributeError):
            pass

        started = self.service.start()
        if not started:
            logger.error("Failed to start ProtectionService in standalone mode.")
            return 1

        try:
            while not self._stop_requested.is_set():
                if not self.service.is_running():
                    state = self.service.get_state()
                    if state == ServiceState.FAILED:
                        logger.error("ProtectionService entered FAILED state. Exiting host loop.")
                        return 1
                    break
                time.sleep(poll_interval)
        except KeyboardInterrupt:
            logger.info("KeyboardInterrupt received.")
        finally:
            self.service.stop()

        return 0


def create_windows_host(
    config: Optional[ServiceConfig] = None,
) -> WindowsServiceHost:
    """Factory creating an initialized WindowsServiceHost instance."""
    cfg = config or get_default_service_config()
    service = ProtectionService(config=cfg)
    return WindowsServiceHost(service=service, config=cfg)
