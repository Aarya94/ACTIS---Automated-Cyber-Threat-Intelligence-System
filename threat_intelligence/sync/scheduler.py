"""
ACTIS Scheduled Threat Intelligence Synchronization
Background scheduler managing periodic threat feed updates with graceful shutdown,
duplicate start protection, configurable intervals, and non-blocking job execution.
"""

import threading
import time
from datetime import datetime, timezone
from typing import Optional

from threat_intelligence.sync.sync_service import ThreatSyncService, threat_sync_service
from threat_intelligence.sync.sync_models import SyncRunResult
from config.config import (
    TI_SYNC_ENABLED,
    TI_SYNC_INTERVAL_SECONDS,
    get_logger,
)

logger = get_logger("ThreatSyncScheduler")


class ThreatSyncScheduler:
    """
    Manages background scheduled execution of threat intelligence synchronization.
    Guarantees thread-safe lifecycle control, non-blocking job triggers, and graceful stops.
    Never spawns background threads on module import.
    """

    def __init__(
        self,
        sync_service: Optional[ThreatSyncService] = None,
        interval_seconds: Optional[int] = None,
        enabled: Optional[bool] = None,
    ):
        self.service = sync_service or threat_sync_service
        self.interval = interval_seconds or TI_SYNC_INTERVAL_SECONDS or 21600
        self.enabled = enabled if enabled is not None else TI_SYNC_ENABLED

        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._lifecycle_lock = threading.Lock()
        self._is_running = False
        self._last_run_time: Optional[float] = None

    @property
    def is_running(self) -> bool:
        """Returns True if the scheduler background thread is currently active."""
        return self._is_running

    def start(self) -> bool:
        """
        Starts the background scheduling thread if enabled and not already running.
        Returns True if started, False if already running or disabled.
        """
        with self._lifecycle_lock:
            if self._is_running:
                logger.warning("Threat intelligence sync scheduler is already running.")
                return False

            if not self.enabled:
                logger.info("Threat intelligence sync scheduler is disabled by configuration.")
                return False

            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._worker_loop,
                name="ACTIS-ThreatSync-Scheduler",
                daemon=True,
            )
            self._is_running = True
            self._thread.start()
            logger.info(f"Threat intelligence sync scheduler started (interval: {self.interval}s).")
            return True

    def stop(self, timeout: float = 5.0) -> bool:
        """
        Signals the background thread to stop and waits up to timeout seconds.
        Returns True if stopped cleanly.
        """
        with self._lifecycle_lock:
            if not self._is_running:
                return True

            logger.info("Stopping threat intelligence sync scheduler...")
            self._stop_event.set()
            if self._thread and self._thread.is_alive():
                self._thread.join(timeout=timeout)

            self._is_running = False
            self._thread = None
            logger.info("Threat intelligence sync scheduler stopped.")
            return True

    def trigger_sync_now(self) -> SyncRunResult:
        """Manually triggers an immediate synchronization cycle."""
        logger.info("Manual threat intelligence sync triggered via scheduler.")
        self._last_run_time = time.time()
        return self.service.sync_all()

    def _worker_loop(self) -> None:
        """Internal daemon loop executing periodic sync cycles."""
        logger.debug("Threat intelligence sync worker loop initialized.")

        # Wait initial short jitter (e.g. 2s) to allow app startup to settle
        if self._stop_event.wait(timeout=2.0):
            return

        while not self._stop_event.is_set():
            try:
                logger.info("Executing scheduled threat intelligence synchronization cycle.")
                self._last_run_time = time.time()
                self.service.sync_all()
            except Exception as e:
                logger.error(f"Error during scheduled threat intelligence synchronization: {e}")

            # Wait for configured interval or stop event
            if self._stop_event.wait(timeout=float(self.interval)):
                break

        self._is_running = False
        logger.debug("Threat intelligence sync worker loop terminated.")


# Global singleton instance (dormant until explicit start())
threat_sync_scheduler = ThreatSyncScheduler()
