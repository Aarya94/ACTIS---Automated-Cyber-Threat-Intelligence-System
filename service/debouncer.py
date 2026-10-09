"""
ACTIS Filesystem Event Debouncer & Coalescer
Consolidates rapid, repetitive Windows filesystem events (e.g. multiple write chunks,
creation followed immediately by modifications) into a single stabilized SecurityEvent.

CRITICAL ARCHITECTURAL POLICY:
Debouncing ensures that one logical file save/download produces exactly one analysis task.
Uses non-blocking timers and file-write stability verification to prevent race conditions.
"""

import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from service.events import SecurityEventType
from service.file_normalizer import NormalizedFileEvent
from scanners.file_watcher import wait_until_file_stable
from config.config import get_logger

logger = get_logger("FileDebouncer")


@dataclass
class _DebounceRecord:
    """Internal record tracking coalescing state for an individual file path."""
    path: str
    event_type: SecurityEventType
    previous_path: Optional[str]
    first_seen: float
    last_seen: float
    event_count: int
    timer: Optional[threading.Timer] = None


class FileEventDebouncer:
    """
    Thread-safe debouncer that suppresses duplicate rapid events on the same path,
    waits for file write locks to release, and emits a single consolidated event.
    """

    def __init__(
        self,
        debounce_seconds: float = 1.0,
        stability_check: bool = True,
        stability_timeout: float = 4.0,
        on_stable_event: Optional[Callable[[NormalizedFileEvent], None]] = None,
    ):
        self.debounce_seconds = max(0.05, debounce_seconds)
        self.stability_check = stability_check
        self.stability_timeout = max(0.5, stability_timeout)
        self.on_stable_event = on_stable_event

        self._lock = threading.Lock()
        self._records: Dict[str, _DebounceRecord] = {}
        self._is_stopped = False

        # Telemetry
        self._events_received = 0
        self._events_coalesced = 0
        self._events_emitted = 0
        self._events_dropped_unstable = 0

    def start(self) -> None:
        """Starts or resets the debouncer to active state."""
        with self._lock:
            self._is_stopped = False

    def submit(self, event: NormalizedFileEvent) -> None:
        """Alias for add_event."""
        self.add_event(event)

    def add_event(self, event: NormalizedFileEvent) -> None:
        """
        Ingests a normalized filesystem event into the debounce pipeline.
        Resets or schedules the debounce timer for the event path.
        """
        with self._lock:
            if self._is_stopped:
                logger.warning(f"FileEventDebouncer: Received event for '{event.path}' after stop(). Ignored.")
                return

            self._events_received += 1
            path_key = event.path

            # Handling file deletions: immediately cancel any pending write debounce
            if event.event_type == SecurityEventType.FILE_DELETED:
                if path_key in self._records:
                    rec = self._records.pop(path_key)
                    if rec.timer:
                        rec.timer.cancel()
                    self._events_coalesced += rec.event_count

                # Emit deleted event immediately if callback configured
                self._events_emitted += 1
                if self.on_stable_event:
                    try:
                        self.on_stable_event(event)
                    except Exception as ex:
                        logger.error(f"FileEventDebouncer: Error in on_stable_event callback: {ex}")
                return

            # Handling created / modified / renamed
            now = time.time()
            if path_key in self._records:
                record = self._records[path_key]
                if record.timer:
                    record.timer.cancel()
                record.event_count += 1
                record.last_seen = now
                self._events_coalesced += 1

                # If originally FILE_CREATED, retain FILE_CREATED semantics even if followed by FILE_MODIFIED
                if record.event_type != SecurityEventType.FILE_CREATED:
                    record.event_type = event.event_type

                if event.previous_path:
                    record.previous_path = event.previous_path
            else:
                record = _DebounceRecord(
                    path=path_key,
                    event_type=event.event_type,
                    previous_path=event.previous_path,
                    first_seen=now,
                    last_seen=now,
                    event_count=1,
                )
                self._records[path_key] = record

            # Schedule timer for emission
            timer = threading.Timer(self.debounce_seconds, self._on_timer_fired, args=[path_key])
            timer.daemon = True
            record.timer = timer
            timer.start()

    def _on_timer_fired(self, path_key: str) -> None:
        """Invoked when the debounce window expires for a given path."""
        with self._lock:
            if self._is_stopped or path_key not in self._records:
                return
            record = self._records.pop(path_key)

        path_obj = Path(record.path)

        # Check write-stability if file exists
        if self.stability_check:
            is_stable = wait_until_file_stable(path_obj, timeout=self.stability_timeout)
            if not is_stable:
                with self._lock:
                    self._events_dropped_unstable += 1
                logger.warning(
                    f"FileEventDebouncer: File '{record.path}' did not stabilize or was deleted "
                    f"within {self.stability_timeout}s timeout. Dropping event."
                )
                return

        # Build consolidated NormalizedFileEvent
        consolidated = NormalizedFileEvent(
            event_type=record.event_type,
            path=record.path,
            previous_path=record.previous_path,
            timestamp=record.last_seen,
            metadata={
                "debounced": True,
                "coalesced_event_count": record.event_count,
                "debounce_window_seconds": round(record.last_seen - record.first_seen, 3),
            },
        )

        with self._lock:
            self._events_emitted += 1

        if self.on_stable_event:
            try:
                self.on_stable_event(consolidated)
            except Exception as ex:
                logger.error(f"FileEventDebouncer: Exception in on_stable_event callback: {ex}", exc_info=True)

    def flush(self) -> int:
        """
        Immediately fires all pending timers and emits stabilized events.
        Returns the number of flushed events.
        """
        with self._lock:
            pending = list(self._records.values())
            self._records.clear()

        flushed = 0
        for record in pending:
            if record.timer:
                record.timer.cancel()

            consolidated = NormalizedFileEvent(
                event_type=record.event_type,
                path=record.path,
                previous_path=record.previous_path,
                timestamp=record.last_seen,
                metadata={
                    "debounced": True,
                    "coalesced_event_count": record.event_count,
                    "flushed_early": True,
                },
            )
            flushed += 1
            with self._lock:
                self._events_emitted += 1
            if self.on_stable_event:
                try:
                    self.on_stable_event(consolidated)
                except Exception as ex:
                    logger.error(f"FileEventDebouncer flush callback error: {ex}")

        return flushed

    def stop(self) -> None:
        """Cancels all active debounce timers and terminates the debouncer."""
        with self._lock:
            self._is_stopped = True
            for record in self._records.values():
                if record.timer:
                    record.timer.cancel()
            self._records.clear()
            logger.info("FileEventDebouncer stopped cleanly; all pending timers cancelled.")

    def pending_count(self) -> int:
        """Returns the number of currently active debounce timers."""
        with self._lock:
            return len(self._records)

    def get_stats(self) -> Dict[str, Any]:
        """Returns operational metrics for debouncing and coalescing."""
        with self._lock:
            return {
                "events_received": self._events_received,
                "events_coalesced": self._events_coalesced,
                "events_emitted": self._events_emitted,
                "events_dropped_unstable": self._events_dropped_unstable,
                "pending_count": len(self._records),
            }
