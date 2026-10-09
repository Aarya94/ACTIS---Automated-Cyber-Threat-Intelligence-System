"""
ACTIS Protection Service Security Event Boundary Contract
Defines the canonical SecurityEvent schema, event types, validation rules,
and thread-safe event queuing for the ACTIS event-driven architecture.

IMPORTANT: This module defines only the event schema and intake boundary contract.
It does NOT generate OS filesystem events or execute detection logic.
"""

import queue
import threading
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional

from config.config import get_logger

logger = get_logger("ServiceEvents")


class SecurityEventType(str, Enum):
    """
    Canonical security event types supported by ACTIS.
    These represent future event sources that will feed the analysis pipeline.
    """
    FILE_CREATED = "FILE_CREATED"
    FILE_MODIFIED = "FILE_MODIFIED"
    FILE_RENAMED = "FILE_RENAMED"
    FILE_DELETED = "FILE_DELETED"
    URL_DETECTED = "URL_DETECTED"
    MESSAGE_RECEIVED = "MESSAGE_RECEIVED"
    MANUAL_SCAN = "MANUAL_SCAN"
    SYSTEM_STARTUP = "SYSTEM_STARTUP"
    SYSTEM_SHUTDOWN = "SYSTEM_SHUTDOWN"


class SecurityEventValidationError(ValueError):
    """Raised when a SecurityEvent fails contract validation."""
    pass


@dataclass
class SecurityEvent:
    """
    Canonical security event contract for the ACTIS intake layer.
    Pure data boundary object: contains no detection or execution logic.
    """
    event_type: SecurityEventType
    source: str
    target: Optional[str] = None
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)
    correlation_id: Optional[str] = None

    def __post_init__(self):
        # Convert string event_type to enum if passed as string
        if isinstance(self.event_type, str) and not isinstance(self.event_type, SecurityEventType):
            try:
                self.event_type = SecurityEventType(self.event_type)
            except ValueError:
                raise SecurityEventValidationError(f"Invalid SecurityEventType: '{self.event_type}'")

    def validate(self) -> None:
        """
        Validates event contract constraints.
        Raises SecurityEventValidationError if constraints are violated.
        """
        if not self.event_id or not isinstance(self.event_id, str) or not self.event_id.strip():
            raise SecurityEventValidationError("event_id must be a non-empty string.")

        if not isinstance(self.event_type, SecurityEventType):
            raise SecurityEventValidationError(
                f"event_type must be an instance of SecurityEventType, got {type(self.event_type).__name__}."
            )

        if not self.source or not isinstance(self.source, str) or not self.source.strip():
            raise SecurityEventValidationError("source must be a non-empty string indicating event origin.")

        if not self.timestamp or not isinstance(self.timestamp, str) or not self.timestamp.strip():
            raise SecurityEventValidationError("timestamp must be a valid ISO-8601 formatted string.")

        if not isinstance(self.metadata, dict):
            raise SecurityEventValidationError("metadata must be a dictionary.")

        # Require target for target-specific event types
        target_requiring_events = {
            SecurityEventType.FILE_CREATED,
            SecurityEventType.FILE_MODIFIED,
            SecurityEventType.FILE_RENAMED,
            SecurityEventType.FILE_DELETED,
            SecurityEventType.URL_DETECTED,
            SecurityEventType.MESSAGE_RECEIVED,
        }
        if self.event_type in target_requiring_events:
            if not self.target or not isinstance(self.target, str) or not self.target.strip():
                raise SecurityEventValidationError(
                    f"Event type '{self.event_type.value}' requires a non-empty target indicator or path."
                )

    def to_dict(self) -> Dict[str, Any]:
        """Serializes event to dictionary representation."""
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "timestamp": self.timestamp,
            "source": self.source,
            "target": self.target,
            "metadata": dict(self.metadata),
            "correlation_id": self.correlation_id,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SecurityEvent":
        """Deserializes event from dictionary with validation."""
        if not isinstance(data, dict):
            raise SecurityEventValidationError("Input data must be a dictionary.")

        raw_type = data.get("event_type")
        if not raw_type:
            raise SecurityEventValidationError("Missing required field: 'event_type'")

        try:
            event_type = SecurityEventType(raw_type)
        except ValueError:
            raise SecurityEventValidationError(f"Invalid SecurityEventType: '{raw_type}'")

        source = data.get("source")
        if not source:
            raise SecurityEventValidationError("Missing required field: 'source'")

        event = cls(
            event_type=event_type,
            source=source,
            target=data.get("target"),
            event_id=data.get("event_id") or str(uuid.uuid4()),
            timestamp=data.get("timestamp") or datetime.now(timezone.utc).isoformat(),
            metadata=data.get("metadata") or {},
            correlation_id=data.get("correlation_id"),
        )
        event.validate()
        return event


class SecurityEventQueue:
    """
    Thread-safe bounded event queue for the ACTIS Protection Service.
    Enforces capacity limits, protects memory, tracks throughput telemetry,
    and supports graceful shutdown non-blocking operations.
    """

    def __init__(self, maxsize: int = 10000):
        self._maxsize = max(10, maxsize)
        self._queue: queue.Queue = queue.Queue(maxsize=self._maxsize)
        self._lock = threading.Lock()
        self._enqueued_count = 0
        self._dequeued_count = 0
        self._dropped_count = 0

    @property
    def maxsize(self) -> int:
        return self._maxsize

    def put(
        self,
        event: SecurityEvent,
        block: bool = True,
        timeout: Optional[float] = 1.0,
    ) -> bool:
        """
        Enqueues a SecurityEvent into the queue.
        Validates event before enqueueing.
        Returns True if enqueued, False if dropped due to capacity limits.
        """
        event.validate()
        try:
            self._queue.put(event, block=block, timeout=timeout)
            with self._lock:
                self._enqueued_count += 1
            return True
        except queue.Full:
            with self._lock:
                self._dropped_count += 1
            logger.warning(
                f"SecurityEventQueue full ({self._queue.qsize()}/{self._maxsize}). "
                f"Dropped event ID: {event.event_id}"
            )
            return False

    def get(
        self,
        block: bool = True,
        timeout: Optional[float] = 0.5,
    ) -> Optional[SecurityEvent]:
        """
        Dequeues a SecurityEvent from the queue.
        Returns None if queue is empty or timeout expires.
        """
        try:
            event = self._queue.get(block=block, timeout=timeout)
            with self._lock:
                self._dequeued_count += 1
            return event
        except queue.Empty:
            return None

    def task_done(self) -> None:
        """Signals completion of a previously dequeued event task."""
        self._queue.task_done()

    def qsize(self) -> int:
        """Returns approximate current size of the queue."""
        return self._queue.qsize()

    def is_empty(self) -> bool:
        """Returns True if the queue is currently empty."""
        return self._queue.empty()

    def is_full(self) -> bool:
        """Returns True if the queue is currently at capacity."""
        return self._queue.full()

    def get_stats(self) -> Dict[str, int]:
        """Returns snapshot telemetry of queue operations."""
        with self._lock:
            return {
                "current_size": self._queue.qsize(),
                "max_size": self._maxsize,
                "enqueued_count": self._enqueued_count,
                "dequeued_count": self._dequeued_count,
                "dropped_count": self._dropped_count,
            }

    def clear(self) -> int:
        """Drains and discards all pending items from the queue."""
        cleared = 0
        while not self._queue.empty():
            try:
                self._queue.get_nowait()
                self._queue.task_done()
                cleared += 1
            except (queue.Empty, ValueError):
                break
        return cleared
