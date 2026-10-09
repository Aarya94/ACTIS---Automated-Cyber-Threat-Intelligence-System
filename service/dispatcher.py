"""
ACTIS Protection Service Event Dispatcher & Analysis Orchestration Boundary
Defines the decoupled handoff boundary between the resident Protection Service
and the downstream ACTIS Analysis Orchestrator.

CRITICAL ARCHITECTURAL GUARANTEE:
The Protection Service and Event Dispatcher DO NOT perform detection logic,
ML model evaluation, PE static analysis, or RiskEngine calculations directly.
Events are dispatched across this boundary to the Analysis Orchestrator.
"""

import threading
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set

from service.events import SecurityEvent, SecurityEventType
from config.config import get_logger

logger = get_logger("EventDispatcher")


class IAnalysisOrchestrationBoundary(ABC):
    """
    Formal interface for the Analysis Orchestrator intake boundary.
    Represents the recipient of security events dispatched by the Protection Service.
    """

    @abstractmethod
    def handle_security_event(self, event: SecurityEvent) -> Dict[str, Any]:
        """
        Consumes a validated security event for downstream orchestration and analysis.
        Returns a receipt or preliminary dispatch status.
        """
        pass


class AnalysisOrchestrationStub(IAnalysisOrchestrationBoundary):
    """
    Reference/default orchestration boundary stub for Day 9.
    Provides safe event receipt, verification, and contract handoff logging without
    executing detection algorithms or risk scoring inside the service layer.
    """

    def __init__(self, name: str = "DefaultAnalysisOrchestrator"):
        self.name = name
        self._received_events: List[SecurityEvent] = []
        self._lock = threading.Lock()

    def handle_security_event(self, event: SecurityEvent) -> Dict[str, Any]:
        """Validates and records event handoff to the analysis layer."""
        event.validate()
        with self._lock:
            self._received_events.append(event)
        logger.info(
            f"Analysis Orchestration Boundary [{self.name}] accepted event "
            f"'{event.event_id}' (type={event.event_type.value}, source={event.source})"
        )
        return {
            "status": "ACCEPTED",
            "orchestrator": self.name,
            "event_id": event.event_id,
            "event_type": event.event_type.value,
            "received_at": datetime.now(timezone.utc).isoformat(),
        }

    @property
    def received_count(self) -> int:
        with self._lock:
            return len(self._received_events)

    def get_received_events(self) -> List[SecurityEvent]:
        with self._lock:
            return list(self._received_events)

    def clear(self) -> None:
        with self._lock:
            self._received_events.clear()


class EventDispatcher:
    """
    Thread-safe event dispatcher for routing SecurityEvents to registered
    analysis handlers and subscribers.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._handlers: Dict[SecurityEventType, List[Callable[[SecurityEvent], Any]]] = {}
        self._wildcard_handlers: List[Callable[[SecurityEvent], Any]] = []
        self._dispatch_count = 0
        self._dispatch_errors = 0

    def register_handler(
        self,
        event_type: SecurityEventType,
        handler: Callable[[SecurityEvent], Any],
    ) -> None:
        """Subscribes a callable handler to a specific SecurityEventType."""
        with self._lock:
            if event_type not in self._handlers:
                self._handlers[event_type] = []
            if handler not in self._handlers[event_type]:
                self._handlers[event_type].append(handler)
        logger.debug(f"Registered handler {getattr(handler, '__name__', str(handler))} for {event_type.value}")

    def register_wildcard_handler(
        self,
        handler: Callable[[SecurityEvent], Any],
    ) -> None:
        """Subscribes a handler to receive ALL event types (e.g. general orchestrator or logger)."""
        with self._lock:
            if handler not in self._wildcard_handlers:
                self._wildcard_handlers.append(handler)
        logger.debug(f"Registered wildcard handler {getattr(handler, '__name__', str(handler))}")

    def unregister_handler(
        self,
        event_type: SecurityEventType,
        handler: Callable[[SecurityEvent], Any],
    ) -> bool:
        """Unsubscribes a previously registered handler."""
        with self._lock:
            handlers = self._handlers.get(event_type, [])
            if handler in handlers:
                handlers.remove(handler)
                return True
            return False

    def dispatch(self, event: SecurityEvent) -> int:
        """
        Dispatches a validated SecurityEvent to all registered handlers.
        Catches and logs individual handler errors so remaining handlers still execute.
        Returns the number of handlers successfully executed.
        """
        event.validate()
        with self._lock:
            specific_handlers = list(self._handlers.get(event.event_type, []))
            all_handlers = specific_handlers + list(self._wildcard_handlers)

        success_count = 0
        for handler in all_handlers:
            try:
                handler(event)
                success_count += 1
            except Exception as ex:
                with self._lock:
                    self._dispatch_errors += 1
                logger.error(
                    f"Handler {getattr(handler, '__name__', str(handler))} failed on "
                    f"event {event.event_id}: {str(ex)}",
                    exc_info=True
                )

        with self._lock:
            self._dispatch_count += 1

        return success_count

    def connect_orchestrator(self, orchestrator: IAnalysisOrchestrationBoundary) -> None:
        """Connects an Analysis Orchestrator boundary as a wildcard event subscriber."""
        self.register_wildcard_handler(orchestrator.handle_security_event)
        logger.info("Connected Analysis Orchestration Boundary to EventDispatcher.")

    def get_stats(self) -> Dict[str, int]:
        """Returns snapshot telemetry for event dispatching."""
        with self._lock:
            return {
                "dispatched_events": self._dispatch_count,
                "dispatch_errors": self._dispatch_errors,
                "registered_event_types": len(self._handlers),
                "wildcard_handlers_count": len(self._wildcard_handlers),
            }

    def clear(self) -> None:
        """Clears all registered handlers and resets telemetry."""
        with self._lock:
            self._handlers.clear()
            self._wildcard_handlers.clear()
            self._dispatch_count = 0
            self._dispatch_errors = 0
