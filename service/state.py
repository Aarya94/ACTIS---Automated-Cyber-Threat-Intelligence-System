"""
ACTIS Protection Service State Management
Defines deterministic state transition rules, thread-safe state synchronization,
and lifecycle transition auditing.
"""

import threading
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Set

from service.lifecycle import ServiceState, ServiceLifecycleError
from config.config import get_logger

logger = get_logger("ServiceState")


# Permitted state transition map
VALID_TRANSITIONS: Dict[ServiceState, Set[ServiceState]] = {
    ServiceState.STOPPED: {ServiceState.STARTING},
    ServiceState.STARTING: {ServiceState.RUNNING, ServiceState.FAILED, ServiceState.STOPPED},
    ServiceState.RUNNING: {
        ServiceState.STOPPING,
        ServiceState.PAUSED,
        ServiceState.DEGRADED,
        ServiceState.FAILED
    },
    ServiceState.PAUSED: {ServiceState.RUNNING, ServiceState.STOPPING, ServiceState.FAILED},
    ServiceState.DEGRADED: {ServiceState.RUNNING, ServiceState.STOPPING, ServiceState.FAILED},
    ServiceState.STOPPING: {ServiceState.STOPPED, ServiceState.FAILED},
    ServiceState.FAILED: {ServiceState.STOPPED, ServiceState.STARTING},
}


@dataclass
class StateTransitionRecord:
    """Historical audit entry for a service state transition."""
    from_state: str
    to_state: str
    timestamp: str
    reason: Optional[str] = None
    success: bool = True

    def to_dict(self) -> Dict[str, str]:
        return asdict(self)


class ServiceStateManager:
    """
    Thread-safe manager for service state transitions and history tracking.
    Enforces deterministic lifecycle progression and logs all changes.
    """

    def __init__(self, initial_state: ServiceState = ServiceState.STOPPED):
        self._lock = threading.Lock()
        self._state = initial_state
        self._last_error: Optional[str] = None
        self._last_transition_time = datetime.now(timezone.utc).isoformat()
        self._history: List[StateTransitionRecord] = []

    @property
    def current_state(self) -> ServiceState:
        with self._lock:
            return self._state

    @property
    def last_error(self) -> Optional[str]:
        with self._lock:
            return self._last_error

    @property
    def last_transition_time(self) -> str:
        with self._lock:
            return self._last_transition_time

    def can_transition(self, target_state: ServiceState) -> bool:
        """Checks if a transition from current state to target state is legally permitted."""
        with self._lock:
            allowed = VALID_TRANSITIONS.get(self._state, set())
            return target_state in allowed

    def transition_to(
        self,
        target_state: ServiceState,
        reason: Optional[str] = None,
        raise_on_error: bool = True
    ) -> bool:
        """
        Executes a synchronized state transition with validation and audit logging.
        
        Args:
            target_state: Destination ServiceState
            reason: Optional explanation for the transition
            raise_on_error: If True, raises ServiceLifecycleError on invalid transitions
        """
        with self._lock:
            from_state = self._state
            allowed = VALID_TRANSITIONS.get(from_state, set())
            now_iso = datetime.now(timezone.utc).isoformat()

            if target_state not in allowed:
                record = StateTransitionRecord(
                    from_state=from_state.value,
                    to_state=target_state.value,
                    timestamp=now_iso,
                    reason=f"Rejected: transition {from_state.value} -> {target_state.value} illegal",
                    success=False
                )
                self._history.append(record)
                err_msg = (
                    f"Illegal service state transition: cannot transition from "
                    f"'{from_state.value}' to '{target_state.value}'."
                )
                logger.warning(err_msg)
                if raise_on_error:
                    raise ServiceLifecycleError(err_msg)
                return False

            # Execute valid transition
            self._state = target_state
            self._last_transition_time = now_iso
            record = StateTransitionRecord(
                from_state=from_state.value,
                to_state=target_state.value,
                timestamp=now_iso,
                reason=reason,
                success=True
            )
            self._history.append(record)
            logger.info(
                f"Service state transition: {from_state.value} -> {target_state.value} "
                f"({reason or 'no reason specified'})"
            )
            return True

    def record_error(self, error_message: str):
        """Records the latest service failure or warning description."""
        with self._lock:
            self._last_error = error_message
            logger.error(f"Service error recorded: {error_message}")

    def get_history(self) -> List[Dict[str, str]]:
        """Returns a snapshot of historical state transitions."""
        with self._lock:
            return [r.to_dict() for r in self._history]

    def reset(self, initial_state: ServiceState = ServiceState.STOPPED):
        """Resets the state manager back to initial state (e.g. for testing)."""
        with self._lock:
            self._state = initial_state
            self._last_error = None
            self._last_transition_time = datetime.now(timezone.utc).isoformat()
            self._history.clear()
