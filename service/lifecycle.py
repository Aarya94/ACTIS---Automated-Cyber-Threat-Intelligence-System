"""
ACTIS Protection Service Lifecycle Contract
Defines deterministic lifecycle states, transition validation rules,
and the formal service lifecycle interface.
"""

from abc import ABC, abstractmethod
from enum import Enum
from typing import Optional


class ServiceState(str, Enum):
    """Deterministic states for the ACTIS Protection Service lifecycle."""
    STOPPED = "STOPPED"
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    STOPPING = "STOPPING"
    PAUSED = "PAUSED"
    FAILED = "FAILED"
    DEGRADED = "DEGRADED"


class ServiceLifecycleError(Exception):
    """Raised when an illegal or unexpected service lifecycle transition occurs."""
    pass


class IServiceLifecycle(ABC):
    """Abstract interface declaring the mandatory lifecycle contract for protection services."""

    @abstractmethod
    def start(self) -> bool:
        """Starts the protection service and background worker threads."""
        pass

    @abstractmethod
    def stop(self, timeout: Optional[float] = None) -> bool:
        """Gracefully stops the protection service and drains workers."""
        pass

    @abstractmethod
    def pause(self) -> bool:
        """Temporarily pauses event consumption without terminating workers."""
        pass

    @abstractmethod
    def resume(self) -> bool:
        """Resumes event consumption after being paused."""
        pass

    @abstractmethod
    def get_state(self) -> ServiceState:
        """Returns the current deterministic service lifecycle state."""
        pass

    @abstractmethod
    def is_running(self) -> bool:
        """Returns True if the service is actively in RUNNING or PAUSED state."""
        pass
