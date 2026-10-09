"""
ACTIS Protection Service Package
Provides the resident Windows Protection Service foundation, lifecycle management,
event intake boundary, worker coordination, and health monitoring.
"""

from service.lifecycle import (
    ServiceState,
    ServiceLifecycleError,
    IServiceLifecycle,
)
from service.config import (
    ServiceConfig,
    get_default_service_config,
)
from service.state import (
    ServiceStateManager,
    StateTransitionRecord,
    VALID_TRANSITIONS,
)
from service.workers import (
    WorkerState,
    WorkerStatus,
    ServiceWorker,
    WorkerManager,
)

__all__ = [
    "ServiceState",
    "ServiceLifecycleError",
    "IServiceLifecycle",
    "ServiceConfig",
    "get_default_service_config",
    "ServiceStateManager",
    "StateTransitionRecord",
    "VALID_TRANSITIONS",
    "WorkerState",
    "WorkerStatus",
    "ServiceWorker",
    "WorkerManager",
]
