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

__all__ = [
    "ServiceState",
    "ServiceLifecycleError",
    "IServiceLifecycle",
    "ServiceConfig",
    "get_default_service_config",
]
