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
from service.events import (
    SecurityEventType,
    SecurityEventValidationError,
    SecurityEvent,
    SecurityEventQueue,
)
from service.dispatcher import (
    IAnalysisOrchestrationBoundary,
    AnalysisOrchestrationStub,
    EventDispatcher,
)
from service.health import ServiceHealth
from service.protection_service import ProtectionService
from service.windows_host import (
    WindowsServiceHost,
    create_windows_host,
)
from service.file_normalizer import (
    normalize_filesystem_path,
    NormalizedFileEvent,
    FilesystemEventNormalizer,
)
from service.file_filter import (
    FilterReason,
    FileFilterPolicy,
    FileEventFilter,
    DEFAULT_TEMPORARY_PATTERNS,
    DEFAULT_EXCLUDED_SEGMENTS,
)
from service.debouncer import FileEventDebouncer

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
    "SecurityEventType",
    "SecurityEventValidationError",
    "SecurityEvent",
    "SecurityEventQueue",
    "IAnalysisOrchestrationBoundary",
    "AnalysisOrchestrationStub",
    "EventDispatcher",
    "ServiceHealth",
    "ProtectionService",
    "WindowsServiceHost",
    "create_windows_host",
    "normalize_filesystem_path",
    "NormalizedFileEvent",
    "FilesystemEventNormalizer",
    "FilterReason",
    "FileFilterPolicy",
    "FileEventFilter",
    "DEFAULT_TEMPORARY_PATTERNS",
    "DEFAULT_EXCLUDED_SEGMENTS",
    "FileEventDebouncer",
]
