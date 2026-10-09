"""
ACTIS Protection Service Health & Diagnostics Model
Provides structured, non-sensitive operational telemetry and health assessments
for the resident Protection Service.
"""

from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional


@dataclass
class ServiceHealth:
    """
    Structured health and diagnostics report for the ACTIS Protection Service.
    Contains operational status, worker count, queue telemetry, and error tracking.
    """
    state: str
    is_running: bool
    is_healthy: bool
    uptime_seconds: float
    start_time: Optional[str]
    workers_total: int
    workers_alive: int
    queue_size: int
    events_enqueued: int
    events_dequeued: int
    events_dropped: int
    events_dispatched: int
    last_error: Optional[str]
    last_transition_time: str
    restart_count: int
    worker_details: List[Dict[str, Any]]
    filesystem_monitoring: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serializes health report to a clean dictionary."""
        return asdict(self)
