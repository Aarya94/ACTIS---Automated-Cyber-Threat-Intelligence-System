"""
ACTIS Threat Intelligence Synchronization Models
Data structures and contracts for upstream threat intelligence feeds,
execution tracking, provider failure isolation, and normalization.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from detection_engine.threat_intel_contract import IndicatorType


class SyncStatus(str, Enum):
    """Execution status for a threat intelligence synchronization run."""
    SUCCESS = "SUCCESS"
    PARTIAL_SUCCESS = "PARTIAL_SUCCESS"
    FAILED = "FAILED"
    SKIPPED_ALREADY_RUNNING = "SKIPPED_ALREADY_RUNNING"
    NEVER_SYNCED = "NEVER_SYNCED"
    RUNNING = "RUNNING"
    DISABLED = "DISABLED"


class SyncErrorCategory(str, Enum):
    """Categorized diagnostic failure reasons for sanitized error reporting."""
    NONE = "NONE"
    NETWORK_TIMEOUT = "NETWORK_TIMEOUT"
    CONNECTION_ERROR = "CONNECTION_ERROR"
    HTTP_ERROR = "HTTP_ERROR"
    RATE_LIMITED = "RATE_LIMITED"
    AUTH_FAILURE = "AUTH_FAILURE"
    MALFORMED_RESPONSE = "MALFORMED_RESPONSE"
    UNSUPPORTED_OPERATION = "UNSUPPORTED_OPERATION"
    DATABASE_ERROR = "DATABASE_ERROR"
    LOCK_HELD = "LOCK_HELD"


@dataclass
class FeedRecord:
    """
    Normalized, validated indicator record extracted from an upstream threat intelligence feed.
    Guarantees consistent contract across providers before persistence.
    """
    indicator: str
    indicator_type: IndicatorType
    source_feed: str
    confidence: float = 0.8
    status: str = "SUSPICIOUS"  # "CONFIRMED", "SUSPICIOUS", "REPORTED"
    threat_type: str = "Generic Threat"
    threat_name: str = "Upstream Feed Detection"
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes FeedRecord to a dictionary suitable for database upserts."""
        return {
            "indicator_type": self.indicator_type.value if hasattr(self.indicator_type, "value") else str(self.indicator_type),
            "indicator_value": self.indicator,
            "source": self.source_feed,
            "confidence": self.confidence,
            "status": self.status,
            "threat_type": self.threat_type,
            "threat_name": self.threat_name,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "tags": list(self.tags),
            "metadata": dict(self.metadata),
        }


@dataclass
class ProviderSyncResult:
    """Detailed synchronization metrics and execution state for a single upstream provider."""
    provider: str
    status: SyncStatus
    started_at: str
    completed_at: str
    records_received: int = 0
    records_validated: int = 0
    records_rejected: int = 0
    records_inserted: int = 0
    records_updated: int = 0
    records_unchanged: int = 0
    error_category: SyncErrorCategory = SyncErrorCategory.NONE
    error_message: Optional[str] = None
    duration_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provider": self.provider,
            "status": self.status.value if hasattr(self.status, "value") else str(self.status),
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "records_received": self.records_received,
            "records_validated": self.records_validated,
            "records_rejected": self.records_rejected,
            "records_inserted": self.records_inserted,
            "records_updated": self.records_updated,
            "records_unchanged": self.records_unchanged,
            "error_category": self.error_category.value if hasattr(self.error_category, "value") else str(self.error_category),
            "error_message": self.error_message,
            "duration_seconds": round(self.duration_seconds, 3),
        }


@dataclass
class SyncRunResult:
    """Overall structured result of a threat intelligence synchronization run across all adapters."""
    run_id: str
    overall_status: SyncStatus
    started_at: str
    completed_at: str
    total_records_received: int = 0
    total_records_inserted: int = 0
    total_records_updated: int = 0
    total_records_rejected: int = 0
    provider_results: Dict[str, ProviderSyncResult] = field(default_factory=dict)
    duration_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "overall_status": self.overall_status.value if hasattr(self.overall_status, "value") else str(self.overall_status),
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "total_records_received": self.total_records_received,
            "total_records_inserted": self.total_records_inserted,
            "total_records_updated": self.total_records_updated,
            "total_records_rejected": self.total_records_rejected,
            "provider_results": {k: v.to_dict() for k, v in self.provider_results.items()},
            "duration_seconds": round(self.duration_seconds, 3),
        }
