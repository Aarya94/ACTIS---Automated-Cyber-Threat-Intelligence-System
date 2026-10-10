"""
ACTIS Threat Intelligence Synchronization Package
Scheduled feed updates, provider adapters, idempotent database persistence,
and non-overlapping background execution.
"""

from threat_intelligence.sync.sync_models import (
    FeedRecord,
    ProviderSyncResult,
    SyncRunResult,
    SyncStatus,
    SyncErrorCategory,
)
from threat_intelligence.sync.feed_adapter import (
    BaseFeedAdapter,
    URLhausFeedAdapter,
    AbuseIPDBFeedAdapter,
    VirusTotalFeedAdapter,
    CentralACTISFeedAdapter,
)
from threat_intelligence.sync.sync_service import (
    ThreatSyncService,
    threat_sync_service,
)
from threat_intelligence.sync.scheduler import (
    ThreatSyncScheduler,
    threat_sync_scheduler,
)

__all__ = [
    "FeedRecord",
    "ProviderSyncResult",
    "SyncRunResult",
    "SyncStatus",
    "SyncErrorCategory",
    "BaseFeedAdapter",
    "URLhausFeedAdapter",
    "AbuseIPDBFeedAdapter",
    "VirusTotalFeedAdapter",
    "CentralACTISFeedAdapter",
    "ThreatSyncService",
    "threat_sync_service",
    "ThreatSyncScheduler",
    "threat_sync_scheduler",
]
