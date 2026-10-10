"""
ACTIS Threat Intelligence Module
Provides indicator validation, local database lookups, TTL caching, external provider adapters,
and scheduled upstream threat feed synchronization.
"""

from threat_intelligence.provider_base import BaseThreatClient
from threat_intelligence.api_clients import (
    vt_client,
    urlhaus_client,
    abuseipdb_client,
    VirusTotalClient,
    URLhausClient,
    AbuseIPDBClient,
)
from threat_intelligence.threat_cache import (
    threat_cache,
    ThreatIntelligenceCache,
)
from threat_intelligence.threat_lookup import (
    ThreatLookup,
    threat_lookup,
)
from threat_intelligence.indicator_validator import (
    validate_and_normalize_indicator,
    detect_indicator_type,
    is_safe_public_ip,
)
from threat_intelligence.sync import (
    FeedRecord,
    ProviderSyncResult,
    SyncRunResult,
    SyncStatus,
    SyncErrorCategory,
    BaseFeedAdapter,
    URLhausFeedAdapter,
    AbuseIPDBFeedAdapter,
    VirusTotalFeedAdapter,
    CentralACTISFeedAdapter,
    ThreatSyncService,
    threat_sync_service,
    ThreatSyncScheduler,
    threat_sync_scheduler,
)
from threat_intelligence.sync_manager import (
    SyncManager,
    sync_manager,
    CentralThreatIntelligenceClient,
)

__all__ = [
    "BaseThreatClient",
    "vt_client",
    "urlhaus_client",
    "abuseipdb_client",
    "VirusTotalClient",
    "URLhausClient",
    "AbuseIPDBClient",
    "threat_cache",
    "ThreatIntelligenceCache",
    "ThreatLookup",
    "threat_lookup",
    "validate_and_normalize_indicator",
    "detect_indicator_type",
    "is_safe_public_ip",
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
    "SyncManager",
    "sync_manager",
    "CentralThreatIntelligenceClient",
]
