"""
ACTIS Threat Intelligence Synchronization Service
Coordinates enabled upstream feed adapters, normalizes and deduplicates indicators,
persists records idempotently to SQLite, tracks metrics, and isolates failures.
"""

import time
import uuid
import threading
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

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
)
from reports.threat_database import (
    upsert_feed_records,
    record_sync_run,
    update_feed_status,
    get_feed_statuses as db_get_feed_statuses,
    get_latest_sync_run as db_get_latest_sync_run,
    get_recent_sync_runs as db_get_recent_sync_runs,
)
from config.config import (
    TI_SYNC_BATCH_SIZE,
    TI_SYNC_MAX_RECORDS,
    get_logger,
)

logger = get_logger("ThreatSyncService")


class ThreatSyncService:
    """
    Coordinates upstream threat intelligence feeds, validates and deduplicates IOCs,
    persists records idempotently, updates live provider health, and prevents overlapping jobs.
    """

    def __init__(
        self,
        adapters: Optional[List[BaseFeedAdapter]] = None,
        batch_size: Optional[int] = None,
        max_records_per_provider: Optional[int] = None,
    ):
        self._sync_lock = threading.Lock()
        self.batch_size = batch_size or TI_SYNC_BATCH_SIZE or 500
        self.max_records = max_records_per_provider or TI_SYNC_MAX_RECORDS or 1000

        if adapters is not None:
            self.adapters = adapters
        else:
            self.adapters = [
                URLhausFeedAdapter(),
                AbuseIPDBFeedAdapter(),
                VirusTotalFeedAdapter(),
            ]

    def register_adapter(self, adapter: BaseFeedAdapter) -> None:
        """Registers a new feed adapter."""
        self.adapters.append(adapter)

    def is_sync_in_progress(self) -> bool:
        """Checks if a synchronization job is currently executing."""
        acquired = self._sync_lock.acquire(blocking=False)
        if acquired:
            self._sync_lock.release()
            return False
        return True

    def sync_all(
        self,
        max_records_per_provider: Optional[int] = None,
        timeout: Optional[float] = None
    ) -> SyncRunResult:
        """
        Executes a synchronization cycle across all configured feed adapters.
        Guarantees non-overlapping execution via internal non-blocking lock.
        """
        run_id = f"sync_{uuid.uuid4().hex[:12]}"
        started_at = datetime.now(timezone.utc).isoformat()
        t0 = time.time()

        # Non-blocking lock acquisition to prevent overlapping runs
        acquired = self._sync_lock.acquire(blocking=False)
        if not acquired:
            dur = time.time() - t0
            completed_at = datetime.now(timezone.utc).isoformat()
            res = SyncRunResult(
                run_id=run_id,
                overall_status=SyncStatus.SKIPPED_ALREADY_RUNNING,
                started_at=started_at,
                completed_at=completed_at,
                duration_seconds=dur,
            )
            logger.warning("Threat intelligence sync skipped: another synchronization is already running.")
            return res

        limit = max_records_per_provider or self.max_records
        provider_results: Dict[str, ProviderSyncResult] = {}
        all_feed_records: List[FeedRecord] = []
        overall_received = 0
        overall_rejected = 0

        try:
            logger.info(f"Starting threat intelligence synchronization run '{run_id}' with {len(self.adapters)} adapters.")

            # Phase 1: Retrieve and validate feeds from each adapter with failure isolation
            for adapter in self.adapters:
                try:
                    records, p_res = adapter.fetch_feed(max_records=limit, timeout=timeout)
                    provider_results[adapter.provider_name] = p_res
                    overall_received += p_res.records_received
                    overall_rejected += p_res.records_rejected
                    all_feed_records.extend(records)
                except Exception as e:
                    logger.error(f"Unhandled exception in feed adapter {adapter.provider_name}: {e}")
                    p_res = ProviderSyncResult(
                        provider=adapter.provider_name,
                        status=SyncStatus.FAILED,
                        started_at=started_at,
                        completed_at=datetime.now(timezone.utc).isoformat(),
                        error_category=SyncErrorCategory.MALFORMED_RESPONSE,
                        error_message=f"Unhandled adapter failure: {e}",
                        duration_seconds=0.0,
                    )
                    provider_results[adapter.provider_name] = p_res

            # Phase 2: Deduplicate records across providers
            dedup_map: Dict[Tuple[str, str], FeedRecord] = {}
            for rec in all_feed_records:
                key = (
                    rec.indicator_type.value if hasattr(rec.indicator_type, "value") else str(rec.indicator_type),
                    rec.indicator.strip().lower(),
                )
                if key not in dedup_map:
                    dedup_map[key] = rec
                else:
                    # Merge metadata and take highest confidence
                    existing = dedup_map[key]
                    existing.confidence = max(existing.confidence, rec.confidence)
                    if "CONFIRMED" in (existing.status, rec.status):
                        existing.status = "CONFIRMED"
                    if rec.tags:
                        existing.tags = list(set(existing.tags + rec.tags))

            deduped_records = list(dedup_map.values())
            raw_dicts = [r.to_dict() for r in deduped_records]

            # Phase 3: Idempotent Batch Database Persistence
            t_db0 = time.time()
            inserted, updated, unchanged = upsert_feed_records(raw_dicts)
            logger.info(
                f"Sync run '{run_id}' database write: {inserted} inserted, {updated} updated, "
                f"{unchanged} unchanged out of {len(raw_dicts)} deduplicated records."
            )

            # Map database counts proportionally to provider results
            for p_name, p_res in provider_results.items():
                if p_res.status == SyncStatus.SUCCESS and p_res.records_validated > 0:
                    # Attribution of written records
                    ratio = p_res.records_validated / max(1, len(all_feed_records))
                    p_res.records_inserted = int(inserted * ratio)
                    p_res.records_updated = int(updated * ratio)
                    p_res.records_unchanged = int(unchanged * ratio)

                # Update persistent feed status table
                update_feed_status({
                    "provider": p_name,
                    "last_attempt": p_res.started_at,
                    "last_successful": p_res.completed_at if p_res.status == SyncStatus.SUCCESS else None,
                    "status": p_res.status.value,
                    "records_received": p_res.records_received,
                    "records_inserted": p_res.records_inserted,
                    "records_updated": p_res.records_updated,
                    "records_rejected": p_res.records_rejected,
                    "error_category": p_res.error_category.value,
                    "error_message": p_res.error_message,
                })

            # Determine overall outcome
            successes = sum(1 for r in provider_results.values() if r.status == SyncStatus.SUCCESS)
            failures = sum(1 for r in provider_results.values() if r.status == SyncStatus.FAILED)

            if successes > 0 and failures == 0:
                overall_status = SyncStatus.SUCCESS
            elif successes > 0 and failures > 0:
                overall_status = SyncStatus.PARTIAL_SUCCESS
            elif failures > 0:
                overall_status = SyncStatus.FAILED
            else:
                overall_status = SyncStatus.SUCCESS

            completed_at = datetime.now(timezone.utc).isoformat()
            duration_total = time.time() - t0

            final_run = SyncRunResult(
                run_id=run_id,
                overall_status=overall_status,
                started_at=started_at,
                completed_at=completed_at,
                total_records_received=overall_received,
                total_records_inserted=inserted,
                total_records_updated=updated,
                total_records_rejected=overall_rejected,
                provider_results=provider_results,
                duration_seconds=duration_total,
            )

            # Record run history in SQLite
            record_sync_run({
                "run_id": run_id,
                "started_at": started_at,
                "completed_at": completed_at,
                "overall_status": overall_status.value,
                "total_records_received": overall_received,
                "total_records_inserted": inserted,
                "total_records_updated": updated,
                "total_records_rejected": overall_rejected,
                "provider_results": {k: v.to_dict() for k, v in provider_results.items()},
            })

            return final_run

        finally:
            self._sync_lock.release()

    def sync_provider(
        self,
        provider_name: str,
        max_records: Optional[int] = None,
        timeout: Optional[float] = None
    ) -> ProviderSyncResult:
        """Synchronizes a single designated provider."""
        adapter = next((a for a in self.adapters if a.provider_name.lower() == provider_name.lower()), None)
        if not adapter:
            now = datetime.now(timezone.utc).isoformat()
            return ProviderSyncResult(
                provider=provider_name,
                status=SyncStatus.FAILED,
                started_at=now,
                completed_at=now,
                error_category=SyncErrorCategory.UNSUPPORTED_OPERATION,
                error_message=f"No adapter registered for provider '{provider_name}'.",
            )

        limit = max_records or self.max_records
        records, p_res = adapter.fetch_feed(max_records=limit, timeout=timeout)

        if p_res.status == SyncStatus.SUCCESS and records:
            raw_dicts = [r.to_dict() for r in records]
            inserted, updated, unchanged = upsert_feed_records(raw_dicts)
            p_res.records_inserted = inserted
            p_res.records_updated = updated
            p_res.records_unchanged = unchanged

        update_feed_status({
            "provider": adapter.provider_name,
            "last_attempt": p_res.started_at,
            "last_successful": p_res.completed_at if p_res.status == SyncStatus.SUCCESS else None,
            "status": p_res.status.value,
            "records_received": p_res.records_received,
            "records_inserted": p_res.records_inserted,
            "records_updated": p_res.records_updated,
            "records_rejected": p_res.records_rejected,
            "error_category": p_res.error_category.value,
            "error_message": p_res.error_message,
        })

        return p_res

    def get_all_feed_statuses(self) -> List[Dict[str, Any]]:
        """Returns live synchronization status for all threat feeds from SQLite."""
        return db_get_feed_statuses()

    def get_latest_sync_run(self) -> Optional[Dict[str, Any]]:
        """Returns the most recent sync run details."""
        return db_get_latest_sync_run()

    def get_recent_sync_runs(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Returns recent sync runs."""
        return db_get_recent_sync_runs(limit=limit)


# Global singleton instance (does NOT start background threads on import)
threat_sync_service = ThreatSyncService()
