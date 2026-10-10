"""
Tests for ACTIS Day 12 Threat Intelligence Synchronization & Pipeline Integration
Covers upstream feed adapters, indicator validation, idempotent SQLite upserts,
failure isolation, scheduler lifecycle, non-overlapping concurrency, and unified detection flow.
"""

import time
import uuid
import pytest
from unittest.mock import MagicMock, patch
import requests

from detection_engine.threat_intel_contract import (
    IndicatorType,
    ThreatIntelVerdict,
)
from detection_engine.detection_contract import DetectionStatus
from detection_engine.threat_detector import ThreatDetector
from threat_intelligence.threat_lookup import ThreatLookup
from threat_intelligence.sync.sync_models import (
    FeedRecord,
    SyncStatus,
    SyncErrorCategory,
    ProviderSyncResult,
)
from threat_intelligence.sync.feed_adapter import (
    URLhausFeedAdapter,
    AbuseIPDBFeedAdapter,
    VirusTotalFeedAdapter,
)
from threat_intelligence.sync.sync_service import ThreatSyncService
from threat_intelligence.sync.scheduler import ThreatSyncScheduler
from reports.threat_database import (
    upsert_feed_records,
    lookup_indicator,
    update_feed_status,
    get_feed_statuses,
    record_sync_run,
    get_latest_sync_run,
    get_recent_sync_runs,
    get_db_connection,
)


# =====================================================================
# 1. Feed Adapter Unit Tests
# =====================================================================

class TestFeedAdapters:
    """Tests for upstream threat feed adapters and response parsers."""

    @patch("requests.post")
    def test_urlhaus_adapter_fetch_success(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "query_status": "ok",
            "urls": [
                {
                    "id": "1001",
                    "url": "http://malicious-distro.com/payload.exe",
                    "url_status": "online",
                    "host": "malicious-distro.com",
                    "threat": "malware_download",
                    "tags": ["exe", "redline"],
                    "date_added": "2026-10-10 12:00:00 UTC",
                },
                {
                    "id": "1002",
                    "url": "https://secondary-c2.net/gate.php",
                    "url_status": "offline",
                    "host": "secondary-c2.net",
                    "threat": "c2_server",
                    "tags": "botnet",
                    "date_added": "2026-10-10 11:30:00 UTC",
                }
            ]
        }
        mock_post.return_value = mock_resp

        adapter = URLhausFeedAdapter(enabled=True)
        records, result = adapter.fetch_feed(max_records=10)

        assert result.status == SyncStatus.SUCCESS
        assert result.records_received == 2
        assert len(records) == 2
        assert records[0].indicator == "http://malicious-distro.com/payload.exe"
        assert records[0].status == "CONFIRMED"
        assert records[0].confidence == 0.95
        assert "redline" in records[0].tags
        assert records[1].status == "SUSPICIOUS"
        assert records[1].confidence == 0.85

    @patch("requests.post")
    def test_urlhaus_adapter_rejects_malformed_urls(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "query_status": "ok",
            "urls": [
                {"id": "1", "url": "ftp://unsupported-scheme.com/payload.exe"},
                {"id": "2", "url": "javascript:alert(1)"},
                {"id": "3", "url": "http://legit-bad-url.com/drop.bin", "url_status": "online"},
                {"id": "4", "invalid_key": "missing_url"},
            ]
        }
        mock_post.return_value = mock_resp

        adapter = URLhausFeedAdapter(enabled=True)
        records, result = adapter.fetch_feed(max_records=10)

        assert result.status == SyncStatus.SUCCESS
        assert len(records) == 1
        assert records[0].indicator == "http://legit-bad-url.com/drop.bin"
        assert result.records_rejected == 3

    @patch("requests.post")
    def test_urlhaus_adapter_timeout_isolation(self, mock_post):
        mock_post.side_effect = requests.exceptions.Timeout("Connection timed out")

        adapter = URLhausFeedAdapter(enabled=True, timeout=1.0)
        records, result = adapter.fetch_feed()

        assert records == []
        assert result.status == SyncStatus.FAILED
        assert result.error_category == SyncErrorCategory.NETWORK_TIMEOUT
        assert "timed out" in (result.error_message or "").lower()

    @patch("requests.post")
    def test_urlhaus_adapter_rate_limit_429(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_post.return_value = mock_resp

        adapter = URLhausFeedAdapter(enabled=True)
        records, result = adapter.fetch_feed()

        assert records == []
        assert result.status == SyncStatus.FAILED
        assert result.error_category == SyncErrorCategory.RATE_LIMITED

    @patch("requests.post")
    def test_urlhaus_adapter_malformed_json(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.side_effect = ValueError("Invalid JSON token")
        mock_post.return_value = mock_resp

        adapter = URLhausFeedAdapter(enabled=True)
        records, result = adapter.fetch_feed()

        assert records == []
        assert result.status == SyncStatus.FAILED
        assert result.error_category == SyncErrorCategory.MALFORMED_RESPONSE

    @patch("requests.get")
    def test_abuseipdb_adapter_fetch_success(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "meta": {"generatedAt": "2026-10-10T12:00:00Z"},
            "data": [
                {
                    "ipAddress": "185.220.101.5",
                    "countryCode": "US",
                    "abuseConfidenceScore": 100,
                    "lastReportedAt": "2026-10-10T11:50:00Z",
                },
                {
                    "ipAddress": "45.33.32.156",
                    "countryCode": "DE",
                    "abuseConfidenceScore": 92,
                    "lastReportedAt": "2026-10-10T11:40:00Z",
                }
            ]
        }
        mock_get.return_value = mock_resp

        adapter = AbuseIPDBFeedAdapter(api_key="valid-mock-abuseipdb-key-12345", enabled=True)
        records, result = adapter.fetch_feed(max_records=10)

        assert result.status == SyncStatus.SUCCESS
        assert len(records) == 2
        assert records[0].indicator == "185.220.101.5"
        assert records[0].indicator_type == IndicatorType.IP_ADDRESS
        assert records[0].status == "CONFIRMED"
        assert records[0].confidence == 1.0

    @patch("requests.get")
    def test_abuseipdb_adapter_shields_private_ips(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": [
                {"ipAddress": "192.168.1.1", "abuseConfidenceScore": 100},  # RFC 1918
                {"ipAddress": "127.0.0.1", "abuseConfidenceScore": 100},    # Loopback
                {"ipAddress": "10.0.50.2", "abuseConfidenceScore": 99},     # RFC 1918
                {"ipAddress": "185.220.101.5", "abuseConfidenceScore": 95}, # Public
            ]
        }
        mock_get.return_value = mock_resp

        adapter = AbuseIPDBFeedAdapter(api_key="valid-mock-abuseipdb-key-12345", enabled=True)
        records, result = adapter.fetch_feed(max_records=10)

        assert result.status == SyncStatus.SUCCESS
        assert len(records) == 1
        assert records[0].indicator == "185.220.101.5"
        assert result.records_rejected == 3

    def test_abuseipdb_adapter_unconfigured_error(self):
        adapter = AbuseIPDBFeedAdapter(api_key="", enabled=True)
        records, result = adapter.fetch_feed()

        assert records == []
        assert result.status == SyncStatus.FAILED
        assert result.error_category == SyncErrorCategory.AUTH_FAILURE

    @patch("requests.get")
    def test_virustotal_adapter_reports_enterprise_limitation(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_get.return_value = mock_resp

        adapter = VirusTotalFeedAdapter(api_key="mock-standard-api-key-12345", enabled=True)
        records, result = adapter.fetch_feed()

        assert records == []
        assert result.status == SyncStatus.FAILED
        assert result.error_category == SyncErrorCategory.UNSUPPORTED_OPERATION
        assert "enterprise" in (result.error_message or "").lower()


# =====================================================================
# 2. Idempotent SQLite Database Persistence Tests
# =====================================================================

class TestThreatDatabaseSyncPersistence:
    """Tests for idempotent persistence, status updates, and history tracking in SQLite."""

    def test_upsert_feed_records_new_indicators(self):
        tag = uuid.uuid4().hex[:8]
        url_val = f"http://sync-test-{tag}.xyz/stealer.exe"
        ip_val = "185.220.101.99"
        records = [
            {
                "indicator_type": "url",
                "indicator_value": url_val,
                "source": "URLhaus_Sync",
                "confidence": 0.95,
                "status": "CONFIRMED",
                "threat_type": "InfoStealer",
                "threat_name": "RedLine Stealer",
            },
            {
                "indicator_type": "ip",
                "indicator_value": ip_val,
                "source": "AbuseIPDB_Sync",
                "confidence": 0.90,
                "status": "SUSPICIOUS",
                "threat_type": "Port Scanner",
                "threat_name": "Reconnaissance Host",
            }
        ]

        inserted, updated, unchanged = upsert_feed_records(records)
        assert inserted >= 1

        # Verify lookup
        res_url = lookup_indicator("url", url_val)
        assert res_url["found"] is True
        assert res_url["status"] == "CONFIRMED"
        assert res_url["threat_name"] == "RedLine Stealer"

    def test_upsert_feed_records_idempotent_duplicate(self):
        tag = uuid.uuid4().hex[:8]
        url_val = f"http://dup-test-{tag}.xyz/payload.exe"
        records = [
            {
                "indicator_type": "url",
                "indicator_value": url_val,
                "source": "URLhaus_Sync",
                "confidence": 0.95,
                "status": "CONFIRMED",
                "threat_type": "InfoStealer",
                "threat_name": "RedLine Stealer",
            }
        ]

        # First run inserts
        ins1, upd1, unc1 = upsert_feed_records(records)
        assert ins1 == 1

        # Re-running with identical data increments unchanged count
        ins2, upd2, unc2 = upsert_feed_records(records)
        assert ins2 == 0
        assert unc2 == 1

    def test_upsert_feed_records_updates_confidence_and_status(self):
        tag = uuid.uuid4().hex[:8]
        dom_val = f"c2-dynamic-{tag}.com"
        # Insert initial suspicious indicator
        initial = [{
            "indicator_type": "domain",
            "indicator_value": dom_val,
            "source": "Feed_A",
            "confidence": 0.60,
            "status": "SUSPICIOUS",
        }]
        upsert_feed_records(initial)

        # Later feed upgrades it to CONFIRMED with 0.98 confidence
        upgraded = [{
            "indicator_type": "domain",
            "indicator_value": dom_val,
            "source": "Feed_B",
            "confidence": 0.98,
            "status": "CONFIRMED",
        }]
        inserted, updated, unchanged = upsert_feed_records(upgraded)

        assert inserted == 0
        assert updated == 1

        rec = lookup_indicator("domain", dom_val)
        assert rec["found"] is True
        assert rec["status"] == "CONFIRMED"
        assert rec["confidence"] == 0.98
        assert "Feed_B" in rec["source"]

    def test_upsert_feed_records_empty_feed_does_not_delete(self):
        # Empty list should do nothing and return 0s
        inserted, updated, unchanged = upsert_feed_records([])
        assert (inserted, updated, unchanged) == (0, 0, 0)

        # Pre-existing indicators must remain intact
        rec = lookup_indicator("url", "http://sync-test-domain.xyz/stealer.exe")
        assert rec["found"] is True

    def test_feed_status_tracking_in_db(self):
        update_feed_status({
            "provider": "MockProvider",
            "last_attempt": "2026-10-10T12:00:00Z",
            "last_successful": "2026-10-10T12:00:00Z",
            "status": "SUCCESS",
            "records_received": 50,
            "records_inserted": 45,
            "records_updated": 5,
            "records_rejected": 0,
            "error_category": "NONE",
            "error_message": None,
        })

        statuses = get_feed_statuses()
        provider_stat = next((s for s in statuses if s["provider"] == "MockProvider"), None)
        assert provider_stat is not None
        assert provider_stat["status"] == "SUCCESS"
        assert provider_stat["records_received"] == 50
        assert provider_stat["records_inserted"] == 45

    def test_sync_run_history_in_db(self):
        run_id = f"test_run_{uuid.uuid4().hex[:8]}"
        run_data = {
            "run_id": run_id,
            "started_at": "2026-10-10T12:00:00Z",
            "completed_at": "2026-10-10T12:00:05Z",
            "overall_status": "SUCCESS",
            "total_records_received": 100,
            "total_records_inserted": 80,
            "total_records_updated": 20,
            "total_records_rejected": 5,
            "provider_results": {"Mock": {"status": "SUCCESS"}},
        }
        record_sync_run(run_data)

        recent = get_recent_sync_runs(limit=10)
        match = next((r for r in recent if r["run_id"] == run_id), None)
        assert match is not None
        assert match["total_inserted"] == 80
        assert match["overall_status"] == "SUCCESS"


# =====================================================================
# 3. Synchronization Service & Scheduler Tests
# =====================================================================

class TestSyncServiceAndScheduler:
    """Tests for multi-adapter coordination, concurrency locks, and scheduler lifecycle."""

    def test_sync_service_sync_all_success(self):
        # Create mock adapters
        mock_a1 = MagicMock(spec=URLhausFeedAdapter)
        mock_a1.provider_name = "MockURLhaus"
        mock_a1.fetch_feed.return_value = (
            [
                FeedRecord(
                    indicator="http://service-sync-test.com/malware.exe",
                    indicator_type=IndicatorType.URL,
                    source_feed="MockURLhaus",
                    confidence=0.90,
                    status="CONFIRMED",
                )
            ],
            ProviderSyncResult(
                provider="MockURLhaus",
                status=SyncStatus.SUCCESS,
                started_at="2026-10-10T12:00:00Z",
                completed_at="2026-10-10T12:00:01Z",
                records_received=1,
                records_validated=1,
            )
        )

        service = ThreatSyncService(adapters=[mock_a1])
        res = service.sync_all()

        assert res.overall_status == SyncStatus.SUCCESS
        assert res.total_records_received == 1
        assert "MockURLhaus" in res.provider_results

        # Verify indicator landed in DB
        db_res = lookup_indicator("url", "http://service-sync-test.com/malware.exe")
        assert db_res["found"] is True

    def test_sync_service_partial_success_when_one_fails(self):
        mock_success = MagicMock(spec=URLhausFeedAdapter)
        mock_success.provider_name = "AdapterSuccess"
        mock_success.fetch_feed.return_value = (
            [FeedRecord(indicator="http://good-sync.com/drop.bin", indicator_type=IndicatorType.URL, source_feed="AdapterSuccess")],
            ProviderSyncResult(provider="AdapterSuccess", status=SyncStatus.SUCCESS, started_at="", completed_at="", records_received=1, records_validated=1)
        )

        mock_fail = MagicMock(spec=AbuseIPDBFeedAdapter)
        mock_fail.provider_name = "AdapterFail"
        mock_fail.fetch_feed.return_value = (
            [],
            ProviderSyncResult(provider="AdapterFail", status=SyncStatus.FAILED, started_at="", completed_at="", error_category=SyncErrorCategory.NETWORK_TIMEOUT)
        )

        service = ThreatSyncService(adapters=[mock_success, mock_fail])
        res = service.sync_all()

        assert res.overall_status == SyncStatus.PARTIAL_SUCCESS
        assert res.provider_results["AdapterSuccess"].status == SyncStatus.SUCCESS
        assert res.provider_results["AdapterFail"].status == SyncStatus.FAILED

    def test_sync_service_prevents_overlapping_runs(self):
        service = ThreatSyncService(adapters=[])

        # Acquire the lock manually to simulate an ongoing sync job
        assert service._sync_lock.acquire(blocking=False) is True
        try:
            # Concurrent sync attempt should be skipped immediately
            res = service.sync_all()
            assert res.overall_status == SyncStatus.SKIPPED_ALREADY_RUNNING
        finally:
            service._sync_lock.release()

    def test_scheduler_lifecycle(self):
        mock_service = MagicMock(spec=ThreatSyncService)
        scheduler = ThreatSyncScheduler(sync_service=mock_service, interval_seconds=3600, enabled=True)

        assert scheduler.is_running is False
        started = scheduler.start()
        assert started is True
        assert scheduler.is_running is True

        # Duplicate start is rejected
        dup_started = scheduler.start()
        assert dup_started is False

        # Stop
        stopped = scheduler.stop(timeout=2.0)
        assert stopped is True
        assert scheduler.is_running is False

    def test_scheduler_disabled_does_not_start(self):
        mock_service = MagicMock(spec=ThreatSyncService)
        scheduler = ThreatSyncScheduler(sync_service=mock_service, enabled=False)

        assert scheduler.start() is False
        assert scheduler.is_running is False

    def test_scheduler_manual_trigger(self):
        mock_service = MagicMock(spec=ThreatSyncService)
        mock_service.sync_all.return_value = ProviderSyncResult(
            provider="All", status=SyncStatus.SUCCESS, started_at="", completed_at=""
        )

        scheduler = ThreatSyncScheduler(sync_service=mock_service, enabled=False)
        scheduler.trigger_sync_now()
        mock_service.sync_all.assert_called_once()


# =====================================================================
# 4. Unified Analysis Pipeline Integration Tests
# =====================================================================

class TestUnifiedPipelineTIIntegration:
    """
    Verifies the end-to-end flow:
    Feed Record -> SQLite -> ThreatLookup (Stage 1 Local DB) -> ThreatDetector -> DetectionResult.
    """

    def test_imported_feed_record_retrieved_by_threat_lookup(self):
        target_url = "http://upstream-trojan-c2.org/download.bin"

        # 1. Feed sync persists the indicator into SQLite
        upsert_feed_records([{
            "indicator_type": "url",
            "indicator_value": target_url,
            "source": "URLhaus_Feed_Sync",
            "confidence": 0.95,
            "status": "CONFIRMED",
            "threat_type": "Trojan Downloader",
            "threat_name": "Emotet",
        }])

        # 2. Existing ThreatLookup queries the indicator
        lookup = ThreatLookup()
        res = lookup.lookup_indicator(target_url, IndicatorType.URL)

        # 3. Must hit local database on Stage 1 with confirmed status
        assert res["outcome_state"] == "FOUND_MALICIOUS"
        assert res["primary_evidence"] is not None
        assert res["primary_evidence"].is_confirmed_threat is True
        assert res["primary_evidence"].verdict == ThreatIntelVerdict.MALICIOUS
        assert res["primary_evidence"].confidence >= 0.90
        assert "Emotet" in res["primary_evidence"].threat_type or "Trojan" in res["primary_evidence"].threat_type

    def test_imported_feed_record_analyzed_by_threat_detector(self):
        target_url = "http://upstream-emotet-feed-url.com/payload.exe"

        # 1. Upsert into database via sync
        upsert_feed_records([{
            "indicator_type": "url",
            "indicator_value": target_url,
            "source": "URLhaus_Sync",
            "confidence": 0.98,
            "status": "CONFIRMED",
            "threat_type": "Malware Download",
            "threat_name": "Emotet Payload",
        }])

        # 2. Analyze URL through central ThreatDetector
        detector = ThreatDetector()
        res = detector.analyze_url(target_url, check_external=False)

        # 3. Verify final structured DetectionResult
        assert res["is_threat"] is True
        assert res["risk_level"] in ("HIGH", "CRITICAL")
        assert res["score"] >= 60.0

        det_result = res.get("detection_result")
        assert det_result is not None
        assert det_result["detection_status"] == DetectionStatus.MALICIOUS.value
        assert any("Emotet" in r or "Malware" in r or "Known" in r for r in res.get("reasons", []))

    def test_unknown_indicator_remains_unknown_when_not_in_feed(self):
        benign_url = "http://legitimate-internal-portal-12345.local/dashboard"
        lookup = ThreatLookup()
        res = lookup.lookup_indicator(benign_url, IndicatorType.URL)

        # Must not be marked as malicious or confirmed
        assert res["primary_evidence"].is_confirmed_threat is False
        assert res["primary_evidence"].verdict in (ThreatIntelVerdict.UNKNOWN, ThreatIntelVerdict.CLEAN)
