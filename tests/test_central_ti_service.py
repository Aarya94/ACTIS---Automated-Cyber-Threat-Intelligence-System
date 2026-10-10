"""
ACTIS Day 13 Test Suite: Central Threat Intelligence Service and Secure ACTIS Synchronization
Comprehensive unit, integration, and architecture regression tests.
Covers:
  - Versioned v1 REST API routes and health telemetry
  - Role-based authentication and authorization (read, contribute, admin)
  - Constant-time token verification and rate limiting (429)
  - Indicator validation, normalization, and RFC 1918 private IP shielding
  - Candidate contribution policy (anti-poisoning: candidate cannot self-promote to confirmed)
  - Administrative verification and review state transitions
  - CentralACTISFeedAdapter error isolation (timeouts, auth failure, connection errors, malformed JSON)
  - Idempotent local SQLite persistence via Day 12 upsert_feed_records
  - Immediate local pipeline queryability via ThreatLookup and AnalysisOrchestrator
"""

import json
import random
import sqlite3
import time
import uuid
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest
import requests
from fastapi.testclient import TestClient

from backend.api import app, rate_limiter
from backend.database import (
    admin_review_indicator,
    get_backend_db_connection,
    get_indicator_by_type_value,
    init_central_database,
    insert_candidate_contribution,
    query_indicators,
)
from detection_engine.detection_contract import DetectionStatus
from detection_engine.orchestrator import analysis_orchestrator
from detection_engine.threat_detector import threat_detector
from detection_engine.threat_intel_contract import IndicatorType
from reports.threat_database import (
    get_feed_statuses,
    initialize_database,
    upsert_feed_records,
)
from threat_intelligence.indicator_validator import is_safe_public_ip, validate_and_normalize_indicator
from threat_intelligence.sync.feed_adapter import CentralACTISFeedAdapter
from threat_intelligence.sync.sync_models import FeedRecord, SyncErrorCategory, SyncStatus
from threat_intelligence.sync.sync_service import ThreatSyncService
from threat_intelligence.sync_manager import SyncManager, sync_manager
from threat_intelligence.threat_lookup import ThreatLookup, threat_lookup

client = TestClient(app)

VALID_CONTRIBUTOR_KEY = "actis-client-default-secret-token"
VALID_READONLY_KEY = "actis-client-readonly-token"
VALID_ADMIN_KEY = "actis-admin-secret-token"


@pytest.fixture(autouse=True)
def reset_rate_limiter_and_db():
    """Resets in-memory rate limiter and ensures test database is initialized."""
    rate_limiter.reset()
    init_central_database()
    initialize_database()
    yield
    rate_limiter.reset()


# ============================================================================
# 1. API Health and Authentication Tests
# ============================================================================


class TestCentralAPIAuthenticationAndHealth:
    def test_health_v1_and_legacy_endpoints(self):
        # Versioned v1 endpoint
        resp_v1 = client.get("/api/v1/health")
        assert resp_v1.status_code == 200
        data_v1 = resp_v1.json()
        assert data_v1["status"] in ("ONLINE", "DEGRADED")
        assert data_v1["api_version"] == "v1"
        assert data_v1["database_status"] == "HEALTHY"
        assert "total_indicators" in data_v1

        # Legacy endpoint
        resp_leg = client.get("/api/health")
        assert resp_leg.status_code == 200
        data_leg = resp_leg.json()
        assert data_leg["status"] == data_v1["status"]

    def test_client_info_with_valid_key(self):
        resp = client.get(
            "/api/v1/client/me",
            headers={"X-ACTIS-API-Key": VALID_CONTRIBUTOR_KEY},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["client_id"] == "actis-endpoint-node-1"
        assert "contribute" in data["roles"]
        assert "read" in data["roles"]
        assert data["is_active"] is True

    def test_bearer_authorization_header_supported(self):
        resp = client.get(
            "/api/v1/client/me",
            headers={"Authorization": f"Bearer {VALID_READONLY_KEY}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["client_id"] == "actis-readonly-client"
        assert "read" in data["roles"]

    def test_missing_credentials_returns_401(self):
        resp = client.get("/api/v1/client/me")
        assert resp.status_code == 401
        assert "Missing authentication credentials" in resp.json()["detail"]

    def test_invalid_key_returns_403(self):
        resp = client.get(
            "/api/v1/client/me",
            headers={"X-ACTIS-API-Key": "completely-invalid-token-12345"},
        )
        assert resp.status_code == 403
        assert "Invalid" in resp.json()["detail"]

    def test_rate_limiting_enforced_when_exceeded(self):
        # actis-readonly-client has 60 rpm limit
        # Perform 61 quick requests
        rate_limited = False
        for _ in range(70):
            r = client.get(
                "/api/v1/client/me",
                headers={"X-ACTIS-API-Key": VALID_READONLY_KEY},
            )
            if r.status_code == 429:
                rate_limited = True
                assert "Rate limit exceeded" in r.json()["detail"]
                break
        assert rate_limited is True


# ============================================================================
# 2. Indicator Lookup and Query Tests
# ============================================================================


class TestCentralAPIIndicatorRetrieval:
    def test_lookup_existing_seed_indicator(self):
        resp = client.get("/api/v1/indicators/domain/paypal-security-verification.xyz")
        assert resp.status_code == 200
        data = resp.json()
        assert data["found"] is True
        assert data["indicator"]["threat_type"] == "Phishing"
        assert data["indicator"]["status"] == "CONFIRMED"
        assert "credential_theft" in data["indicator"]["tags"]

    def test_lookup_nonexistent_indicator(self):
        resp = client.get("/api/v1/indicators/domain/totally-clean-unknown-domain-999.org")
        assert resp.status_code == 200
        data = resp.json()
        assert data["found"] is False
        assert data["indicator"] is None
        assert "not recorded" in data["message"]

    def test_lookup_private_ip_is_shielded(self):
        resp = client.get("/api/v1/indicators/ip/192.168.1.100")
        assert resp.status_code == 200
        data = resp.json()
        assert data["found"] is False
        assert "Private" in data["message"]

    def test_paged_query_with_envelope_and_filters(self):
        resp = client.get("/api/v1/indicators?min_confidence=0.5&limit=10&offset=0")
        assert resp.status_code == 200
        data = resp.json()
        assert "total" in data
        assert "limit" in data
        assert "has_more" in data
        assert isinstance(data["indicators"], list)
        assert len(data["indicators"]) >= 2

    def test_authenticated_post_sync_pull(self):
        payload = {
            "min_confidence": 0.8,
            "status_filter": "CONFIRMED",
            "limit": 10,
            "offset": 0,
        }
        resp = client.post(
            "/api/v1/sync/pull",
            json=payload,
            headers={"X-ACTIS-API-Key": VALID_READONLY_KEY},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 2
        assert any(i["indicator_type"] == "sha256" for i in data["indicators"])


# ============================================================================
# 3. Candidate Contribution and Anti-Poisoning Policy Tests
# ============================================================================


class TestCandidateContributionAndAntiPoisoning:
    def test_readonly_client_cannot_contribute(self):
        payload = {
            "indicator_type": "sha256",
            "indicator_value": "a" * 64,
            "threat_type": "Trojan",
            "threat_name": "TestTrojan",
        }
        resp = client.post(
            "/api/v1/contributions",
            json=payload,
            headers={"X-ACTIS-API-Key": VALID_READONLY_KEY},
        )
        assert resp.status_code == 403
        assert "lacks required role 'contribute'" in resp.json()["detail"]

    def test_contribute_candidate_indicator_forces_candidate_status(self):
        test_sha = uuid.uuid4().hex + uuid.uuid4().hex
        payload = {
            "indicator_type": "sha256",
            "indicator_value": test_sha,
            "threat_type": "Ransomware",
            "threat_name": "CandidatePoisonAttempt",
            "confidence": 0.99,  # High confidence
            "tags": ["malware", "ransomware"],
            "notes": "Observed on endpoint",
        }
        resp = client.post(
            "/api/v1/contributions",
            json=payload,
            headers={"X-ACTIS-API-Key": VALID_CONTRIBUTOR_KEY},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        # Must be CANDIDATE, cannot self-promote to CONFIRMED!
        assert data["status"] == "CANDIDATE"
        assert data["review_status"] == "PENDING"

    def test_contribute_private_ip_rejected_with_422(self):
        payload = {
            "indicator_type": "ip",
            "indicator_value": "10.0.0.1",
            "threat_type": "LateralMovement",
        }
        resp = client.post(
            "/api/v1/contributions",
            json=payload,
            headers={"X-ACTIS-API-Key": VALID_CONTRIBUTOR_KEY},
        )
        assert resp.status_code == 422
        assert "Private" in resp.json()["detail"]

    def test_contribute_malformed_hash_rejected_with_422(self):
        payload = {
            "indicator_type": "sha256",
            "indicator_value": "not-a-valid-sha256",
            "threat_type": "Malware",
        }
        resp = client.post(
            "/api/v1/contributions",
            json=payload,
            headers={"X-ACTIS-API-Key": VALID_CONTRIBUTOR_KEY},
        )
        assert resp.status_code == 422
        assert "Invalid indicator format" in resp.json()["detail"]

    def test_admin_review_promotes_candidate_to_confirmed(self):
        test_sha = uuid.uuid4().hex + uuid.uuid4().hex
        # 1. Contributor submits candidate
        submit_resp = client.post(
            "/api/v1/contributions",
            json={
                "indicator_type": "sha256",
                "indicator_value": test_sha,
                "threat_type": "Trojan",
                "threat_name": "PendingReviewTrojan",
            },
            headers={"X-ACTIS-API-Key": VALID_CONTRIBUTOR_KEY},
        )
        assert submit_resp.status_code == 200
        ind_id = submit_resp.json()["indicator_id"]
        assert submit_resp.json()["status"] == "CANDIDATE"

        # 2. Non-admin cannot review
        review_denied = client.post(
            f"/api/v1/admin/indicators/{ind_id}/review",
            json={"action": "APPROVE", "notes": "Unauthorized approval"},
            headers={"X-ACTIS-API-Key": VALID_CONTRIBUTOR_KEY},
        )
        assert review_denied.status_code == 403

        # 3. Admin approves and promotes to CONFIRMED
        review_ok = client.post(
            f"/api/v1/admin/indicators/{ind_id}/review",
            json={"action": "APPROVE", "notes": "Verified by SOC analyst"},
            headers={"X-ACTIS-API-Key": VALID_ADMIN_KEY},
        )
        assert review_ok.status_code == 200
        assert review_ok.json()["new_status"] == "CONFIRMED"
        assert review_ok.json()["new_review_status"] == "APPROVED"

        # 4. Lookup now reflects CONFIRMED status
        lookup_resp = client.get(f"/api/v1/indicators/sha256/{test_sha}")
        assert lookup_resp.status_code == 200
        assert lookup_resp.json()["indicator"]["status"] == "CONFIRMED"


# ============================================================================
# 4. CentralACTISFeedAdapter Synchronization Tests
# ============================================================================


class TestCentralACTISFeedAdapter:
    def test_adapter_fetch_success_with_mocked_central_service(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "total": 2,
            "limit": 500,
            "offset": 0,
            "has_more": False,
            "indicators": [
                {
                    "indicator_type": "url",
                    "indicator_value": "http://evil-central-campaign.com/payload.exe",
                    "threat_type": "Dropper",
                    "threat_name": "CentralDropper",
                    "confidence": 0.95,
                    "status": "CONFIRMED",
                    "tags": ["dropper", "active"],
                    "verified_at": "2026-10-10T12:00:00Z",
                },
                {
                    "indicator_type": "ip",
                    "indicator_value": "185.220.101.5",
                    "threat_type": "C2",
                    "threat_name": "CentralC2",
                    "confidence": 0.88,
                    "status": "CONFIRMED",
                    "tags": ["c2", "tor_exit"],
                    "verified_at": "2026-10-10T12:00:00Z",
                },
            ],
        }

        adapter = CentralACTISFeedAdapter(
            backend_url="http://mock-central-actis:8000",
            api_key="mock-api-key",
            enabled=True,
        )

        with patch("requests.get", return_value=mock_response):
            records, result = adapter.fetch_feed(max_records=500)

        assert result.status == SyncStatus.SUCCESS
        assert result.records_received == 2
        assert result.records_validated == 2
        assert result.records_rejected == 0
        assert len(records) == 2
        assert adapter.provider_name == "CentralACTIS"
        assert records[0].indicator_type == IndicatorType.URL
        assert records[1].indicator_type == IndicatorType.IP_ADDRESS

    def test_adapter_shields_private_ips_from_central_response(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "total": 2,
            "indicators": [
                {
                    "indicator_type": "ip",
                    "indicator_value": "192.168.1.1",  # Private
                    "threat_type": "C2",
                },
                {
                    "indicator_type": "ip",
                    "indicator_value": "45.33.32.156",  # Public routable
                    "threat_type": "Scanner",
                },
            ],
        }

        adapter = CentralACTISFeedAdapter(enabled=True)
        with patch("requests.get", return_value=mock_response):
            records, result = adapter.fetch_feed(max_records=500)

        assert result.status == SyncStatus.SUCCESS
        assert result.records_received == 2
        assert result.records_validated == 1
        assert result.records_rejected == 1
        assert records[0].indicator == "45.33.32.156"

    def test_adapter_timeout_isolation(self):
        adapter = CentralACTISFeedAdapter(enabled=True, timeout=1.0)
        with patch("requests.get", side_effect=requests.exceptions.Timeout("Connection timed out")):
            records, result = adapter.fetch_feed()

        assert result.status == SyncStatus.FAILED
        assert result.error_category == SyncErrorCategory.NETWORK_TIMEOUT
        assert records == []

    def test_adapter_connection_error_isolation(self):
        adapter = CentralACTISFeedAdapter(enabled=True)
        with patch("requests.get", side_effect=requests.exceptions.ConnectionError("Connection refused")):
            records, result = adapter.fetch_feed()

        assert result.status == SyncStatus.FAILED
        assert result.error_category == SyncErrorCategory.CONNECTION_ERROR
        assert records == []

    def test_adapter_auth_failure_401(self):
        mock_err = MagicMock()
        mock_err.status_code = 401
        adapter = CentralACTISFeedAdapter(enabled=True)
        with patch("requests.get", return_value=mock_err):
            records, result = adapter.fetch_feed()

        assert result.status == SyncStatus.FAILED
        assert result.error_category == SyncErrorCategory.AUTH_FAILURE

    def test_adapter_rate_limit_429(self):
        mock_err = MagicMock()
        mock_err.status_code = 429
        adapter = CentralACTISFeedAdapter(enabled=True)
        with patch("requests.get", return_value=mock_err):
            records, result = adapter.fetch_feed()

        assert result.status == SyncStatus.FAILED
        assert result.error_category == SyncErrorCategory.RATE_LIMITED

    def test_adapter_malformed_json_resilience(self):
        mock_bad = MagicMock()
        mock_bad.status_code = 200
        mock_bad.json.side_effect = json.JSONDecodeError("Expecting value", "bad json", 0)
        adapter = CentralACTISFeedAdapter(enabled=True)
        with patch("requests.get", return_value=mock_bad):
            records, result = adapter.fetch_feed()

        assert result.status == SyncStatus.FAILED
        assert result.error_category == SyncErrorCategory.MALFORMED_RESPONSE

    def test_adapter_disabled_does_not_execute(self):
        adapter = CentralACTISFeedAdapter(enabled=False)
        records, result = adapter.fetch_feed()
        assert result.status == SyncStatus.DISABLED
        assert records == []


# ============================================================================
# 5. Database Persistence and Client Synchronization Tests
# ============================================================================


class TestCentralDatabasePersistenceAndClientSync:
    def test_central_feed_records_persisted_idempotently_in_local_db(self):
        unique_token = uuid.uuid4().hex[:8]
        test_url = f"http://central-threat-{unique_token}.net/malware.exe"
        test_ip = f"185.220.{random.randint(10, 240)}.{random.randint(1, 250)}"

        records = [
            FeedRecord(
                indicator=test_url,
                indicator_type=IndicatorType.URL,
                source_feed="central_actis_network",
                confidence=0.92,
                status="CONFIRMED",
                threat_type="Malware",
                threat_name="CentralDownloader",
                tags=["central", "malware"],
                metadata={"notes": "Central network observation"},
            ),
            FeedRecord(
                indicator=test_ip,
                indicator_type=IndicatorType.IP_ADDRESS,
                source_feed="central_actis_network",
                confidence=0.85,
                status="CONFIRMED",
                threat_type="C2",
                threat_name="CentralC2",
                tags=["c2"],
                metadata={"notes": "Central network observation"},
            ),
        ]

        # First upsert
        ins1, upd1, _ = upsert_feed_records([r.to_dict() for r in records])
        assert ins1 == 2
        assert upd1 == 0

        # Duplicate upsert: zero new rows, unchanged records preserved
        ins2, upd2, unc2 = upsert_feed_records([r.to_dict() for r in records])
        assert ins2 == 0
        assert unc2 == 2

    def test_sync_manager_pull_verified_intelligence(self):
        unique_token = uuid.uuid4().hex[:8]
        test_sha = f"{unique_token}" + "0" * (64 - len(unique_token))

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "total": 1,
            "indicators": [
                {
                    "indicator_type": "sha256",
                    "indicator_value": test_sha,
                    "threat_type": "Ransomware",
                    "threat_name": "SyncManagerTest",
                    "confidence": 0.95,
                    "status": "CONFIRMED",
                    "tags": ["test"],
                }
            ],
        }

        mgr = SyncManager(backend_url="http://mock-backend:8000")
        with patch("requests.get", return_value=mock_resp):
            res = mgr.pull_verified_intelligence()

        assert res["success"] is True
        assert res["synced_count"] >= 1
        assert res["inserted"] >= 1

    def test_sync_manager_push_verified_threat(self):
        unique_token = uuid.uuid4().hex[:8]
        test_sha = f"{unique_token}" + "1" * (64 - len(unique_token))

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "success": True,
            "indicator_id": 101,
            "indicator_type": "sha256",
            "indicator_value": test_sha,
            "status": "CANDIDATE",
            "review_status": "PENDING",
            "message": "Candidate indicator received.",
        }

        mgr = SyncManager(backend_url="http://mock-backend:8000")
        with patch("requests.post", return_value=mock_resp):
            res = mgr.push_verified_threat(
                indicator_type="sha256",
                indicator_value=test_sha,
                threat_type="Trojan",
                threat_name="LocalSample",
            )

        assert res["success"] is True
        assert res["data"]["status"] == "CANDIDATE"


# ============================================================================
# 6. Unified Architecture Integration Tests
# ============================================================================


class TestUnifiedPipelineCentralTIIntegration:
    def test_central_record_retrieved_by_local_threat_lookup(self):
        unique_token = uuid.uuid4().hex[:8]
        test_url = f"http://central-verified-{unique_token}.com/gate.php"

        # Import record into local DB
        record = FeedRecord(
            indicator=test_url,
            indicator_type=IndicatorType.URL,
            source_feed="central_actis_network",
            confidence=0.96,
            status="CONFIRMED",
            threat_type="Phishing",
            threat_name="CredentialHarvester",
            tags=["central_network", "phishing"],
            metadata={"notes": "Synchronized from central intelligence fleet."},
        )
        upsert_feed_records([record.to_dict()])

        # Query via ThreatLookup
        tl = ThreatLookup()
        intel = tl.lookup_url(test_url, query_external=False)

        assert intel["is_known_threat"] is True
        assert intel["outcome_state"] == "FOUND_MALICIOUS"
        evidence = intel["primary_evidence"]
        assert evidence is not None
        assert evidence.confidence >= 0.90
        assert evidence.raw_data.get("source") == "central_actis_network"

    def test_central_record_evaluated_by_threat_detector_analysis(self):
        unique_token = uuid.uuid4().hex[:8]
        test_url = f"http://confirmed-central-threat-{unique_token}.biz/stealer.exe"

        record = FeedRecord(
            indicator=test_url,
            indicator_type=IndicatorType.URL,
            source_feed="central_actis_network",
            confidence=0.95,
            status="CONFIRMED",
            threat_type="Malware",
            threat_name="InfoStealer",
            tags=["stealer"],
        )
        upsert_feed_records([record.to_dict()])

        # Analyze URL using ThreatDetector
        res = threat_detector.analyze_url(test_url, check_external=False)
        assert res["is_threat"] is True
        assert res["score"] >= 60.0
        assert res["risk_level"] in ("HIGH", "CRITICAL")
        # Evidence from threat database contributed to findings
        assert any("threat intelligence database" in reason for reason in res["reasons"])

    def test_local_scanning_functions_when_central_backend_is_offline(self):
        # Even if central backend is completely offline, local scanning must remain fully functional
        clean_url = "http://example.com/safe-article.html"
        res = analysis_orchestrator.analyze_url(clean_url, check_external=False)
        assert res is not None
        assert "score" in res
        assert "is_threat" in res
