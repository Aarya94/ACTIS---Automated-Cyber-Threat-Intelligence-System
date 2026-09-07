"""
Unit Tests for Central Threat Intelligence REST API Backend
"""

import pytest
from fastapi.testclient import TestClient
from backend.api import app

client = TestClient(app)
VALID_API_KEY = "actis-client-default-secret-token"


def test_health_endpoint():
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ONLINE"
    assert "total_indicators" in data


def test_indicator_lookup():
    resp = client.get("/api/indicator/domain/paypal-security-verification.xyz")
    assert resp.status_code == 200
    data = resp.json()
    assert data["found"] is True
    assert data["indicator"]["threat_type"] == "Phishing"


def test_unauthenticated_submission():
    payload = {
        "indicator_type": "sha256",
        "indicator_value": "b" * 64,
        "threat_type": "Malware",
        "threat_name": "UnauthorizedTest"
    }
    resp = client.post("/api/indicator", json=payload)
    assert resp.status_code == 401


def test_authenticated_submission_and_sync():
    test_hash = "c" * 64
    payload = {
        "indicator_type": "sha256",
        "indicator_value": test_hash,
        "threat_type": "Ransomware",
        "threat_name": "AuthenticatedSubmissionTest",
        "confidence": 0.95,
        "status": "CONFIRMED",
        "notes": "Verified by ACTIS automated unit test suite"
    }
    resp = client.post(
        "/api/indicator",
        json=payload,
        headers={"X-ACTIS-API-Key": VALID_API_KEY}
    )
    assert resp.status_code == 200
    created = resp.json()
    assert created["indicator_value"] == test_hash
    assert created["status"] == "CONFIRMED"

    # Verify sync endpoint retrieves it
    sync_resp = client.get("/api/indicators?min_confidence=0.9&status_filter=CONFIRMED")
    assert sync_resp.status_code == 200
    sync_data = sync_resp.json()
    assert any(i["indicator_value"] == test_hash for i in sync_data["indicators"])
