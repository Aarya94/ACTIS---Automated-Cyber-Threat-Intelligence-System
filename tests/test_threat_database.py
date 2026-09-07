"""
Unit Tests for Local Threat Database and Scan History
"""

import pytest
from reports.threat_database import (
    lookup_indicator,
    register_indicator,
    record_detection,
    get_db_connection
)
from reports.scan_database import (
    create_scan_session,
    finish_scan_session,
    get_system_statistics,
    get_recent_detections
)


def test_seed_indicators_present():
    # WannaCry seed hash
    wc = lookup_indicator("sha256", "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa")
    assert wc["found"] is True
    assert wc["threat_name"] == "WannaCry"
    assert wc["status"] == "CONFIRMED"

    # Phishing domain seed
    ph = lookup_indicator("domain", "paypal-security-verification.xyz")
    assert ph["found"] is True
    assert ph["threat_type"] == "Phishing"


def test_register_and_lookup_custom_indicator():
    test_val = "suspicious-test-domain-99.top"
    ind_id = register_indicator(
        indicator_type="domain",
        indicator_value=test_val,
        source="unit_test",
        confidence=0.88,
        status="SUSPICIOUS",
        threat_type="Phishing",
        threat_name="UnitTestThreat"
    )
    assert ind_id > 0

    found = lookup_indicator("domain", test_val)
    assert found["found"] is True
    assert found["threat_name"] == "UnitTestThreat"
    assert found["confidence"] == 0.88


def test_scan_session_lifecycle():
    scan_id = create_scan_session("quick", "Test Target")
    assert scan_id > 0

    finish_scan_session(scan_id, status="completed", files_scanned=10, threats_found=1)
    
    stats = get_system_statistics()
    assert stats["total_scans"] >= 1
    assert stats["total_files_scanned"] >= 10
