"""
Unit Tests for ACTIS Multi-Criteria Risk Engine
"""

import pytest
from detection_engine.risk_engine import RiskEngine


def test_confirmed_threat_fast_track():
    known_intel = {
        "found": True,
        "status": "CONFIRMED",
        "confidence": 1.0,
        "threat_type": "Ransomware"
    }
    res = RiskEngine.calculate_risk(
        target_type="hash",
        target_value="test_hash_123",
        known_intel=known_intel
    )
    assert res["risk_level"] == "CRITICAL"
    assert res["score"] >= 90.0
    assert any("CONFIRMED threat" in r for r in res["reasons"])


def test_benign_low_risk():
    ml_res = {
        "available": True,
        "probability": 0.05,
        "is_malware": False,
        "model_name": "test_model"
    }
    res = RiskEngine.calculate_risk(
        target_type="file",
        target_value="safe.exe",
        ml_result=ml_res
    )
    assert res["risk_level"] == "LOW"
    assert res["score"] < 35.0
    assert res["is_threat"] is False


def test_combined_ml_and_heuristic_escalation():
    ml_res = {
        "available": True,
        "probability": 0.85,
        "is_phishing": True,
        "model_name": "phishing_rf"
    }
    heur_res = {
        "heuristic_score": 60.0,
        "rules_triggered": ["RULE_URL_SUSPICIOUS_TLD", "RULE_URL_IP_HOST"],
        "reasons": ["Uses IP host", "Suspicious TLD"]
    }
    res = RiskEngine.calculate_risk(
        target_type="url",
        target_value="http://192.168.1.1/login.xyz",
        ml_result=ml_res,
        heuristic_result=heur_res
    )
    assert res["risk_level"] in ["HIGH", "CRITICAL"]
    assert res["score"] >= 60.0
    assert res["is_threat"] is True
    assert len(res["reasons"]) >= 3
