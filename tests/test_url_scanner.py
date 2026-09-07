"""
Unit Tests for ACTIS URL Scanner and Feature Extraction
"""

import pytest
from scanners.url_scanner import normalize_url, extract_url_features, scan_url_logic
from detection_engine.rule_engine import RuleEngine


def test_normalize_url():
    assert normalize_url("example.com") == "http://example.com"
    assert normalize_url("www.google.com/search?q=test") == "http://google.com/search?q=test"
    assert normalize_url("https://WWW.PAYPAL.COM/login") == "https://paypal.com/login"


def test_extract_url_features_length_and_types():
    url = "https://example.com/test-page?a=1&b=2#sec"
    features = extract_url_features(url)
    assert len(features) == 19
    assert all(isinstance(x, (int, float)) for x in features)
    # Check url_length
    assert features[0] == len(normalize_url(url))
    # Check count of dots
    assert features[1] == normalize_url(url).count(".")


def test_rule_engine_url_heuristics():
    # 1. IP Host
    res1 = RuleEngine.evaluate_url("http://192.168.1.1/admin")
    assert "RULE_URL_IP_HOST" in res1["rules_triggered"]
    assert res1["heuristic_score"] >= 35

    # 2. Suspicious TLD & sensitive keyword
    res2 = RuleEngine.evaluate_url("http://secure-account-verify.xyz/login.php")
    assert "RULE_URL_SUSPICIOUS_TLD" in res2["rules_triggered"]
    assert "RULE_URL_CREDENTIAL_KEYWORD" in res2["rules_triggered"]
    assert res2["heuristic_score"] >= 45


def test_scan_url_logic_safe_and_phishing():
    # Safe domain
    safe_res = scan_url_logic("https://google.com")
    assert safe_res["risk_level"] in ["LOW", "MEDIUM"]
    assert safe_res["score"] < 50

    # High-risk phishing URL
    phish_res = scan_url_logic("http://paypal-security-verification.xyz/login.php")
    assert phish_res["risk_level"] in ["HIGH", "CRITICAL"]
    assert phish_res["is_threat"] is True
    assert len(phish_res["reasons"]) > 0
