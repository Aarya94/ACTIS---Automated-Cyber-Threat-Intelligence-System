"""
Unit Tests for ACTIS URL Scanner, Validation, Normalization, and Feature Extraction
"""

import pytest
from scanners.url_scanner import (
    normalize_url,
    extract_domain,
    validate_url,
    is_valid_url,
    extract_url_features,
    extract_url_features_dict,
    validate_extracted_features,
    scan_url_logic,
    PHISHING_URL_FEATURE_NAMES,
    MAX_URL_LENGTH
)
from detection_engine.rule_engine import RuleEngine
from detection_engine.threat_detector import threat_detector


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


# ==============================================================================
# Day 7 Hardening & Edge-Case Test Suite
# ==============================================================================

def test_url_validation_valid_cases():
    valid_samples = [
        "https://example.com",
        "http://example.com/path/to/resource",
        "https://sub.domain.example.co.uk:8080/app?param=value#frag",
        "http://192.168.1.100/status",
        "https://user:pass@vault.internal.net:8443/api"
    ]
    for url in valid_samples:
        valid, err = validate_url(url)
        assert valid is True, f"Failed for {url}: {err}"
        assert is_valid_url(url) is True


def test_url_validation_invalid_and_hostile_cases():
    assert validate_url(None)[0] is False
    assert validate_url("")[0] is False
    assert validate_url("   ")[0] is False
    assert validate_url(12345)[0] is False
    assert validate_url("ftp://unsupported-scheme.com")[0] is False
    assert validate_url("javascript:alert(1)")[0] is False
    assert validate_url("http://")[0] is False
    assert validate_url("http://   ")[0] is False
    assert validate_url("http://exam ple.com/path")[0] is False
    assert validate_url("http://example.com/bad\x00byte")[0] is False

    # Excessively long URL
    too_long = "http://example.com/" + ("a" * (MAX_URL_LENGTH + 10))
    valid, err = validate_url(too_long)
    assert valid is False
    assert "exceeds maximum allowed length" in err


def test_canonical_normalization_hardening():
    # Mixed case and default port stripping
    assert normalize_url("  HTTPS://WWW.EXAMPLE.COM:443/login  ") == "https://example.com/login"
    assert normalize_url("http://www.example.com:80/index.html") == "http://example.com/index.html"
    
    # Non-standard port preserved
    assert normalize_url("http://example.com:8080/dashboard") == "http://example.com:8080/dashboard"
    assert normalize_url("https://example.com:8443/secure") == "https://example.com:8443/secure"

    # Enclosing quotes and brackets stripped
    assert normalize_url("\"https://example.com/api\"") == "https://example.com/api"
    assert normalize_url("<https://example.com/about>") == "https://example.com/about"
    assert normalize_url("(https://example.com/help)") == "https://example.com/help"

    # Query parameters and fragments preserved
    full_url = "https://example.com/search?q=cyber&sort=desc#results"
    assert normalize_url(full_url) == full_url

    # Safe null and non-string handling
    assert normalize_url(None) == ""
    assert normalize_url("") == ""
    assert normalize_url("   ") == ""


def test_extract_domain():
    assert extract_domain("https://www.example.com/path") == "example.com"
    assert extract_domain("http://sub.domain.org:8080/") == "sub.domain.org"
    assert extract_domain("https://paypal.com") == "paypal.com"
    assert extract_domain(None) == ""
    assert extract_domain("") == ""


def test_feature_extraction_contract_and_dictionary():
    assert len(PHISHING_URL_FEATURE_NAMES) == 19
    url = "https://legit-site.com/login?u=admin&ref=home"
    feat_dict = extract_url_features_dict(url)
    assert len(feat_dict) == 19
    for name in PHISHING_URL_FEATURE_NAMES:
        assert name in feat_dict
        assert isinstance(feat_dict[name], (int, float))

    # Validation helper
    features = extract_url_features(url)
    valid, err = validate_extracted_features(features)
    assert valid is True
    assert err is None

    # Safe handling of None / empty input
    none_feats = extract_url_features(None)
    assert len(none_feats) == 19
    assert all(x == 0 for x in none_feats)

    # Invalid feature vectors caught
    assert validate_extracted_features([1, 2, 3])[0] is False
    assert validate_extracted_features("not a list")[0] is False
    assert validate_extracted_features([float("nan")] * 19)[0] is False


def test_expanded_url_heuristics():
    # Long URL rule
    long_url = "https://example.com/" + ("subpath/" * 25)
    res_long = RuleEngine.evaluate_url(long_url)
    assert "RULE_URL_EXCESSIVE_LENGTH" in res_long["rules_triggered"]

    # Suspicious encoding rule
    encoded_url = "https://example.com/login%20page%2fadmin%40portal"
    res_enc = RuleEngine.evaluate_url(encoded_url)
    assert "RULE_URL_SUSPICIOUS_ENCODING" in res_enc["rules_triggered"]

    # Non-standard service port rule
    port_url = "http://example.com:1337/shell"
    res_port = RuleEngine.evaluate_url(port_url)
    assert "RULE_URL_SUSPICIOUS_PORT" in res_port["rules_triggered"]

    # Safe null and empty handling
    assert RuleEngine.evaluate_url(None)["score"] == 0
    assert RuleEngine.evaluate_url("")["score"] == 0


def test_scan_url_logic_safe_error_handling_and_caching():
    threat_detector.clear_cache()

    # Invalid input fails safely without raising exceptions
    invalid_res = scan_url_logic(None)
    assert invalid_res["is_valid"] is False
    assert invalid_res["score"] == 0.0
    assert invalid_res["is_threat"] is False
    assert "Invalid URL" in invalid_res["reasons"][0]

    # In-memory scan cache verification
    url = "https://google.com"
    res1 = scan_url_logic(url)
    assert res1["from_cache"] is False

    res2 = scan_url_logic(url)
    assert res2["from_cache"] is True
    assert res1["score"] == res2["score"]
    assert res1["risk_level"] == res2["risk_level"]

