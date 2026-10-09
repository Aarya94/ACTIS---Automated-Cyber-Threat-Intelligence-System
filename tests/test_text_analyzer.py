"""
Unit Tests for Message & Email Text Analyzer
"""

from unittest.mock import MagicMock
import pytest
from scanners.text_analyzer import TextAnalyzer, MessageScanResult
import scanners.text_analyzer as text_analyzer_module


def test_extract_urls_multiple_formats():
    text = (
        "Check this out: https://secure-bank.com/login and also "
        "http://test.org/path?id=123, or visit www.example.net for details!"
    )
    urls = TextAnalyzer.extract_urls(text)
    assert len(urls) == 3
    assert "https://secure-bank.com/login" in urls
    assert "http://test.org/path?id=123" in urls
    assert "www.example.net" in urls


def test_social_engineering_detection():
    urgent_msg = "URGENT: Your account has been suspended! Please verify your password immediately."
    se = TextAnalyzer.evaluate_social_engineering(urgent_msg)
    assert se["has_urgency"] is True
    assert se["has_credential_request"] is True
    assert se["se_score"] >= 40

    benign_msg = "Hey Alice, see you at lunch tomorrow around noon."
    se_benign = TextAnalyzer.evaluate_social_engineering(benign_msg)
    assert se_benign["has_urgency"] is False
    assert se_benign["has_credential_request"] is False
    assert se_benign["se_score"] == 0


def test_end_to_end_message_analysis():
    phish_email = (
        "SECURITY ALERT: Unauthorized access detected. You must confirm your password "
        "within 24 hours at http://paypal-security-verification.xyz/login.php to prevent account termination."
    )
    res = TextAnalyzer.analyze_message(phish_email)
    assert res["url_count"] == 1
    assert res["is_suspicious_message"] is True
    assert res["overall_risk_level"] in ["HIGH", "CRITICAL"]
    assert res["threat_urls_count"] >= 1


# ==============================================================================
# Day 7 Hardening: Deduplication, Delegation, and Boundary Tests
# ==============================================================================

def test_extract_urls_boundary_and_punctuation_handling():
    # Trailing punctuation in sentences
    sample = "Please check https://example.com/login. Also visit https://example.org, thank you!"
    urls = TextAnalyzer.extract_urls(sample)
    assert "https://example.com/login" in urls
    assert "https://example.org" in urls
    assert not any(u.endswith((".", ",")) for u in urls)

    # Parentheses and brackets
    bracketed = "Look at (https://example.com/parens) and [https://example.org/brackets]."
    b_urls = TextAnalyzer.extract_urls(bracketed)
    assert "https://example.com/parens" in b_urls
    assert "https://example.org/brackets" in b_urls

    # Quotes
    quoted = "Quoted 'https://example.com/single' and \"https://example.com/double\"."
    q_urls = TextAnalyzer.extract_urls(quoted)
    assert "https://example.com/single" in q_urls
    assert "https://example.com/double" in q_urls

    # Balanced parens inside URL paths (e.g., Wikipedia)
    wiki = "Read https://en.wikipedia.org/wiki/Phishing_(security) for info."
    w_urls = TextAnalyzer.extract_urls(wiki)
    assert "https://en.wikipedia.org/wiki/Phishing_(security)" in w_urls


def test_message_url_canonical_deduplication():
    # Repeated URLs with varying casing and punctuation
    text = (
        "Visit https://example.com/portal. "
        "Again visit https://example.com/portal. "
        "And visit HTTPS://EXAMPLE.COM/portal."
    )
    canonical_urls, counts = TextAnalyzer.extract_canonical_urls(text)
    assert len(canonical_urls) == 1
    assert canonical_urls[0] == "https://example.com/portal"
    assert counts["https://example.com/portal"] == 3


def test_100_repeated_urls_delegates_once_to_scanner(monkeypatch):
    # Message with 100 identical URLs
    repeated_url = "https://example.com/verify"
    text = "Action required: " + (repeated_url + " ") * 100

    scan_call_count = 0
    original_scan = text_analyzer_module.scan_url_logic

    def mock_scan(url, check_external=False):
        nonlocal scan_call_count
        scan_call_count += 1
        return original_scan(url, check_external=check_external)

    monkeypatch.setattr(text_analyzer_module, "scan_url_logic", mock_scan)

    res = TextAnalyzer.analyze_message(text)

    # Must invoke scanner EXACTLY ONCE despite 100 occurrences
    assert scan_call_count == 1
    assert res["total_url_count"] == 100
    assert res["unique_url_count"] == 1
    assert len(res["url_results"]) == 1
    assert res["url_results"][0]["occurrence_count"] == 100


def test_message_scanner_delegates_to_common_url_scanner_path(monkeypatch):
    """
    CRITICAL DAY 7 ARCHITECTURAL TEST:
    Verifies that TextAnalyzer delegates per-URL analysis to scan_url_logic
    and does NOT duplicate TI lookups, feature extraction, or model calls.
    """
    text = "Visit https://trusted-partner.com/update"

    delegation_verified = False

    def mock_scan(url, check_external=False):
        nonlocal delegation_verified
        delegation_verified = True
        return {
            "target_type": "url",
            "url": url,
            "domain": "trusted-partner.com",
            "score": 15.0,
            "risk_level": "LOW",
            "is_threat": False,
            "reasons": ["Mocked scan result for delegation test."],
            "recommended_action": "No action needed.",
            "ml_result": {},
            "heuristic_result": {},
            "threat_intel": {}
        }

    monkeypatch.setattr(text_analyzer_module, "scan_url_logic", mock_scan)

    res = TextAnalyzer.analyze_message(text)
    assert delegation_verified is True
    assert res["url_results"][0]["score"] == 15.0
    assert res["url_results"][0]["risk_level"] == "LOW"


def test_empty_none_and_no_url_messages():
    # None input
    res_none = TextAnalyzer.analyze_message(None)
    assert res_none["url_count"] == 0
    assert res_none["overall_risk_level"] == "LOW"

    # Empty string
    res_empty = TextAnalyzer.analyze_message("   ")
    assert res_empty["url_count"] == 0
    assert res_empty["overall_score"] == 0.0

    # Message without URLs
    no_url_msg = "Hello team, tomorrow's meeting has been moved to 3pm."
    res_no_url = TextAnalyzer.analyze_message(no_url_msg)
    assert res_no_url["url_count"] == 0
    assert res_no_url["is_suspicious_message"] is False
    assert res_no_url["overall_risk_level"] == "LOW"


def test_structured_message_scan_result_contract():
    sample = "Urgent: review http://paypal-security-verification.xyz/login.php right now."
    result = TextAnalyzer.analyze_message_structured(sample)

    assert isinstance(result, MessageScanResult)
    assert result.total_url_count == 1
    assert result.unique_url_count == 1
    assert result.threat_urls_count >= 1
    assert result.overall_risk_level in ["HIGH", "CRITICAL"]
    assert len(result.explanation_summary) > 0
    assert len(result.recommended_action) > 0

    # Serialization test
    d = result.to_dict()
    assert isinstance(d, dict)
    assert "explanation_summary" in d
    assert "recommended_action" in d
    assert "social_engineering" in d
    assert d["overall_score"] == result.overall_score

