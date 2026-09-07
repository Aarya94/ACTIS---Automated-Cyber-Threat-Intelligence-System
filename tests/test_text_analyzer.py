"""
Unit Tests for Message & Email Text Analyzer
"""

import pytest
from scanners.text_analyzer import TextAnalyzer


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
