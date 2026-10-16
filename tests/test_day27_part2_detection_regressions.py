"""
ACTIS Day 27 — Part 2: Phishing and Benign URL Regression Tests.
Protects against:
1. False-positive regressions on benign URLs with percent-encoded query parameters.
2. Safe attachment extensions (.pdf, .docx, .xlsx, .png) improperly flagged as dangerous.
3. Clean HTML messages with matching anchor domains falsely triggering display mismatch.
4. Preservation of core phishing detections (explicit userinfo deception, standard executable attachments).
5. Protection of historical benign baseline samples.
"""

import json
import pytest
from detection_engine.threat_detector import ThreatDetector
from detection_engine.rule_engine import RuleEngine
from scanners.url_scanner import validate_url, deobfuscate_and_analyze_url
from scanners.mime_parser import DANGEROUS_ATTACHMENT_EXTENSIONS, SafeMIMEParser
from benchmarks.message_analysis.dataset import DEFAULT_MANIFEST_PATH


class TestDay27Part2DetectionRegressions:
    """Regression tests protecting false-positive boundaries and phishing detection invariants."""

    def test_benign_url_query_percent40_not_flagged_as_userinfo_deception(self):
        """
        Validates that a URL containing percent-encoded '@' (%40) in query parameters
        (e.g. an email address or SSO redirect parameter) is parsed validly
        and does NOT falsely trigger userinfo deception heuristics.
        """
        clean_url = "https://portal.example.com/profile?email=alice%40example.org&ref=sso"
        is_val, err = validate_url(clean_url)
        assert is_val is True
        assert err is None

        analysis = deobfuscate_and_analyze_url(clean_url)
        assert analysis.is_valid is True
        assert analysis.parsed_hostname == "portal.example.com"
        assert not any("Deceptive userinfo" in f for f in analysis.suspicious_encoding_findings)

        rule_res = RuleEngine.evaluate_url(clean_url, analysis_result=analysis)
        assert "RULE_URL_USERINFO_OBFUSCATION" not in rule_res["rules_triggered"]

    def test_benign_attachments_not_flagged_as_dangerous(self):
        """
        Validates that standard business documents and image files
        (.pdf, .docx, .xlsx, .pptx, .png, .jpg, .txt) are never included
        in DANGEROUS_ATTACHMENT_EXTENSIONS.
        """
        benign_exts = {".pdf", ".docx", ".xlsx", ".pptx", ".png", ".jpg", ".txt", ".csv"}
        overlap = benign_exts.intersection(DANGEROUS_ATTACHMENT_EXTENSIONS)
        assert len(overlap) == 0, f"Benign extensions falsely in dangerous set: {overlap}"

    def test_clean_html_anchor_with_matching_domain_does_not_trigger_display_mismatch(self):
        """
        Validates that standard HTML emails where displayed text matches the
        destination domain do not produce display mismatches.
        """
        content = (
            "From: notifications@service.example.com\n"
            "Content-Type: text/html\n\n"
            "<html><body><p>Please visit our portal at "
            "<a href=\"https://service.example.com/dashboard\">https://service.example.com</a>.</p></body></html>"
        )
        parsed = SafeMIMEParser().parse_message(content)
        assert len(parsed.extracted_urls) == 1
        assert parsed.extracted_urls[0].is_display_mismatch is False
        assert parsed.extracted_urls[0].display_text == "https://service.example.com"

        detector = ThreatDetector()
        res = detector.analyze_message(content)
        assert not any("Display-text mismatch" in r for r in res["reasons"])

    def test_benchmark_benign_samples_remain_unflagged(self):
        """
        Validates that representative benign samples from the versioned benchmark corpus
        remain classified as non-threats without false-positive regressions.
        """
        assert DEFAULT_MANIFEST_PATH.exists()
        with open(DEFAULT_MANIFEST_PATH, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        sample_map = {s["id"]: s for s in manifest["samples"]}
        detector = ThreatDetector()

        for sample_id in ("BENIGN_SEC_010", "BENIGN_FIN_010", "EDGE_ROB_010"):
            sample = sample_map[sample_id]
            res = detector.analyze_message(sample["content"])
            assert res["is_threat"] is False, f"Sample {sample_id} unexpectedly flagged as threat with score {res['score']}"
            assert res["risk_level"] in ("LOW", "INFORMATIONAL")

    def test_standard_dangerous_attachment_extensions_preserved(self):
        """
        Validates that classic executable, script, and archive delivery vectors
        are preserved in DANGEROUS_ATTACHMENT_EXTENSIONS.
        """
        required_exts = {".exe", ".bat", ".cmd", ".vbs", ".ps1", ".scr", ".hta", ".pif", ".lnk"}
        missing = required_exts - DANGEROUS_ATTACHMENT_EXTENSIONS
        assert len(missing) == 0, f"Critical malicious extensions missing: {missing}"

    def test_explicit_userinfo_deception_remains_detectable(self):
        """
        Validates that explicit '@' userinfo deception in URLs
        (e.g. http://google.com@evil.com/login) continues to trigger high-severity rules.
        """
        phish_url = "http://google.com@evil.com/login"
        detector = ThreatDetector()
        res = detector.analyze_url(phish_url)

        assert res["score"] >= 60.0
        assert res["risk_level"] in ("HIGH", "CRITICAL")
        assert res["is_threat"] is True
        assert any("userinfo" in r.lower() or "@" in r for r in res["reasons"])

    def test_macro_attachment_extensions_recognized_as_dangerous(self):
        """
        Validates that macro-enabled Office document formats (.docm, .xlsm, .pptm, .dotm, .xltm)
        are categorized under DANGEROUS_ATTACHMENT_EXTENSIONS.
        """
        macro_exts = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm"}
        assert macro_exts.issubset(DANGEROUS_ATTACHMENT_EXTENSIONS)

    def test_unclosed_html_anchor_flushes_and_detects_display_mismatch(self):
        """
        Validates that unclosed HTML anchor tags interrupted by formatting tags (like <p>)
        correctly flush accumulated display text and trigger display-text mismatch detection.
        """
        html = "<html><body><a href=\"https://attacker.example.com\">https://secure.example.com <p>unclosed tag"
        parsed = SafeMIMEParser().parse_message(f"Content-Type: text/html\n\n{html}")
        assert len(parsed.extracted_urls) == 1
        link = parsed.extracted_urls[0]
        assert link.url == "https://attacker.example.com"
        assert link.display_text == "https://secure.example.com"
        assert link.is_display_mismatch is True

    def test_percent_encoded_userinfo_delimiter_deobfuscation(self):
        """
        Validates that URLs with percent-encoded userinfo delimiters (%40 in authority)
        are properly deobfuscated to extract the true destination hostname and flag deception.
        """
        deceptive_url = "https://legit-service.example.org%40evil-host.example.com/login"
        is_val, err = validate_url(deceptive_url)
        assert is_val is True
        assert err is None

        analysis = deobfuscate_and_analyze_url(deceptive_url)
        assert analysis.is_valid is True
        assert analysis.parsed_hostname == "evil-host.example.com"
        assert any("Deceptive userinfo" in f for f in analysis.suspicious_encoding_findings)

