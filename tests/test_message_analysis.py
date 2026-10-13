"""
Tests for ACTIS Day 25: Safe MIME Parsing and Message Analysis.
Deterministic, offline, adversarially focused test suite.
"""

import os
import email
from email.message import EmailMessage
import pytest
from unittest.mock import patch, MagicMock

from scanners.mime_parser import (
    SafeMIMEParser,
    MIMEAnalysisLimits,
    MIMEAnalysisResult,
    AttachmentMetadata,
    ExtractedMessageURL,
    safe_mime_parser,
    is_domain_mismatch
)
from scanners.text_analyzer import (
    TextAnalyzer,
    MessageScanResult,
    URGENCY_PATTERNS,
    CREDENTIAL_PATTERNS,
    FINANCIAL_PATTERNS,
    IMPERSONATION_PATTERNS,
    SECURITY_EVASION_PATTERNS,
    SENSITIVE_INFO_PATTERNS
)
from detection_engine.threat_detector import ThreatDetector, threat_detector
from detection_engine.rule_engine import RuleEngine, RuleSeverity, RuleTargetType
from detection_engine.detection_contract import InputType, RiskLevel, DetectionStatus
from detection_engine.evidence_model import EvidenceSource, EvidenceSeverity


class TestMIMEParsingSafeAndBounded:
    """7.1 MIME parsing tests: boundaries, malformed structures, resource limits."""

    def test_valid_plain_text_email(self):
        msg = (
            "From: alice@example.com\r\n"
            "To: bob@example.com\r\n"
            "Subject: Project Status\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            "\r\n"
            "Hi Bob, please review the document at https://example.com/docs.\r\n"
        ).encode("utf-8")
        parser = SafeMIMEParser()
        res = parser.parse_message(msg)
        assert res.is_mime is True
        assert res.headers.get("Subject") == "Project Status"
        assert res.headers.get("From") == "alice@example.com"
        assert "Hi Bob" in res.plain_text_body
        assert "https://example.com/docs" in res.unique_canonical_urls
        assert res.analysis_completeness == "COMPLETE"
        assert len(res.attachments) == 0

    def test_valid_html_email(self):
        msg = (
            "From: service@alerts.com\r\n"
            "To: user@example.com\r\n"
            "Subject: Monthly Newsletter\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            "\r\n"
            "<html><body><p>Read online: <a href=\"https://news.example.com/digest\">Newsletter</a></p></body></html>\r\n"
        ).encode("utf-8")
        parser = SafeMIMEParser()
        res = parser.parse_message(msg)
        assert res.is_mime is True
        assert "https://news.example.com/digest" in res.unique_canonical_urls
        assert len(res.extracted_urls) == 1
        assert res.extracted_urls[0].display_text == "Newsletter"
        assert res.extracted_urls[0].source_type == "html_href"

    def test_multipart_alternative_plain_and_html(self):
        msg = EmailMessage()
        msg["From"] = "info@service.org"
        msg["To"] = "victim@target.com"
        msg["Subject"] = "Account Alert"
        msg.set_content("Please click here: https://portal.service.org/login")
        msg.add_alternative(
            "<html><body>Please <a href=\"https://portal.service.org/login\">click here</a></body></html>",
            subtype="html"
        )
        raw = msg.as_bytes()

        parser = SafeMIMEParser()
        res = parser.parse_message(raw)
        assert res.is_mime is True
        assert "https://portal.service.org/login" in res.unique_canonical_urls
        # Both alternatives reference the same URL, so unique count is 1
        assert len(res.unique_canonical_urls) == 1
        assert res.url_occurrence_counts.get("https://portal.service.org/login") == 2
        assert len(res.extracted_urls) == 2

    def test_multipart_mixed_with_attachment(self):
        msg = EmailMessage()
        msg["From"] = "billing@vendor.com"
        msg["To"] = "client@example.com"
        msg["Subject"] = "Invoice #1094"
        msg.set_content("Attached is your invoice.")
        msg.add_attachment(b"%PDF-1.4 simulated pdf data", maintype="application", subtype="pdf", filename="invoice_1094.pdf")

        parser = SafeMIMEParser()
        res = parser.parse_message(msg.as_bytes())
        assert len(res.attachments) == 1
        att = res.attachments[0]
        assert att.filename == "invoice_1094.pdf"
        assert att.extension == ".pdf"
        assert att.is_suspicious_extension is False
        assert att.size_bytes == len(b"%PDF-1.4 simulated pdf data")

    def test_suspicious_attachment_extension(self):
        msg = EmailMessage()
        msg["From"] = "malicious@bad.com"
        msg["To"] = "target@example.com"
        msg["Subject"] = "Urgent: payment slip"
        msg.set_content("Execute this patch.")
        msg.add_attachment(b"MZ\x90\x00 fake pe", maintype="application", subtype="octet-stream", filename="patch_update.exe")

        parser = SafeMIMEParser()
        res = parser.parse_message(msg.as_bytes())
        assert len(res.attachments) == 1
        att = res.attachments[0]
        assert att.filename == "patch_update.exe"
        assert att.extension == ".exe"
        assert att.is_suspicious_extension is True

    def test_attachment_filename_sanitization_path_traversal(self):
        msg = EmailMessage()
        msg["From"] = "attacker@evil.com"
        msg["Subject"] = "Traversal test"
        msg.set_content("File included")
        msg.add_attachment(b"echo pwned", maintype="application", subtype="octet-stream", filename="../../Windows/System32/evil.bat")

        parser = SafeMIMEParser()
        res = parser.parse_message(msg.as_bytes())
        assert len(res.attachments) == 1
        att = res.attachments[0]
        # Filename must be strictly sanitized to base name; no directory traversal characters
        assert att.filename == "evil.bat"
        assert ".." not in att.filename
        assert "/" not in att.filename
        assert "\\" not in att.filename
        assert att.is_suspicious_extension is True

    def test_missing_attachment_filename(self):
        msg = (
            "From: test@test.com\r\n"
            "Content-Type: multipart/mixed; boundary=\"BOUNDARY\"\r\n"
            "\r\n"
            "--BOUNDARY\r\n"
            "Content-Type: text/plain\r\n"
            "\r\n"
            "Body\r\n"
            "--BOUNDARY\r\n"
            "Content-Type: application/octet-stream\r\n"
            "Content-Disposition: attachment\r\n"
            "\r\n"
            "rawbytes\r\n"
            "--BOUNDARY--\r\n"
        ).encode("utf-8")
        parser = SafeMIMEParser()
        res = parser.parse_message(msg)
        assert len(res.attachments) == 1
        assert res.attachments[0].filename.startswith("unnamed_attachment_")

    def test_missing_mime_boundary_does_not_crash(self):
        corrupted = (
            b"From: test@test.com\r\n"
            b"Content-Type: multipart/mixed; boundary=\"MISSING_BOUNDARY\"\r\n"
            b"\r\n"
            b"Content without the boundary marker at all.\r\n"
        )
        parser = SafeMIMEParser()
        res = parser.parse_message(corrupted)
        # Standard parser may register defect or parse cleanly; must never crash
        assert isinstance(res, MIMEAnalysisResult)
        assert res.is_valid is True

    def test_invalid_charset_fallback(self):
        # Body declared as utf-8 but contains illegal byte sequences
        malformed = (
            b"From: test@test.com\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"\r\n"
            b"Bad bytes: \xff\xfe\xfa\xfb and a URL https://example.com/ok\r\n"
        )
        parser = SafeMIMEParser()
        res = parser.parse_message(malformed)
        assert res.is_valid is True
        assert "https://example.com/ok" in res.unique_canonical_urls

    def test_empty_message_handling(self):
        parser = SafeMIMEParser()
        res = parser.parse_message(b"")
        assert res.is_valid is False
        assert len(res.unique_canonical_urls) == 0
        assert res.analysis_completeness == "FAILED"

    def test_oversized_message_boundary_limit(self):
        limits = MIMEAnalysisLimits(max_message_bytes=100)
        parser = SafeMIMEParser(limits=limits)
        oversized = b"From: a@b.com\r\nSubject: Test\r\n\r\n" + b"A" * 500
        res = parser.parse_message(oversized)
        assert res.analysis_completeness == "PARTIAL"
        assert res.limit_reached in ("MAX_RAW_MESSAGE_SIZE", "MAX_MESSAGE_BYTES")
        assert any("truncated" in w for w in res.warnings)

    def test_oversized_header_limit(self):
        limits = MIMEAnalysisLimits(max_header_bytes=50)
        parser = SafeMIMEParser(limits=limits)
        msg = b"From: " + b"X" * 100 + b"@example.com\r\n\r\nBody"
        res = parser.parse_message(msg)
        assert res.analysis_completeness == "PARTIAL"
        assert res.limit_reached in ("MAX_HEADER_LENGTH", "MAX_HEADER_BYTES")

    def test_excessive_mime_parts_limit(self):
        limits = MIMEAnalysisLimits(max_parts=3)
        parser = SafeMIMEParser(limits=limits)
        msg = (
            "From: test@test.com\r\n"
            "Content-Type: multipart/mixed; boundary=\"B\"\r\n"
            "\r\n"
            "--B\r\nContent-Type: text/plain\r\n\r\nPart 1\r\n"
            "--B\r\nContent-Type: text/plain\r\n\r\nPart 2\r\n"
            "--B\r\nContent-Type: text/plain\r\n\r\nPart 3\r\n"
            "--B\r\nContent-Type: text/plain\r\n\r\nPart 4\r\n"
            "--B--\r\n"
        ).encode("utf-8")
        res = parser.parse_message(msg)
        assert res.analysis_completeness == "PARTIAL"
        assert res.limit_reached in ("MAX_MIME_PARTS", "MAX_PARTS")

    def test_deep_nesting_limit(self):
        limits = MIMEAnalysisLimits(max_depth=2)
        parser = SafeMIMEParser(limits=limits)
        # Level 1 inside Level 0 inside Root
        nested = (
            "From: test@test.com\r\n"
            "Content-Type: multipart/mixed; boundary=\"B1\"\r\n\r\n"
            "--B1\r\n"
            "Content-Type: multipart/mixed; boundary=\"B2\"\r\n\r\n"
            "--B2\r\n"
            "Content-Type: multipart/mixed; boundary=\"B3\"\r\n\r\n"
            "--B3\r\nContent-Type: text/plain\r\n\r\nDeep part\r\n"
            "--B3--\r\n--B2--\r\n--B1--\r\n"
        ).encode("utf-8")
        res = parser.parse_message(nested)
        assert res.analysis_completeness == "PARTIAL"
        assert res.limit_reached in ("MAX_MIME_DEPTH", "MAX_DEPTH")

    def test_excessive_decoded_text_limit(self):
        limits = MIMEAnalysisLimits(max_decoded_text_chars=100)
        parser = SafeMIMEParser(limits=limits)
        msg = ("From: test@test.com\r\n\r\n" + "Z" * 500).encode("utf-8")
        res = parser.parse_message(msg)
        assert res.analysis_completeness == "PARTIAL"
        assert res.limit_reached == "MAX_DECODED_TEXT"
        assert len(res.plain_text_body) <= 100

    def test_url_extraction_limit(self):
        limits = MIMEAnalysisLimits(max_extracted_urls=3)
        parser = SafeMIMEParser(limits=limits)
        body = " ".join([f"https://site{i}.com" for i in range(10)])
        msg = f"From: test@test.com\r\n\r\n{body}".encode("utf-8")
        res = parser.parse_message(msg)
        assert len(res.unique_canonical_urls) <= 3
        assert res.limit_reached == "MAX_EXTRACTED_URLS"
        assert res.analysis_completeness == "PARTIAL"

    def test_plain_text_sms_with_header_like_prefix_handled_safely(self):
        sms = "Urgent: your account is suspended! Verify at https://secure-bank.example.com"
        parser = SafeMIMEParser()
        res = parser.parse_message(sms)
        assert "https://secure-bank.example.com" in res.unique_canonical_urls


class TestURLExtractionAndProvenance:
    """7.2 URL extraction tests: plain text, HTML, display mismatches, deduplication."""

    def test_plain_text_and_html_url_extraction(self):
        html_msg = (
            "From: service@alerts.com\r\n"
            "Content-Type: text/html; charset=utf-8\r\n\r\n"
            "<html><body>"
            "<p>Plain link in text: https://plain.example.org</p>"
            "<a href=\"https://anchor.example.org/path?k=v\">Click</a>"
            "</body></html>"
        ).encode("utf-8")
        parser = SafeMIMEParser()
        res = parser.parse_message(html_msg)
        assert "https://plain.example.org" in res.unique_canonical_urls
        assert "https://anchor.example.org/path?k=v" in res.unique_canonical_urls

    def test_display_text_versus_destination_mismatch_positive(self):
        # Display text portrays paypal.com but points to phishing domain evil-pay.com
        html_msg = (
            "Content-Type: text/html; charset=utf-8\r\n\r\n"
            "<a href=\"https://evil-pay.com/signin\">https://www.paypal.com/signin</a>"
        ).encode("utf-8")
        parser = SafeMIMEParser()
        res = parser.parse_message(html_msg)
        assert len(res.extracted_urls) == 1
        url_obj = res.extracted_urls[0]
        assert url_obj.canonical_url == "https://evil-pay.com/signin"
        assert url_obj.is_display_mismatch is True
        assert url_obj.display_text == "https://www.paypal.com/signin"

    def test_display_text_matching_destination_negative(self):
        html_msg = (
            "Content-Type: text/html; charset=utf-8\r\n\r\n"
            "<a href=\"https://www.paypal.com/signin\">https://www.paypal.com/signin</a>"
        ).encode("utf-8")
        parser = SafeMIMEParser()
        res = parser.parse_message(html_msg)
        assert len(res.extracted_urls) == 1
        assert res.extracted_urls[0].is_display_mismatch is False

    def test_display_text_generic_text_not_mismatch(self):
        # Anchor text says "Click Here", which is generic and does not contain a deceptive domain
        html_msg = (
            "Content-Type: text/html; charset=utf-8\r\n\r\n"
            "<a href=\"https://trusted-site.com/doc\">Click Here to Read</a>"
        ).encode("utf-8")
        parser = SafeMIMEParser()
        res = parser.parse_message(html_msg)
        assert len(res.extracted_urls) == 1
        assert res.extracted_urls[0].is_display_mismatch is False

    def test_subdomain_relationship_not_mismatch(self):
        # Visible text: "login.company.com", href: "https://auth.company.com"
        assert is_domain_mismatch("login.company.com", "https://auth.company.com") is False

    def test_relative_html_links_ignored_safely(self):
        html_msg = (
            "Content-Type: text/html; charset=utf-8\r\n\r\n"
            "<a href=\"/relative/path/index.html\">Local Link</a>"
            "<a href=\"#section2\">Anchor</a>"
            "<a href=\"mailto:support@example.com\">Mailto</a>"
        ).encode("utf-8")
        parser = SafeMIMEParser()
        res = parser.parse_message(html_msg)
        # Relative or non-HTTP links should not be registered as web URLs
        assert len(res.unique_canonical_urls) == 0

    def test_duplicate_url_occurrences_retained_in_provenance(self):
        body = (
            "Please click: https://example.com/action\n"
            "Again: https://example.com/action\n"
            "Final reminder: https://example.com/action\n"
        )
        parser = SafeMIMEParser()
        res = parser.parse_message(body)
        assert len(res.unique_canonical_urls) == 1
        assert res.url_occurrence_counts["https://example.com/action"] == 3
        assert len(res.extracted_urls) == 3

    def test_subject_header_url_extraction(self):
        msg = (
            "From: alerts@service.com\r\n"
            "Subject: Action Required: https://phish.example.org/verify\r\n"
            "\r\n"
            "Message body without urls.\r\n"
        ).encode("utf-8")
        parser = SafeMIMEParser()
        res = parser.parse_message(msg)
        assert "https://phish.example.org/verify" in res.unique_canonical_urls
        assert any(u.source_type == "header_subject" for u in res.extracted_urls)

    def test_malformed_html_tags_do_not_crash_parser(self):
        malformed_html = (
            "<html><body>"
            "<a href=\"https://valid.com/one\" <invalid attribute>>Text</a>"
            "<<<a href='https://valid.com/two'>"
            "<a href=>Empty href</a>"
            "</body></html>"
        )
        parser = SafeMIMEParser()
        res = parser.parse_message(malformed_html)
        assert "https://valid.com/one" in res.unique_canonical_urls
        assert "https://valid.com/two" in res.unique_canonical_urls


class TestSocialEngineeringRules:
    """7.3 Deterministic Social-Engineering heuristic rule tests."""

    def test_urgency_pressure_positive(self):
        text = "Your account will be suspended within 24 hours unless you act immediately!"
        res = TextAnalyzer.evaluate_social_engineering(text)
        assert res["has_urgency"] is True
        assert len(res["urgency_indicators"]) > 0

    def test_urgency_pressure_negative(self):
        text = "Please submit your monthly project status report by Friday if possible."
        res = TextAnalyzer.evaluate_social_engineering(text)
        assert res["has_urgency"] is False

    def test_credential_harvesting_positive(self):
        text = "Verify your password and confirm your account login credentials."
        res = TextAnalyzer.evaluate_social_engineering(text)
        assert res["has_credential_request"] is True
        assert len(res["credential_indicators"]) > 0

    def test_credential_harvesting_negative(self):
        text = "We updated our password security guidelines. Check our internal wiki."
        res = TextAnalyzer.evaluate_social_engineering(text)
        assert res["has_credential_request"] is False

    def test_financial_lure_positive(self):
        text = "Claim your urgent tax refund payout. Update bank account details now."
        res = TextAnalyzer.evaluate_social_engineering(text)
        assert res["has_financial_lure"] is True

    def test_impersonation_positive(self):
        text = "This is a notification from IT Support / Human Resources regarding payroll."
        res = TextAnalyzer.evaluate_social_engineering(text)
        assert res["has_impersonation"] is True

    def test_security_control_evasion_positive(self):
        text = "Disable antivirus and ignore security warning to proceed with installation."
        res = TextAnalyzer.evaluate_social_engineering(text)
        assert res["has_security_evasion"] is True

    def test_sensitive_info_prompt_positive(self):
        text = "Enter your one-time password (OTP) and verification code to authenticate."
        res = TextAnalyzer.evaluate_social_engineering(text)
        assert res["has_sensitive_info_prompt"] is True

    def test_benign_newsletter_discussing_phishing_not_flagged(self):
        text = (
            "Cybersecurity Awareness Weekly:\n"
            "Phishing attackers often use urgency and fake login prompts to compromise accounts.\n"
            "Remember never to share passwords or click untrusted links."
        )
        res = TextAnalyzer.evaluate_social_engineering(text)
        # Although words appear in context, evaluate rule engine output
        scan = TextAnalyzer.analyze_message_structured(text)
        # No links, no attachments, overall score should remain benign/low
        assert scan.overall_risk_level == "LOW"
        assert scan.threat_urls_count == 0

    def test_benign_invoice_notification(self):
        text = "Hello, your regular monthly invoice #8812 for cloud storage has been processed successfully."
        res = TextAnalyzer.evaluate_social_engineering(text)
        assert res["has_credential_request"] is False
        assert res["has_security_evasion"] is False
        scan = TextAnalyzer.analyze_message_structured(text)
        assert scan.overall_risk_level == "LOW"

    def test_rule_engine_message_evaluation(self):
        scan_dict = {
            "social_engineering": {
                "has_urgency": True,
                "urgency_indicators": ["within 24 hours"],
                "has_credential_request": True,
                "credential_indicators": ["verify your password"],
                "has_financial_lure": False,
                "has_impersonation": True,
                "impersonation_indicators": ["it support"],
                "has_security_evasion": True,
                "security_evasion_indicators": ["disable antivirus"],
                "has_sensitive_info_prompt": False
            },
            "display_mismatches_count": 1,
            "suspicious_attachments_count": 1,
            "attachments": [{"filename": "trojan.exe", "is_suspicious_extension": True}],
            "mime_defects": ["Missing boundary"]
        }
        res = RuleEngine.evaluate_message(scan_dict)
        triggered = res["rules_triggered"]
        assert "RULE_MSG_URGENCY_PRESSURE" in triggered
        assert "RULE_MSG_CREDENTIAL_HARVEST" in triggered
        assert "RULE_MSG_IMPERSONATION" in triggered
        assert "RULE_MSG_SECURITY_EVASION" in triggered
        assert "RULE_MSG_DISPLAY_TEXT_MISMATCH" in triggered
        assert "RULE_MSG_SUSPICIOUS_ATTACHMENT" in triggered
        assert "RULE_MSG_MIME_DEFECT_ANOMALY" in triggered
        assert res["score"] > 50


class TestEvidenceScoringAndPipelineIntegration:
    """7.4 Pipeline integration, scoring fusion, and explainability tree."""

    def test_threat_detector_analyze_message_with_clean_text(self):
        msg = "Hi team, please find meeting notes from today's discussion."
        res = threat_detector.analyze_message(msg)
        assert res["target_type"] == "message"
        assert res["risk_level"] in ("LOW", "INFORMATIONAL")
        assert res["score"] < 35.0
        assert res["is_threat"] is False
        assert res["is_valid"] is True
        assert res["detection_result"] is not None
        assert res["explainability_tree"] is not None

    def test_threat_detector_analyze_message_with_phishing_lures_and_mismatch(self):
        email_content = (
            "From: security@support-dept.com\r\n"
            "Subject: Immediate action required: Account Suspension\r\n"
            "Content-Type: text/html; charset=utf-8\r\n\r\n"
            "<html><body>"
            "<p>Your access will expire immediately! Enter your password to verify credentials.</p>"
            "<a href=\"https://evil-harvest-phish.xyz/login\">https://paypal.com/verify</a>"
            "</body></html>"
        ).encode("utf-8")

        res = threat_detector.analyze_message(email_content)
        assert res["target_type"] == "message"
        assert res["is_mime"] is True
        assert res["display_mismatches_count"] == 1
        assert res["risk_level"] in ("HIGH", "CRITICAL")
        assert res["is_threat"] is True
        assert res["score"] >= 40.0
        assert res["overall_score"] >= 60.0

        # Check explainability tree
        tree = res["explainability_tree"]
        assert tree is not None
        root_node = tree.get("root", tree)
        assert "ACTIS Threat Evaluation" in root_node.get("title", "")
        # Check input analysis branch includes message structure
        children = root_node.get("children", [])
        input_nodes = [c for c in children if c.get("node_id") == "input_analysis"]
        assert len(input_nodes) == 1
        msg_nodes = [c for c in input_nodes[0].get("children", []) if c.get("node_id") == "message_structure"]
        assert len(msg_nodes) == 1
        assert msg_nodes[0]["metadata"]["display_mismatches_count"] == 1

    def test_duplicate_urls_do_not_inflate_risk_score(self):
        # 1 URL repeated 20 times vs 1 URL appearing once
        single_url_msg = "Please review: https://example.com/portal"
        multi_url_msg = " ".join(["Please review: https://example.com/portal"] * 20)

        res_single = threat_detector.analyze_message(single_url_msg)
        res_multi = threat_detector.analyze_message(multi_url_msg)

        # Risk score must be identical; no duplicate score inflation
        assert res_single["score"] == res_multi["score"]
        assert res_multi["unique_url_count"] == 1
        assert res_multi["total_url_count"] == 20

    def test_invalid_input_handling(self):
        res = threat_detector.analyze_message(None)
        assert res["is_valid"] is False
        assert res["score"] == 0.0
        assert res["risk_level"] == "LOW"
        assert res["is_threat"] is False


class TestPrivacyAndSafetyGuarantees:
    """7.5 Privacy, safe execution, and network boundary restrictions."""

    def test_remote_redirect_inspection_disabled_by_default(self):
        """Proves remote redirect inspection is not enabled during message analysis."""
        from scanners.url_scanner import scan_url_logic
        with patch("scanners.url_scanner.deobfuscate_and_analyze_url") as mock_deobf:
            mock_res = MagicMock()
            mock_res.normalized_url = "https://example.com/test"
            mock_res.redirect_hops = []
            mock_res.final_destination = "https://example.com/test"
            mock_res.redirect_result = None
            mock_res.to_dict.return_value = {}
            mock_deobf.return_value = mock_res
            TextAnalyzer.analyze_message("Link: https://example.com/test")
            # Verify deobfuscate_and_analyze_url was called with follow_redirects=False
            assert mock_deobf.called
            call_kwargs = mock_deobf.call_args[1]
            assert call_kwargs.get("follow_redirects") is False

    def test_no_network_calls_during_offline_message_analysis(self):
        """Proves zero network socket connections or HTTP requests occur during message scanning."""
        msg = (
            "From: test@domain.com\r\n"
            "Content-Type: text/html\r\n\r\n"
            "<a href=\"https://remote-site.com/endpoint?token=secret123\">Link</a>"
        ).encode("utf-8")

        with patch("urllib.request.urlopen") as mock_urlopen, \
             patch("http.client.HTTPConnection.connect") as mock_conn:
            res = threat_detector.analyze_message(msg, check_external=False)
            assert mock_urlopen.call_count == 0
            assert mock_conn.call_count == 0
            assert res["is_valid"] is True

    def test_attachment_content_is_never_executed(self):
        """Verifies attachment analysis is strictly metadata-only; no execution or process spawning."""
        msg = EmailMessage()
        msg["From"] = "attacker@evil.com"
        msg["Subject"] = "Infection attempt"
        msg.set_content("Run this executable.")
        msg.add_attachment(b"\x4d\x5a\x90 fake payload", maintype="application", subtype="octet-stream", filename="payload.exe")

        with patch("subprocess.Popen") as mock_popen, \
             patch("subprocess.run") as mock_run, \
             patch("os.system") as mock_sys:
            res = threat_detector.analyze_message(msg.as_bytes())
            assert mock_popen.call_count == 0
            assert mock_run.call_count == 0
            assert mock_sys.call_count == 0
            assert res["suspicious_attachments_count"] == 1

    def test_html_javascript_not_executed(self):
        """HTML parser extracts URLs without executing embedded scripts."""
        html_msg = (
            "Content-Type: text/html; charset=utf-8\r\n\r\n"
            "<html><body>"
            "<script>window.location='http://evil.com/stolen';</script>"
            "<a href=\"https://safe.com\">Safe</a>"
            "</body></html>"
        ).encode("utf-8")
        parser = SafeMIMEParser()
        res = parser.parse_message(html_msg)
        # Script tags are discarded; only explicit <a> hrefs are captured
        assert "https://safe.com" in res.unique_canonical_urls
        assert not any("evil.com" in u for u in res.unique_canonical_urls)
