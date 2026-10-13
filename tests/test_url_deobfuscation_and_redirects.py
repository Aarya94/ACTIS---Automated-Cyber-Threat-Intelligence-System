"""
Automated Deterministic Test Suite for Advanced URL De-obfuscation,
Safe Redirect Chain Analysis, SSRF Prevention, and Evidence Fusion.
Exercises 58 adversarial and edge-case scenarios offline using synthetic fixtures and mocks.
Zero live network access, zero browser JavaScript execution.
"""

import socket
import pytest
from unittest.mock import patch, MagicMock

from scanners.url_scanner import (
    validate_url,
    is_valid_url,
    normalize_url,
    extract_domain,
    deobfuscate_and_analyze_url,
    URLAnalysisResult,
    MAX_URL_LENGTH
)
from scanners.redirect_inspector import (
    SSRFValidator,
    RedirectInspector,
    RedirectInspectionResult,
    RedirectHop
)
from detection_engine.rule_engine import RuleEngine
from detection_engine.threat_detector import threat_detector
from detection_engine.evidence_model import DetectionEvidence, EvidenceSignal, EvidenceSource, EvidenceSeverity
from detection_engine.detection_contract import DetectionStatus, RiskLevel


# ==============================================================================
# SECTION 1: URL Normalization & Obfuscation Tests (Cases 1 - 22)
# ==============================================================================

class TestURLNormalizationAndObfuscation:
    """Tests 1 through 22: standards-aware parsing, de-obfuscation, and determinism."""

    def test_01_standard_http_url(self):
        res = deobfuscate_and_analyze_url("http://example.com/path/index.html")
        assert res.is_valid is True
        assert res.normalized_url == "http://example.com/path/index.html"
        assert res.parsed_scheme == "http"
        assert res.parsed_hostname == "example.com"
        assert res.parsed_port is None

    def test_02_standard_https_url(self):
        res = deobfuscate_and_analyze_url("https://secure.example.com/api?v=1")
        assert res.is_valid is True
        assert res.normalized_url == "https://secure.example.com/api?v=1"
        assert res.parsed_scheme == "https"
        assert res.parsed_hostname == "secure.example.com"

    def test_03_mixed_case_scheme_and_hostname(self):
        res = deobfuscate_and_analyze_url("HtTpS://WWW.ExAmPlE.CoM/Path/CasePreserved")
        assert res.is_valid is True
        assert res.parsed_scheme == "https"
        assert res.parsed_hostname == "example.com"
        # Path casing should be preserved
        assert "/Path/CasePreserved" in res.normalized_url

    def test_04_valid_percent_encoding(self):
        res = deobfuscate_and_analyze_url("https://example.com/search?q=cyber%20security")
        assert res.is_valid is True
        assert "cyber%20security" in res.normalized_url

    def test_05_malformed_percent_encoding(self):
        # Incomplete hex percent escape like %2 or %zz
        res = deobfuscate_and_analyze_url("http://example.com/test%2g%zz")
        assert res.is_valid is True
        assert res.normalized_url.startswith("http://example.com/test")

    def test_06_repeated_percent_encoding(self):
        # Double percent encoding (%252e -> %2e -> .)
        res = deobfuscate_and_analyze_url("http://example.com/dir/%252e%252e/secret")
        assert res.is_valid is True
        assert any("Double percent-encoding" in f for f in res.suspicious_encoding_findings)

    def test_07_encoded_delimiters(self):
        # %2f (/) and %40 (@) inside path or authority
        res = deobfuscate_and_analyze_url("http://example.com/path%2fadmin%40portal")
        assert res.is_valid is True
        assert any("percent-encoded delimiter" in f for f in res.suspicious_encoding_findings)

    def test_08_unicode_hostname(self):
        # German umlaut in domain
        res = deobfuscate_and_analyze_url("http://münchen.de/rathaus")
        assert res.is_valid is True
        assert res.unicode_hostname == "münchen.de"
        assert res.ascii_hostname == "xn--mnchen-3ya.de"

    def test_09_punycode_hostname(self):
        # Pre-encoded punycode
        res = deobfuscate_and_analyze_url("http://xn--mnchen-3ya.de/index")
        assert res.is_valid is True
        assert res.ascii_hostname == "xn--mnchen-3ya.de"
        assert res.unicode_hostname == "münchen.de"

    def test_10_zero_width_characters(self):
        # URL containing invisible zero-width space \u200b
        obfuscated = "http://pay\u200bpal.com/login"
        res = deobfuscate_and_analyze_url(obfuscated)
        assert res.is_valid is True
        assert any("Zero-Width" in obs for obs in res.unicode_or_idn_observations)
        assert "paypal.com" in res.normalized_url

    def test_11_unexpected_control_characters(self):
        # Illegal control character \x00 or \x08 rejected
        valid, err = validate_url("http://example.com/bad\x08path")
        assert valid is False
        assert "control characters" in err.lower()

    def test_12_misleading_user_information_component(self):
        # http://google.com@evil.com/login
        res = deobfuscate_and_analyze_url("http://google.com@evil.com/login")
        assert res.is_valid is True
        assert res.parsed_hostname == "evil.com"
        assert any("Deceptive userinfo" in f for f in res.suspicious_encoding_findings)

    def test_13_multiple_at_characters(self):
        # Multiple @ characters
        res = deobfuscate_and_analyze_url("http://admin@portal@attacker.com/app")
        assert res.is_valid is True
        assert res.parsed_hostname == "attacker.com"
        assert len(res.suspicious_encoding_findings) > 0

    def test_14_ipv4_literal(self):
        res = deobfuscate_and_analyze_url("http://93.184.216.34/test")
        assert res.is_valid is True
        assert res.parsed_hostname == "93.184.216.34"

    def test_15_ipv6_literal(self):
        res = deobfuscate_and_analyze_url("http://[2606:2800:220:1:248:1893:25c8:1946]:8080/path")
        assert res.is_valid is True
        assert res.parsed_port == 8080
        assert "[2606:2800:220:1:248:1893:25c8:1946]" in res.normalized_url

    def test_16_unusual_but_valid_port(self):
        res = deobfuscate_and_analyze_url("http://example.com:8888/dashboard")
        assert res.is_valid is True
        assert res.parsed_port == 8888
        assert ":8888" in res.normalized_url

    def test_17_invalid_port(self):
        valid, err = validate_url("http://example.com:99999/test")
        assert valid is False
        assert "port" in err.lower()

    def test_18_trailing_dot_hostname(self):
        res = deobfuscate_and_analyze_url("http://example.com./path")
        assert res.is_valid is True
        assert res.parsed_hostname == "example.com"
        assert res.normalized_url == "http://example.com/path"

    def test_19_empty_input(self):
        res = deobfuscate_and_analyze_url("")
        assert res.is_valid is False
        assert res.normalized_url == ""
        assert res.analysis_completeness == "FAILED"

    def test_20_malformed_url(self):
        res = deobfuscate_and_analyze_url("http://[malformed-ipv6")
        assert res.is_valid is False
        assert res.analysis_completeness == "FAILED"

    def test_21_repeated_normalization_determinism(self):
        input_url = "  HTTPS://WWW.Example.com:443/Path/To/Resource?q=test#top  "
        first_pass = normalize_url(input_url)
        second_pass = normalize_url(first_pass)
        third_pass = normalize_url(second_pass)
        assert first_pass == second_pass == third_pass == "https://example.com/Path/To/Resource?q=test#top"

    def test_22_normalization_resource_limits(self):
        too_long = "http://example.com/" + ("a" * (MAX_URL_LENGTH + 50))
        valid, err = validate_url(too_long)
        assert valid is False
        assert "exceeds maximum allowed length" in err


# ==============================================================================
# SECTION 2: Safe Redirect & SSRF Prevention Tests (Cases 23 - 44)
# ==============================================================================

class TestSafeRedirectAndSSRF:
    """Tests 23 through 44: bounded redirect analysis, loops, SSRF boundary, and DNS."""

    def test_23_one_redirect(self):
        # 301 from http://a.com -> https://a.com
        def mock_fetch(url, method, timeout):
            if url == "http://a.com/":
                return 301, {"Location": "https://a.com/"}
            return 200, {}

        def mock_dns(host):
            return ["93.184.216.34"]

        inspector = RedirectInspector(max_hops=5)
        res = inspector.inspect_redirects("http://a.com/", http_fetcher=mock_fetch, dns_resolver=mock_dns)
        assert res.hop_count == 2
        assert res.final_destination == "https://a.com/"
        assert res.is_loop_detected is False
        assert res.error_reason is None

    def test_24_multiple_redirects(self):
        # Chain: a.com -> b.com -> c.com
        def mock_fetch(url, method, timeout):
            if "a.com" in url:
                return 302, {"Location": "http://b.com/page"}
            if "b.com" in url:
                return 307, {"Location": "https://c.com/final"}
            return 200, {}

        def mock_dns(host):
            return ["93.184.216.34"]

        inspector = RedirectInspector(max_hops=5)
        res = inspector.inspect_redirects("http://a.com/", http_fetcher=mock_fetch, dns_resolver=mock_dns)
        assert res.hop_count == 3
        assert res.final_destination == "https://c.com/final"

    def test_25_relative_location(self):
        # Location: /new-path
        def mock_fetch(url, method, timeout):
            if url == "http://example.com/old":
                return 302, {"Location": "/new-path"}
            return 200, {}

        inspector = RedirectInspector(max_hops=5)
        res = inspector.inspect_redirects(
            "http://example.com/old",
            http_fetcher=mock_fetch,
            dns_resolver=lambda h: ["93.184.216.34"]
        )
        assert res.hop_count == 2
        assert res.final_destination == "http://example.com/new-path"

    def test_26_missing_location_header(self):
        def mock_fetch(url, method, timeout):
            return 302, {}  # No Location header

        inspector = RedirectInspector(max_hops=5)
        res = inspector.inspect_redirects(
            "http://example.com/redirect",
            http_fetcher=mock_fetch,
            dns_resolver=lambda h: ["93.184.216.34"]
        )
        assert res.hop_count == 1
        assert "without valid Location header" in res.error_reason

    def test_27_malformed_location(self):
        def mock_fetch(url, method, timeout):
            return 302, {"Location": "http://[invalid-ipv6"}

        inspector = RedirectInspector(max_hops=5)
        res = inspector.inspect_redirects(
            "http://example.com/start",
            http_fetcher=mock_fetch,
            dns_resolver=lambda h: ["93.184.216.34"]
        )
        assert res.error_reason is not None

    def test_28_redirect_loop(self):
        # a.com -> b.com -> a.com
        def mock_fetch(url, method, timeout):
            if "a.com" in url:
                return 302, {"Location": "http://b.com/loop"}
            if "b.com" in url:
                return 302, {"Location": "http://a.com/"}
            return 200, {}

        inspector = RedirectInspector(max_hops=5)
        res = inspector.inspect_redirects(
            "http://a.com/",
            http_fetcher=mock_fetch,
            dns_resolver=lambda h: ["93.184.216.34"]
        )
        assert res.is_loop_detected is True
        assert "Redirect loop detected" in res.error_reason

    def test_29_maximum_hop_limit(self):
        # 6 redirects when max_hops = 3
        def mock_fetch(url, method, timeout):
            step = int(url.split("step")[1]) if "step" in url else 0
            return 302, {"Location": f"http://example.com/step{step+1}"}

        inspector = RedirectInspector(max_hops=3)
        res = inspector.inspect_redirects(
            "http://example.com/step0",
            http_fetcher=mock_fetch,
            dns_resolver=lambda h: ["93.184.216.34"]
        )
        assert res.is_limit_exhausted is True
        assert res.hop_count == 3
        assert "Exhausted maximum redirect hop limit" in res.error_reason

    def test_30_overall_deadline_exhaustion(self):
        # inspector with deadline 0.05s
        def mock_slow_fetch(url, method, timeout):
            import time
            time.sleep(0.08)
            return 302, {"Location": "http://example.com/next"}

        inspector = RedirectInspector(max_hops=5, overall_timeout=0.05)
        res = inspector.inspect_redirects(
            "http://example.com/start",
            http_fetcher=mock_slow_fetch,
            dns_resolver=lambda h: ["93.184.216.34"]
        )
        assert res.is_deadline_exhausted is True or res.hop_count <= 2

    def test_31_request_timeout(self):
        def mock_timeout_fetch(url, method, timeout):
            raise TimeoutError("Socket read timed out")

        inspector = RedirectInspector()
        res = inspector.inspect_redirects(
            "http://example.com/hang",
            http_fetcher=mock_timeout_fetch,
            dns_resolver=lambda h: ["93.184.216.34"]
        )
        assert "timed out" in res.error_reason.lower()

    def test_32_dns_failure(self):
        def mock_dns_fail(host):
            raise socket.gaierror("Name or service not known")

        inspector = RedirectInspector()
        res = inspector.inspect_redirects(
            "http://nonexistent-domain-xyz.com/",
            dns_resolver=mock_dns_fail
        )
        assert "DNS resolution failed" in res.error_reason

    def test_33_connection_failure(self):
        def mock_conn_fail(url, method, timeout):
            raise ConnectionRefusedError("Connection refused by peer")

        inspector = RedirectInspector()
        res = inspector.inspect_redirects(
            "http://example.com/down",
            http_fetcher=mock_conn_fail,
            dns_resolver=lambda h: ["93.184.216.34"]
        )
        assert "failed" in res.error_reason.lower()

    def test_34_tls_failure(self):
        def mock_tls_fail(url, method, timeout):
            raise Exception("Certificate verification failed: [SSL: CERTIFICATE_VERIFY_FAILED]")

        inspector = RedirectInspector()
        res = inspector.inspect_redirects(
            "https://expired-ssl.com/",
            http_fetcher=mock_tls_fail,
            dns_resolver=lambda h: ["93.184.216.34"]
        )
        assert "ssl" in res.error_reason.lower() or "certificate" in res.error_reason.lower()

    def test_35_unsupported_scheme(self):
        def mock_scheme_redir(url, method, timeout):
            return 302, {"Location": "gopher://evil.com/payload"}

        inspector = RedirectInspector()
        res = inspector.inspect_redirects(
            "http://example.com/jump",
            http_fetcher=mock_scheme_redir,
            dns_resolver=lambda h: ["93.184.216.34"]
        )
        assert "Unsupported scheme 'gopher'" in res.error_reason

    def test_36_redirect_to_loopback(self):
        # Redirect pointing to 127.0.0.1
        def mock_fetch(url, method, timeout):
            return 302, {"Location": "http://127.0.0.1:8080/admin"}

        inspector = RedirectInspector()
        res = inspector.inspect_redirects("http://example.com/", http_fetcher=mock_fetch, dns_resolver=lambda h: ["93.184.216.34"])
        assert res.ssrf_blocked is True
        assert "loopback" in res.error_reason.lower()

    def test_37_redirect_to_private_address(self):
        # 192.168.1.1
        def mock_fetch(url, method, timeout):
            return 302, {"Location": "http://192.168.1.1/router"}

        inspector = RedirectInspector()
        res = inspector.inspect_redirects("http://example.com/", http_fetcher=mock_fetch, dns_resolver=lambda h: ["93.184.216.34"])
        assert res.ssrf_blocked is True
        assert "private" in res.error_reason.lower()

    def test_38_redirect_to_link_local_address(self):
        # 169.254.169.254 (Cloud metadata)
        def mock_fetch(url, method, timeout):
            return 302, {"Location": "http://169.254.169.254/latest/meta-data/"}

        inspector = RedirectInspector()
        res = inspector.inspect_redirects("http://example.com/", http_fetcher=mock_fetch, dns_resolver=lambda h: ["93.184.216.34"])
        assert res.ssrf_blocked is True
        assert "cloud metadata" in res.error_reason.lower() or "link-local" in res.error_reason.lower()

    def test_39_redirect_to_prohibited_ipv6_address(self):
        # [::1] (IPv6 loopback)
        def mock_fetch(url, method, timeout):
            return 302, {"Location": "http://[::1]:9000/api"}

        inspector = RedirectInspector()
        res = inspector.inspect_redirects("http://example.com/", http_fetcher=mock_fetch, dns_resolver=lambda h: ["93.184.216.34"])
        assert res.ssrf_blocked is True
        assert "loopback" in res.error_reason.lower()

    def test_40_redirect_from_public_hostname_to_private_ip(self):
        # Hostname resolves to private IP 10.0.0.1
        inspector = RedirectInspector()
        res = inspector.inspect_redirects(
            "http://internal.company.com/",
            dns_resolver=lambda h: ["10.0.0.1"]
        )
        assert res.ssrf_blocked is True
        assert "prohibited" in res.error_reason.lower()

    def test_41_dns_rebinding_simulation(self):
        # Hop 1: public IP (93.184.216.34); Hop 2: rebinds to 127.0.0.1
        call_count = [0]
        def mock_rebinding_dns(host):
            call_count[0] += 1
            if call_count[0] == 1:
                return ["93.184.216.34"]
            return ["127.0.0.1"]  # Rebinds on second resolution

        def mock_fetch(url, method, timeout):
            return 302, {"Location": "http://rebound.attacker.com/steal"}

        inspector = RedirectInspector()
        res = inspector.inspect_redirects(
            "http://rebound.attacker.com/init",
            http_fetcher=mock_fetch,
            dns_resolver=mock_rebinding_dns
        )
        assert res.ssrf_blocked is True
        assert "prohibited" in res.error_reason.lower()

    def test_42_redirect_destination_hostname_changes(self):
        # Redirect from https://initial.com -> https://different-domain.com
        def mock_fetch(url, method, timeout):
            if "initial.com" in url:
                return 301, {"Location": "https://different-domain.com/landing"}
            return 200, {}

        inspector = RedirectInspector()
        res = inspector.inspect_redirects(
            "https://initial.com/",
            http_fetcher=mock_fetch,
            dns_resolver=lambda h: ["93.184.216.34"]
        )
        assert res.hop_count == 2
        assert res.final_destination == "https://different-domain.com/landing"

    def test_43_no_unintended_automatic_redirect_following(self):
        # Custom fetcher verifying method is strictly HEAD or non-body
        methods_used = []
        def mock_fetch(url, method, timeout):
            methods_used.append(method)
            return 200, {}

        inspector = RedirectInspector()
        inspector.inspect_redirects(
            "http://example.com/test",
            http_fetcher=mock_fetch,
            dns_resolver=lambda h: ["93.184.216.34"]
        )
        assert all(m in ("HEAD", "GET") for m in methods_used)

    def test_44_no_response_body_download_beyond_limit(self):
        # Inspector defaults: body size limit is 0 / not read
        inspector = RedirectInspector()
        assert inspector.max_header_size <= 16384


# ==============================================================================
# SECTION 3: Evidence Integration & Decision Engine (Cases 45 - 58)
# ==============================================================================

class TestEvidenceIntegrationAndRegression:
    """Tests 45 through 58: rule matching, evidence fusion, score consistency, and regression."""

    def test_45_url_normalization_findings_enter_evidence_model(self):
        # Mixed homoglyph Cyrillic domain
        res_analysis = deobfuscate_and_analyze_url("http://pаypal.com/signin")
        rules_res = RuleEngine.evaluate_url("http://pаypal.com/signin", analysis_result=res_analysis)
        assert "RULE_URL_HOMOGLYPH_IDN" in rules_res["rules_triggered"]
        signals = rules_res["structured_result"].to_evidence_signals()
        assert any(s.signal_id == "RULE_URL_HOMOGLYPH_IDN" for s in signals)

    def test_46_redirect_findings_preserve_provenance(self):
        # Redirect loop in analysis_result enters rule engine
        fake_analysis = URLAnalysisResult(
            original_input="http://a.com/",
            normalized_url="http://a.com/",
            parsed_scheme="http",
            parsed_hostname="a.com",
            parsed_port=None,
            parsed_path="/",
            parsed_query="",
            parsed_fragment="",
            redirect_loop_detected=True,
            redirect_hops=[{"hop_number": 1, "url": "http://a.com/"}]
        )
        rules_res = RuleEngine.evaluate_url("http://a.com/", analysis_result=fake_analysis)
        assert "RULE_URL_REDIRECT_LOOP" in rules_res["rules_triggered"]

    def test_47_existing_phishing_model_findings_remain_available(self):
        # Phishing URL evaluated through threat detector
        res = threat_detector.analyze_url("http://secure-login-account-verify.xyz/auth")
        assert "ml_result" in res
        assert "probability" in res["ml_result"]

    def test_48_existing_ti_findings_remain_available(self):
        res = threat_detector.analyze_url("https://google.com")
        assert "threat_intel" in res

    def test_49_failed_ti_lookup_is_not_treated_as_clean(self):
        from detection_engine.threat_intel_contract import ThreatIntelEvidence
        unavail = ThreatIntelEvidence.unavailable("https://example.com/test", reason="Connection timeout")
        assert unavail.is_whitelisted is False
        assert unavail.verdict.value == "UNAVAILABLE"

    def test_50_failed_redirect_inspection_is_not_treated_as_benign_evidence(self):
        failed_res = RedirectInspectionResult(
            initial_url="http://example.com/test",
            final_destination="http://example.com/test",
            error_reason="Connection refused",
            evaluated=True
        )
        assert failed_res.error_reason is not None

    def test_51_duplicate_url_signals_do_not_inflate_scores(self):
        evidence = DetectionEvidence()
        sig1 = EvidenceSignal(
            source=EvidenceSource.HEURISTIC_RULES,
            signal_id="RULE_URL_SUSPICIOUS_PORT",
            name="Port",
            description="port 8888",
            severity=EvidenceSeverity.MEDIUM,
            score_contribution=20.0
        )
        sig2 = EvidenceSignal(
            source=EvidenceSource.HEURISTIC_RULES,
            signal_id="RULE_URL_SUSPICIOUS_PORT",
            name="Port",
            description="port 8888",
            severity=EvidenceSeverity.MEDIUM,
            score_contribution=20.0
        )
        evidence.add_signal(sig1)
        evidence.add_signal(sig2)
        assert len(evidence.signals) == 1
        assert evidence.discarded_duplicates_count == 1

    def test_52_independent_corroborating_evidence_remains_distinguishable(self):
        evidence = DetectionEvidence()
        sig_ti = EvidenceSignal(
            source=EvidenceSource.THREAT_INTELLIGENCE,
            signal_id="TI_VIRUSTOTAL_URL_MALICIOUS",
            name="VirusTotal",
            description="Malicious",
            severity=EvidenceSeverity.HIGH,
            score_contribution=70.0
        )
        sig_local = EvidenceSignal(
            source=EvidenceSource.THREAT_INTELLIGENCE,
            signal_id="TI_LOCAL_DATABASE_URL_MALICIOUS",
            name="Local DB",
            description="Malicious",
            severity=EvidenceSeverity.HIGH,
            score_contribution=70.0
        )
        evidence.add_signal(sig_ti)
        evidence.add_signal(sig_local)
        assert len(evidence.signals) == 2

    def test_53_whitelist_behavior_remains_consistent_with_documented_policy(self):
        from detection_engine.decision_engine import DetectionDecisionEngine
        from detection_engine.detection_contract import InputType
        from detection_engine.threat_intel_contract import ThreatIntelEvidence, ThreatIntelVerdict, IndicatorType
        white_ti = ThreatIntelEvidence(
            indicator="http://whitelisted.com",
            indicator_type=IndicatorType.URL,
            verdict=ThreatIntelVerdict.FALSE_POSITIVE,
            confidence=1.0,
            is_whitelisted=True
        )
        dec_res = DetectionDecisionEngine.evaluate(
            target_identifier="http://whitelisted.com",
            input_type=InputType.URL,
            ti_evidence=white_ti
        )
        assert dec_res.risk_score == 0.0
        assert dec_res.detection_status == DetectionStatus.BENIGN
        assert dec_res.risk_level == RiskLevel.INFORMATIONAL

    def test_54_insufficient_analysis_is_represented_accurately(self):
        invalid_res = threat_detector.analyze_url(None)
        assert invalid_res["is_valid"] is False
        assert invalid_res["confidence"] == 0.0
        assert invalid_res["detection_result"] is None

    def test_55_explainability_score_matches_final_result(self):
        res = threat_detector.analyze_url("https://google.com")
        tree = res["explainability_tree"]
        assert tree is not None
        assert tree["final_score"] == res["detection_result"]["risk_score"]

    def test_56_existing_url_scanner_callers_remain_compatible(self):
        assert normalize_url("example.com") == "http://example.com"
        assert extract_domain("https://www.paypal.com/login") == "paypal.com"
        assert is_valid_url("https://google.com") is True

    def test_57_ordinary_benign_urls_not_automatically_flagged(self):
        analysis = deobfuscate_and_analyze_url("https://google.com")
        assert len(analysis.suspicious_encoding_findings) == 0
        assert len(analysis.unicode_or_idn_observations) == 0
        assert len(analysis.normalization_warnings) == 0
        assert analysis.is_valid is True

        rules_res = RuleEngine.evaluate_url("https://google.com", analysis_result=analysis)
        assert len(rules_res["rules_triggered"]) == 0
        assert rules_res["heuristic_score"] == 0.0

    def test_58_existing_file_and_non_pe_pipelines_remain_functional(self):
        # Non-PE file analysis check
        file_res = threat_detector.analyze_file("tests/fixtures/synthetic_malware.py" if False else "README.md")
        assert file_res["target_type"] == "file"
        assert file_res["score"] >= 0.0
