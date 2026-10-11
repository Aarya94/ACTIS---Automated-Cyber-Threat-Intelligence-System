"""
ACTIS Day 15 Adversarial Security Test Suite
Verifies robustness against malformed PE binaries, oversized files,
malformed and adversarial URLs, regex/message resource consumption,
and false-positive safety boundaries.
"""

import math
import os
import struct
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from config.config import MAX_FILE_SIZE_BYTES
from detection_engine.decision_engine import DetectionDecisionEngine
from detection_engine.detection_contract import DetectionStatus, InputType, RiskLevel
from detection_engine.evidence_model import (
    DetectionEvidence,
    EvidenceSeverity,
    EvidenceSignal,
    EvidenceSource,
)
from detection_engine.risk_engine import RiskEngine, RiskScoringEngine
from detection_engine.threat_intel_contract import (
    IndicatorType,
    ThreatIntelEvidence,
    ThreatIntelVerdict,
)
from scanners.file_feature_extractor import (
    DOS_SIGNATURE,
    PE_SIGNATURE,
    FileFeatureExtractor,
    calculate_entropy,
    detect_pe_format,
    is_pe_file,
)
from scanners.pe_feature_contract import PEStaticFeatures
from scanners.text_analyzer import MessageScanResult, TextAnalyzer
from scanners.url_scanner import (
    extract_domain,
    extract_url_features,
    extract_url_features_dict,
    is_valid_url,
    normalize_url,
    validate_extracted_features,
    validate_url,
)


class TestMalformedPEFiles:
    """Verifies non-destructive, graceful handling of malformed and corrupted PE inputs."""

    def test_empty_file_handling(self, tmp_path):
        """0-byte file must be handled safely without unhandled exceptions."""
        empty_file = tmp_path / "empty.exe"
        empty_file.write_bytes(b"")

        is_pe, reason = detect_pe_format(empty_file)
        assert is_pe is False
        assert reason == "TOO_SMALL_FOR_PE"
        assert is_pe_file(empty_file) is False

        features = FileFeatureExtractor.extract_features(empty_file)
        assert features["is_valid"] is True
        assert features["file_size"] == 0
        assert features["is_pe"] is False
        assert any("empty" in w.lower() for w in features["warnings"])

        contract = FileFeatureExtractor.extract_structured_features(empty_file)
        assert isinstance(contract, PEStaticFeatures)
        assert contract.file_metadata.file_size == 0
        assert contract.file_metadata.is_pe is False

    def test_truncated_dos_header(self, tmp_path):
        """Files with fewer than 64 bytes cannot contain a valid DOS header."""
        trunc_file = tmp_path / "truncated_dos.exe"
        trunc_file.write_bytes(b"MZ" + b"\x00" * 20)  # Only 22 bytes

        is_pe, reason = detect_pe_format(trunc_file)
        assert is_pe is False
        assert reason == "TOO_SMALL_FOR_PE"

        features = FileFeatureExtractor.extract_features(trunc_file)
        assert features["is_valid"] is True
        assert features["is_pe"] is False
        assert len(features["sha256"]) == 64

    def test_invalid_dos_magic(self, tmp_path):
        """64-byte file without MZ magic signature must be classified as non-PE."""
        invalid_dos = tmp_path / "invalid_dos.exe"
        invalid_dos.write_bytes(b"PK\x03\x04" + b"\x00" * 60)  # Zip magic

        is_pe, reason = detect_pe_format(invalid_dos)
        assert is_pe is False
        assert reason == "INVALID_DOS_SIGNATURE"

        features = FileFeatureExtractor.extract_features(invalid_dos)
        assert features["is_pe"] is False

    def test_pe_offset_out_of_bounds(self, tmp_path):
        """e_lfanew offset pointing past EOF must be rejected gracefully."""
        bad_offset = tmp_path / "bad_offset.exe"
        data = bytearray(64)
        data[0:2] = b"MZ"
        # Offset 0x3C points to 0x1000 (4096), but file is only 64 bytes
        struct.pack_into("<I", data, 0x3C, 4096)
        bad_offset.write_bytes(bytes(data))

        is_pe, reason = detect_pe_format(bad_offset)
        assert is_pe is False
        assert reason == "INVALID_PE_OFFSET"

        features = FileFeatureExtractor.extract_features(bad_offset)
        assert features["is_pe"] is False

    def test_pe_offset_below_dos_header(self, tmp_path):
        """e_lfanew offset below 64 bytes must be rejected as invalid."""
        bad_offset = tmp_path / "low_offset.exe"
        data = bytearray(64)
        data[0:2] = b"MZ"
        struct.pack_into("<I", data, 0x3C, 32)
        bad_offset.write_bytes(bytes(data))

        is_pe, reason = detect_pe_format(bad_offset)
        assert is_pe is False
        assert reason == "INVALID_PE_OFFSET"

    def test_invalid_pe_signature(self, tmp_path):
        """File with valid MZ header but corrupted PE signature at e_lfanew."""
        bad_sig = tmp_path / "bad_pe_sig.exe"
        data = bytearray(128)
        data[0:2] = b"MZ"
        struct.pack_into("<I", data, 0x3C, 64)
        data[64:68] = b"NE\x00\x00"  # OS/2 NE signature instead of PE\0\0
        bad_sig.write_bytes(bytes(data))

        is_pe, reason = detect_pe_format(bad_sig)
        assert is_pe is False
        assert reason == "INVALID_PE_SIGNATURE"

        features = FileFeatureExtractor.extract_features(bad_sig)
        assert features["is_pe"] is False

    def test_truncated_pe_header_body(self, tmp_path):
        """File with valid PE signature but truncated COFF/Optional headers."""
        trunc_pe = tmp_path / "trunc_pe_body.exe"
        data = bytearray(72)
        data[0:2] = b"MZ"
        struct.pack_into("<I", data, 0x3C, 64)
        data[64:68] = b"PE\x00\x00"
        struct.pack_into("<H", data, 68, 0x8664)  # AMD64
        trunc_pe.write_bytes(bytes(data))

        # detect_pe_format recognizes signature and architecture
        is_pe, arch = detect_pe_format(trunc_pe)
        assert is_pe is True
        assert arch == "IMAGE_FILE_MACHINE_AMD64"

        # FileFeatureExtractor attempts pefile.PE parsing and catches formatting errors safely
        features = FileFeatureExtractor.extract_features(trunc_pe)
        assert features["is_valid"] is True
        # Either pefile parsed minimal header or safely recorded warning
        assert isinstance(features["warnings"], list)

    def test_random_bytes_with_exe_extension(self, tmp_path):
        """Pure random noise named .exe must not crash static analysis."""
        noise_file = tmp_path / "random_payload.exe"
        noise_data = os.urandom(2048)
        noise_file.write_bytes(noise_data)

        features = FileFeatureExtractor.extract_features(noise_file)
        assert features["is_valid"] is True
        assert features["extension"] == ".exe"
        assert features["file_size"] == 2048
        assert features["is_pe"] is False
        assert features["entropy"] > 6.0  # High entropy random data


class TestOversizedFileBoundaries:
    """Verifies that static analysis respects size bounds without reading entire file to RAM."""

    def test_file_size_limit_constant(self):
        """Configured MAX_FILE_SIZE_BYTES must be at least 10MB."""
        assert MAX_FILE_SIZE_BYTES >= 10 * 1024 * 1024

    def test_oversized_file_rejection(self, tmp_path):
        """Files exceeding MAX_FILE_SIZE_BYTES must be bounded and not crash."""
        oversized = tmp_path / "giant.exe"
        # Create sparse file of size MAX_FILE_SIZE_BYTES + 1024 without writing 50MB to disk
        with open(oversized, "wb") as f:
            f.seek(MAX_FILE_SIZE_BYTES + 1024 - 1)
            f.write(b"\x00")

        features = FileFeatureExtractor.extract_features(oversized)
        assert features["is_valid"] is True
        assert features["file_size"] == MAX_FILE_SIZE_BYTES + 1024
        assert any("exceeds maximum safe" in w.lower() for w in features["warnings"])
        # Should not attempt deep PE parsing
        assert features["is_pe"] is False


class TestMalformedURLs:
    """Verifies robust validation, canonicalization, and feature extraction across adversarial URLs."""

    def test_extremely_long_url_rejected(self):
        """URLs exceeding MAX_URL_LENGTH (4096) must be rejected explicitly."""
        long_url = "https://example.com/" + "a" * 5000
        valid, err = validate_url(long_url)
        assert valid is False
        assert "exceeds maximum allowed length" in err

    def test_null_byte_in_url_rejected(self):
        """URLs containing null bytes or control characters must be rejected."""
        null_url = "https://example.com/login\x00.php"
        valid, err = validate_url(null_url)
        assert valid is False
        assert "control characters or null bytes" in err

    def test_unsupported_schemes_rejected(self):
        """Dangerous or unsupported schemes must be rejected explicitly."""
        schemes = [
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "file:///C:/Windows/System32/calc.exe",
            "mailto:admin@company.com",
            "ftp://ftp.example.com/archive.zip",
        ]
        for url in schemes:
            valid, err = validate_url(url)
            assert valid is False, f"Scheme {url} should have been rejected"
            assert "Unsupported URL scheme" in err or "Malformed hostname" in err or "Only HTTP and HTTPS" in err

    def test_missing_and_invalid_hostname(self):
        """URLs without a valid hostname structure must be rejected."""
        invalid_hosts = [
            "http://",
            "https:///",
            "http://   ",
            "https://.",
            "https://..com",
        ]
        for url in invalid_hosts:
            valid, _ = validate_url(url)
            assert valid is False

    def test_embedded_credentials_and_ports(self):
        """Valid URLs with embedded credentials and non-standard ports normalize safely."""
        url = "https://user:pass@example.com:8443/api/v1/auth?token=123#sec"
        assert is_valid_url(url) is True

        normalized = normalize_url(url)
        assert "example.com:8443" in normalized
        assert normalized.startswith("https://")
        assert extract_domain(url) == "example.com"

    def test_multiple_at_symbols(self):
        """URLs with multiple @ characters should extract features without throwing."""
        multi_at = "http://user@attacker.com@legit.com/path"
        # extract_url_features must extract 19 features without crashing
        feats = extract_url_features(multi_at)
        assert len(feats) == 19
        assert feats[7] >= 2  # n_at count is at least 2

    def test_url_feature_extraction_never_crashes(self):
        """extract_url_features must handle non-string, None, and empty inputs gracefully."""
        cases = [None, "", "   ", 12345, [], {}, b"http://example.com"]
        for case in cases:
            feats = extract_url_features(case)
            assert len(feats) == 19
            assert all(isinstance(v, int) for v in feats)
            is_valid, err = validate_extracted_features(feats)
            assert is_valid is True, f"Features invalid for {case}: {err}"


class TestMessageAndRegexSafety:
    """Verifies that text/message parsing does not hang or consume unbounded resources."""

    def test_large_message_processing(self):
        """Large text (100KB) with repeated punctuation and social engineering cues completes fast."""
        t0 = time.time()
        large_body = (
            "URGENT: Your account has been suspended! "
            "Please confirm your identity and verify your password immediately within 24 hours. "
            "Claim your refund and wire transfer now: https://verify-login.example.com/auth. "
        ) * 500  # ~85 KB
        result = TextAnalyzer.analyze_message_structured(large_body)
        duration = time.time() - t0

        assert duration < 2.5, f"Message analysis took too long ({duration:.2f}s)"
        assert isinstance(result, MessageScanResult)
        assert result.unique_url_count == 1
        assert result.social_engineering["has_urgency"] is True
        assert result.social_engineering["has_credential_request"] is True
        assert result.social_engineering["has_financial_lure"] is True
        assert result.overall_score >= 50.0

    def test_nested_quotes_and_brackets_url_cleaning(self):
        """TextAnalyzer safely unwraps nested quotes, parentheses, and brackets without hanging."""
        messy_text = (
            'Check this: "((https://sub.domain.com/path(1)/test?q=[val]))" '
            "and '<https://phish.net/login.php!>' "
            "and [http://clean.org]."
        )
        urls = TextAnalyzer.extract_urls(messy_text)
        assert len(urls) == 3
        # Balanced parens inside path preserved, outer quotes/brackets stripped
        assert urls[0] == "https://sub.domain.com/path(1)/test?q=[val]"
        assert urls[1] == "https://phish.net/login.php"
        assert urls[2] == "http://clean.org"

    def test_pathological_repetition_does_not_redos(self):
        """Pathological repeated sequences designed to trigger catastrophic regex backtracking."""
        t0 = time.time()
        # Repeated dots, slashes, spaces
        nasty = "http://www." + "a." * 1000 + "com" + "////" * 500 + "?q=" + "=====" * 500
        _ = TextAnalyzer.extract_urls(nasty)
        assert (time.time() - t0) < 1.0


class TestClassificationAndFalsePositiveSafety:
    """Verifies that benign inputs and missing intelligence do not yield false classifications."""

    def test_benign_pe_with_no_findings_is_low_risk(self):
        """A file with zero threat intel, no ML malware signal, and no suspicious rules is LOW."""
        evidence = DetectionEvidence()
        score, breakdown = RiskScoringEngine.score_evidence(evidence)
        assert score == 0.0
        assert breakdown.active_layers == []

        result = DetectionDecisionEngine.evaluate(
            target_identifier="clean_calc.exe",
            input_type=InputType.FILE,
        )
        assert result.risk_level in (RiskLevel.INFORMATIONAL, RiskLevel.LOW)
        assert result.detection_status == DetectionStatus.BENIGN
        assert result.risk_score == 0.0

    def test_missing_intelligence_does_not_bias_classification(self):
        """Missing threat intel does NOT force a malicious classification or false positive."""
        unavailable_ti = ThreatIntelEvidence.unavailable(
            indicator="test_hash_123",
            reason="Service offline",
            indicator_type=IndicatorType.SHA256,
            provider="MockProvider",
        )
        assert unavailable_ti.verdict == ThreatIntelVerdict.UNAVAILABLE
        assert unavailable_ti.is_confirmed_threat is False
        assert unavailable_ti.to_evidence_signal() is None

        # Evidence evaluation without other signals remains clean
        evidence = DetectionEvidence()
        sig = unavailable_ti.to_evidence_signal()
        if sig:
            evidence.add_signal(sig)
        score, _ = RiskScoringEngine.score_evidence(evidence)
        assert score == 0.0

    def test_single_weak_heuristic_does_not_force_critical(self):
        """A single weak heuristic rule (score 15) must not escalate to CRITICAL severity."""
        evidence = DetectionEvidence()
        evidence.add_signal(
            EvidenceSignal(
                source=EvidenceSource.HEURISTIC_RULES,
                signal_id="RULE-WEAK-01",
                name="AnomalousSectionName",
                description="Minor anomalous section name",
                severity=EvidenceSeverity.LOW,
                score_contribution=15.0,
            )
        )
        score, breakdown = RiskScoringEngine.score_evidence(evidence)
        assert score <= 20.0
        assert "HEURISTIC_RULES" in breakdown.active_layers

    def test_confirmed_threat_intel_enforces_critical_floor(self):
        """A confirmed malicious threat intelligence finding enforces a minimum score of 90."""
        evidence = DetectionEvidence()
        evidence.add_signal(
            EvidenceSignal(
                source=EvidenceSource.THREAT_INTELLIGENCE,
                signal_id="TI-WANNACRY-01",
                name="WannaCryHashMatch",
                description="Confirmed WannaCry ransomware signature in threat database",
                severity=EvidenceSeverity.CRITICAL,
                score_contribution=100.0,
            )
        )
        score, breakdown = RiskScoringEngine.score_evidence(evidence)
        assert score >= 90.0
        assert breakdown.threat_intel_score == 100.0
