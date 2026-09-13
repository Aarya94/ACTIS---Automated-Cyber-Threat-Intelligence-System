"""
Unit Tests for Safe Static File Analysis, PE Detection, and Feature Extraction
Automated Cyber Threat Intelligence System — Week 1 Day 5
"""

import hashlib
import struct
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from detection_engine.malware_dataset_schema import MALWARE_FEATURE_COLUMNS
from detection_engine.model_manager import model_manager
from scanners.file_feature_extractor import (
    FileFeatureExtractor,
    analyze_pe_entropy_distribution,
    calculate_entropy,
    calculate_file_entropy,
    calculate_file_hashes,
    calculate_shannon_entropy,
    detect_pe_format,
    extract_pe_header_metadata,
    extract_pe_import_features,
    extract_pe_section_features,
    is_pe_file,
)
from scanners.file_scanner import scan_file
from scanners.pe_feature_contract import (
    FileMetadata,
    PEIdentifiers,
    PEImportFeature,
    PEMetadata,
    PESectionFeature,
    PEStaticFeatures,
)


def create_minimal_synthetic_pe() -> bytes:
    """
    Creates a minimal, compliant, benign synthetic 32-bit Windows PE binary in memory.
    Contains valid DOS header, COFF header, Optional header, and one .text section.
    Requires no real malware or external sample downloads.
    """
    # DOS Header (64 bytes)
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<I", dos_header, 0x3C, 0x80)  # e_lfanew = 0x80

    # DOS Stub padding to 0x80
    dos_stub = b"\x00" * (0x80 - 64)

    # PE Signature (4 bytes)
    pe_sig = b"PE\x00\x00"

    # COFF File Header (20 bytes)
    coff_header = struct.pack(
        "<HHIIIHH",
        0x014C,     # Machine (x86, 332)
        1,          # NumberOfSections
        123456789,  # TimeDateStamp
        0,          # PointerToSymbolTable
        0,          # NumberOfSymbols
        224,        # SizeOfOptionalHeader (0xE0)
        0x0102      # Characteristics
    )

    # Standard Optional Header (28 bytes)
    opt_standard = struct.pack(
        "<HBBIIIIII",
        0x010B,     # Magic (PE32)
        14, 0,      # Major/MinorLinkerVersion
        0x200,      # SizeOfCode
        0x200,      # SizeOfInitializedData
        0,          # SizeOfUninitializedData
        0x1000,     # AddressOfEntryPoint
        0x1000,     # BaseOfCode
        0x2000      # BaseOfData
    )

    # NT-specific Optional Header fields (68 bytes) + Loader/RVA (8 bytes) = 76 bytes
    opt_nt = struct.pack(
        "<IIIHHHHHHIIIIHHIIIIII",
        0x00400000, # ImageBase
        0x1000,     # SectionAlignment
        0x200,      # FileAlignment
        6, 0,       # Major/MinorOSVersion
        1, 0,       # Major/MinorImageVersion
        6, 0,       # Major/MinorSubsystemVersion
        0,          # Win32VersionValue
        0x3000,     # SizeOfImage
        0x400,      # SizeOfHeaders
        0,          # CheckSum
        3,          # Subsystem (WINDOWS_CUI)
        0x8140,     # DllCharacteristics
        0x100000,   # SizeOfStackReserve
        0x1000,     # SizeOfStackCommit
        0x100000,   # SizeOfHeapReserve
        0x1000,     # SizeOfHeapCommit
        0,          # LoaderFlags
        16          # NumberOfRvaAndSizes
    )

    # 16 Data Directories (16 * 8 = 128 bytes)
    data_dirs = b"\x00" * 128
    optional_header = opt_standard + opt_nt + data_dirs

    # Section Header (40 bytes)
    sec_header = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        0x200,      # VirtualSize
        0x1000,     # VirtualAddress
        0x200,      # SizeOfRawData
        0x400,      # PointerToRawData
        0, 0,       # Relocations, Linenumbers
        0, 0,       # Counts
        0x60000020  # Characteristics (CNT_CODE | MEM_EXECUTE | MEM_READ)
    )

    headers = dos_header + dos_stub + pe_sig + coff_header + optional_header + sec_header
    headers_padded = headers + b"\x00" * (0x400 - len(headers))
    section_data = b"\x90" * 0x200  # NOP instructions

    return headers_padded + section_data


class TestSafeFileHashing:
    """Tests for streaming multi-algorithm cryptographic hashing."""

    def test_calculate_file_hashes_success(self, tmp_path):
        sample_file = tmp_path / "hash_sample.bin"
        content = b"ACTIS Day 5 Security Static Analysis"
        sample_file.write_bytes(content)

        hashes = calculate_file_hashes(sample_file)
        assert len(hashes["sha256"]) == 64
        assert len(hashes["md5"]) == 32
        assert len(hashes["sha1"]) == 40
        assert hashes["sha256"] == hashlib.sha256(content).hexdigest()
        assert hashes["md5"] == hashlib.md5(content).hexdigest()
        assert hashes["sha1"] == hashlib.sha1(content).hexdigest()

    def test_calculate_file_hashes_nonexistent_file(self):
        with pytest.raises(FileNotFoundError):
            calculate_file_hashes("non_existent_file_path.xyz")

    def test_calculate_file_hashes_unsupported_algo(self, tmp_path):
        sample = tmp_path / "sample.txt"
        sample.write_text("test")
        with pytest.raises(ValueError, match="Unsupported hash algorithm"):
            calculate_file_hashes(sample, algorithms=["sha256", "invalid_algo_xyz"])


class TestShannonEntropyCalculations:
    """Tests for Shannon entropy calculation across bytes, files, and distributions."""

    def test_entropy_empty_data(self):
        assert calculate_entropy(b"") == 0.0
        assert calculate_shannon_entropy(b"") == 0.0

    def test_entropy_homogeneous_bytes(self):
        assert calculate_entropy(b"A" * 1000) == 0.0

    def test_entropy_uniform_distribution(self):
        all_bytes = bytes(range(256))
        entropy = calculate_entropy(all_bytes)
        assert 7.95 < entropy <= 8.0

    def test_calculate_file_entropy(self, tmp_path):
        sample = tmp_path / "entropy.bin"
        sample.write_bytes(bytes(range(256)) * 4)
        file_entropy = calculate_file_entropy(sample)
        assert 7.95 < file_entropy <= 8.0

    def test_calculate_file_entropy_empty(self, tmp_path):
        empty_file = tmp_path / "empty.bin"
        empty_file.write_bytes(b"")
        assert calculate_file_entropy(empty_file) == 0.0

    def test_analyze_pe_entropy_distribution(self):
        sections = [
            {"name": ".text", "entropy": 6.2},
            {"name": ".data", "entropy": 3.1},
            {"name": ".rsrc", "entropy": 7.5},
        ]
        dist = analyze_pe_entropy_distribution(sections, file_entropy=6.8)
        assert dist["file_entropy"] == 6.8
        assert dist["section_entropy_max"] == 7.5
        assert dist["section_entropy_min"] == 3.1
        assert dist["high_entropy_section_count"] == 1
        assert dist["is_likely_packed"] is True


class TestWindowsPEFileDetection:
    """Tests for non-destructive pre-parser binary signature detection."""

    def test_detect_pe_synthetic_pe(self, tmp_path):
        pe_file = tmp_path / "synthetic.exe"
        pe_file.write_bytes(create_minimal_synthetic_pe())

        assert is_pe_file(pe_file) is True
        is_pe, desc = detect_pe_format(pe_file)
        assert is_pe is True
        assert desc == "IMAGE_FILE_MACHINE_I386"

    def test_detect_pe_text_file(self, tmp_path):
        txt_file = tmp_path / "notes.txt"
        txt_file.write_text("Hello world", encoding="utf-8")

        assert is_pe_file(txt_file) is False
        is_pe, desc = detect_pe_format(txt_file)
        assert is_pe is False
        assert desc == "TOO_SMALL_FOR_PE"

    def test_detect_pe_random_binary(self, tmp_path):
        bin_file = tmp_path / "random.bin"
        bin_file.write_bytes(b"\xFF" * 128)

        assert is_pe_file(bin_file) is False
        is_pe, desc = detect_pe_format(bin_file)
        assert is_pe is False
        assert desc == "INVALID_DOS_SIGNATURE"

    def test_detect_pe_truncated_pe(self, tmp_path):
        # File with MZ header but e_lfanew pointing out of bounds
        bad_dos = bytearray(64)
        bad_dos[0:2] = b"MZ"
        struct.pack_into("<I", bad_dos, 0x3C, 0x9999)  # offset out of bounds
        trunc_file = tmp_path / "trunc.exe"
        trunc_file.write_bytes(bad_dos)

        assert is_pe_file(trunc_file) is False
        is_pe, desc = detect_pe_format(trunc_file)
        assert is_pe is False
        assert desc == "INVALID_PE_OFFSET"


class TestPEMetadataAndSectionExtraction:
    """Tests for header, section, and import extraction logic."""

    def test_synthetic_pe_extraction(self, tmp_path):
        pe_file = tmp_path / "synthetic.exe"
        pe_file.write_bytes(create_minimal_synthetic_pe())

        info = FileFeatureExtractor.extract_features(pe_file)
        assert info["is_valid"] is True
        assert info["is_pe"] is True
        assert info["file_size"] == 1536
        assert len(info["sha256"]) == 64
        assert len(info["md5"]) == 32
        assert len(info["sha1"]) == 40

        # Verify PE headers
        pe_feats = info["pe_features"]
        assert pe_feats["Machine"] == 332  # x86
        assert pe_feats["NumberOfSections"] == 1
        assert pe_feats["MajorLinkerVersion"] == 14
        assert pe_feats["MajorOSVersion"] == 6
        assert pe_feats["SizeOfStackReserve"] == 0x100000

        # Verify section
        sections = info["sections"]
        assert len(sections) == 1
        assert sections[0]["name"] == ".text"
        assert sections[0]["is_executable"] is True
        assert sections[0]["is_readable"] is True

        # Verify exact 15 ML features vector
        ml_vec = info["ml_feature_vector"]
        assert len(ml_vec) == 15
        assert len(MALWARE_FEATURE_COLUMNS) == 15

    def test_mocked_import_feature_extraction(self):
        # Test extract_pe_import_features with mock PE instance
        mock_pe = MagicMock()
        entry1 = MagicMock()
        entry1.dll = b"KERNEL32.dll"
        imp1 = MagicMock()
        imp1.name = b"VirtualAlloc"
        imp2 = MagicMock()
        imp2.name = b"CreateFileA"
        entry1.imports = [imp1, imp2]

        entry2 = MagicMock()
        entry2.dll = b"user32.dll"
        imp3 = MagicMock()
        imp3.name = b"FindWindowA"
        entry2.imports = [imp3]

        mock_pe.DIRECTORY_ENTRY_IMPORT = [entry1, entry2]

        imp_res = extract_pe_import_features(mock_pe)
        assert imp_res["imported_dll_count"] == 2
        assert "kernel32.dll" in imp_res["imported_dlls"]
        assert "user32.dll" in imp_res["imported_dlls"]
        assert imp_res["imported_function_count"] == 3
        assert "VirtualAlloc" in imp_res["suspicious_apis_found"]
        assert "FindWindowA" in imp_res["suspicious_apis_found"]
        assert imp_res["suspicious_api_count"] == 2


class TestStructuredPEFeatureContract:
    """Tests for strongly-typed PEStaticFeatures dataclass contract."""

    def test_structured_features_extraction(self, tmp_path):
        pe_file = tmp_path / "test_sample.exe"
        pe_file.write_bytes(create_minimal_synthetic_pe())

        contract = FileFeatureExtractor.extract_structured_features(pe_file)
        assert isinstance(contract, PEStaticFeatures)
        assert isinstance(contract.identifiers, PEIdentifiers)
        assert isinstance(contract.file_metadata, FileMetadata)
        assert isinstance(contract.pe_metadata, PEMetadata)

        # Verify separation of threat intelligence identifiers from ML features
        assert contract.identifiers.filename == "test_sample.exe"
        assert len(contract.identifiers.sha256) == 64
        assert contract.file_metadata.is_pe is True

        # Verify ML vector extraction
        vec = contract.to_ml_feature_vector()
        assert len(vec) == 15
        assert vec[0] == 332  # Machine is first feature

        # Verify dictionary serialization
        as_dict = contract.to_dict()
        assert "identifiers" in as_dict
        assert "file_metadata" in as_dict
        assert "pe_metadata" in as_dict
        assert "ml_feature_vector" in as_dict


class TestMalformedAndEdgeCaseHandling:
    """Tests ensuring analyzer never crashes on invalid, corrupted, or missing files."""

    def test_nonexistent_file(self):
        res = FileFeatureExtractor.extract_features("does_not_exist_file_9999.exe")
        assert res["is_valid"] is False
        assert "does_not_exist" in res.get("error", "")

    def test_empty_file(self, tmp_path):
        empty = tmp_path / "empty.exe"
        empty.write_bytes(b"")
        res = FileFeatureExtractor.extract_features(empty)
        assert res["is_valid"] is True
        assert res["file_size"] == 0
        assert res["is_pe"] is False
        assert any("empty" in w.lower() for w in res["warnings"])

    def test_corrupted_pe_signature(self, tmp_path):
        # Valid DOS header, but PE signature is corrupted
        raw = bytearray(create_minimal_synthetic_pe())
        raw[0x80:0x84] = b"NOPE"  # Corrupt PE signature
        corrupt_file = tmp_path / "corrupt.exe"
        corrupt_file.write_bytes(raw)

        res = FileFeatureExtractor.extract_features(corrupt_file)
        assert res["is_valid"] is True
        assert res["is_pe"] is False
        assert len(res["sha256"]) == 64  # Hash calculation still succeeds safely

    def test_directory_passed_as_file(self, tmp_path):
        sub_dir = tmp_path / "subdir"
        sub_dir.mkdir()
        res = FileFeatureExtractor.extract_features(sub_dir)
        assert res["is_valid"] is False
        assert "directory" in res.get("error", "").lower()


def test_pe_static_analysis_notepad():
    """Existing integration test on Windows host executable if present."""
    notepad_path = Path("C:/Windows/notepad.exe")
    if notepad_path.exists():
        info = FileFeatureExtractor.extract_features(notepad_path)
        assert info["is_pe"] is True
        assert len(info["sha256"]) == 64
        pe_feats = info.get("pe_features", {})
        assert "Machine" in pe_feats
        assert "NumberOfSections" in pe_feats
        assert "DllCharacteristics" in pe_feats
        assert len(info["ml_feature_vector"]) == 15

        # Test malware model prediction on real PE features
        pred = model_manager.predict_malware(info["ml_feature_vector"])
        assert pred["available"] is True
        assert "probability" in pred
