"""
Unit Tests for Safe Static File Analysis and PE Feature Extraction
"""

import pytest
from pathlib import Path
from scanners.file_feature_extractor import FileFeatureExtractor, calculate_entropy
from scanners.file_scanner import scan_file
from detection_engine.model_manager import model_manager


def test_entropy_calculation():
    assert calculate_entropy(b"") == 0.0
    # Homogeneous byte sequence has 0 entropy
    assert calculate_entropy(b"A" * 100) == 0.0
    # Uniform distribution across 256 bytes has theoretical maximum entropy 8.0
    all_bytes = bytes(range(256))
    assert 7.9 < calculate_entropy(all_bytes) <= 8.0


def test_non_pe_static_analysis(tmp_path):
    txt_file = tmp_path / "sample.txt"
    txt_file.write_text("This is safe test text content.", encoding="utf-8")
    
    info = FileFeatureExtractor.extract_features(txt_file)
    assert info["is_valid"] is True
    assert info["is_pe"] is False
    assert len(info["sha256"]) == 64
    assert len(info["md5"]) == 32
    assert info["entropy"] > 0.0

    res = scan_file(txt_file)
    assert res["risk_level"] == "LOW"
    assert res["is_threat"] is False


def test_pe_static_analysis_notepad():
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
        assert pred["is_malware"] is False
