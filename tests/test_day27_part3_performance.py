"""
Tests for ACTIS Day 27 Part 3: Performance, Regression Validation & Multi-URL Analysis.
Reproduces:
1. Redundant ML model inference per URL (double inference in ThreatDetector.analyze_url).
2. scikit-learn RandomForest single-sample inference threadpool dispatch overhead.
3. Message-level redundant analysis for identical canonical URLs.
4. Bounded analysis and timeout safety (never silently convert timeout to benign).
"""

import pytest
import time
from unittest.mock import patch, MagicMock

from detection_engine.threat_detector import threat_detector, ThreatDetector
from detection_engine.model_manager import model_manager, MLModelType
from scanners.text_analyzer import TextAnalyzer


class TestDay27Part3PerformanceBottleneck:
    """Deterministic regression tests capturing multi-URL bottlenecks."""

    def test_reproduce_double_ml_inference_per_url(self):
        """
        Verify that analyze_url currently executes predict_phishing_structured twice
        due to calling both predict_phishing_structured and predict_phishing (which wraps it).
        In optimized performance, predict_phishing_structured should only be invoked once.
        """
        sample_url = "http://perf-test-indicator-01.com/login"
        
        call_count = 0
        original_structured = model_manager.predict_phishing_structured

        def counting_predict(features):
            nonlocal call_count
            call_count += 1
            return original_structured(features)

        with patch.object(model_manager, "predict_phishing_structured", side_effect=counting_predict):
            res = threat_detector.analyze_url(sample_url, check_external=False)
            assert res is not None
            assert res["url"] == sample_url

        # Post-optimization verification: exactly 1 ML inference per URL
        assert call_count == 1, f"Expected exactly 1 ML inference call per URL, found {call_count}"

    def test_model_manager_n_jobs_configuration(self):
        """
        Verify the n_jobs setting of the loaded models is configured to 1
        to avoid single-sample threadpool dispatch overhead.
        """
        if model_manager.is_phishing_model_available():
            assert model_manager.phishing_model.n_jobs == 1
        if model_manager.is_malware_model_available():
            assert model_manager.malware_model.n_jobs == 1

    def test_prediction_to_legacy_dict_fidelity(self):
        """
        Verify that prediction_to_legacy_dict accurately converts MLPredictionResult
        into legacy dict format with all required keys and correct labels.
        """
        from detection_engine.ml_prediction_contract import MLPredictionResult, MLPredictionStatus
        
        # Test available result
        available_res = MLPredictionResult(
            model_name="test_rf",
            model_version="1.0.0",
            model_type=MLModelType.PHISHING_URL,
            status=MLPredictionStatus.AVAILABLE,
            is_threat=True,
            probability=0.95,
            confidence=0.95,
            prediction_label="phishing",
            features_used=["f1"]
        )
        legacy_dict = model_manager.prediction_to_legacy_dict(available_res)
        assert legacy_dict["available"] is True
        assert legacy_dict["is_phishing"] is True
        assert legacy_dict["probability"] == 0.95
        assert legacy_dict["confidence"] == 0.95
        assert legacy_dict["label"] == "phishing"

        # Test unavailable result
        unavail_res = MLPredictionResult.unavailable("test_rf", MLModelType.PHISHING_URL, "Model missing")
        unavail_dict = model_manager.prediction_to_legacy_dict(unavail_res)
        assert unavail_dict["available"] is False
        assert unavail_dict["is_phishing"] is False
        assert "Model missing" in unavail_dict["error"]

    def test_extract_url_features_fast_path_fidelity(self):
        """
        Verify that is_already_normalized=True yields identical features
        to the standard extraction path without mutating feature schema.
        """
        from scanners.url_scanner import extract_url_features, normalize_url
        
        test_url = "https://example.com/login?token=abc#section"
        canonical = normalize_url(test_url)
        
        feat_standard = extract_url_features(canonical, is_already_normalized=False)
        feat_fast = extract_url_features(canonical, is_already_normalized=True)
        
        assert feat_standard == feat_fast
        assert len(feat_fast) == 19

    def test_multi_url_message_with_repeated_canonical_urls(self):
        """
        Verify that a message containing duplicate URLs correctly deduplicates them
        and does not produce corrupted score or evidence.
        """
        msg_text = (
            "URGENT: Verify your account immediately.\n"
            "Link 1: https://secure-bank-login.com/auth\n"
            "Link 2: https://secure-bank-login.com/auth\n"
            "Link 3: https://secure-bank-login.com/auth\n"
            "Link 4: http://another-link.org/test\n"
        )
        
        scan_res = TextAnalyzer.analyze_message_structured(msg_text, check_external=False)
        assert scan_res.is_valid
        assert scan_res.total_url_count == 4
        # Unique canonical URLs must be 2
        assert scan_res.unique_url_count == 2
        assert len(scan_res.url_results) == 2

    def test_timeout_preserves_partial_or_failure_semantics(self):
        """
        Security Invariant: A timeout or processing limitation must never silently
        convert an incomplete analysis into a benign verdict.
        """
        from scanners.mime_parser import SafeMIMEParser, MIMEAnalysisLimits
        
        # Test SafeMIMEParser with strict deadline
        strict_limits = MIMEAnalysisLimits(max_analysis_time_seconds=0.000001)
        parser = SafeMIMEParser(limits=strict_limits)
        
        # Parse large multi-part content
        large_body = "Subject: Test\n\n" + ("http://example.com/item\n" * 50)
        res = parser.parse_message(large_body, deadline_time=time.time() - 1.0)
        
        assert res.analysis_completeness in ("PARTIAL", "FAILED")
        assert res.limit_reached == "MAX_ANALYSIS_TIME"
