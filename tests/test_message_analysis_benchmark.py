"""
Tests for ACTIS Day 26: Message Analysis and Phishing Verification Benchmark.
Validates dataset loading, validation errors, metric math, runner isolation,
report generation, determinism, and zero external network calls.
"""

import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from benchmarks.message_analysis.dataset import (
    BenchmarkDataset,
    BenchmarkSample,
    DatasetValidationError,
    validate_dataset_manifest,
    load_benchmark_dataset,
    compute_manifest_hash
)
from benchmarks.message_analysis.metrics import (
    ConfusionMatrix,
    ClassificationMetrics,
    CoverageMetrics,
    PerRuleMetric,
    calculate_confusion_matrix,
    calculate_classification_metrics,
    calculate_coverage_metrics,
    calculate_performance_metrics
)
from benchmarks.message_analysis.runner import (
    BenchmarkRunner,
    BenchmarkRunResult,
    map_actis_verdict_to_prediction
)
from benchmarks.message_analysis.report import (
    BenchmarkReporter,
    generate_reports
)


class TestBenchmarkDatasetAndValidation:
    """Tests for dataset loading, manifest integrity, and validation constraints."""

    def test_load_production_benchmark_dataset(self):
        """Verifies canonical dataset loads with valid version, hash, and non-empty sample count."""
        dataset = load_benchmark_dataset()
        assert dataset.version == "1.0.0"
        assert len(dataset) >= 100
        assert len(dataset.dataset_hash) == 64
        assert len(dataset.phishing_samples) > 0
        assert len(dataset.benign_samples) > 0
        assert len(dataset.edge_case_samples) > 0

    def test_dataset_summary_statistics(self):
        """Verifies summary dictionary matches expected scenario distributions."""
        dataset = load_benchmark_dataset()
        summary = dataset.summary()
        assert summary["version"] == "1.0.0"
        assert summary["total_count"] == len(dataset)
        assert "credential_harvesting" in summary["scenarios"]
        assert "legitimate_security_account" in summary["scenarios"]

    def test_validation_rejects_missing_dataset_version(self):
        """Rejects manifest missing dataset_version."""
        data = {"samples": [{"id": "S1", "label": "BENIGN", "scenario": "credential_harvesting", "description": "d", "content": "c"}]}
        with pytest.raises(DatasetValidationError, match="dataset_version"):
            validate_dataset_manifest(data)

    def test_validation_rejects_empty_samples(self):
        """Rejects manifest with empty samples list."""
        data = {"dataset_version": "1.0.0", "samples": []}
        with pytest.raises(DatasetValidationError, match="cannot be empty"):
            validate_dataset_manifest(data)

    def test_validation_rejects_duplicate_sample_id(self):
        """Rejects manifest containing duplicate sample IDs."""
        data = {
            "dataset_version": "1.0.0",
            "samples": [
                {"id": "SAMPLE_001", "label": "PHISHING", "scenario": "credential_harvesting", "description": "d1", "content": "c1"},
                {"id": "SAMPLE_001", "label": "BENIGN", "scenario": "credential_harvesting", "description": "d2", "content": "c2"}
            ]
        }
        with pytest.raises(DatasetValidationError, match="Duplicate sample ID"):
            validate_dataset_manifest(data)

    def test_validation_rejects_invalid_label(self):
        """Rejects manifest with unsupported label."""
        data = {
            "dataset_version": "1.0.0",
            "samples": [
                {"id": "SAMPLE_001", "label": "UNKNOWN_LABEL", "scenario": "credential_harvesting", "description": "d", "content": "c"}
            ]
        }
        with pytest.raises(DatasetValidationError, match="invalid label"):
            validate_dataset_manifest(data)

    def test_validation_rejects_unsupported_scenario(self):
        """Rejects manifest with unsupported scenario."""
        data = {
            "dataset_version": "1.0.0",
            "samples": [
                {"id": "SAMPLE_001", "label": "PHISHING", "scenario": "unsupported_cat", "description": "d", "content": "c"}
            ]
        }
        with pytest.raises(DatasetValidationError, match="unsupported scenario"):
            validate_dataset_manifest(data)

    def test_validation_rejects_missing_field(self):
        """Rejects sample missing required description field."""
        data = {
            "dataset_version": "1.0.0",
            "samples": [
                {"id": "SAMPLE_001", "label": "PHISHING", "scenario": "credential_harvesting", "content": "c"}
            ]
        }
        with pytest.raises(DatasetValidationError, match="missing required field 'description'"):
            validate_dataset_manifest(data)

    def test_load_nonexistent_file_raises_not_found(self):
        """Rejects non-existent manifest path."""
        with pytest.raises(FileNotFoundError):
            load_benchmark_dataset(Path("tests/fixtures/non_existent_manifest.json"))


class TestMetricsCalculationEngine:
    """Deterministic tests for confusion matrix, precision, recall, F1, and edge conditions."""

    def test_confusion_matrix_perfect_predictions(self):
        """Tests CM calculation on perfect binary predictions."""
        pairs = [
            ("PHISHING", "PHISHING"),
            ("PHISHING", "PHISHING"),
            ("BENIGN", "BENIGN"),
            ("BENIGN", "BENIGN")
        ]
        cm = calculate_confusion_matrix(pairs)
        assert cm.true_positives == 2
        assert cm.true_negatives == 2
        assert cm.false_positives == 0
        assert cm.false_negatives == 0
        assert cm.total_evaluated == 4

        m = calculate_classification_metrics(cm)
        assert m.precision == 1.0
        assert m.recall == 1.0
        assert m.f1_score == 1.0
        assert m.specificity == 1.0
        assert m.accuracy == 1.0
        assert m.false_positive_rate == 0.0
        assert m.false_negative_rate == 0.0

    def test_confusion_matrix_mixed_predictions(self):
        """Tests CM with known FP and FN."""
        pairs = [
            ("PHISHING", "PHISHING"),  # TP
            ("PHISHING", "BENIGN"),    # FN
            ("BENIGN", "PHISHING"),    # FP
            ("BENIGN", "BENIGN")       # TN
        ]
        cm = calculate_confusion_matrix(pairs)
        assert cm.true_positives == 1
        assert cm.true_negatives == 1
        assert cm.false_positives == 1
        assert cm.false_negatives == 1

        m = calculate_classification_metrics(cm)
        assert m.precision == 0.5
        assert m.recall == 0.5
        assert m.f1_score == 0.5
        assert m.accuracy == 0.5
        assert m.specificity == 0.5
        assert m.balanced_accuracy == 0.5
        assert m.false_positive_rate == 0.5
        assert m.false_negative_rate == 0.5

    def test_zero_denominator_precision_handling(self):
        """Tests precision returns None when no positive predictions are made (TP + FP = 0)."""
        pairs = [
            ("BENIGN", "BENIGN"),
            ("PHISHING", "BENIGN")
        ]
        cm = calculate_confusion_matrix(pairs)
        assert cm.true_positives == 0
        assert cm.false_positives == 0
        assert cm.false_negatives == 1
        assert cm.true_negatives == 1

        m = calculate_classification_metrics(cm)
        assert m.precision is None
        assert m.recall == 0.0
        assert m.f1_score is None

    def test_zero_denominator_recall_handling(self):
        """Tests recall returns None when no actual positive samples exist (TP + FN = 0)."""
        pairs = [
            ("BENIGN", "BENIGN"),
            ("BENIGN", "PHISHING")
        ]
        cm = calculate_confusion_matrix(pairs)
        m = calculate_classification_metrics(cm)
        assert m.recall is None
        assert m.f1_score is None

    def test_coverage_and_abstention_metrics(self):
        """Verifies coverage rate calculation ignores abstentions in binary counts."""
        cov = calculate_coverage_metrics(
            total_samples=100,
            valid_predictions=90,
            abstentions=10,
            incomplete_analyses=8,
            invalid_inputs=2,
            exceptions=0
        )
        assert cov.total_samples == 100
        assert cov.valid_binary_predictions == 90
        assert cov.abstentions == 10
        assert cov.coverage_rate == 0.9

    def test_performance_metrics_calculations(self):
        """Tests mean, median, and p95 latency calculation."""
        durations = [0.010, 0.020, 0.030, 0.040, 0.050]
        perf = calculate_performance_metrics(durations)
        assert perf.sample_count == 5
        assert perf.min_seconds == 0.010
        assert perf.max_seconds == 0.050
        assert pytest.approx(perf.mean_seconds, 0.0001) == 0.030
        assert pytest.approx(perf.median_seconds, 0.0001) == 0.030
        assert pytest.approx(perf.p95_seconds, 0.0001) == 0.050

    def test_empty_durations_returns_clean_defaults(self):
        """Empty durations list returns zeroed performance metrics."""
        perf = calculate_performance_metrics([])
        assert perf.sample_count == 0
        assert perf.mean_seconds == 0.0


class TestBenchmarkRunnerAndMapping:
    """Tests evaluating verdict mapping, runner behavior, and offline network boundaries."""

    def test_verdict_mapping_phishing_cases(self):
        """Maps threat/high risk to PHISHING."""
        assert map_actis_verdict_to_prediction({"is_threat": True, "risk_level": "HIGH", "score": 85.0}) == "PHISHING"
        assert map_actis_verdict_to_prediction({"is_threat": False, "risk_level": "HIGH", "score": 65.0}) == "PHISHING"
        assert map_actis_verdict_to_prediction({"is_threat": False, "risk_level": "LOW", "score": 70.0}) == "PHISHING"

    def test_verdict_mapping_benign_cases(self):
        """Maps clear low risk to BENIGN."""
        assert map_actis_verdict_to_prediction({"is_threat": False, "risk_level": "LOW", "score": 10.0, "analysis_completeness": "COMPLETE", "is_valid": True}) == "BENIGN"
        assert map_actis_verdict_to_prediction({"is_threat": False, "risk_level": "INFORMATIONAL", "score": 0.0, "analysis_completeness": "COMPLETE", "is_valid": True}) == "BENIGN"

    def test_verdict_mapping_abstain_cases(self):
        """Maps invalid input and partial analyses to ABSTAIN."""
        assert map_actis_verdict_to_prediction({"is_valid": False, "score": 0.0}) == "ABSTAIN"
        assert map_actis_verdict_to_prediction({"analysis_completeness": "PARTIAL", "score": 50.0}) == "ABSTAIN"

    def test_no_network_calls_during_benchmark_run(self):
        """Proves runner initiates zero socket or urllib network calls."""
        mini_dataset = BenchmarkDataset(
            version="1.0.0",
            description="mini",
            created_date="2026-10-13",
            license="MIT",
            dataset_hash="fakehash",
            samples=[
                BenchmarkSample(
                    id="TEST_001",
                    label="BENIGN",
                    scenario="benign_financial_business",
                    description="test",
                    content="Hello team, project update at https://example.com/status"
                )
            ]
        )
        runner = BenchmarkRunner(mini_dataset)

        with patch("urllib.request.urlopen") as mock_url, \
             patch("http.client.HTTPConnection.connect") as mock_conn:
            res = runner.run()
            assert mock_url.call_count == 0
            assert mock_conn.call_count == 0
            assert len(res.sample_results) == 1
            assert res.sample_results[0].sample_id == "TEST_001"

    def test_sample_exception_captured_without_crashing_runner(self):
        """Verifies runner isolates single sample crashes and reports exception cleanly."""
        bad_sample = BenchmarkSample(
            id="CRASH_001",
            label="PHISHING",
            scenario="credential_harvesting",
            description="crash test",
            content="test"
        )
        dataset = BenchmarkDataset(
            version="1.0.0",
            description="crash dataset",
            created_date="2026-10-13",
            license="MIT",
            dataset_hash="hash",
            samples=[bad_sample]
        )
        runner = BenchmarkRunner(dataset)

        with patch("detection_engine.threat_detector.ThreatDetector.analyze_message", side_effect=RuntimeError("Forced test explosion")):
            res = runner.run()
            assert len(res.sample_results) == 1
            eval_res = res.sample_results[0]
            assert eval_res.sample_id == "CRASH_001"
            assert eval_res.predicted_label == "ABSTAIN"
            assert "Forced test explosion" in eval_res.exception_message
            assert res.coverage_metrics.exceptions_encountered == 1


class TestReportGeneration:
    """Tests verifying JSON and Markdown report rendering and privacy protections."""

    def test_generate_json_and_markdown_reports(self, tmp_path):
        """Verifies report generation produces non-empty JSON and Markdown files with privacy protection."""
        sample = BenchmarkSample(
            id="PRIV_001",
            label="PHISHING",
            scenario="credential_harvesting",
            description="password prompt",
            content="SUPER_CONFIDENTIAL_SECRET_TOKEN verify password immediately at https://example.com/login"
        )
        dataset = BenchmarkDataset(
            version="1.0.0",
            description="test",
            created_date="2026-10-13",
            license="MIT",
            dataset_hash="hash123",
            samples=[sample]
        )
        runner = BenchmarkRunner(dataset)
        run_res = runner.run()

        reporter = BenchmarkReporter(run_res, output_dir=tmp_path)
        json_file = reporter.generate_json_report("test_out.json")
        md_file = reporter.generate_markdown_report("test_out.md")

        assert json_file.exists()
        assert md_file.exists()

        # Check JSON structure
        with open(json_file, "r", encoding="utf-8") as f:
            j_data = json.load(f)
            assert "confusion_matrix" in j_data
            assert "classification_metrics" in j_data
            assert "limitations_and_provenance" in j_data
            # Verify confidential raw text is NOT dumped in failure IDs
            raw_json_str = json.dumps(j_data)
            assert "SUPER_CONFIDENTIAL_SECRET_TOKEN" not in raw_json_str

        # Check Markdown structure
        with open(md_file, "r", encoding="utf-8") as f:
            md_text = f.read()
            assert "ACTIS — Phishing & Message Analysis Verification Benchmark" in md_text
            assert "Confusion Matrix" in md_text
            assert "SUPER_CONFIDENTIAL_SECRET_TOKEN" not in md_text
