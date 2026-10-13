"""
ACTIS Message & Phishing Analysis Verification Benchmark Package.
Provides dataset modeling, metric calculations, runner execution, and reporting.
"""

from benchmarks.message_analysis.dataset import (
    BenchmarkSample,
    BenchmarkDataset,
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
    URLMetrics,
    PerformanceMetrics,
    calculate_confusion_matrix,
    calculate_classification_metrics,
    calculate_coverage_metrics,
    calculate_performance_metrics
)
from benchmarks.message_analysis.runner import (
    BenchmarkRunner,
    BenchmarkRunResult,
    SampleEvaluationResult,
    map_actis_verdict_to_prediction
)
from benchmarks.message_analysis.report import (
    BenchmarkReporter,
    generate_reports
)

__all__ = [
    "BenchmarkSample",
    "BenchmarkDataset",
    "DatasetValidationError",
    "validate_dataset_manifest",
    "load_benchmark_dataset",
    "compute_manifest_hash",
    "ConfusionMatrix",
    "ClassificationMetrics",
    "CoverageMetrics",
    "PerRuleMetric",
    "URLMetrics",
    "PerformanceMetrics",
    "calculate_confusion_matrix",
    "calculate_classification_metrics",
    "calculate_coverage_metrics",
    "calculate_performance_metrics",
    "BenchmarkRunner",
    "BenchmarkRunResult",
    "SampleEvaluationResult",
    "map_actis_verdict_to_prediction",
    "BenchmarkReporter",
    "generate_reports"
]
