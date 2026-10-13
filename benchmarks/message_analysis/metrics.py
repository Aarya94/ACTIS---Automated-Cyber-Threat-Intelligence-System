"""
ACTIS Message & Phishing Analysis Benchmark Metrics Module.
Provides deterministic computation of confusion matrices, precision, recall, F1,
false-positive/negative rates, coverage, abstentions, per-rule telemetry, and URL statistics.
Strictly handles zero denominators by returning None instead of masking with 0.0.
"""

import math
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Set, Tuple


@dataclass
class ConfusionMatrix:
    """Confusion matrix for binary classification where PHISHING is positive class."""
    true_positives: int = 0
    true_negatives: int = 0
    false_positives: int = 0
    false_negatives: int = 0

    @property
    def total_evaluated(self) -> int:
        return self.true_positives + self.true_negatives + self.false_positives + self.false_negatives

    def to_dict(self) -> Dict[str, int]:
        return {
            "true_positives": self.true_positives,
            "true_negatives": self.true_negatives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "total_evaluated": self.total_evaluated
        }


@dataclass
class ClassificationMetrics:
    """Standard binary classification metrics with explicit handling of undefined states."""
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1_score: Optional[float] = None
    specificity: Optional[float] = None
    balanced_accuracy: Optional[float] = None
    accuracy: Optional[float] = None
    false_positive_rate: Optional[float] = None
    false_negative_rate: Optional[float] = None

    def to_dict(self) -> Dict[str, Optional[float]]:
        return {
            "precision": round(self.precision, 4) if self.precision is not None else None,
            "recall": round(self.recall, 4) if self.recall is not None else None,
            "f1_score": round(self.f1_score, 4) if self.f1_score is not None else None,
            "specificity": round(self.specificity, 4) if self.specificity is not None else None,
            "balanced_accuracy": round(self.balanced_accuracy, 4) if self.balanced_accuracy is not None else None,
            "accuracy": round(self.accuracy, 4) if self.accuracy is not None else None,
            "false_positive_rate": round(self.false_positive_rate, 4) if self.false_positive_rate is not None else None,
            "false_negative_rate": round(self.false_negative_rate, 4) if self.false_negative_rate is not None else None,
        }


@dataclass
class CoverageMetrics:
    """Coverage and abstention telemetry."""
    total_samples: int = 0
    valid_binary_predictions: int = 0
    abstentions: int = 0
    incomplete_analyses: int = 0
    invalid_inputs: int = 0
    exceptions_encountered: int = 0
    coverage_rate: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_samples": self.total_samples,
            "valid_binary_predictions": self.valid_binary_predictions,
            "abstentions": self.abstentions,
            "incomplete_analyses": self.incomplete_analyses,
            "invalid_inputs": self.invalid_inputs,
            "exceptions_encountered": self.exceptions_encountered,
            "coverage_rate": round(self.coverage_rate, 4)
        }


@dataclass
class PerRuleMetric:
    """Evaluation telemetry for a single detection rule identifier."""
    rule_id: str
    firing_count: int = 0
    phishing_firings: int = 0
    benign_firings: int = 0
    precision: Optional[float] = None
    recall_contribution: Optional[float] = None
    false_positive_sample_ids: List[str] = field(default_factory=list)
    false_negative_sample_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "firing_count": self.firing_count,
            "phishing_firings": self.phishing_firings,
            "benign_firings": self.benign_firings,
            "precision": round(self.precision, 4) if self.precision is not None else None,
            "recall_contribution": round(self.recall_contribution, 4) if self.recall_contribution is not None else None,
            "false_positive_sample_ids": list(self.false_positive_sample_ids),
            "false_negative_sample_ids": list(self.false_negative_sample_ids)
        }


@dataclass
class URLMetrics:
    """Telemetry specific to embedded URL detection and resolution."""
    messages_with_urls: int = 0
    total_urls_extracted: int = 0
    unique_canonical_urls: int = 0
    url_threat_findings: int = 0
    url_scenarios_total: int = 0
    url_scenarios_correct: int = 0
    url_scenarios_missed: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "messages_with_urls": self.messages_with_urls,
            "total_urls_extracted": self.total_urls_extracted,
            "unique_canonical_urls": self.unique_canonical_urls,
            "url_threat_findings": self.url_threat_findings,
            "url_scenarios_total": self.url_scenarios_total,
            "url_scenarios_correct": self.url_scenarios_correct,
            "url_scenarios_missed": self.url_scenarios_missed
        }


@dataclass
class PerformanceMetrics:
    """Latency and execution runtime measurements."""
    sample_count: int = 0
    total_runtime_seconds: float = 0.0
    mean_seconds: float = 0.0
    median_seconds: float = 0.0
    p95_seconds: float = 0.0
    min_seconds: float = 0.0
    max_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sample_count": self.sample_count,
            "total_runtime_seconds": round(self.total_runtime_seconds, 4),
            "mean_seconds": round(self.mean_seconds, 6),
            "median_seconds": round(self.median_seconds, 6),
            "p95_seconds": round(self.p95_seconds, 6),
            "min_seconds": round(self.min_seconds, 6),
            "max_seconds": round(self.max_seconds, 6),
            "mean_ms": round(self.mean_seconds * 1000.0, 2),
            "median_ms": round(self.median_seconds * 1000.0, 2),
            "p95_ms": round(self.p95_seconds * 1000.0, 2),
        }


def calculate_confusion_matrix(
    predictions: List[Tuple[str, str]]  # list of (ground_truth_label, predicted_label)
) -> ConfusionMatrix:
    """
    Computes binary confusion matrix for valid predictions where:
    Ground Truth in ("PHISHING", "BENIGN") and Prediction in ("PHISHING", "BENIGN").
    Abstentions ("ABSTAIN") are skipped and tracked separately.
    """
    tp = tn = fp = fn = 0
    for gt, pred in predictions:
        if pred not in ("PHISHING", "BENIGN"):
            continue
        if gt == "PHISHING":
            if pred == "PHISHING":
                tp += 1
            elif pred == "BENIGN":
                fn += 1
        elif gt == "BENIGN":
            if pred == "BENIGN":
                tn += 1
            elif pred == "PHISHING":
                fp += 1

    return ConfusionMatrix(
        true_positives=tp,
        true_negatives=tn,
        false_positives=fp,
        false_negatives=fn
    )


def calculate_classification_metrics(cm: ConfusionMatrix) -> ClassificationMetrics:
    """
    Computes precision, recall, F1, specificity, balanced accuracy, accuracy, FPR, and FNR.
    Returns None for any metric with a zero denominator.
    """
    tp = cm.true_positives
    tn = cm.true_negatives
    fp = cm.false_positives
    fn = cm.false_negatives

    # Precision = TP / (TP + FP)
    precision = (tp / (tp + fp)) if (tp + fp) > 0 else None

    # Recall = TP / (TP + FN)
    recall = (tp / (tp + fn)) if (tp + fn) > 0 else None

    # F1 = 2 * P * R / (P + R)
    f1: Optional[float] = None
    if precision is not None and recall is not None:
        if (precision + recall) > 0:
            f1 = 2.0 * (precision * recall) / (precision + recall)
        else:
            f1 = 0.0

    # Specificity = TN / (TN + FP)
    specificity = (tn / (tn + fp)) if (tn + fp) > 0 else None

    # Balanced Accuracy = (Recall + Specificity) / 2
    balanced_acc: Optional[float] = None
    if recall is not None and specificity is not None:
        balanced_acc = (recall + specificity) / 2.0

    # Accuracy = (TP + TN) / Total
    total = cm.total_evaluated
    accuracy = ((tp + tn) / total) if total > 0 else None

    # FPR = FP / (FP + TN)
    fpr = (fp / (fp + tn)) if (fp + tn) > 0 else None

    # FNR = FN / (FN + TP)
    fnr = (fn / (fn + tp)) if (fn + tp) > 0 else None

    return ClassificationMetrics(
        precision=precision,
        recall=recall,
        f1_score=f1,
        specificity=specificity,
        balanced_accuracy=balanced_acc,
        accuracy=accuracy,
        false_positive_rate=fpr,
        false_negative_rate=fnr
    )


def calculate_coverage_metrics(
    total_samples: int,
    valid_predictions: int,
    abstentions: int,
    incomplete_analyses: int,
    invalid_inputs: int,
    exceptions: int
) -> CoverageMetrics:
    """Calculates coverage rate and abstention distributions."""
    coverage = (valid_predictions / total_samples) if total_samples > 0 else 0.0
    return CoverageMetrics(
        total_samples=total_samples,
        valid_binary_predictions=valid_predictions,
        abstentions=abstentions,
        incomplete_analyses=incomplete_analyses,
        invalid_inputs=invalid_inputs,
        exceptions_encountered=exceptions,
        coverage_rate=coverage
    )


def calculate_performance_metrics(durations: List[float]) -> PerformanceMetrics:
    """Calculates summary latency statistics using monotonic time durations."""
    if not durations:
        return PerformanceMetrics()

    sorted_d = sorted(durations)
    n = len(sorted_d)
    tot = sum(sorted_d)
    mean_val = tot / n

    if n % 2 == 1:
        median_val = sorted_d[n // 2]
    else:
        median_val = (sorted_d[n // 2 - 1] + sorted_d[n // 2]) / 2.0

    # 95th percentile
    p95_idx = int(math.ceil(0.95 * n)) - 1
    p95_idx = max(0, min(n - 1, p95_idx))
    p95_val = sorted_d[p95_idx]

    return PerformanceMetrics(
        sample_count=n,
        total_runtime_seconds=tot,
        mean_seconds=mean_val,
        median_seconds=median_val,
        p95_seconds=p95_val,
        min_seconds=sorted_d[0],
        max_seconds=sorted_d[-1]
    )
