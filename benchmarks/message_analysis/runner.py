"""
ACTIS Message & Phishing Analysis Benchmark Runner.
Executes the synthetic evaluation corpus deterministically against the canonical
ACTIS detection engine entry point (ThreatDetector.analyze_message).
Measures accuracy, rule contributions, URL resolution, robustness boundaries, and runtime.
Enforces zero external network calls during benchmark runs.
"""

import sys
import time
import subprocess
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple, Set

from benchmarks.message_analysis.dataset import (
    BenchmarkDataset,
    BenchmarkSample,
    load_benchmark_dataset
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
from detection_engine.threat_detector import threat_detector
from detection_engine.rule_engine import RuleEngine


@dataclass
class SampleEvaluationResult:
    """Detailed evaluation telemetry for a single benchmark fixture execution."""
    sample_id: str
    ground_truth_label: str
    scenario: str
    predicted_label: str
    is_correct: Optional[bool]
    is_abstain: bool
    score: float
    risk_level: str
    is_threat: bool
    is_valid: bool
    analysis_completeness: str
    rules_triggered: List[str]
    urls_extracted_count: int
    unique_urls_count: int
    threat_urls_count: int
    display_mismatches_count: int
    suspicious_attachments_count: int
    mime_defects: List[str]
    limit_reached: Optional[str]
    duration_seconds: float
    exception_message: Optional[str] = None
    reasons_summary: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sample_id": self.sample_id,
            "ground_truth_label": self.ground_truth_label,
            "scenario": self.scenario,
            "predicted_label": self.predicted_label,
            "is_correct": self.is_correct,
            "is_abstain": self.is_abstain,
            "score": self.score,
            "risk_level": self.risk_level,
            "is_threat": self.is_threat,
            "is_valid": self.is_valid,
            "analysis_completeness": self.analysis_completeness,
            "rules_triggered": list(self.rules_triggered),
            "urls_extracted_count": self.urls_extracted_count,
            "unique_urls_count": self.unique_urls_count,
            "threat_urls_count": self.threat_urls_count,
            "display_mismatches_count": self.display_mismatches_count,
            "suspicious_attachments_count": self.suspicious_attachments_count,
            "mime_defects": list(self.mime_defects),
            "limit_reached": self.limit_reached,
            "duration_ms": round(self.duration_seconds * 1000.0, 3),
            "exception_message": self.exception_message,
            "reasons_summary": list(self.reasons_summary[:3])
        }


@dataclass
class BenchmarkRunResult:
    """Comprehensive structured outcome of a benchmark execution pass."""
    dataset_version: str
    dataset_hash: str
    git_commit: str
    python_version: str
    timestamp_iso: str
    sample_results: List[SampleEvaluationResult]
    confusion_matrix: ConfusionMatrix
    classification_metrics: ClassificationMetrics
    coverage_metrics: CoverageMetrics
    per_rule_metrics: Dict[str, PerRuleMetric]
    scenario_metrics: Dict[str, Dict[str, Any]]
    url_metrics: URLMetrics
    performance_metrics: PerformanceMetrics
    robustness_summary: Dict[str, Any]
    false_positives: List[str]
    false_negatives: List[str]
    abstentions: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "metadata": {
                "dataset_version": self.dataset_version,
                "dataset_hash": self.dataset_hash,
                "git_commit": self.git_commit,
                "python_version": self.python_version,
                "timestamp_iso": self.timestamp_iso
            },
            "confusion_matrix": self.confusion_matrix.to_dict(),
            "classification_metrics": self.classification_metrics.to_dict(),
            "coverage_metrics": self.coverage_metrics.to_dict(),
            "per_rule_metrics": {k: v.to_dict() for k, v in self.per_rule_metrics.items()},
            "scenario_metrics": self.scenario_metrics,
            "url_metrics": self.url_metrics.to_dict(),
            "performance_metrics": self.performance_metrics.to_dict(),
            "robustness_summary": self.robustness_summary,
            "failures": {
                "false_positive_count": len(self.false_positives),
                "false_positive_ids": self.false_positives,
                "false_negative_count": len(self.false_negatives),
                "false_negative_ids": self.false_negatives,
                "abstention_count": len(self.abstentions),
                "abstention_ids": self.abstentions
            }
        }


def get_git_commit_hash() -> str:
    """Extracts current git commit hash, safely falling back to 'unknown'."""
    try:
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True
        )
        return res.stdout.strip()
    except Exception:
        return "unknown"


def map_actis_verdict_to_prediction(scan_res: Dict[str, Any]) -> str:
    """
    Explicit, documented mapping between ACTIS detection contract output
    and binary benchmark classification labels.

    Mapping Rules:
    - ABSTAIN: If input is marked invalid (is_valid=False) or analysis is PARTIAL.
    - PHISHING: If is_threat=True OR risk_level in ('HIGH', 'CRITICAL') OR score >= 60.0.
    - BENIGN: If is_threat=False AND risk_level in ('LOW', 'INFORMATIONAL') AND completeness=='COMPLETE'.
    - If risk_level is MEDIUM but is_threat is False, classified as BENIGN; if is_threat is True, PHISHING.
    """
    is_valid = scan_res.get("is_valid", True)
    completeness = scan_res.get("analysis_completeness", "COMPLETE")

    if not is_valid or completeness == "PARTIAL":
        return "ABSTAIN"

    is_threat = bool(scan_res.get("is_threat", False))
    risk_level = str(scan_res.get("risk_level", "LOW")).upper()
    score = float(scan_res.get("score", 0.0) or 0.0)

    if is_threat or risk_level in ("HIGH", "CRITICAL") or score >= 60.0:
        return "PHISHING"

    return "BENIGN"


class BenchmarkRunner:
    """
    Orchestrates deterministic benchmark runs against the canonical ACTIS detection engine.
    Ensures network boundary restrictions, measures fine-grained latencies,
    and isolates edge-case failures without aborting the overall suite.
    """

    def __init__(self, dataset: Optional[BenchmarkDataset] = None):
        self.dataset = dataset or load_benchmark_dataset()

    def evaluate_sample(self, sample: BenchmarkSample) -> SampleEvaluationResult:
        """Evaluates a single benchmark fixture sample through threat_detector.analyze_message."""
        start_time = time.perf_counter()
        exception_msg = None
        scan_dict: Dict[str, Any] = {}

        try:
            # Canonical detection entry point
            scan_dict = threat_detector.analyze_message(
                sample.content,
                check_external=False  # Strictly offline
            )
        except Exception as ex:
            exception_msg = f"{type(ex).__name__}: {str(ex)}"
            scan_dict = {
                "is_valid": False,
                "analysis_completeness": "PARTIAL",
                "score": 0.0,
                "risk_level": "LOW",
                "is_threat": False,
                "reasons": [f"Uncaught exception: {exception_msg}"],
                "urls_found": [],
                "url_results": [],
                "rules_triggered": [],
                "heuristic_result": {"rules_triggered": []},
                "display_mismatches_count": 0,
                "suspicious_attachments_count": 0,
                "mime_defects": ["UNCAUGHT_EXCEPTION"]
            }

        duration = time.perf_counter() - start_time

        # Map to prediction
        pred_label = map_actis_verdict_to_prediction(scan_dict)
        is_abstain = (pred_label == "ABSTAIN")

        # Determine correctness for binary predictions
        is_correct: Optional[bool] = None
        if not is_abstain:
            is_correct = (pred_label == sample.label)

        # Extract telemetry
        heuristics = scan_dict.get("heuristic_result") or {}
        rules_triggered = list(heuristics.get("rules_triggered") or [])
        url_results = scan_dict.get("url_results") or []
        threat_urls = sum(1 for u in url_results if u.get("is_threat"))

        limit_reached = None
        for reason in scan_dict.get("reasons", []):
            if "Resource boundary" in reason:
                limit_reached = reason

        return SampleEvaluationResult(
            sample_id=sample.id,
            ground_truth_label=sample.label,
            scenario=sample.scenario,
            predicted_label=pred_label,
            is_correct=is_correct,
            is_abstain=is_abstain,
            score=float(scan_dict.get("score", 0.0) or 0.0),
            risk_level=str(scan_dict.get("risk_level", "LOW")),
            is_threat=bool(scan_dict.get("is_threat", False)),
            is_valid=bool(scan_dict.get("is_valid", True)),
            analysis_completeness=str(scan_dict.get("analysis_completeness", "COMPLETE")),
            rules_triggered=rules_triggered,
            urls_extracted_count=int(scan_dict.get("total_url_count", 0)),
            unique_urls_count=int(scan_dict.get("unique_url_count", 0)),
            threat_urls_count=threat_urls,
            display_mismatches_count=int(scan_dict.get("display_mismatches_count", 0)),
            suspicious_attachments_count=int(scan_dict.get("suspicious_attachments_count", 0)),
            mime_defects=list(scan_dict.get("mime_defects", [])),
            limit_reached=limit_reached,
            duration_seconds=duration,
            exception_message=exception_msg,
            reasons_summary=list(scan_dict.get("reasons", []))
        )

    def run(self) -> BenchmarkRunResult:
        """Executes full benchmark evaluation across all loaded dataset samples."""
        sample_results: List[SampleEvaluationResult] = []
        durations: List[float] = []

        for sample in self.dataset.samples:
            res = self.evaluate_sample(sample)
            sample_results.append(res)
            durations.append(res.duration_seconds)

        # 1. Confusion Matrix & Classification Metrics
        pairs = [(r.ground_truth_label, r.predicted_label) for r in sample_results]
        cm = calculate_confusion_matrix(pairs)
        class_metrics = calculate_classification_metrics(cm)

        # 2. Coverage Metrics
        total_samples = len(sample_results)
        valid_binary = cm.total_evaluated
        abstentions = sum(1 for r in sample_results if r.is_abstain)
        incomplete = sum(1 for r in sample_results if r.analysis_completeness == "PARTIAL")
        invalid_inputs = sum(1 for r in sample_results if not r.is_valid)
        exceptions = sum(1 for r in sample_results if r.exception_message is not None)

        cov_metrics = calculate_coverage_metrics(
            total_samples=total_samples,
            valid_predictions=valid_binary,
            abstentions=abstentions,
            incomplete_analyses=incomplete,
            invalid_inputs=invalid_inputs,
            exceptions=exceptions
        )

        # 3. Performance Metrics
        perf_metrics = calculate_performance_metrics(durations)

        # 4. Per-Rule Telemetry
        known_rules: Set[str] = {
            RuleEngine.RULE_MSG_URGENCY_PRESSURE,
            RuleEngine.RULE_MSG_CREDENTIAL_HARVEST,
            RuleEngine.RULE_MSG_FINANCIAL_LURE,
            RuleEngine.RULE_MSG_IMPERSONATION,
            RuleEngine.RULE_MSG_SECURITY_EVASION,
            RuleEngine.RULE_MSG_SENSITIVE_INFO_PROMPT,
            RuleEngine.RULE_MSG_DISPLAY_TEXT_MISMATCH,
            RuleEngine.RULE_MSG_SUSPICIOUS_ATTACHMENT,
            RuleEngine.RULE_MSG_MIME_DEFECT_ANOMALY
        }
        for r in sample_results:
            known_rules.update(r.rules_triggered)

        total_phishing = sum(1 for r in sample_results if r.ground_truth_label == "PHISHING")
        per_rule_map: Dict[str, PerRuleMetric] = {}

        for rule_id in sorted(known_rules):
            fired_samples = [r for r in sample_results if rule_id in r.rules_triggered]
            phish_fired = [r for r in fired_samples if r.ground_truth_label == "PHISHING"]
            benign_fired = [r for r in fired_samples if r.ground_truth_label == "BENIGN"]

            firing_cnt = len(fired_samples)
            precision = (len(phish_fired) / firing_cnt) if firing_cnt > 0 else None
            recall_contrib = (len(phish_fired) / total_phishing) if total_phishing > 0 else None

            # FP sample IDs: benign samples where rule fired
            fp_ids = [r.sample_id for r in benign_fired]
            # FN sample IDs: phishing samples where rule was expected but did not fire
            fn_ids = []
            for sample in self.dataset.samples:
                if sample.label == "PHISHING" and rule_id in sample.expected_indicators:
                    matched = any(rule_id in r.rules_triggered for r in sample_results if r.sample_id == sample.id)
                    if not matched:
                        fn_ids.append(sample.id)

            per_rule_map[rule_id] = PerRuleMetric(
                rule_id=rule_id,
                firing_count=firing_cnt,
                phishing_firings=len(phish_fired),
                benign_firings=len(benign_fired),
                precision=precision,
                recall_contribution=recall_contrib,
                false_positive_sample_ids=fp_ids,
                false_negative_sample_ids=fn_ids
            )

        # 5. Per-Scenario Metrics
        scenario_map: Dict[str, Dict[str, Any]] = {}
        all_scenarios = sorted(set(r.scenario for r in sample_results))
        for sc in all_scenarios:
            sc_results = [r for r in sample_results if r.scenario == sc]
            sc_pairs = [(r.ground_truth_label, r.predicted_label) for r in sc_results]
            sc_cm = calculate_confusion_matrix(sc_pairs)
            sc_class = calculate_classification_metrics(sc_cm)
            sc_abstain = sum(1 for r in sc_results if r.is_abstain)
            sc_durations = [r.duration_seconds for r in sc_results]
            scenario_map[sc] = {
                "total_samples": len(sc_results),
                "evaluated": sc_cm.total_evaluated,
                "abstentions": sc_abstain,
                "true_positives": sc_cm.true_positives,
                "true_negatives": sc_cm.true_negatives,
                "false_positives": sc_cm.false_positives,
                "false_negatives": sc_cm.false_negatives,
                "accuracy": sc_class.accuracy,
                "precision": sc_class.precision,
                "recall": sc_class.recall,
                "mean_runtime_ms": round(sum(sc_durations) / len(sc_durations) * 1000.0, 2) if sc_durations else 0.0
            }

        # 6. URL Metrics
        url_scenarios = [r for r in sample_results if r.scenario == "deceptive_links_url_obfuscation"]
        url_metrics = URLMetrics(
            messages_with_urls=sum(1 for r in sample_results if r.urls_extracted_count > 0),
            total_urls_extracted=sum(r.urls_extracted_count for r in sample_results),
            unique_canonical_urls=sum(r.unique_urls_count for r in sample_results),
            url_threat_findings=sum(r.threat_urls_count for r in sample_results),
            url_scenarios_total=len(url_scenarios),
            url_scenarios_correct=sum(1 for r in url_scenarios if r.is_correct is True),
            url_scenarios_missed=sum(1 for r in url_scenarios if r.is_correct is False)
        )

        # 7. Robustness Summary
        robustness_samples = [r for r in sample_results if r.scenario == "malformed_resource_limits"]
        robustness_summary = {
            "total_edge_cases": len(robustness_samples),
            "uncaught_exceptions": sum(1 for r in robustness_samples if r.exception_message is not None),
            "resource_limits_triggered": sum(1 for r in robustness_samples if r.limit_reached is not None),
            "partial_analyses": sum(1 for r in robustness_samples if r.analysis_completeness == "PARTIAL"),
            "invalid_inputs_handled": sum(1 for r in robustness_samples if not r.is_valid),
            "structured_results_returned": sum(1 for r in robustness_samples if r.predicted_label is not None)
        }

        # 8. Failure ID lists
        fps = [r.sample_id for r in sample_results if r.ground_truth_label == "BENIGN" and r.predicted_label == "PHISHING"]
        fns = [r.sample_id for r in sample_results if r.ground_truth_label == "PHISHING" and r.predicted_label == "BENIGN"]
        absts = [r.sample_id for r in sample_results if r.is_abstain]

        return BenchmarkRunResult(
            dataset_version=self.dataset.version,
            dataset_hash=self.dataset.dataset_hash,
            git_commit=get_git_commit_hash(),
            python_version=sys.version.split()[0],
            timestamp_iso=datetime.now(timezone.utc).isoformat(),
            sample_results=sample_results,
            confusion_matrix=cm,
            classification_metrics=class_metrics,
            coverage_metrics=cov_metrics,
            per_rule_metrics=per_rule_map,
            scenario_metrics=scenario_map,
            url_metrics=url_metrics,
            performance_metrics=perf_metrics,
            robustness_summary=robustness_summary,
            false_positives=fps,
            false_negatives=fns,
            abstentions=absts
        )


def main():
    """CLI entry point for running the ACTIS message analysis benchmark."""
    print("=" * 60)
    print("ACTIS — Phishing & Message Analysis Verification Benchmark")
    print("=" * 60)

    runner = BenchmarkRunner()
    print(f"[*] Loaded dataset version {runner.dataset.version} ({len(runner.dataset)} samples)")
    print(f"[*] Dataset SHA-256: {runner.dataset.dataset_hash[:16]}...")
    print("[*] Executing offline evaluation against canonical pipeline...")

    res = runner.run()

    from benchmarks.message_analysis.report import generate_reports
    paths = generate_reports(res)

    cm = res.confusion_matrix
    m = res.classification_metrics
    cov = res.coverage_metrics

    print("\n[+] Benchmark Execution Completed Successfully!")
    print(f"  • Total Samples: {cov.total_samples}")
    print(f"  • Valid Binary Predictions: {cov.valid_binary_predictions} ({cov.coverage_rate * 100:.1f}% coverage)")
    print(f"  • Abstentions / Incomplete: {cov.abstentions}")
    print(f"  • Confusion Matrix: TP={cm.true_positives}, TN={cm.true_negatives}, FP={cm.false_positives}, FN={cm.false_negatives}")
    if m.precision is not None:
        print(f"  • Precision: {m.precision:.4f}")
    if m.recall is not None:
        print(f"  • Recall: {m.recall:.4f}")
    if m.f1_score is not None:
        print(f"  • F1 Score: {m.f1_score:.4f}")
    if m.accuracy is not None:
        print(f"  • Accuracy: {m.accuracy:.4f}")
    if m.balanced_accuracy is not None:
        print(f"  • Balanced Accuracy: {m.balanced_accuracy:.4f}")

    print(f"\n[+] Generated Reports:")
    print(f"  • JSON: {paths['json']}")
    print(f"  • Markdown: {paths['markdown']}")
    print("=" * 60)


if __name__ == "__main__":
    main()
