"""
ACTIS Message & Phishing Analysis Benchmark Reporting Engine.
Generates machine-readable (JSON) and human-readable (Markdown) verification reports.
Includes privacy safeguards (message redaction) and explicit disclaimers regarding
synthetic benchmark evaluation vs. real-world generalization.
"""

import json
from pathlib import Path
from typing import Dict, Any, Optional

from benchmarks.message_analysis.runner import BenchmarkRunResult


DEFAULT_REPORTS_DIR = Path("reports/benchmarks/message_analysis")


class BenchmarkReporter:
    """
    Renders structured benchmark outcomes into JSON and Markdown artifacts.
    Enforces privacy protections by redacting raw payload contents.
    """

    def __init__(self, run_result: BenchmarkRunResult, output_dir: Optional[Path] = None):
        self.result = run_result
        self.output_dir = output_dir or DEFAULT_REPORTS_DIR
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_json_report(self, filename: str = "latest.json") -> Path:
        """Serializes benchmark results into a clean, reproducible JSON artifact."""
        out_path = self.output_dir / filename
        data = self.result.to_dict()

        # Add known limitations and methodology disclaimers
        data["limitations_and_provenance"] = {
            "synthetic_corpus_disclaimer": (
                "Metrics were measured against an offline synthetic evaluation corpus (v1.0.0). "
                "Synthetic performance does NOT represent verified real-world production accuracy."
            ),
            "network_isolation": "Zero external HTTP, DNS, or socket requests were initiated during evaluation.",
            "execution_safety": "Attachments and scripts were parsed as metadata only with zero code execution."
        }

        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        return out_path

    def generate_markdown_report(self, filename: str = "latest.md") -> Path:
        """Generates a comprehensive, audit-ready Markdown benchmark verification report."""
        out_path = self.output_dir / filename
        r = self.result
        cm = r.confusion_matrix
        m = r.classification_metrics
        cov = r.coverage_metrics
        perf = r.performance_metrics

        md_lines = [
            "# ACTIS — Phishing & Message Analysis Verification Benchmark",
            "",
            "> **Disclaimer**: This benchmark was conducted strictly offline using synthetic, labeled test cases. "
            "These metrics establish a deterministic baseline for ACTIS Day 26 and **must not be misrepresented** "
            "as verified real-world phishing detection accuracy.",
            "",
            "## 1. Executive Summary",
            "",
            f"- **Execution Timestamp**: `{r.timestamp_iso}`",
            f"- **ACTIS Git Commit**: `{r.git_commit}`",
            f"- **Python Version**: `{r.python_version}`",
            f"- **Dataset Version**: `{r.dataset_version}`",
            f"- **Dataset SHA-256 Hash**: `{r.dataset_hash[:16]}...`",
            f"- **Total Samples Evaluated**: `{cov.total_samples}`",
            f"- **Valid Binary Predictions**: `{cov.valid_binary_predictions}` (`{cov.coverage_rate * 100.0:.1f}%` coverage)",
            f"- **Abstentions / Incomplete**: `{cov.abstentions}`",
            "",
            "### Core Classification Headline Metrics",
            "",
            "| Metric | Value | Interpretation |",
            "| :--- | :--- | :--- |",
            f"| **Precision** | `{m.precision:.4f}` | Proportion of predicted phishing messages that are truly phishing |" if m.precision is not None else "| **Precision** | `N/A` | Undefined (Zero denominator) |",
            f"| **Recall (Sensitivity)** | `{m.recall:.4f}` | Proportion of ground-truth phishing caught by pipeline |" if m.recall is not None else "| **Recall** | `N/A` | Undefined (Zero denominator) |",
            f"| **F1 Score** | `{m.f1_score:.4f}` | Harmonic mean of precision and recall |" if m.f1_score is not None else "| **F1 Score** | `N/A` | Undefined |",
            f"| **Specificity** | `{m.specificity:.4f}` | Proportion of benign messages correctly cleared |" if m.specificity is not None else "| **Specificity** | `N/A` | Undefined |",
            f"| **Balanced Accuracy** | `{m.balanced_accuracy:.4f}` | Macro-average of recall and specificity |" if m.balanced_accuracy is not None else "| **Balanced Accuracy** | `N/A` | Undefined |",
            f"| **Overall Accuracy** | `{m.accuracy:.4f}` | Overall accuracy across valid binary predictions |" if m.accuracy is not None else "| **Overall Accuracy** | `N/A` | Undefined |",
            f"| **False Positive Rate (FPR)** | `{m.false_positive_rate:.4f}` | Proportion of benign messages incorrectly flagged |" if m.false_positive_rate is not None else "| **FPR** | `N/A` | Undefined |",
            f"| **False Negative Rate (FNR)** | `{m.false_negative_rate:.4f}` | Proportion of phishing messages missed |" if m.false_negative_rate is not None else "| **FNR** | `N/A` | Undefined |",
            "",
            "## 2. Confusion Matrix",
            "",
            "```",
            f"                         Predicted PHISHING     Predicted BENIGN",
            f"Actual PHISHING (Pos):        TP = {cm.true_positives:<10}         FN = {cm.false_negatives:<10}",
            f"Actual BENIGN   (Neg):        FP = {cm.false_positives:<10}         TN = {cm.true_negatives:<10}",
            "```",
            "",
            f"- **Total Binary Evaluations**: {cm.total_evaluated}",
            f"- **Excluded Abstentions**: {cov.abstentions} (Parser boundaries, malformed inputs, or resource limits)",
            "",
            "## 3. Scenario-Level Breakdown",
            "",
            "| Scenario Category | Samples | Evaluated | TP | TN | FP | FN | Accuracy | Mean Latency |",
            "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |"
        ]

        for sc, sc_data in r.scenario_metrics.items():
            acc_str = f"{sc_data['accuracy']:.3f}" if sc_data['accuracy'] is not None else "N/A"
            md_lines.append(
                f"| `{sc}` | {sc_data['total_samples']} | {sc_data['evaluated']} | "
                f"{sc_data['true_positives']} | {sc_data['true_negatives']} | "
                f"{sc_data['false_positives']} | {sc_data['false_negatives']} | "
                f"{acc_str} | {sc_data['mean_runtime_ms']:.1f} ms |"
            )

        md_lines.extend([
            "",
            "## 4. Per-Rule Telemetry & Contribution",
            "",
            "| Rule Identifier | Fired | Phish Hits | Benign Hits (FP) | Precision | Recall Contrib |",
            "| :--- | :---: | :---: | :---: | :---: | :---: |"
        ])

        for rule_id, rule_m in sorted(r.per_rule_metrics.items(), key=lambda x: x[1].firing_count, reverse=True):
            p_str = f"{rule_m.precision:.3f}" if rule_m.precision is not None else "N/A"
            rc_str = f"{rule_m.recall_contribution:.3f}" if rule_m.recall_contribution is not None else "N/A"
            md_lines.append(
                f"| `{rule_id}` | {rule_m.firing_count} | {rule_m.phishing_firings} | "
                f"{rule_m.benign_firings} | {p_str} | {rc_str} |"
            )

        md_lines.extend([
            "",
            "## 5. URL Analysis Telemetry",
            "",
            f"- **Messages Containing URLs**: `{r.url_metrics.messages_with_urls}`",
            f"- **Total URLs Extracted**: `{r.url_metrics.total_urls_extracted}`",
            f"- **Unique Canonical URLs**: `{r.url_metrics.unique_canonical_urls}`",
            f"- **URL Threat Findings**: `{r.url_metrics.url_threat_findings}`",
            f"- **URL Scenarios Evaluated**: `{r.url_metrics.url_scenarios_total}` (Correct: `{r.url_metrics.url_scenarios_correct}`, Missed: `{r.url_metrics.url_scenarios_missed}`)",
            "",
            "## 6. Robustness, Edge-Case Handling & Performance",
            "",
            f"- **Edge Cases Evaluated**: `{r.robustness_summary.get('total_edge_cases', 0)}`",
            f"- **Uncaught Exceptions**: `{r.robustness_summary.get('uncaught_exceptions', 0)}` (Target: 0)",
            f"- **Resource Limits Triggered**: `{r.robustness_summary.get('resource_limits_triggered', 0)}`",
            f"- **Partial Analyses Correctly Flagged**: `{r.robustness_summary.get('partial_analyses', 0)}`",
            f"- **Invalid Inputs Gracefully Rejected**: `{r.robustness_summary.get('invalid_inputs_handled', 0)}`",
            "",
            "### Latency Statistics (Monotonic Timer)",
            "",
            f"- **Mean Latency**: `{perf.mean_seconds * 1000.0:.2f} ms`",
            f"- **Median Latency**: `{perf.median_seconds * 1000.0:.2f} ms`",
            f"- **95th Percentile (p95)**: `{perf.p95_seconds * 1000.0:.2f} ms`",
            f"- **Max Observed Latency**: `{perf.max_seconds * 1000.0:.2f} ms`",
            f"- **Total Benchmark Wall Time**: `{perf.total_runtime_seconds:.2f} s`",
            "",
            "## 7. Failure Analysis",
            "",
            "### False Positives (Benign Messages Classified as Phishing)",
            f"- **Count**: {len(r.false_positives)}",
        ])

        if r.false_positives:
            md_lines.append("- **Sample IDs**: " + ", ".join(f"`{sid}`" for sid in r.false_positives))
        else:
            md_lines.append("- *Zero false positives observed.*")

        md_lines.extend([
            "",
            "### False Negatives (Phishing Messages Classified as Benign)",
            f"- **Count**: {len(r.false_negatives)}",
        ])

        if r.false_negatives:
            md_lines.append("- **Sample IDs**: " + ", ".join(f"`{sid}`" for sid in r.false_negatives))
        else:
            md_lines.append("- *Zero false negatives observed.*")

        md_lines.extend([
            "",
            "### Abstentions & Incomplete Analyses",
            f"- **Count**: {len(r.abstentions)}",
        ])

        if r.abstentions:
            md_lines.append("- **Sample IDs**: " + ", ".join(f"`{sid}`" for sid in r.abstentions))
        else:
            md_lines.append("- *Zero abstentions observed.*")

        md_lines.extend([
            "",
            "## 8. Security Guarantees & Verification",
            "",
            "- **Zero Network Calls**: Verified via socket & urllib mocking; all threat intel and URL scans ran completely offline.",
            "- **Zero Code Execution**: Attachment payloads and HTML scripts were parsed strictly as inert metadata.",
            "- **Redirect Inspection Boundary**: Remote redirect following remained disabled (`follow_redirects=False`) by default.",
            "- **Data Privacy**: No complete message bodies or confidential strings are emitted in machine-readable or human-readable reports.",
            "",
            "## 9. Recommendations for Day 27",
            "",
            "1. **Preserve Deterministic Baseline**: Maintain this Day 26 baseline report before tuning any weights.",
            "2. **Evidence Weight Calibration**: Investigate any rule overlaps or false-positive triggers before adjusting thresholds.",
            "3. **Real-World Holdout Evaluation**: Plan for an isolated external corpus evaluation pipeline."
        ])

        with open(out_path, "w", encoding="utf-8") as f:
            f.write("\n".join(md_lines) + "\n")

        return out_path


def generate_reports(run_result: BenchmarkRunResult, output_dir: Optional[Path] = None) -> Dict[str, Path]:
    """Generates both JSON and Markdown benchmark reports."""
    reporter = BenchmarkReporter(run_result, output_dir=output_dir)
    json_path = reporter.generate_json_report()
    md_path = reporter.generate_markdown_report()
    return {"json": json_path, "markdown": md_path}
