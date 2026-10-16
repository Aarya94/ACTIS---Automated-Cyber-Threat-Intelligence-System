"""
ACTIS Day 27 — Part 1: Benchmark Baseline Preservation & Manifest Integrity Test.
Verifies that:
1. Phishing benchmark dataset manifest SHA-256 hash strictly matches baa051b9daf69dd49e5a715bf07879d440d97244e7d10723993382f65b1eea85.
2. The historical Day 26 baseline report (reports/benchmarks/message_analysis/baseline.json) remains intact.
3. The newly preserved Day 27 pre-change baseline matches the verified Day 26 metrics:
   TP=84, TN=32, FP=19, FN=3, precision=0.8155, recall=0.9655, F1=0.8842, accuracy=0.8406.
"""

import json
import hashlib
from pathlib import Path
import pytest

from benchmarks.message_analysis.dataset import (
    DEFAULT_MANIFEST_PATH,
    compute_manifest_hash,
    load_benchmark_dataset,
)

EXPECTED_MANIFEST_HASH = "baa051b9daf69dd49e5a715bf07879d440d97244e7d10723993382f65b1eea85"
REPORTS_DIR = Path("reports/benchmarks/message_analysis")
HISTORICAL_BASELINE_PATH = REPORTS_DIR / "baseline.json"
DAY27_PRECHANGE_BASELINE_PATH = REPORTS_DIR / "day27_prechange_baseline.json"


def test_manifest_sha256_hash_integrity():
    """Validates that the benchmark dataset manifest SHA-256 matches the canonical hash."""
    assert DEFAULT_MANIFEST_PATH.exists(), f"Benchmark manifest missing at {DEFAULT_MANIFEST_PATH}"
    dataset = load_benchmark_dataset(DEFAULT_MANIFEST_PATH)
    assert dataset.dataset_hash == EXPECTED_MANIFEST_HASH, (
        f"Manifest SHA-256 hash mismatch! Expected {EXPECTED_MANIFEST_HASH}, got {dataset.dataset_hash}"
    )


def test_historical_day26_baseline_preserved():
    """Validates that the historical Day 26 baseline artifact is present and unmodified."""
    assert HISTORICAL_BASELINE_PATH.exists(), f"Historical baseline.json missing at {HISTORICAL_BASELINE_PATH}"
    with open(HISTORICAL_BASELINE_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    meta = data["metadata"]
    assert meta["dataset_hash"] == EXPECTED_MANIFEST_HASH

    cm = data["confusion_matrix"]
    assert cm["true_positives"] == 84
    assert cm["true_negatives"] == 32
    assert cm["false_positives"] == 19
    assert cm["false_negatives"] == 3
    assert cm["total_evaluated"] == 138

    m = data["classification_metrics"]
    assert m["precision"] == 0.8155
    assert m["recall"] == 0.9655
    assert m["f1_score"] == 0.8842
    assert m["accuracy"] == 0.8406
    assert m["false_positive_rate"] == 0.3725


def test_day27_prechange_baseline_matches_historical():
    """Validates that the preserved Day 27 pre-change baseline faithfully reflects Day 26 results."""
    assert DAY27_PRECHANGE_BASELINE_PATH.exists(), (
        f"Day 27 pre-change baseline missing at {DAY27_PRECHANGE_BASELINE_PATH}"
    )
    with open(DAY27_PRECHANGE_BASELINE_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    cm = data["confusion_matrix"]
    assert cm["true_positives"] == 84
    assert cm["true_negatives"] == 32
    assert cm["false_positives"] == 19
    assert cm["false_negatives"] == 3

    m = data["classification_metrics"]
    assert m["precision"] == 0.8155
    assert m["recall"] == 0.9655
    assert m["f1_score"] == 0.8842

    cov = data["coverage_metrics"]
    assert cov["total_samples"] == 140
    assert cov["valid_binary_predictions"] == 138
    assert cov["abstentions"] == 2
