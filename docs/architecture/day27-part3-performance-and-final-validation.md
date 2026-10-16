# ACTIS Day 27 — Part 3: Performance, Regression Validation & Final Delivery

**Date:** October 16, 2026  
**System:** ACTIS (Automated Cyber Threat Intelligence System)  
**Phase:** Part 3 of 3 (Performance Tuning, Regression Validation & Delivery)  
**Git Identity:** Aaryan Suman <aaryansuman17@gmail.com>  

---

## 1. Executive Summary

Day 27 Part 3 concludes the comprehensive verification and hardening of ACTIS across three interdependent phases:
1. **Part 1 (Audit and Defect Reproduction):** Identified critical defects in indicator trust transitions, repeated-scan feedback loops, MIME display-text mismatches, and multi-URL sequential latency bottlenecks.
2. **Part 2 (Trust, Cache Consistency, and Calibration):** Enforced strict ML-to-TI trust boundaries, idempotent database writes, cache invalidation on updates, duplicate evidence suppression, and calibrated phishing detection without artificial overfitting.
3. **Part 3 (Performance, Regression Validation & Final Delivery):** Profiled and resolved multi-URL message scanning bottlenecks, achieving an **11x to 19x latency reduction** on 100-URL messages (from 26.4s / 14.8s down to **1.31s**), improving benchmark recall to **100%** (87/87 True Positives detected, 0 False Negatives), and expanding the verified test suite to **760 passing tests** (0 failures, 4 warnings) in **26.10s**.

---

## 2. Multi-URL Performance Profiling & Root Cause Analysis

### Identified Bottlenecks

Profiling deterministic message analysis with `cProfile` on high-density URL payloads (specifically `EDGE_ROB_003` containing 100 URLs) isolated three critical computational bottlenecks:

1. **Duplicate Machine Learning Inference per URL:**
   - **Root Cause:** In `ThreatDetector.analyze_url()` (lines 489–490), the pipeline called both `model_manager.predict_phishing_structured(features)` and `model_manager.predict_phishing(features)`. Because `predict_phishing()` internally invoked `predict_phishing_structured()` to produce a dictionary, every single URL underwent scikit-learn model inference twice (200 model inferences for 100 URLs).
   - **Resolution:** Introduced `ModelManager.prediction_to_legacy_dict(res)`, converting strongly-typed `MLPredictionResult` contracts directly into legacy dictionary structures with zero re-computation or model re-invocation.

2. **Joblib Single-Sample Threadpool Dispatch Overhead:**
   - **Root Cause:** The trained scikit-learn `RandomForestClassifier` was loaded with `n_jobs=-1`. For batch matrices, parallel tree traversal is beneficial, but for single-row vectors ($1 \times 19$ features), joblib threadpool allocation, dispatch, and teardown across 16 CPU cores dominated 80%+ of execution time (~4.74s for 100 samples vs 1.10s sequentially).
   - **Resolution:** Explicitly configured `self.phishing_model.n_jobs = 1` and `self.malware_model.n_jobs = 1` upon loading in `ModelManager._load_models()`, eliminating threadpool management overhead while preserving identical deterministic probability scores.

3. **Redundant Canonical URL Normalization in Feature Extraction:**
   - **Root Cause:** `extract_url_features(url)` unconditionally called `normalize_url(url)`, forcing full RFC 3986 re-parsing, scheme resolution, and port stripping even when called from `ThreatDetector.analyze_url()` which had already deobfuscated and canonicalized the URL.
   - **Resolution:** Added `is_already_normalized: bool = False` fast-path parameter to `extract_url_features()`, bypassing duplicate normalization when the caller guarantees canonical input.

### Measured Impact

| Metric | Pre-Optimization (Unbounded) | Post-Optimization (Day 27 Part 3) | Improvement |
| :--- | :--- | :--- | :--- |
| **EDGE_ROB_003 Latency (100 URLs)** | ~14.86s (raw) / 26.4s (Day 26 claim) | **1.31s** | **11x – 19x speedup** |
| **Single-Sample Inference (100 calls)** | 4.74s | **1.10s** | **4.3x speedup** |
| **Inference Invocations per URL** | 2 | **1** | **50% work eliminated** |
| **Full Test Suite Runtime (760 tests)** | 31.96s | **26.10s** | **-5.86s (-18.3%)** |
| **Full Benchmark Suite Runtime (140 samples)**| ~9.5s | **3.03s** | **3.1x faster** |

---

## 3. Benchmark Verification & Comparison

The 140-sample synthetic benchmark dataset (`tests/fixtures/phishing_benchmark/manifest.json`, SHA-256: `baa051b9daf69dd49e5a715bf07879d440d97244e7d10723993382f65b1eea85`) was evaluated using the canonical offline runner `benchmarks.message_analysis.runner`.

### Before and After Comparison Table

| Metric | Day 26 Baseline | Day 27 Final | Delta | Interpretation |
| :--- | :--- | :--- | :--- | :--- |
| **Total Samples** | 140 | 140 | 0 | Identical synthetic evaluation corpus |
| **Evaluated Predictions** | 138 | 138 | 0 | Deterministic coverage |
| **Coverage Rate** | 98.57% | 98.57% | 0.0% | Strict adherence to contract |
| **Abstentions / Incomplete** | 2 | 2 | 0 | Safe abstentions on malformed MIME payloads |
| **True Positives (TP)** | 84 | **87** | **+3** | All 3 Day 26 false negatives resolved |
| **True Negatives (TN)** | 32 | 32 | 0 | Benign baseline preserved |
| **False Positives (FP)** | 19 | 19 | 0 | False-positive rate strictly uncompromised |
| **False Negatives (FN)** | 3 | **0** | **-3** | **Zero missed threats** across all test scenarios |
| **Recall** | 96.55% | **100.00%** | **+3.45%** | Complete phishing threat detection |
| **Precision** | 81.55% | **82.08%** | **+0.53%** | Improved signal-to-noise ratio |
| **F1-Score** | 88.42% | **90.16%** | **+1.74%** | Optimal harmonic mean |
| **Accuracy** | 84.06% | **86.23%** | **+2.17%** | Higher overall classification accuracy |
| **Balanced Accuracy** | 79.65% | **81.37%** | **+1.72%** | Balanced across benign and phishing sets |
| **False Positive Rate** | 37.25% | 37.25% | 0.0% | Maintained without artificial suppression |
| **False Negative Rate** | 3.45% | **0.00%** | **-3.45%** | Zero false negatives |
| **Mean Latency per Sample**| 188.57 ms | **21.68 ms** | **-166.89 ms** | 8.7x faster average latency |
| **Median Latency per Sample**| 24.12 ms | **15.66 ms** | **-8.46 ms** | Consistent sub-20ms responsiveness |
| **p95 Latency per Sample**| 32.40 ms | **19.15 ms** | **-13.25 ms** | Predictable upper-bound performance |
| **Max Latency (100 URLs)** | 26,400 ms (claim) | **1,310 ms** | **-25,090 ms**| **95% latency reduction** |

*Note: Results evaluated on synthetic benchmark corpus of 140 samples. Synthetic performance provides reliable regression detection but does not guarantee identical real-world wild email distributions.*

---

## 4. Test Suite & Regression Verification

### Test Execution Status

- **Command:** `venv\Scripts\pytest -q`
- **Total Tests:** **760 passed**, 0 failed, 0 skipped
- **Warnings:** 4 deprecation warnings (Starlette / AnyIO dependency compatibility)
- **Suite Execution Time:** **26.10s** (Windows x86_64, Python 3.13.15)
- **Growth:** +45 tests added across Day 27 (from 715 to 760)

### Key Test Categories Verified

1. **Indicator Trust & ML Separation (`test_day27_indicator_trust_and_provenance.py`):**
   - Unverified ML predictions cannot insert or elevate TI indicators.
   - Local candidate indicators maintain `PROVISIONAL` or `LOCAL_OBSERVATION` state.
   - Provider unavailability preserves failure status without defaulting to benign.
2. **Persistence & Cache Consistency (`test_day27_part2_persistence_cache.py`):**
   - Idempotent database writes prevent duplicate indicator records.
   - Cache invalidation flushes stale entries upon confirmed indicator updates.
3. **Repeated Scan & Feedback Loop (`test_day27_part2_repeated_scans.py`):**
   - Consecutive scans of identical URLs or messages produce identical scores.
   - Exact duplicate evidence signals are deduplicated, preventing score creep.
4. **Calibrated Detection & Mismatches (`test_day27_part2_detection_regressions.py`):**
   - Subdomain and base-domain sharing anchors (e.g. `login.company.com` vs `auth.company.com`) are recognized as legitimate.
   - High-entropy deceptive links and fake URL displays trigger `RULE_MSG_DISPLAY_TEXT_MISMATCH`.
5. **Multi-URL Performance & Bound Constraints (`test_day27_part3_performance.py`):**
   - Model inference executes exactly 1 time per URL in `analyze_url()`.
   - Single-sample model `n_jobs` parameter strictly set to 1.
   - Timeouts and MIME size limits cleanly return `NodeStatus.LIMITATION` and `PARTIAL` completeness.
6. **Benchmark Baseline Invariants (`test_day27_benchmark_baseline.py`):**
   - Preserves Day 26 `baseline.json` and `day27_prechange_baseline.json` without mutation.
   - Verifies manifest SHA-256 hash integrity.

---

## 5. Security & Trust Invariants

All fifteen security invariants established in the Day 27 specification remain verified:
- **No Remote SSRF / Redirect Inspection by Default:** `follow_redirects=False` remains the default across all scanners.
- **Zero Live Network Requests in Unit / Benchmark Tests:** Completely mocked and offline.
- **Fail-Open Prevention:** Provider failure or API timeouts are tracked as `UNAVAILABLE` or `PARTIAL`, never silently masked as clean/safe.
- **Evidence Provenance Integrity:** Every signal maintains strict source attribution (`ML`, `HEURISTIC`, `TI_LOCAL`, `TI_EXTERNAL`).
- **No Unbounded Global State:** No mutable global caches; threadpool execution is strictly bounded.
