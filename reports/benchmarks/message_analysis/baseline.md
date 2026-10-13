# ACTIS — Phishing & Message Analysis Verification Benchmark

> **Disclaimer**: This benchmark was conducted strictly offline using synthetic, labeled test cases. These metrics establish a deterministic baseline for ACTIS Day 26 and **must not be misrepresented** as verified real-world phishing detection accuracy.

## 1. Executive Summary

- **Execution Timestamp**: `2026-10-13T15:20:03.260772+00:00`
- **ACTIS Git Commit**: `3438abfda29b8a49580b4efd9bc3a71b1f90cab7`
- **Python Version**: `3.13.15`
- **Dataset Version**: `1.0.0`
- **Dataset SHA-256 Hash**: `baa051b9daf69dd4...`
- **Total Samples Evaluated**: `140`
- **Valid Binary Predictions**: `138` (`98.6%` coverage)
- **Abstentions / Incomplete**: `2`

### Core Classification Headline Metrics

| Metric | Value | Interpretation |
| :--- | :--- | :--- |
| **Precision** | `0.8155` | Proportion of predicted phishing messages that are truly phishing |
| **Recall (Sensitivity)** | `0.9655` | Proportion of ground-truth phishing caught by pipeline |
| **F1 Score** | `0.8842` | Harmonic mean of precision and recall |
| **Specificity** | `0.6275` | Proportion of benign messages correctly cleared |
| **Balanced Accuracy** | `0.7965` | Macro-average of recall and specificity |
| **Overall Accuracy** | `0.8406` | Overall accuracy across valid binary predictions |
| **False Positive Rate (FPR)** | `0.3725` | Proportion of benign messages incorrectly flagged |
| **False Negative Rate (FNR)** | `0.0345` | Proportion of phishing messages missed |

## 2. Confusion Matrix

```
                         Predicted PHISHING     Predicted BENIGN
Actual PHISHING (Pos):        TP = 84                 FN = 3         
Actual BENIGN   (Neg):        FP = 19                 TN = 32        
```

- **Total Binary Evaluations**: 138
- **Excluded Abstentions**: 2 (Parser boundaries, malformed inputs, or resource limits)

## 3. Scenario-Level Breakdown

| Scenario Category | Samples | Evaluated | TP | TN | FP | FN | Accuracy | Mean Latency |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `benign_financial_business` | 18 | 18 | 0 | 12 | 6 | 0 | 0.667 | 92.9 ms |
| `credential_harvesting` | 18 | 18 | 18 | 0 | 0 | 0 | 1.000 | 205.4 ms |
| `deceptive_links_url_obfuscation` | 18 | 18 | 17 | 0 | 0 | 1 | 0.944 | 277.8 ms |
| `financial_manipulation` | 15 | 15 | 15 | 0 | 0 | 0 | 1.000 | 285.1 ms |
| `impersonation_social_engineering` | 18 | 18 | 18 | 0 | 0 | 0 | 1.000 | 260.8 ms |
| `legitimate_security_account` | 18 | 18 | 0 | 12 | 6 | 0 | 0.667 | 84.3 ms |
| `malformed_resource_limits` | 10 | 8 | 2 | 4 | 1 | 1 | 0.750 | 2733.0 ms |
| `mixed_phishing_indicators` | 15 | 15 | 14 | 0 | 0 | 1 | 0.933 | 127.0 ms |
| `security_awareness_education` | 10 | 10 | 0 | 4 | 6 | 0 | 0.400 | 154.0 ms |

## 4. Per-Rule Telemetry & Contribution

| Rule Identifier | Fired | Phish Hits | Benign Hits (FP) | Precision | Recall Contrib |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `RULE_MSG_URGENCY_PRESSURE` | 43 | 41 | 2 | 0.953 | 0.466 |
| `RULE_MSG_CREDENTIAL_HARVEST` | 39 | 39 | 0 | 1.000 | 0.443 |
| `RULE_MSG_IMPERSONATION` | 28 | 25 | 3 | 0.893 | 0.284 |
| `RULE_MSG_FINANCIAL_LURE` | 22 | 22 | 0 | 1.000 | 0.250 |
| `RULE_MSG_DISPLAY_TEXT_MISMATCH` | 17 | 17 | 0 | 1.000 | 0.193 |
| `RULE_MSG_SENSITIVE_INFO_PROMPT` | 6 | 5 | 1 | 0.833 | 0.057 |
| `RULE_MSG_SUSPICIOUS_ATTACHMENT` | 6 | 6 | 0 | 1.000 | 0.068 |
| `RULE_MSG_SECURITY_EVASION` | 5 | 5 | 0 | 1.000 | 0.057 |
| `RULE_MSG_MIME_DEFECT_ANOMALY` | 2 | 1 | 1 | 0.500 | 0.011 |

## 5. URL Analysis Telemetry

- **Messages Containing URLs**: `96`
- **Total URLs Extracted**: `146`
- **Unique Canonical URLs**: `97`
- **URL Threat Findings**: `95`
- **URL Scenarios Evaluated**: `18` (Correct: `17`, Missed: `1`)

## 6. Robustness, Edge-Case Handling & Performance

- **Edge Cases Evaluated**: `10`
- **Uncaught Exceptions**: `2` (Target: 0)
- **Resource Limits Triggered**: `0`
- **Partial Analyses Correctly Flagged**: `2`
- **Invalid Inputs Gracefully Rejected**: `2`

### Latency Statistics (Monotonic Timer)

- **Mean Latency**: `368.82 ms`
- **Median Latency**: `256.56 ms`
- **95th Percentile (p95)**: `305.62 ms`
- **Max Observed Latency**: `26412.33 ms`
- **Total Benchmark Wall Time**: `51.64 s`

## 7. Failure Analysis

### False Positives (Benign Messages Classified as Phishing)
- **Count**: 19
- **Sample IDs**: `BENIGN_SEC_002`, `BENIGN_SEC_004`, `BENIGN_SEC_005`, `BENIGN_SEC_007`, `BENIGN_SEC_008`, `BENIGN_SEC_015`, `BENIGN_FIN_003`, `BENIGN_FIN_006`, `BENIGN_FIN_007`, `BENIGN_FIN_009`, `BENIGN_FIN_011`, `BENIGN_FIN_018`, `BENIGN_AWR_001`, `BENIGN_AWR_002`, `BENIGN_AWR_005`, `BENIGN_AWR_006`, `BENIGN_AWR_008`, `BENIGN_AWR_010`, `EDGE_ROB_004`

### False Negatives (Phishing Messages Classified as Benign)
- **Count**: 3
- **Sample IDs**: `PHISH_URL_010`, `PHISH_MIX_012`, `EDGE_ROB_009`

### Abstentions & Incomplete Analyses
- **Count**: 2
- **Sample IDs**: `EDGE_ROB_002`, `EDGE_ROB_003`

## 8. Security Guarantees & Verification

- **Zero Network Calls**: Verified via socket & urllib mocking; all threat intel and URL scans ran completely offline.
- **Zero Code Execution**: Attachment payloads and HTML scripts were parsed strictly as inert metadata.
- **Redirect Inspection Boundary**: Remote redirect following remained disabled (`follow_redirects=False`) by default.
- **Data Privacy**: No complete message bodies or confidential strings are emitted in machine-readable or human-readable reports.

## 9. Recommendations for Day 27

1. **Preserve Deterministic Baseline**: Maintain this Day 26 baseline report before tuning any weights.
2. **Evidence Weight Calibration**: Investigate any rule overlaps or false-positive triggers before adjusting thresholds.
3. **Real-World Holdout Evaluation**: Plan for an isolated external corpus evaluation pipeline.
