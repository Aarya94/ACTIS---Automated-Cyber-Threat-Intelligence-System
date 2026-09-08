# ACTIS Detection Workflow & Multi-Criteria Evidence Fusion

This document details the multi-layered threat evaluation pipeline employed by ACTIS to evaluate incoming targets (URLs, messages, files) without relying on any single point of failure.

---

## The End-to-End Pipeline

```text
                                  +-----------------------+
                                  |    Target Input       |
                                  | (URL, Message, File)  |
                                  +-----------+-----------+
                                              |
                                              v
                                  +-----------------------+
                                  |    Scanner Ingest     |
                                  | (Syntax/Header Read)  |
                                  +-----------+-----------+
                                              |
                                              v
                                  +-----------------------+
                                  |  Feature Extraction   |
                                  | (Tokens, Hashes, PE)  |
                                  +-----------+-----------+
                                              |
                                              v
                                  +-----------------------+
                                  | Threat Intelligence   |
                                  |  Lookup (Local DB)    |
                                  +-----------+-----------+
                                              |
                                              v
                                  +-----------------------+
                                  |  ML Model Inference   |
                                  | (Phishing / Malware)  |
                                  +-----------+-----------+
                                              |
                                              v
                                  +-----------------------+
                                  |  Rule-Based Engine    |
                                  | (Heuristic Signatures)|
                                  +-----------+-----------+
                                              |
                                              v
                                  +-----------------------+
                                  | Risk/Decision Engine  |
                                  |  (Evidence Fusion)    |
                                  +-----------+-----------+
                                              |
                                              v
                                  +-----------------------+
                                  | Threat Classification |
                                  | (CRITICAL, HIGH, etc) |
                                  +-----------+-----------+
                                              |
                                              v
                                  +-----------------------+
                                  | Persistence & Audit   |
                                  | (SQLite Scan History) |
                                  +-----------+-----------+
                                              |
                                              v
                                  +-----------------------+
                                  | User Notification &   |
                                  |  Dashboard Display    |
                                  +-----------------------+
```

---

## Multi-Criteria Evidence Layers

ACTIS explicitly rejects binary reliance on raw machine learning predictions. Because ML models inherently carry false-positive and false-negative margins, the Detection Engine fuses four independent analytical layers:

| Layer | Evidence Source | Default Weight | Role & Verification |
|---|---|---|---|
| **Layer 1: Known Intelligence** | Local SQLite Threat DB | `0.35` | Instant deterministic match against locally verified hashes, domains, or URLs. |
| **Layer 2: ML Inference** | Random Forest Classifiers | `0.30` | Statistical scoring based on structural feature patterns (URL morphology or PE header metrics). |
| **Layer 3: Heuristic Rules** | Rule Engine | `0.20` | Deterministic logic: high section entropy, known packer sections (UPX), injection APIs, unescaped IPs. |
| **Layer 4: External Enrichment**| Online TI APIs (VirusTotal) | `0.15` | External community reputation scoring (optional / offline-safe fallback). |

---

## Dynamic Weight Normalization

When a target is novel (unseen in local threat intelligence) or when the endpoint is offline (external intelligence unavailable), the Risk Engine dynamically re-normalizes the active evidence weights:

$$\text{Active Weights Sum} = \sum_{i \in \text{Available}} W_i$$

$$W_i^{\text{normalized}} = \frac{W_i}{\text{Active Weights Sum}}$$

$$\text{Composite Score} = 100 \times \sum_{i \in \text{Available}} \left( S_i \times W_i^{\text{normalized}} \right)$$

This ensures that missing external feeds do not artificially suppress the risk score of an inherently malicious binary or phishing link.

---

## Threat Classification Thresholds

The composite score maps directly to actionable severity categories:

- **`CRITICAL` (80 – 100)**: Immediate high-confidence threat. High probability of weaponized malware or confirmed credential harvester. Requires immediate user alert.
- **`HIGH` (60 – 79)**: Strong malicious indicators present (e.g. packed PE with injection APIs or high ML phishing probability).
- **`MEDIUM` (35 – 59)**: Suspicious characteristics detected (e.g. urgent social engineering language, novel domains, anomalous section headers).
- **`LOW` (0 – 34)**: Benign or standard characteristics. Minimal indicator overlap.

---

## Core Rule: ML Predictions Are Not Globally Confirmed Intelligence

A machine learning prediction (regardless of model confidence) is an **evidentiary signal**, not a verified fact.
- ML predictions are stored locally as `CANDIDATE` or `SUSPICIOUS` detections.
- **Under NO circumstances** does an unverified ML prediction get promoted directly to `CONFIRMED` threat intelligence or broadcast across the central sharing network without corroborating evidence or manual verification.
