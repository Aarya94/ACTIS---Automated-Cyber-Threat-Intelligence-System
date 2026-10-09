# ACTIS Detection Workflow & Multi-Criteria Evidence Fusion

**Authoritative Architecture Document**  
**Milestone:** Post-Day-7 Architectural Evolution  
**Status:** Approved Target Architecture  

This document details the multi-layered threat evaluation pipeline employed by ACTIS to evaluate incoming security events without relying on any single point of failure or fragile detection mechanism.

---

## 1. End-to-End Pipeline in the Target Architecture

In the event-driven architecture, target inputs (including real-time filesystem events connected in Day 10) flow from the **Event/Input Layer** through the **Analysis Orchestrator** into the **Detection Decision Engine**:

```text
                                  +---------------------------------------+
                                  |            Security Event             |
                                  | (Filesystem Event, File, URL, Message)|
                                  +-------------------+-------------------+
                                                      |
                                                      v
                                  +---------------------------------------+
                                  |         Analysis Orchestrator         |
                                  | (Coordinate Incremental State & Deep  |
                                  |  Inspection via ThreatDetector)       |
                                  +-------------------+-------------------+
                                              |
                        +---------------------+---------------------+
                        |                     |                     |
                        v                     v                     v
            +-----------------------+ +---------------+ +-----------------------+
            | Threat Intelligence   | | ML Inference  | |  Rule-Based Engine    |
            |  Lookup (Local/Online)| | (RF Models)   | | (Deterministic Rules) |
            +-----------+-----------+ +-------+-------+ +-----------+-----------+
                        |                     |                     |
                        +---------------------+---------------------+
                                              |
                                              v
                                  +-----------------------+
                                  | Detection Engine Core |
                                  | (Evidence Collector)  |
                                  +-----------+-----------+
                                              |
                                              v
                                  +-----------------------+
                                  |   Risk / Decision     |
                                  | (Evidence Fusion,     |
                                  |  Score, Confidence)   |
                                  +-----------+-----------+
                                              |
                                              v
                                  +-----------------------+
                                  | Threat Classification |
                                  | (CONFIRMED, SUSPICIOUS|
                                  |  CANDIDATE, etc.)     |
                                  +-----------+-----------+
                                              |
                                              v
                                  +-----------------------+
                                  | Persistence & Egress  |
                                  | (SQLite, Alerts, UI,  |
                                  |  Security Assistant)  |
                                  +-----------------------+
```

---

## 2. Multi-Criteria Evidence Layers

ACTIS explicitly rejects binary reliance on raw machine learning predictions. Because ML models inherently carry false-positive and false-negative margins, the Detection Engine fuses four orthogonal analytical layers:

| Layer | Evidence Source | Default Weight | Role & Verification |
|---|---|---|---|
| **Layer 1: Known Intelligence** | Local SQLite Threat DB | `0.35` | Deterministic match against locally verified hashes, domains, or URLs. |
| **Layer 2: ML Inference** | Random Forest Classifiers | `0.30` | Statistical scoring based on structural feature patterns (URL morphology or PE metrics). |
| **Layer 3: Heuristic Rules** | Rule Engine | `0.20` | Deterministic logic: high section entropy, known packer sections, injection APIs, unescaped IPs. |
| **Layer 4: External Enrichment**| Online TI APIs (VirusTotal v3) | `0.15` | External community reputation scoring (optional / offline-safe fallback). |

---

## 3. Dynamic Weight Normalization

When a target is novel (unseen in threat intelligence) or when the endpoint operates in an offline or air-gapped environment (external intelligence unavailable), the Risk Engine dynamically re-normalizes active weights:

$$\text{Active Weights Sum} = \sum_{i \in \text{Available}} W_i$$

$$W_i^{\text{normalized}} = \frac{W_i}{\text{Active Weights Sum}}$$

$$\text{Composite Score} = 100 \times \sum_{i \in \text{Available}} \left( S_i \times W_i^{\text{normalized}} \right)$$

This ensures that missing external feeds do not artificially suppress the risk score of an inherently malicious binary or phishing link.

---

## 4. Threat Classification & Lifecycle States

### 4.1 Severity Risk Bands (0–100 Score)
- **`CRITICAL` (80–100):** Clear malicious indicators corroborated across multiple analytical layers. Immediate user alert.
- **`HIGH` (60–79):** Strong malicious indicators or high ML probability with corroborating heuristics.
- **`MEDIUM` (35–59):** Suspicious structural anomalies, unverified external reports, or moderate ML probability.
- **`LOW` (0–34):** Benign characteristics, clean threat intelligence lookups, standard binary structures.

### 4.2 Categorical Verification States
1. **`CONFIRMED`:** A thoroughly verified malicious indicator corroborated by multiple trusted intelligence sources.
2. **`SUSPICIOUS`:** An indicator exhibiting multiple corroborating warning signs but lacking definitive external consensus.
3. **`CANDIDATE`:** A preliminary flag identified by ML or heuristics awaiting corroboration.
4. **`REPORTED`:** An incoming telemetry submission pending verification.
5. **`FALSE_POSITIVE`:** A verified benign indicator that explicitly overrides heuristic and statistical warnings.

---

## 5. Confidence Calculation & Itemized Explainability

Every detection decision produces:
- **`confidence` (0.0 to 1.0):** Reflects the volume, agreement, and reliability of contributing evidence sources.
- **`evidence_breakdown`:** An itemized tree detailing each signal: source name, raw score, normalized weight, and contributing rule IDs.
- **`explanation`:** A human-readable summary detailing exactly what was detected and why the verdict was rendered.
