# ACTIS Detection Engine & Decision Fusion Workflow

**Module**: `detection_engine`  
**Milestone**: `Day 6 — Detection Engine & ML Model Integration Foundation`  
**Status**: `Verified & Active`  
**Author**: `Aaryan Suman <aaryansuman17@gmail.com>`

---

## 1. Overview & Purpose

The **ACTIS Detection Engine** represents the core analytical intelligence layer of the Automated Cyber Threat Intelligence System. Positioned directly between raw data scanners/feature extractors and reporting/alerting interfaces, the engine unifies heterogeneous signals from:

1. **Threat Intelligence (TI)**: Local SQLite reputation cache and indicator lookups.
2. **Machine Learning (ML)**: Random Forest classifiers for URL phishing (19 features) and Windows PE malware (15 features).
3. **Heuristic Rule Engine**: Deterministic behavioral, structural, and syntactic security rules.
4. **Static Analysis & Anomalies**: PE header anomalies, section entropy differentials, and packing indicators.

Rather than blindly trusting any single analytical modality, the Detection Engine executes multi-attribute utility theory (MAUT) with dynamic weight re-normalization, deterministic classification boundaries, and rigorous provenance tracking.

---

## 2. Analytical Architecture & Flow

```
                      +-----------------------------+
                      |   Input Target Identifier   |
                      |    (Hash, URL, File, IOC)   |
                      +--------------+--------------+
                                     |
                                     v
            +------------------------------------------------+
            |          Heterogeneous Evidence Gathering      |
            +------------------------------------------------+
            | - Threat Intelligence: ThreatIntelEvidence     |
            | - Machine Learning:    MLPredictionResult      |
            | - Heuristic Rules:     RuleEvaluationResult    |
            | - Static PE Features:  EvidenceSignal(s)       |
            +------------------------+-----------------------+
                                     |
                                     v
                 +---------------------------------------+
                 |    DetectionEvidence Container        |
                 |  (Provenance, Severity, Clamping)     |
                 +-------------------+-------------------+
                                     |
                                     v
            +------------------------------------------------+
            |              Risk Scoring Engine               |
            |  - Dynamic Layer Re-normalization              |
            |  - Mutual Confirmation Escalation              |
            |  - Reputation / Whitelist Mitigation           |
            +------------------------+-----------------------+
                                     |
                                     v
            +------------------------------------------------+
            |                 Risk Classifier                |
            |  - Deterministic Threshold Boundaries          |
            |  - Safety Overrides (Confirmed Threat/Whitelist)|
            +------------------------+-----------------------+
                                     |
                                     v
            +------------------------------------------------+
            |   Confidence & Explanation Generation          |
            |  - Internal Decision Confidence (0.0 - 1.0)    |
            |  - Grounded Human-Readable Reason List         |
            +------------------------+-----------------------+
                                     |
                                     v
            +------------------------------------------------+
            |             Final DetectionResult              |
            |  (Target, Status, RiskLevel, Score, Confidence)|
            +------------------------------------------------+
```

---

## 3. Core Component Specifications

### A. Detection Result Contract (`detection_engine.detection_contract`)
Provides immutable, typed schemas defining the final decision interface:
- **`InputType`**: `FILE`, `PE_BINARY`, `URL`, `DOMAIN`, `IP_ADDRESS`, `HASH`, `IOC`, `GENERIC`.
- **`DetectionStatus`**: `BENIGN`, `SUSPICIOUS`, `MALICIOUS`, `UNKNOWN`, `ERROR`.
- **`RiskLevel`**: `INFORMATIONAL` (0-20), `LOW` (20-35), `MEDIUM` (35-70), `HIGH` (70-85), `CRITICAL` (85-100).
- **`DetectionResult`**: Immutable container exposing `risk_score` (clamped $[0.0, 100.0]$), `confidence` (clamped $[0.0, 1.0]$), `primary_reason`, `reasons`, `contributing_signals`, and `analysis_metadata`.

### B. Structured Evidence Model (`detection_engine.evidence_model`)
Every analytical finding is converted into an `EvidenceSignal`:
- Retains source provenance (`THREAT_INTELLIGENCE`, `MACHINE_LEARNING`, `HEURISTIC_RULES`, `STATIC_PE`, `REPUTATION`, `ANOMALY`, `USER_OVERRIDE`).
- Assigns typed severity (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- Scores bounded contribution with individual signal weights.
- Aggregated inside `DetectionEvidence` for filtering and severity ranking.

### C. Machine Learning Prediction Contract (`detection_engine.ml_prediction_contract`)
- Encapsulates model name, version, status (`AVAILABLE`, `NOT_APPLICABLE`, `MODEL_UNAVAILABLE`, `INFERENCE_ERROR`, `SCHEMA_MISMATCH`), probabilities, and decision confidence.
- Exposes `to_evidence_signal()` to map prediction probabilities to evidence severity and score contributions.

### D. Generic Rule Engine & Results (`detection_engine.rule_engine`)
- **`RuleMatch`**: Records rule ID, severity, contribution score, and contextual evidence details.
- **`RuleEvaluationResult`**: Aggregates all matches for a target with total score and max severity.
- **`GenericRuleRegistry`**: Permits dynamic registration of custom security rules with clean condition predicates.

### E. Threat Intelligence Evidence (`detection_engine.threat_intel_contract`)
- Strongly typed verdicts: `CLEAN`, `SUSPICIOUS`, `MALICIOUS`, `FALSE_POSITIVE`, `UNKNOWN`, `UNAVAILABLE`.
- Factory methods: `from_local_intel()`, `unknown()`, `unavailable()`.
- Maps database records to high-impact evidence signals.

### F. Mathematical Risk Scoring Engine (`detection_engine.risk_engine`)
To prevent missing layers from skewing composite calculations, ACTIS employs **Dynamic Active Layer Normalization**:

$$	ext{Composite Score} = rac{\sum_{i \in 	ext{Active}} w_i \cdot S_i}{\sum_{i \in 	ext{Active}} w_i} - 	ext{Mitigations}$$

Where default layer weights are:
- $W_{	ext{TI}} = 0.35$
- $W_{	ext{ML}} = 0.35$
- $W_{	ext{Rules}} = 0.20$
- $W_{	ext{StaticPE}} = 0.10$

**Mutual Confirmation Escalation**: If both machine learning ($S_{	ext{ML}} \ge 70.0$) and heuristic rules ($S_{	ext{Rules}} \ge 50.0$) independently report high threat, the composite score is boosted by $1.25	imes$.

---

## 4. Decision Confidence vs. Risk Score

A critical architectural distinction in ACTIS is the separation of **Risk Score** and **Decision Confidence**:

| Metric | Dimension | Definition | Scale |
|---|---|---|---|
| **Risk Score** | *Threat Severity* | The estimated degree of malice or danger presented by the target. | $0.0 - 100.0$ |
| **Confidence** | *Evidence Reliability* | The internal decision confidence based on breadth of active corroborating layers, signal weights, and absence of inter-layer conflict. | $0.0 - 1.0$ |

---

## 5. Security & Safety Boundaries

1. **Read-Only Operation**: The detection engine executes strictly in memory. It does not modify local files, execute binaries, or launch processes.
2. **No Secret Leakage**: File paths and raw binary bytes are never stored in `DetectionResult`. Identifiers are restricted to cryptographic hashes, sanitized URLs, or domain names.
3. **No Network Side-Effects**: Day 6 components operate entirely offline without connecting to external cloud services or live third-party APIs.
4. **Deterministic Reproducibility**: Given identical input evidence, the decision engine is mathematically guaranteed to output identical scores, risk tiers, and explanations.
