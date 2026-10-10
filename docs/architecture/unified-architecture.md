# Unified ACTIS Architecture — Core + Extensions

<p align="center">
  <img src="../../assets/branding/actis-logo-original.png" alt="ACTIS — Automated Cyber Threat Intelligence System logo" width="300" />
</p>

**Document Status:** Authoritative Unified Architecture Specification  
**Architecture Paradigm:** Core + Extensions  
**Adopted Milestone:** Architectural Unification & Repository Audit  
**Classification:** Source of Truth (Core Engine, Contracts, and Extension Boundaries)

---

## 1. Executive Summary & Architectural Decision

ACTIS (**Automated Cyber Threat Intelligence System**) follows the **Unified ACTIS Architecture**, combining the event-driven endpoint protection capabilities with a decoupled **Core + Extensions** model.

The primary objective is to maintain **ONE authoritative, coherent, modular, and testable analysis pipeline** across all ingestion surfaces (files, URLs, messages/text, external events, and background monitoring), preventing competing detection engines, duplicated risk formulas, or tight coupling to optional services.

### Core Architectural Distinctions

To ensure complete technical clarity and honesty, ACTIS documentation strictly distinguishes between four architectural tiers:

1. **Current Architecture (Verified Implementation)**: Components, schemas, classes, and pipelines actively verified with unit and integration tests in the repository.
2. **Target Architecture**: The unified structural design ACTIS is actively adopting and aligning toward, defining interface contracts, boundaries, and data flows.
3. **Reference Architecture**: Conceptual designs, RFCs, educational models, and protocol drafts (e.g., decentralized threat-sharing protocols, investigation graphs).
4. **Development Roadmap**: Planned milestones scheduled for future implementation without claiming present completion.

---

## 2. Target Unified Architecture Diagram

The authoritative target topology established for ACTIS is structured as follows:

```
                         ACTIS APPLICATION
                                │
                  ┌─────────────┼─────────────┐
                  │             │             │
              URL Input     File Input   Message Input
                  │             │             │
                  └─────────────┬─────────────┘
                                │
                                ▼
                       INPUT NORMALIZATION
                                │
                                ▼
                      ANALYSIS ORCHESTRATOR
                                │
                  ┌─────────────┼─────────────┐
                  │             │             │
                  ▼             ▼             ▼
              ML ENGINE    RULE ENGINE   STATIC ANALYSIS
                  │             │             │
                  └─────────────┬─────────────┘
                                │
                                ▼
                       INDICATOR EXTRACTION
                                │
                                ▼
                   THREAT INTELLIGENCE SERVICE
                                │
                    ┌───────────┼───────────┐
                    │           │           │
                    ▼           ▼           ▼
                 LOCAL TI    PROVIDER A   PROVIDER B
                 DATABASE     ADAPTER      ADAPTER
                    │           │           │
                    └───────────┼───────────┘
                                │
                                ▼
                      EVIDENCE NORMALIZATION
                                │
                                ▼
                      EVIDENCE AGGREGATION
                                │
                                ▼
                         DETECTION ENGINE
                                │
                                ▼
                            RISK ENGINE
                                │
                                ▼
                       STRUCTURED RESULT
                                │
                   ┌────────────┼────────────┐
                   │            │            │
                   ▼            ▼            ▼
                STORAGE       REPORTS     NOTIFICATIONS
                                │
                                ▼
                         USER INTERFACE


         SEPARATE WINDOWS MONITORING SUBSYSTEM

                    Windows File Events
                            │
                            ▼
                   Event Normalization
                            │
                            ▼
                  Filtering and Debouncing
                            │
                            ▼
                    Bounded Event Queue
                            │
                            ▼
                 Incremental Scan Coordinator
                            │
                            ▼
                    ANALYSIS ORCHESTRATOR


                    FUTURE EXTENSIONS

             ┌──────────────┬──────────────┐
             │              │              │
             ▼              ▼              ▼
        AI Assistant   Central ACTIS TI   Additional
                           Service       Integrations
```

---

## 3. Core Principles & Architecture Contracts

### 3.1 One Authoritative Analysis Pipeline
- All input providers (`scanners.FileScanner`, `scanners.URLScanner`, `scanners.TextAnalyzer`, `scanners.DeviceScanner`) and the `service.FileProtectionPipeline` submit work exclusively through the central analysis boundary: `detection_engine.AnalysisOrchestrator` (inheriting from `detection_engine.ThreatDetector`).
- **No Competing Engines**: No scanner or monitoring service implements its own detection thresholding, ML scoring, or risk-calculation engine. All analysis flows converge at `DetectionDecisionEngine.evaluate()` and `RiskEngine.calculate_risk()`.

### 3.2 Canonical Structured Analysis Contract (`DetectionResult`)
Every analysis workflow returns a structured, typed contract with complete provenance:

```python
@dataclass
class DetectionResult:
    target: str                          # Normalized target identifier or path
    target_type: str                     # "url", "file", "message", "device"
    verdict: ThreatVerdict               # CLEAN, SUSPICIOUS, MALICIOUS, UNKNOWN
    confidence: float                    # 0.0 to 1.0 calibrated confidence
    risk_score: float                    # 0.0 to 100.0 ACTIS Risk Score
    severity: ThreatSeverity             # NONE, LOW, MEDIUM, HIGH, CRITICAL
    layers_evaluated: List[str]          # Evaluated engines ["ml", "rules", "ti", "static"]
    findings: List[DetectionFinding]     # Individual normalized evidence items
    mitre_attack_ids: List[str]          # MITRE ATT&CK technique IDs
    timestamp: datetime                  # UTC timestamp
    metadata: Dict[str, Any]             # Engine details, provider status, explainability
```

### 3.3 Separation of Analysis and Decision-Making
ACTIS strictly separates observational evidence from definitive decisions:
- **ML Probability / Confidence**: The raw likelihood emitted by a classifier (`url_model.pkl`, `pe_malware_detector.pkl`).
- **Rule Matches & Heuristics**: Deterministic pattern or YARA-like matches (`rules/*.json`).
- **Provider Reputation**: Raw counts from VirusTotal, URLhaus, or AbuseIPDB.
- **ACTIS Risk Score**: Weighted, calibrated score on a 0–100 scale computed by `RiskEngine`.
- **Final Classification**: `ThreatVerdict` produced by `DetectionDecisionEngine` based on multi-criteria fusion.
- **Uncertainty Preservation**: An unknown indicator or unavailable provider is **never** converted into a negative ("safe") finding; it is explicitly marked with `ThreatVerdict.UNKNOWN` and logged with low confidence.

### 3.4 Failure Isolation & Resilience
External provider queries or optional extension failures must never degrade local analysis:
- **Timeouts**: Provider HTTP queries use bounded timeouts (default: 5.0 seconds).
- **HTTP 429 Rate Limiting & 5xx Failures**: Safely caught, recorded in `metadata["provider_failures"]`, and isolated without throwing unhandled exceptions.
- **Offline / Local First**: When external providers or networks are unavailable, local static analysis, heuristic rules, ML inference, and the local SQLite intelligence database continue operating at 100% fidelity.

---

## 4. Subsystem Decomposition: Core vs. Extensions

| Layer / Component | Type | Responsibility | Implementation State |
|---|---|---|---|
| **Input Normalization** | Core | Normalizes URLs, file paths, and text payloads before pipeline entry | **Verified & Implemented** |
| **Analysis Orchestrator** | Core | Single authority dispatching input to static, rule, ML, and TI engines | **Verified & Implemented** (`AnalysisOrchestrator`) |
| **Machine Learning Engine** | Core | Offline inference for PE binaries & URLs with threshold calibrators | **Verified & Implemented** |
| **Rule & Heuristics Engine** | Core | Deterministic pattern matching, entropy inspection, suspicious API calls | **Verified & Implemented** |
| **Static PE Analyzer** | Core | Header validation, section hashing, import table parsing, entropy calculation | **Verified & Implemented** |
| **Local Threat Intel (TI) DB** | Core | SQLite-backed indicator repository (`threat_intel.db`) with cache lookups | **Verified & Implemented** |
| **External TI Providers** | Core | VirusTotal, AbuseIPDB, URLhaus adapters with rate limiting & error handling | **Verified & Implemented** |
| **Evidence Normalization** | Core | Converting heterogeneous findings into canonical `DetectionFinding` objects | **Verified & Implemented** |
| **Detection Decision Engine** | Core | Multi-criteria evidence fusion and verdict determination | **Verified & Implemented** |
| **Risk Assessment Engine** | Core | Calibrated 0–100 risk scoring with severity mapping | **Verified & Implemented** |
| **Windows Protection Service** | Core Subsystem | File event watcher, path filtering, debouncing, bounded queue, incremental state | **Verified & Implemented** |
| **Reports Engine** | Extension | Structured JSON, Markdown, and text report generation | **Verified & Implemented** |
| **Notifications Service** | Extension | Desktop notifications, email/webhook alerts (optional delivery) | **Verified & Implemented** |
| **Dashboard** | Extension | Monitoring web GUI & telemetry visualizer | **Prototype / In Progress** |
| **AI Security Assistant** | Extension | Constrained LLM/RAG assistant with read-only security boundaries | **Prototype / Planned** |
| **Central ACTIS TI Backend** | Extension | Federated intelligence exchange server for fleet sharing | **Planned (Roadmap)** |

---

## 5. Threat Intelligence Integration & Evidence Flow

1. **Indicator Extraction**: Inputs are parsed to extract primary indicators (SHA-256, MD5, domain, IP, URL).
2. **Local Cache First**: Queries `LocalThreatIntelDB` (SQLite) to avoid redundant external network roundtrips.
3. **External Provider Queries**: When configured and enabled with API keys, queries external adapters concurrently (`ThreadPoolExecutor`) with strict timeouts:
   - `VirusTotalAdapter`: Hash and URL lookups.
   - `AbuseIPDBAdapter`: IPv4/IPv6 reputation lookups.
   - `URLhausAdapter`: Malicious URL payload lookups.
4. **Evidence Provenance & Validation**: Each provider response is parsed into a normalized dictionary preserving:
   - Provider name and query timestamp.
   - Malicious/suspicious vote counts and total engines.
   - Raw tags and category classifications.
5. **Decision Fusion**: The `ThreatDetector` passes normalized provider evidence into `DetectionDecisionEngine` alongside ML confidence and rule matches, weighting external intelligence with calibrated confidence.

---

## 6. Windows Monitoring Subsystem Architecture

The Windows Protection Service (`service.WindowsProtectionService` and `service.FileProtectionPipeline`) runs as a dedicated, event-driven subsystem:

```
Windows Filesystem (ReadDirectoryChangesW / watchdog)
                       │
                       ▼
             FileProtectionPipeline
                       │
                       ▼
             PathFilter & Extension Filter
   (Ignores Windows system dirs, temp files, .tmp, swap)
                       │
                       ▼
             Debounce Buffer & Coalescer
   (Debounces rapid writes within configured window, e.g., 500ms)
                       │
                       ▼
              Bounded Event Queue
   (Prevents memory exhaustion under heavy file churn)
                       │
                       ▼
         Incremental Scan State & Hash Dedup
   (Checks SHA-256 against seen cache to avoid redundant analysis)
                       │
                       ▼
             AnalysisOrchestrator
   (Dispatches to canonical pipeline: PE analysis, rules, ML, TI)
```

**Safety Guarantees**:
- **Read-Only**: ACTIS never executes, modifies, encrypts, or deletes user files.
- **Zero Kernel Drivers**: Operates entirely in user mode using standard Windows filesystem APIs.
- **Defender Coexistence**: ACTIS acts as an intelligence and triage layer, complementing rather than interfering with Windows Defender or enterprise EDRs.

---

## 7. Security and Privacy Boundaries

1. **No Automatic File Execution**: Dynamic execution is strictly prohibited. Static PE analysis parses headers safely using structured binary readers without executing target binaries.
2. **No Automatic Destructive Actions**: ACTIS reports findings; it never unilaterally deletes, quarantines, or alters user files.
3. **No File Uploads by Default**: Full file contents are never transmitted to external services. Threat intelligence lookups use cryptographic hashes (SHA-256) exclusively.
4. **Privacy-Preserving Reporting**: Analysis results, telemetry, and log files scrub credentials, personal file contents, and API keys.
5. **Bounded Resource Limits**: Scanners enforce file size maximums (e.g., 50MB default for PE analysis), regex timeout bounds, and bounded memory queues to prevent Denial of Service.

---

## 8. Verification & Test Coverage

The unified architecture is continuously verified by the ACTIS test suite:
- **Baseline Test Suite**: 267 comprehensive tests across core config, scanners, ML models, detection engine, threat intel, reports, and services.
- **Unified Architecture Suite (`tests/test_unified_architecture.py`)**: 12 dedicated architectural compliance tests covering:
  1. Multi-modal ingestion (`analyze_file`, `analyze_url`, `analyze_message`) via `AnalysisOrchestrator`.
  2. Contract symmetry between URL and file analysis (verifying presence and schema of `DetectionResult`).
  3. `SecurityEvent` handoff boundary for Windows monitoring subsystem.
  4. Failure isolation when external threat intelligence providers time out or encounter HTTP 429.
  5. Scanners delegating to the orchestrator without maintaining competing detection engines.
- **Current Test Status**: **279 passed, 0 failed** (100% pass rate).
