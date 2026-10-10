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
| **Scheduled Threat Intel Sync** | Core Subsystem | URLhaus & AbuseIPDB scheduled feed adapters, SQLite batch upserts, status tracking | **Verified & Implemented** (`threat_intelligence/sync/`) |
| **External TI Providers** | Core | VirusTotal, AbuseIPDB, URLhaus adapters with rate limiting & error handling | **Verified & Implemented** |
| **Evidence Normalization** | Core | Converting heterogeneous findings into canonical `DetectionFinding` objects | **Verified & Implemented** |
| **Detection Decision Engine** | Core | Multi-criteria evidence fusion and verdict determination | **Verified & Implemented** |
| **Risk Assessment Engine** | Core | Calibrated 0–100 risk scoring with severity mapping | **Verified & Implemented** |
| **Windows Protection Service** | Core Subsystem | File event watcher, path filtering, debouncing, bounded queue, incremental state | **Verified & Implemented** |
| **Reports Engine** | Extension | Structured JSON, Markdown, and text report generation | **Verified & Implemented** |
| **Notifications Service** | Extension | Desktop notifications, email/webhook alerts (optional delivery) | **Verified & Implemented** |
| **Dashboard** | Extension | Monitoring web GUI, telemetry visualizer, feed sync status & manual controls | **Verified & Implemented** (`dashboard/app.py`) |
| **Central ACTIS TI Backend** | Extension | Federated intelligence exchange server for fleet sharing | **Verified & Implemented** (Day 13, `backend/`) |
| **AI Security Assistant** | Extension | Grounded natural language security assistant with read-only boundaries | **Verified & Implemented** (Day 14, `assistant/`) |

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

### 5.1 Scheduled Threat Intelligence Synchronization Subsystem

The threat intelligence synchronization service runs as a decoupled background subsystem that periodically refreshes the local SQLite intelligence database without interrupting live file and URL scans:

```
Upstream Feeds (URLhaus Recent URLs, AbuseIPDB Blacklist)
                       │
                       ▼
                 Feed Adapters
     (URLhausFeedAdapter, AbuseIPDBFeedAdapter,
      VirusTotalFeedAdapter [Enterprise boundary isolation])
                       │
                       ▼
       Validation & Normalization Layer
     (Canonical URLs, IP/RFC 1918 shielding, SHA-256 validation)
                       │
                       ▼
          In-Memory Deduplication
                       │
                       ▼
         Idempotent SQLite Persistence
     (Parameterized batch upsert into `indicators` & `threats`,
      run telemetry in `threat_sync_runs` & `threat_feed_status`)
                       │
                       ▼
     Existing Local Threat Intel Lookup (`ThreatLookup`)
                       │
                       ▼
    Unified Analysis Pipeline (`AnalysisOrchestrator`)
```

**Key Architectural Guarantees**:
- **Zero Live Scan Disruption**: Database write transactions use short, parameterized batches. Scan read operations use read-only queries with connection isolation.
- **Provider Failure Isolation**: If a provider experiences timeouts, HTTP 429 rate limits, or network failures, unrelated providers continue synchronization and the run reports `PARTIAL_SUCCESS`.
- **Concurrency Protection**: An explicit `threading.Lock` prevents overlapping synchronization jobs; duplicate manual or scheduled triggers are rejected safely with `SKIPPED_ALREADY_RUNNING`.
- **Honest Capability Reporting**: Bulk feeds are implemented only where upstream APIs genuinely support them (URLhaus CSV/JSON recent URLs; AbuseIPDB blacklist API). VirusTotal bulk feeds require enterprise agreements and explicitly report `UNSUPPORTED_OPERATION` rather than fabricating synthetic feeds.
- **Immediate Analysis Availability**: Indicators upserted into SQLite are immediately discoverable by `threat_lookup.lookup_url()`, `threat_lookup.lookup_ip()`, and `threat_lookup.lookup_hash()`, feeding directly into `DetectionDecisionEngine` and `RiskEngine`.

---

## 6. Central Threat Intelligence Service & Secure Synchronization

The Central Threat Intelligence Service (`backend/`) extends the unified architecture by enabling ACTIS endpoint nodes to synchronize verified threat intelligence and contribute candidate detections through a hardened REST API.

```
External Upstream Feeds (URLhaus, AbuseIPDB)
                   │
                   ▼
       Central ACTIS Backend API (/api/v1)
        [FastAPI + HMAC Auth + SQLite Central DB]
                   │
         ┌─────────┴─────────┐
         ▼                   ▲
   GET /api/v1/sync/pull     │ POST /api/v1/contributions
   (Batch indicator pull)    │ (Candidate submission only)
         │                   │
         ▼                   │
    CentralACTISFeedAdapter  │
         │                   │
         ▼                   │
  Local Threat Database (SQLite) ── (Contribute verified local alerts)
         │
         ▼
  ThreatLookup / Detection Pipeline
```

### Versioned API Contracts (`/api/v1`)

| Endpoint | Method | Role | Description |
|----------|--------|------|-------------|
| `/api/v1/health` | GET | Public | Service health, database status, indicator count, and system uptime. |
| `/api/v1/client/info` | GET | Authenticated | Token verification, client identity, assigned roles, and rate limit. |
| `/api/v1/indicators/{type}/{value}` | GET | `read` | Point lookup for normalized indicator with provenance and review status. |
| `/api/v1/indicators` | GET | `read` | Bounded pagination query with filtering by status, threat type, and min confidence. |
| `/api/v1/sync/pull` | POST | `read` | Bulk incremental synchronization pull for client fleet updates. |
| `/api/v1/contributions` | POST | `contribute` | Submits candidate indicator report into review queue (anti-poisoning enforced). |
| `/api/v1/admin/indicators/{id}/review` | POST | `admin` | Administrative verification (`APPROVE`, `REJECT`) promoting candidate records. |

### Authentication & Authorization Model
- **Token Verification**: Supports `Bearer <token>` in `Authorization` header and `X-ACTIS-API-Key`. Credentials are authenticated in constant time using `hmac.compare_digest` to prevent timing attacks.
- **Role-Based Authorization**: Granular roles (`read`, `contribute`, `admin`). Endpoints reject requests lacking appropriate scopes with HTTP 403.
- **Rate Limiting**: In-memory sliding-window limiter enforcing client-specific requests-per-minute (RPM) quotas (60–300 RPM default). Returns HTTP 429 when exceeded.
- **Defensive Shielding**: All queries, pulls, and submissions validate syntax and enforce RFC 1918 / RFC 5737 private and loopback IP rejection (`is_safe_public_ip`) to prevent internal network leakage.

### Anti-Poisoning Candidate State Machine
- Submissions via `/api/v1/contributions` are strictly stored with `status="CANDIDATE"`, `review_status="PENDING"`, and `source_type="CLIENT_CONTRIBUTION"`.
- Contributing clients cannot self-promote indicators to `CONFIRMED`.
- Only authorized operators with the `admin` role can review and transition candidate records to `CONFIRMED` / `APPROVED`.

### Failure & Outage Isolation
- **100% Local Autonomy**: The client `CentralACTISFeedAdapter` traps network timeouts, connection errors, HTTP 429, and HTTP 401 failures into categorized `ProviderSyncResult` telemetry.
- **Zero Impact on Scanning**: Outages of the central service do NOT block or degrade local scanning, file monitoring, or detection pipelines. Local SQLite lookups continue seamlessly.

---

## 7. Windows Monitoring Subsystem Architecture

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

## 8. Security and Privacy Boundaries

1. **No Automatic File Execution**: Dynamic execution is strictly prohibited. Static PE analysis parses headers safely using structured binary readers without executing target binaries.
2. **No Automatic Destructive Actions**: ACTIS reports findings; it never unilaterally deletes, quarantines, or alters user files.
3. **No File Uploads by Default**: Full file contents are never transmitted to external services. Threat intelligence lookups use cryptographic hashes (SHA-256) exclusively.
4. **Privacy-Preserving Reporting**: Analysis results, telemetry, and log files scrub credentials, personal file contents, and API keys.
5. **Bounded Resource Limits**: Scanners enforce file size maximums (e.g., 50MB default for PE analysis), regex timeout bounds, and bounded memory queues to prevent Denial of Service.

---

## 9. Verification & Test Coverage

The unified architecture is continuously verified by the ACTIS test suite:
- **Baseline Unified Test Suite**: 279 comprehensive tests across core config, scanners, ML models, detection engine, threat intel, reports, Windows protection service, and architectural contracts.
- **Threat Intelligence Sync Suite (`tests/test_threat_sync.py`)**: 24 dedicated unit and integration tests covering feed adapters, SQLite batch persistence, failure isolation, and scheduler lifecycle.
- **Central TI Service & Synchronization Suite (`tests/test_central_ti_service.py`)**: 30 comprehensive tests covering:
  1. Versioned REST API endpoints, health telemetry, and client metadata inspection.
  2. Constant-time token verification (`hmac.compare_digest`), missing/invalid auth rejection, and sliding-window rate limiting (429).
  3. Bounded pagination queries, filtering envelopes, and indicator point lookups.
  4. Candidate contribution anti-poisoning policy (cannot self-promote to `CONFIRMED`).
  5. Administrative verification state machine (`APPROVE`, `REJECT`).
  6. Strict indicator validation and RFC 1918 private IP shielding on API and adapter layers.
  7. `CentralACTISFeedAdapter` failure isolation (timeouts, connection errors, HTTP 401/429, malformed JSON).
  8. Idempotent SQLite persistence via Day 12 `upsert_feed_records` and immediate queryability through `ThreatLookup`.
  9. Complete offline resilience: local scanning and background file monitoring remain 100% functional when central service is offline.
- **Grounded AI Security Assistant Suite (`tests/test_security_assistant.py`)**: 27 dedicated unit, integration, and security boundary tests covering:
  1. Deterministic intent routing: recent detections, flagged target explanations, indicator lookups, scan stats, methodology, and safe defensive guidance.
  2. Multi-factor scoring provenance breakdown: Threat Intelligence (35%), Machine Learning (30%), Heuristic Rules (20%).
  3. Candidate indicator anti-poisoning warnings (`CANDIDATE` vs `CONFIRMED`).
  4. Disambiguation policy for ambiguous target matches instead of arbitrary row selection.
  5. Absence-of-evidence safety warnings (unknown indicator is not reported as safe).
  6. Read-only non-destructive boundaries (zero OS shell execution, zero automated file deletion/quarantine).
  7. Automated secret masking and credential sanitization (`mask_sensitive_strings`).
  8. Offline isolation and provider fallback (`DeterministicAssistantProvider` / `ExternalLLMProvider`).
  9. Streamlit dashboard session conversation history and native Markdown rendering.
- **Current Test Status**: **360 passed, 0 failed** (100% pass rate).
