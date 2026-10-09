# ACTIS Architecture Evolution & Post-Day-7 Breakthrough

**Authoritative Architecture Document**  
**Milestone:** Post-Day-7 Architectural Evolution  
**Author:** Aaryan Suman <aaryansuman17@gmail.com>  
**Status:** Approved Architectural Direction  

---

## 1. Executive Summary

During the implementation of Days 1 through 7, ACTIS successfully established a solid foundation: type-safe configuration, enterprise logging, normalized SQLite threat storage, static Windows PE header analysis, machine-learning inference contracts, a 19-feature Random Forest phishing model, safe heuristic rules, and hardened URL and message scanning pipelines.

However, practical development across Days 6 and 7 revealed a fundamental architectural insight:
> **ACTIS cannot remain merely a collection of independent, isolated scanners.**

Operating as standalone scanners creates redundant parsing pipelines, risks inconsistent threat scoring, obscures the operational security state of the endpoint, and fails to deliver proactive, real-time protection for modern Windows operating systems.

To resolve these architectural limitations, ACTIS is formally evolving into a **Windows-oriented, event-driven cyber protection platform** featuring a lightweight resident protection layer, an event/input intake layer, a centralized analysis orchestrator, shared threat intelligence, unified multi-criteria detection, evidence-based risk evaluation, and controlled user-facing presentations.

---

## 2. The Original Architecture & Limitations Discovered (Days 1–7)

### 2.1 The Original "Scanner-Centric" Model
In the initial design, ACTIS conceived cybersecurity capabilities as independent scanning tools:
- A URL Scanner
- A Message Scanner (Text Analyzer)
- A File Scanner (PE Static Analyzer)
- A Device Scanner (Filesystem crawler)
- A Background File Watcher
- A Clipboard Scanner

Each scanner was conceptually responsible for ingesting its own target, extracting features, and attempting to coordinate with analytical tools.

### 2.2 Critical Limitations Discovered During Days 1–7
1. **Redundant Analysis Paths:** In Day 7, it became apparent that without strict structural boundaries, the Message Scanner could easily duplicate URL normalization, feature extraction, and ML scoring. Day 7 resolved this locally by enforcing strict delegation, but highlighted the need for a global architectural pattern.
2. **Absence of a Unified Resident Lifecycle:** Standalone scanners require manual user invocation. Real-world threat vectors on Windows (drive-by downloads, dropped executables, malicious clipboard links) require a lightweight, continuously resident service that maintains protection state, handles debouncing, and schedules tasks without monopolizing system resources.
3. **Sensor vs. Intelligence Coupling:** Treating sensors as detectors tightly couples input ingestion with analytical algorithms. When a new scanner is added, it should only produce an *input event*—not re-implement detection logic.
4. **Threat Intelligence Duplication:** Multiple sensors querying disparate databases or external APIs independently leads to uncoordinated caching, rate-limit exhaustion, and fragmented audit trails.

---

## 3. The Core Architectural Breakthrough

The breakthrough realization is that **scanners and sensors are input mechanisms, not detection engines.**

ACTIS must separate **event acquisition** from **centralized threat intelligence and detection**. The platform transitions from a loose collection of scanners into a cohesive, layered architecture:

```text
                    WINDOWS
                       │
                       ▼
              ┌───────────────────┐
              │ ACTIS PROTECTION  │
              │      SERVICE      │
              │ Lightweight /     │
              │ Resident Layer    │
              └─────────┬─────────┘
                        │
                        ▼
              ┌───────────────────┐
              │ EVENT / INPUT     │
              │      LAYER        │
              └─────────┬─────────┘
                        │
             ┌──────────┼───────────┐
             │          │           │
             ▼          ▼           ▼
        FILE EVENTS  URL EVENTS  MESSAGE EVENTS
             │          │           │
             └──────────┼───────────┘
                        ▼
              ┌───────────────────┐
              │ ANALYSIS          │
              │ ORCHESTRATOR      │
              ├───────────────────┤
              │ • ML              │
              │ • Rules           │
              │ • Static Analysis │
              │ • Feature Extract │
              └─────────┬─────────┘
                        │
                        ▼
              ┌───────────────────┐
              │ THREAT            │
              │ INTELLIGENCE      │
              ├───────────────────┤
              │ Local TI          │
              │ Online TI         │
              │ Shared ACTIS TI   │
              └─────────┬─────────┘
                        │
                        ▼
              ┌───────────────────┐
              │ DETECTION ENGINE  │
              └─────────┬─────────┘
                        │
                        ▼
              ┌───────────────────┐
              │ RISK ENGINE       │
              │ + Evidence        │
              │ + Confidence      │
              │ + Classification  │
              └─────────┬─────────┘
                        │
                        ▼
              ┌───────────────────┐
              │ USER / SYSTEM     │
              ├───────────────────┤
              │ Dashboard         │
              │ Notifications     │
              │ Reports           │
              │ AI Assistant      │
              └───────────────────┘
```

---

## 4. Key Architectural Pillars

### 4.1 Lightweight Resident Protection Service (`ACTIS Protection Service`)
- **Role:** Resident Windows background service/daemon that maintains endpoint protection state.
- **Responsibilities:**
  - Manages service lifecycle (startup, resume, graceful termination).
  - Listens for security-relevant operating system hooks and sensor signals.
  - Applies lightweight intake filtering and debouncing (e.g. file-write completion locks).
  - Enqueues jobs to the analysis pipeline asynchronously without blocking OS threads.
  - **Non-Responsibilities:** Does *not* execute machine learning models or perform heavy PE parsing directly inside the resident event-loop.

### 4.2 Event / Input Layer
- **Role:** Standardized ingestion gateway converting raw environmental interactions into typed security events.
- **Event Types:**
  - `FileSecurityEvent`: File dropped, created, modified, or targeted by user scan.
  - `UrlSecurityEvent`: URL submitted by user, pasted into browser/clipboard, or extracted from documents.
  - `MessageSecurityEvent`: Raw text, email, or communication submitted for triage.
  - `OnDemandScanEvent`: User-configured recursive directory or custom target scan.

### 4.3 Centralized Analysis Orchestrator
- **Role:** Canonical coordinator of all static inspection and feature extraction algorithms.
- **Design Rule:** **There is strictly ONE canonical analysis pipeline per target type.**
- **Responsibilities:**
  - Coordinates input validation and canonical normalization.
  - Extracts deterministic morphological and static PE features.
  - Dispatches feature vectors to machine learning inference engines.
  - Evaluates deterministic heuristic rule suites.
  - Assembles unified evidence objects and passes them to the Detection Engine.

### 4.4 Shared Threat Intelligence Layer
- **Role:** Consolidated intelligence infrastructure shared across all analysis workflows.
- **Sub-tiers:**
  - *Local TI Database:* Fast SQLite lookup of verified hashes, domains, and indicators.
  - *Online TI Connectors:* Read-only reputation feeds (VirusTotal v3, URLhaus) with strict timeout and fallback handling.
  - *Central ACTIS TI Network:* Federated sharing API synchronizing corroborated threat indicators across endpoints.

### 4.5 Detection Engine & Risk Engine Integration
- **Role:** The analytical intelligence core.
- **Multi-Criteria Fusion:** Evaluates targets across four orthogonal analytical signals:
  1. Known Local Intelligence (`0.35`)
  2. Machine Learning Inference (`0.30`)
  3. Deterministic Heuristic Rules (`0.20`)
  4. External Reputation Feeds (`0.15`)
- **Categorical Risk Classification:** Indicators and targets are categorized explicitly into verifiable lifecycle states:
  - `CONFIRMED`: Multi-source corroborated malicious threats.
  - `SUSPICIOUS`: Strong anomalous signals lacking external consensus.
  - `CANDIDATE`: Preliminary heuristic or ML flags awaiting corroboration.
  - `REPORTED`: Incoming unverified telemetry submissions.
  - `FALSE_POSITIVE`: Verified benign software overriding statistical models.
- **Explainability:** Every verdict provides itemized reasoning, confidence scores, and contributing rule IDs.

---

## 5. Security & Privacy Guarantees

The evolution to an event-driven architecture strictly maintains all established ACTIS safety policies:
1. **Strictly Read-Only Analysis:** Analysis is limited to static file parsing, header inspection, byte entropy, and mathematical hashing. Zero code is executed.
2. **Zero Automatic Remediation:** ACTIS never automatically deletes, renames, quarantines destructively, or encrypts user files. All actions are advisory.
3. **Privacy-First Data Flow:** Personal documents and executable payloads are **NEVER** uploaded to central servers or third-party APIs. Only cryptographic hashes (SHA-256/MD5), public domain names, and URLs are queried.
4. **No Covert Surveillance:** ACTIS does not record keystrokes, capture screens, or harvest browser history.
5. **No Unrestricted Shell Access:** The AI Security Assistant operates solely through structured SQLite and application interfaces, with zero access to `cmd.exe` or PowerShell execution.

---

## 6. Implementation Status Baseline (Day 7 Baseline)

To ensure absolute transparency and prevent misleading claims, components are categorized according to their verified repository realization:

| Subsystem / Component | Realization Status | Verified Baseline |
|---|---|---|
| **Configuration Subsystem (`config/`)** | `IMPLEMENTED` | Complete typed settings, paths, environment variable validation (11 passing tests). |
| **Logging Infrastructure (`config/logger.py`)** | `IMPLEMENTED` | Rotating file handlers, audit formatting, sanitization. |
| **Local Threat DB (`reports/threat_database.py`)** | `IMPLEMENTED` | SQLite WAL mode, normalized schemas (`threats`, `indicators`, `scans`, `detections`). |
| **Static PE Extraction (`scanners/file_feature_extractor.py`)** | `IMPLEMENTED` | Safe read-only PE header, section, and entropy parsing (21 passing tests). |
| **Phishing ML Model (`models/`, `detection_engine/model_manager.py`)** | `IMPLEMENTED` | 19-feature Random Forest model contract and metadata schema. |
| **URL Scanner Hardening (`scanners/url_scanner.py`)** | `IMPLEMENTED` | RFC validation, canonical normalization, 19-feature contract, session caching. |
| **Message Scanner (`scanners/text_analyzer.py`)** | `IMPLEMENTED` | Boundary cleanup, canonical deduplication, strict delegation to URL scanner. |
| **Detection Decision Engine (`detection_engine/`)** | `IMPLEMENTED` | Multi-criteria fusion, dynamic weight normalization, rule engine, confidence scoring. |
| **Device Scanner (`scanners/device_scanner.py`)** | `IMPLEMENTED` | Completed in Day 8: loop safety, chunked streaming SHA-256, structured scan result, incremental state tracking. |
| **Windows Protection Service (`service/`)** | `IMPLEMENTED` | Completed in Day 9: deterministic lifecycle, state machine, worker management, SecurityEvent contract, bounded intake queue, EventDispatcher, AnalysisOrchestrator handoff, and Windows SCM host adapter. |
| **Automated Test Suite (`tests/`)** | `IMPLEMENTED` | 200 automated unit and integration tests passing with 100% success rate. |
| **Event-Driven File Watcher (`scanners/file_watcher.py`)** | `PLANNED` | Prototype watchdog script exists; event filtering and orchestrator handoff planned for Day 10. |
| **Online Threat Intelligence (`threat_intelligence/api_clients.py`)** | `PROTOTYPE / NOT YET MILESTONE-COMPLETE` | Prototype VT client; rate-limiting and normalized abstraction scheduled for Day 11. |
| **Central ACTIS TI API (`backend/`, `threat_intelligence/sync_manager.py`)** | `PROTOTYPE / NOT YET MILESTONE-COMPLETE` | Prototype FastAPI server; federated synchronization scheduled for Day 12. |
| **Dashboard & Notifications (`dashboard/`, `notifications/`)** | `PROTOTYPE / NOT YET MILESTONE-COMPLETE` | Streamlit and notifier prototypes; integrated UI and alerts scheduled for Day 13. |
| **AI Security Assistant (`assistant/`)** | `PROTOTYPE / NOT YET MILESTONE-COMPLETE` | Prototype SQLite explainer; safe conversational interface scheduled for Day 14. |

---

## 7. Next Roadmap Steps (Days 8–16)

Following this architectural evolution, future development will systematically build out the event-driven platform:

- **Day 8:** Device Scanner + Incremental Scan State
- **Day 9:** Windows Protection Service Foundation
- **Day 10:** Event-Driven File Protection
- **Day 11:** Online Threat Intelligence
- **Day 12:** Central ACTIS Threat Intelligence
- **Day 13:** Dashboard + Notification Layer
- **Day 14:** AI Security Assistant
- **Day 15:** Security Hardening + Broad Threat Coverage Testing
- **Day 16:** Final Integration + Demo + Release
