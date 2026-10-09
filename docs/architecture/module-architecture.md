# ACTIS Module Architecture

**Authoritative Architecture Document**  
**Milestone:** Post-Day-7 Architectural Evolution  
**Status:** Approved Target Architecture  

This document defines the architectural responsibilities, input/output contracts, system dependencies, permitted actions, forbidden operations, and current realization status for every core package in ACTIS.

---

## 1. Status Definitions

To maintain absolute architectural truthfulness and prevent overclaiming, every subsystem is classified under one of four explicit categories:

- **`IMPLEMENTED`**: Fully realized in the workspace with active source code, verifiable interfaces, and passing automated test suites.
- **`PROTOTYPE / NOT YET MILESTONE-COMPLETE`**: Initial prototype scripts or scaffolding exist historically in the repository, but formal architectural integration, state management, or milestone test suites remain pending.
- **`PLANNED`**: Formally specified in the approved architecture and scheduled for subsequent roadmap days, but not yet implemented.
- **`FUTURE`**: Long-term conceptual extensions outside the current 16-day roadmap.

---

## 2. Module Specifications

### 2.1 Configuration Subsystem (`config/`)
- **Status:** `IMPLEMENTED` (Completed in Day 2)
- **Purpose:** Centralized, type-annotated configuration management, environment variable parsing (`ACTIS_*`), dynamic project path anchoring, runtime defaults, and constraint validation.
- **Inputs:** Environment variables (`os.environ`), `.env` file, runtime overrides.
- **Outputs:** Strongly typed `AppConfig` instance and backward-compatible module constants.
- **Dependencies:** `pathlib`, `os`, `dotenv`, `logging`.
- **Allowed Operations:** Read local environment; resolve repository relative paths; validate parameters; instantiate loggers.
- **Forbidden Operations:** Write to production filesystems outside temporary logs/dirs; log raw secret keys; expose plaintext tokens in `__repr__`.

---

### 2.2 Event Ingestion & Scanners (`scanners/`)
- **Status:** `PARTIALLY IMPLEMENTED`
  - *URL Scanner (`url_scanner.py`):* `IMPLEMENTED` (RFC validation, canonical normalization, 19-feature vector, session cache).
  - *Text Analyzer (`text_analyzer.py`):* `IMPLEMENTED` (Boundary-aware link extraction, social engineering heuristics, canonical deduplication, strict delegation to URL scanner).
  - *PE Feature Extractor (`file_feature_extractor.py`):* `IMPLEMENTED` (Read-only static extraction of PE headers, sections, byte entropy, SHA-256, and MD5 hashes).
  - *Device Scanner (`device_scanner.py`):* `IMPLEMENTED` (Completed in Day 8: safe recursive crawler, junction/reparse-point loop safety, safe metadata, streaming chunked SHA-256 fingerprinting with race detection, cancellation, structured `DeviceScanResult`).
  - *Incremental Scan State (`incremental_state.py`):* `IMPLEMENTED` (Completed in Day 8: change classification for `NEW`, `UNCHANGED`, `CHANGED`, `REMOVED`, version invalidation tags, SQLite persistence).
  - *File Watcher (`file_watcher.py`):* `IMPLEMENTED` (Completed in Day 10: `FilesystemEventSource` watchdog bridge, thread-safe lifecycle, observer management, non-blocking callback bridge).
  - *Clipboard Scanner (`clipboard_scanner.py`):* `PROTOTYPE / NOT YET MILESTONE-COMPLETE` (URL clipboard monitor prototype).
- **Role in Target Architecture:** Event and input providers. Scanners do NOT implement independent detection or risk logic; they normalize input and delegate to the Analysis Orchestrator.
- **Dependencies:** `config`, `pefile`, `hashlib`, `urllib.parse`, `re`, `watchdog`.
- **Allowed Operations:** Read files in binary mode; compute mathematical hashes; extract structural metadata; observe filesystem change events.
- **Forbidden Operations:** Execute inspected binaries; alter user files; follow infinite junction loops; capture keystrokes.

---

### 2.3 Detection Engine (`detection_engine/`)
- **Status:** `IMPLEMENTED` (Foundation established in Days 5–7)
  - *Threat Detector (`threat_detector.py`):* `IMPLEMENTED` (Central coordinator tying together feature extraction, TI lookups, ML inference, and rule evaluation).
  - *Model Manager (`model_manager.py`):* `IMPLEMENTED` (Validates feature metadata schemas and manages ML inference).
  - *Rule Engine (`rule_engine.py`):* `IMPLEMENTED` (Deterministic heuristic rules for PE characteristics, URLs, and social engineering language).
  - *Risk Engine / Decision Engine (`risk_engine.py`):* `IMPLEMENTED` (Multi-criteria evidence fusion, confidence scoring, explainability).
- **Inputs:** Extracted feature vectors, target hashes/URLs, metadata dictionaries, threat intelligence evidence.
- **Outputs:** Structured `DetectionResult` objects containing raw scores, normalized risk scores (0–100), severity levels (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), confidence ratings, and itemized evidence breakdowns.
- **Dependencies:** `config`, `models/`, `scikit-learn`, `numpy`.
- **Allowed Operations:** Load serialized models; compute probabilities; evaluate boolean rules; normalize weights.
- **Forbidden Operations:** Modify inspected files; alter model weights at runtime; make direct network connections outside authorized TI clients.

---

### 2.4 Threat Intelligence (`threat_intelligence/`)
- **Status:** `PARTIALLY IMPLEMENTED`
  - *Threat Lookup (`threat_lookup.py`):* `IMPLEMENTED` (Local SQLite query wrapper for offline indicator matching).
  - *API Clients (`api_clients.py`):* `PROTOTYPE / NOT YET MILESTONE-COMPLETE` (VirusTotal v3 client prototype; rate-limiting and normalized abstraction scheduled for Day 11).
  - *Sync Manager (`sync_manager.py`):* `PROTOTYPE / NOT YET MILESTONE-COMPLETE` (Client sync prototype for central API; federated sharing scheduled for Day 12).
- **Role in Target Architecture:** Shared intelligence infrastructure providing verified indicators to the Analysis Orchestrator.
- **Dependencies:** `config`, `reports/threat_database.py`, `requests`.
- **Allowed Operations:** Query local SQLite database; issue read-only HTTP GET requests to authorized threat APIs.
- **Forbidden Operations:** Upload complete user files to external APIs; exfiltrate personal telemetry.

---

### 2.5 Relational Persistence & Reporting (`reports/`)
- **Status:** `IMPLEMENTED`
  - *Threat Database (`threat_database.py`):* `IMPLEMENTED` (SQLite database schema with tables: `threats`, `indicators`, `scans`, `detections`, `scan_items`, `file_scan_states`).
  - *Scan Database (`scan_database.py`):* `IMPLEMENTED` (Query interfaces for scan history and telemetry).
  - *Report Generator (`report_generator.py`):* `IMPLEMENTED` (Exports scan results to JSON, CSV, and Markdown).
- **Dependencies:** `config`, `sqlite3`, `json`, `csv`, `pathlib`.
- **Allowed Operations:** Read and write local SQLite database file in `data/`; export sanitized audit reports.
- **Forbidden Operations:** Store plaintext user credentials or personal file contents; modify system registry.

---

### 2.6 Windows Protection Service (`service/`)
- **Status:** `IMPLEMENTED` (Foundation completed in Day 9, Event-Driven File Protection completed in Day 10)
- **Purpose:** Lightweight Windows resident service foundation maintaining deterministic lifecycle (`start`, `stop`, `pause`, `resume`), worker thread coordination, bounded failure recovery, `SecurityEvent` canonical contract, bounded FIFO queue (`SecurityEventQueue`) with peak tracking and drop backpressure, `EventDispatcher` subscription routing, decoupled `AnalysisOrchestrationBoundary` handoff, Windows SCM host bridge (`WindowsServiceHost`), filesystem path normalization (`FilesystemEventNormalizer`), temporary/directory event filtering (`FileEventFilter`), rapid-write debouncing and stability checks (`FileEventDebouncer`), and incremental state file analysis pipeline (`FileProtectionPipeline`).
- **Inputs:** Windows filesystem events via `FilesystemEventSource`, manual scan tasks, and client security events.
- **Outputs:** Debounced, normalized security events dispatched across the analysis boundary; `ServiceHealth` operational telemetry; structured `EventProcessingResult` records.
- **Dependencies:** `config`, `service.lifecycle`, `service.state`, `service.workers`, `service.events`, `service.dispatcher`, `service.health`, `service.windows_host`, `service.file_normalizer`, `service.file_filter`, `service.debouncer`, `service.file_pipeline`, `scanners.incremental_state`, `scanners.file_scanner`.
- **Allowed Operations:** Thread-safe state transitions; queueing events; managing worker threads; non-blocking SCM control dispatch; read-only file event ingestion; incremental state verification; delegating analysis to `ThreatDetector`.
- **Forbidden Operations:** Execute inspected binaries; delete or quarantine user files; tamper with OS security controls; create stealth persistence / registry run keys.

---

### 2.7 User Presentations & Interface Subsystems
- **Notifications (`notifications/`):** `PROTOTYPE / NOT YET MILESTONE-COMPLETE` (Console alerts operational; native Windows desktop toast notifications scheduled for Day 13).
- **Dashboard (`dashboard/`):** `PROTOTYPE / NOT YET MILESTONE-COMPLETE` (Streamlit command center prototype; full telemetry views and scan controls scheduled for Day 13).
- **AI Security Assistant (`assistant/`):** `PROTOTYPE / NOT YET MILESTONE-COMPLETE` (Offline SQLite explainer prototype; safe conversational interface scheduled for Day 14).
- **Central Threat Sharing API (`backend/`):** `PROTOTYPE / NOT YET MILESTONE-COMPLETE` (FastAPI REST service prototype; client synchronization scheduled for Day 12).
