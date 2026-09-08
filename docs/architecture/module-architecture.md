# ACTIS Module Architecture

This document defines the architectural responsibilities, input/output contracts, system dependencies, permitted actions, forbidden operations, and current realization status for every core package in ACTIS.

---

## Status Definitions

- **`IMPLEMENTED`**: Fully realized in the workspace with active source code and passing automated tests.
- **`PARTIALLY IMPLEMENTED`**: Core interfaces or basic routines exist, but advanced capabilities or complete subsystem integration remain pending.
- **`PLANNED`**: Fully specified in architecture, scheduled for later roadmap phases, but not yet authoritatively implemented.

---

## Module Specifications

### 1. `config/`
- **Status**: `IMPLEMENTED` (Completed in Week 1 Day 2)
- **Purpose**: Centralized, type-annotated configuration management, environment variable parsing, dynamic project path anchoring, runtime defaults, and constraint validation.
- **Inputs**: Environment variables (`os.environ`), `.env` configuration file, runtime overrides.
- **Outputs**: Strongly typed `AppConfig` instance and backward-compatible module constants.
- **Dependencies**: `pathlib`, `os`, `dotenv`, `logging`.
- **Allowed Operations**: Read local environment; resolve repository relative paths; validate parameters; instantiate loggers.
- **Forbidden Operations**: Write to production filesystems outside temporary logs/dirs; log raw secret keys; expose plain text tokens in `__repr__`.

---

### 2. `scanners/`
- **Status**: `PARTIALLY IMPLEMENTED`
  - *URL Scanner*: `IMPLEMENTED` (Extracts 19 morphological features, normalizes URLs).
  - *Text Analyzer*: `IMPLEMENTED` (Link extraction via regex, urgency/credential prompt scoring).
  - *File Scanner / PE Feature Extractor*: `IMPLEMENTED` (Read-only static extraction of PE headers, sections, entropy, and cryptographic hashes using `pefile` and `hashlib`).
  - *Device Scanner*: `IMPLEMENTED` (Recursive directory crawler with cancellation tokens and junction loop protection).
  - *File Watcher*: `IMPLEMENTED` (Directory monitoring using `watchdog` with debounce).
  - *Clipboard Scanner*: `IMPLEMENTED` (Polls clipboard for URLs).
  - *Subsystem Status*: Components exist as prototypes; full pipeline unification and integration tests scheduled for Month 2.
- **Inputs**: Raw URL strings, message text strings, file system paths, filesystem change events, clipboard contents.
- **Outputs**: Extracted morphological vectors, cryptographic hashes (SHA-256, MD5), byte entropy, PE metadata dictionaries.
- **Dependencies**: `config`, `pefile`, `watchdog`, `hashlib`, `urllib.parse`, `re`.
- **Allowed Operations**: Read files in binary mode; compute mathematical hashes; extract structural metadata; observe user-authorized folders.
- **Forbidden Operations**: Execute inspected binaries; write to user files; rename/delete user files; follow infinite directory junction loops; collect user keystrokes.

---

### 3. `detection_engine/`
- **Status**: `PARTIALLY IMPLEMENTED`
  - *Model Manager*: `IMPLEMENTED` (Enforces feature order and calls model inference).
  - *Rule Engine*: `IMPLEMENTED` (Deterministic heuristics for PE characteristics, URLs, and text).
  - *Risk Engine*: `IMPLEMENTED` (Multi-criteria dynamic evidence fusion with explainability).
  - *Threat Detector*: `IMPLEMENTED` (Orchestrator tying together ML, rules, and local cache).
  - *Subsystem Status*: Core engines exist; full multi-layered integration tests scheduled across Months 1–2.
- **Inputs**: Extracted feature vectors, target hashes/URLs, metadata dictionaries.
- **Outputs**: Structured detection objects containing raw scores, normalized risk scores (0–100), severity levels (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), and evidence breakdown trees.
- **Dependencies**: `config`, `models/`, `scikit-learn`, `numpy`.
- **Allowed Operations**: Load serialized scikit-learn models; compute dot products/probabilities; evaluate boolean heuristic rules; normalize weights.
- **Forbidden Operations**: Modify input files; alter model weights at runtime; make arbitrary external network connections directly without going through threat intelligence clients.

---

### 4. `threat_intelligence/`
- **Status**: `PARTIALLY IMPLEMENTED`
  - *Threat Lookup*: `IMPLEMENTED` (Local SQLite query wrapper).
  - *API Clients*: `IMPLEMENTED` (VirusTotal v3 client with offline fallback).
  - *Sync Manager*: `IMPLEMENTED` (Client sync client for central backend).
  - *Subsystem Status*: Full integration with AbuseIPDB, URLhaus, and standalone `indicator_manager.py` scheduled for Month 3.
- **Inputs**: Canonical indicators (URLs, domains, IP addresses, SHA-256/MD5 hashes).
- **Outputs**: Threat intelligence records, reputation scores, detection counts, and verification status (`CONFIRMED`, `SUSPICIOUS`, `CANDIDATE`, `REPORTED`, `FALSE_POSITIVE`).
- **Dependencies**: `config`, `reports/threat_database.py`, `urllib.request` / `requests`.
- **Allowed Operations**: Query local SQLite database; issue read-only HTTP GET requests to authorized threat APIs; cache query responses.
- **Forbidden Operations**: Upload user files or file contents to external APIs (only cryptographic hashes or public URLs may be queried); send personal telemetry.

---

### 5. `reports/`
- **Status**: `PARTIALLY IMPLEMENTED`
  - *Threat Database*: `IMPLEMENTED` (SQLite database schema with tables: `threats`, `indicators`, `scans`, `detections`, `scan_items`).
  - *Scan Database*: `IMPLEMENTED` (Query interfaces for scan history and telemetry).
  - *Report Generator*: `IMPLEMENTED` (Exports scan results to JSON, CSV, and Markdown).
  - *Subsystem Status*: Core schema and exporters exist; formal schema migration and deep integrity validation scheduled for Week 1 Day 4.
- **Inputs**: Scan results, detection records, threat intelligence entries, user-requested output format.
- **Outputs**: SQLite persistent records, formatted JSON documents, CSV tables, Markdown reports.
- **Dependencies**: `config`, `sqlite3`, `json`, `csv`, `pathlib`.
- **Allowed Operations**: Read and write local SQLite database file in `data/`; export sanitized threat reports.
- **Forbidden Operations**: Store plaintext user credentials or personal file contents; modify system registry.

---

### 6. `notifications/`
- **Status**: `PARTIALLY IMPLEMENTED`
  - *Notifier*: `IMPLEMENTED` (Formatting alerts, terminal badges, and logging queues).
  - *Subsystem Status*: Native Windows toast notifications and audio alerts scheduled for Month 4 (Week 14).
- **Inputs**: High-risk detection objects, system events.
- **Outputs**: Formatted console banners, desktop notification dispatches.
- **Dependencies**: `config`, `logging`.
- **Allowed Operations**: Format and log critical alert messages; emit desktop notifications.
- **Forbidden Operations**: Block operating system threads indefinitely; execute remediation scripts without user confirmation.

---

### 7. `dashboard/`
- **Status**: `PARTIALLY IMPLEMENTED`
  - *Streamlit App (`dashboard/app.py`)*: `IMPLEMENTED` (Interactive web dashboard with telemetry views, manual scanning inputs, threat lookup, and Plotly visualizations).
  - *Subsystem Status*: Prototype complete; full production polish, live background watcher stream, and security hardening scheduled for Month 4 (Week 13).
- **Inputs**: User interface interactions, database queries.
- **Outputs**: Real-time browser-based command center interface.
- **Dependencies**: `config`, `reports`, `scanners`, `streamlit`, `plotly`.
- **Allowed Operations**: Render read-only security dashboards; dispatch user-requested on-demand scans.
- **Forbidden Operations**: Expose arbitrary command shell; bypass user confirmation for scans.

---

### 8. `assistant/`
- **Status**: `PARTIALLY IMPLEMENTED`
  - *Security Assistant*: `IMPLEMENTED` (Offline natural language security explainer querying local SQLite threat records).
  - *Subsystem Status*: Grounded LLM integration, mitigation guidance, and conversational memory scheduled for Month 4 (Week 14).
- **Inputs**: Natural language user security questions, target threat records.
- **Outputs**: Grounded, plain-English explanations of detected threats, risk scores, and recommended actions.
- **Dependencies**: `config`, `reports/threat_database.py`.
- **Allowed Operations**: Query local detection records; explain cryptographic/PE heuristics in plain language.
- **Forbidden Operations**: Execute system commands or shell scripts; access unrestricted Windows API; modify files or user settings.

---

### 9. `backend/`
- **Status**: `PARTIALLY IMPLEMENTED`
  - *Central API (`backend/api.py`)*: `IMPLEMENTED` (FastAPI REST service with endpoints for health, indicator push, indicator pull, and client verification).
  - *Database (`backend/database.py`, `backend/models.py`)*: `IMPLEMENTED` (SQLite backend database with verification status checks).
  - *Subsystem Status*: Multi-client peer sync validation, rate limiting, and production deployment configuration scheduled for Month 3 (Week 12).
- **Inputs**: HTTP REST requests from authenticated ACTIS clients.
- **Outputs**: JSON payloads containing shared, verified indicators and sync tokens.
- **Dependencies**: `config`, `fastapi`, `uvicorn`, `sqlite3`.
- **Allowed Operations**: Authenticate client API keys; persist shared indicators; serve verified threat intelligence feeds.
- **Forbidden Operations**: Accept raw executable binary uploads; allow unauthorized administrative overrides.

---

### 10. `tests/`
- **Status**: `IMPLEMENTED` (35 automated tests active and passing across 8 test suites).
- **Purpose**: Verifies functional correctness, regression safety, interface schemas, and boundary constraints.
- **Inputs**: Synthetic test binaries, dummy URLs, test fixtures, temporary SQLite test databases.
- **Outputs**: Pytest assertion results, coverage metrics, error traces.
- **Dependencies**: `pytest`, `fastapi.testclient`.
- **Allowed Operations**: Execute unit tests against isolated test doubles and mock objects; verify return types and error paths.
- **Forbidden Operations**: Access real live malware files during test runs; perform network requests to live third-party APIs during automated test runs.
