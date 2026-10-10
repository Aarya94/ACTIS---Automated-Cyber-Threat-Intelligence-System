# ACTIS — Automated Cyber Threat Intelligence System

<p align="center">
  <img src="assets/branding/actis-logo-original.png" alt="ACTIS — Automated Cyber Threat Intelligence System logo" width="380" />
</p>

> **Development Status:** ACTIS is currently a development-stage endpoint cybersecurity and threat intelligence platform for Windows.

ACTIS operates under a strictly **read-only, non-destructive, privacy-first** architecture. Rather than operating as an isolated collection of ad-hoc scanners, ACTIS is evolving into a **Windows-oriented, event-driven cyber protection platform** combining lightweight resident event handling, centralized analysis orchestration, multi-layered threat intelligence, and explainable multi-criteria detection.

---

## 🛡 Security Principles & Scope

ACTIS operates under strict defensive boundaries:

- **What ACTIS DOES:**
  - Reads metadata, file headers, and calculates cryptographic hashes (SHA-256, MD5) strictly in read-only binary mode (`'rb'`).
  - Statically parses Windows Portable Executable (PE) headers, section tables, byte entropy, and imports without code execution.
  - Normalizes and sanitizes web URLs, extracting 19 morphological features.
  - Parses text messages and emails, strips boundary punctuation, canonically deduplicates links, and detects social engineering urgency cues.
  - Combines offline threat intelligence, machine learning probabilities, and deterministic heuristic rules into explainable 0–100 risk scores.
  - Categorizes threat indicators into formal lifecycle states (`CONFIRMED`, `SUSPICIOUS`, `CANDIDATE`, `REPORTED`, `FALSE_POSITIVE`).
- **What ACTIS DOES NOT DO:**
  - **Never executes suspicious files or binaries.**
  - **Never deletes, modifies, or renames user files automatically.**
  - **Never encrypts user data.**
  - **Never uploads user files or documents to cloud servers or third-party APIs** (only canonical hashes, domains, or URLs are queried).
  - **Never installs keyloggers, screen recording hooks, or covert surveillance tools.**
  - **Never grants unrestricted operating system shell access to the AI assistant.**
  - **Never disables Windows Defender or interferes with operating system security controls.**

---

## 🏛 Target System Architecture

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

## 📊 Current Implementation vs. Roadmap

### Implemented Baseline Foundation (Days 1–14)
- **Configuration Management (`config/`):** Strongly-typed `AppConfig`, environment loader, path resolver, constraint validation (11 passing tests).
- **Enterprise Logging (`config/logger.py`):** Rotating file logs, structured JSON formatters, credential sanitization.
- **Relational Threat Database & Scan History (`reports/`):** SQLite schema with WAL mode (`threats`, `indicators`, `scans`, `detections`, `scan_items`, `file_scan_states`, `threat_sync_runs`, `threat_feed_status`), indexed queries, JSON/CSV/Markdown report generation.
- **Phishing Machine Learning Foundation (`models/`, `detection_engine/`):** 19-feature morphological Random Forest classifier with formal metadata contract validation.
- **Static Windows PE Binary Analysis (`scanners/file_feature_extractor.py`):** Read-only PE header and section parsing (`pefile`), Shannon byte entropy, 64 KB chunked SHA-256 and MD5 hashing (21 passing tests).
- **URL Analysis Hardening (`scanners/url_scanner.py`):** RFC scheme validation, canonical normalization, default port stripping, 19-feature vector extraction, session caching.
- **Message URL Analysis (`scanners/text_analyzer.py`):** Boundary-aware link extraction, canonical deduplication, social engineering heuristics, and strict delegation to canonical URL analysis.
- **Detection Decision & Risk Engine (`detection_engine/`):** Multi-criteria evidence fusion, dynamic weight normalization, deterministic heuristic rules, confidence calculation, and explainability trees.
- **Device Scanner (`scanners/device_scanner.py`):** User-authorized directory and drive traversal, junction/reparse-point loop safety, safe file metadata extraction, streaming chunked SHA-256 fingerprinting with race detection, cooperative cancellation, structured `DeviceScanResult`.
- **Incremental Scan State (`scanners/incremental_state.py`):** Deterministic change classification (`NEW_FILE`, `UNCHANGED_FILE`, `CHANGED_FILE`, `REMOVED_FILE`, `UNAVAILABLE_FILE`), analytical/model version invalidation tags, SQLite scan state persistence, and skipping deep analysis for verified unchanged files.
- **Windows Protection Service Foundation (`service/`):** Lightweight resident background service managing endpoint state, deterministic lifecycle (`start`, `stop`, `pause`, `resume`), state transitions (`STOPPED`, `STARTING`, `RUNNING`, `PAUSED`, `DEGRADED`, `FAILED`), worker pool coordination, bounded recovery, canonical `SecurityEvent` schema, bounded intake queue, `EventDispatcher` routing, and decoupled `AnalysisOrchestrationBoundary` handoff.
- **Event-Driven File Protection (`scanners/file_watcher.py`, `service/file_pipeline.py`):** Real-time Windows filesystem event monitoring (`watchdog` bridge `FilesystemEventSource`), canonical path normalization (`FilesystemEventNormalizer`), temporary/editor file filtering (`FileEventFilter`), sliding-window debouncing (`FileEventDebouncer`), bounded queue backpressure (`SecurityEventQueue`), incremental scan state integration (`FileProtectionPipeline`), pre/post-inspection race condition hardening, and direct delegation to the existing `ThreatDetector` static analysis pipeline.
- **Online Threat Intelligence Integration (Day 11, `threat_intelligence/`):** Extensible `BaseThreatClient` abstraction, client adapters for VirusTotal v3, URLhaus API v1, and AbuseIPDB API v2 with sliding-window rate limiting and bounded HTTP timeouts. Strict indicator validation (`indicator_validator.py`) with RFC 1918 private/loopback IP shielding, thread-safe in-memory TTL caching (`threat_cache.py`), and unified 9-stage local-first threat lookup (`threat_lookup.py`) with 8 explicit outcome states and multi-provider conflict resolution.
- **Scheduled Feed Synchronization & Dashboard Integration (Day 12, `threat_intelligence/sync/`, `dashboard/`):** Decoupled `ThreatSyncService` importing upstream feeds into local SQLite, feed adapters for URLhaus and AbuseIPDB, explicit `UNSUPPORTED_OPERATION` modeling for VirusTotal bulk feeds, non-blocking lock preventing overlapping runs, thread-safe `ThreatSyncScheduler` lifecycle, parameterized idempotent batch upserts (`upsert_feed_records`), and live feed controls on the Streamlit command center dashboard.
- **Central Threat Intelligence Service & Secure Synchronization (Day 13, `backend/`, `threat_intelligence/`):** Hardened FastAPI central intelligence REST API (`/api/v1`), constant-time API key verification (`hmac.compare_digest`), role-based authorization (`read`, `contribute`, `admin`), in-memory sliding-window rate limiting (60–300 RPM default), strict RFC 1918 IP shielding, candidate contribution anti-poisoning policy (forces `CANDIDATE` / `PENDING`), administrative review endpoint (`APPROVE`, `REJECT`), client `CentralACTISFeedAdapter`, and total offline scanning isolation.
- **Grounded AI Security Assistant & Explainable Threat Analysis (Day 14, `assistant/`, `dashboard/`):** Read-only security assistant providing explainable detection breakdowns, multi-factor scoring provenance (Intel 35%, ML 30%, Rules 20%), candidate indicator anti-poisoning caveats, deterministic target disambiguation, secret masking (`mask_sensitive_strings`), and safe defensive incident response recommendations without arbitrary shell or file modifications. Integrated with the Streamlit dashboard via session conversation history and native Markdown.
- **Automated Test Infrastructure (`tests/`):** 360 unit, integration, and architecture validation tests passing with 100% success rate (+27 tests for Day 14 security assistant).

### Planned Subsystems in Target Architecture (Days 15–16)
- **Security Hardening & Broad Testing (Day 15):** Adversarial sample evaluation, false-positive auditing, and malformed input stress testing.
- **Final Integration & Release (Day 16):** Milestone packaging, documentation finalization, and demonstration scripts.

*(Note: Prototype files for some future modules exist historically in the repository; they are being systematically hardened and integrated per the post-Day-7 roadmap and are not yet production-ready. ACTIS is a development-stage prototype, not a full commercial antivirus or EDR system.)*

---

## 📦 Project Structure

```text
ACTIS/
├── assets/                   # Official branding assets (logos, icons, favicons)
├── config/                   # Type-safe configuration, environment loader, logging
├── data/                     # Local SQLite databases, training datasets
├── models/                   # Serialized ML model artifacts (*.pkl) and JSON metadata
├── service/                  # Windows Protection Service & file protection pipeline (lifecycle, state, workers, queue, dispatcher, debouncer)
├── scanners/                 # Event/input providers (URL, text, PE static analyzer, device scanner, file watcher)
├── detection_engine/         # Decision engine, risk engine, heuristic rule engine
├── threat_intelligence/      # Local indicator lookup, external API clients, sync manager, feed adapters
├── reports/                  # SQLite threat database schemas, query interfaces, reports
├── notifications/            # Alert formatting and user dispatch queue
├── dashboard/                # Streamlit web command center UI
├── assistant/                # Grounded AI security assistant & explainable analysis (Day 14)
├── backend/                  # Central FastAPI intelligence sharing service
├── tests/                    # Automated unit, integration, and validation suites
├── docs/                     # Architectural source of truth, roadmaps, and generated reports
│   ├── architecture/         # System design, module contracts, workflows, security rules
│   ├── roadmap/              # Authoritative daily execution roadmaps
│   └── generated/            # Empirical repository status, schema refs, test telemetry
└── main.py                   # Unified application CLI and launcher
```

---

## 🧪 Testing & Verification

ACTIS maintains comprehensive test coverage across all implemented modules. To execute the test suite:

```bash
pytest tests/ -v
```

**Current Verification Status:**
- **360 tests collected**
- **360 tests passed (100% success rate)**
- **0 failures / 0 errors / 4 warnings**

---

## 🔒 Privacy & Operational Principles

1. **Indicator Sharing Only:** Only verified threat indicators (cryptographic hashes, malicious URLs, domains) are submitted to threat networks — user documents, private files, and personal data are never uploaded.
2. **Offline-First Functionality:** ACTIS operates with full analytical capability in completely offline or air-gapped environments using local machine learning models and SQLite threat databases. External API feeds serve as an optional enrichment layer.
3. **Transparent Explainability:** Every threat evaluation provides understandable, itemized reasoning detailing why a risk score was assigned and what defensive action is advised.
