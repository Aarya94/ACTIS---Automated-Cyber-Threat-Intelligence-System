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

### Implemented Baseline Foundation (Days 1–16: Milestone 1 Release Candidate)
- **Configuration Management (`config/`):** Strongly-typed `AppConfig`, environment loader, path resolver, constraint validation (11 passing tests).
- **Enterprise Logging (`config/config.py`):** Rotating file logs, structured formatters, and automated `SecretMaskingFilter` redacting API keys, bearer tokens, and credentials from console and file logs.
- **Relational Threat Database & Scan History (`reports/`):** SQLite schema with WAL mode (`threats`, `indicators`, `scans`, `detections`, `scan_items`, `file_scan_states`, `threat_sync_runs`, `threat_feed_status`), indexed queries, JSON/CSV/Markdown report generation.
- **Phishing Machine Learning Foundation (`models/`, `detection_engine/`):** 19-feature morphological Random Forest classifier with formal metadata contract validation.
- **Static Windows PE Binary Analysis (`scanners/file_feature_extractor.py`):** Read-only PE header and section parsing (`pefile`), Shannon byte entropy, 64 KB chunked SHA-256 and MD5 hashing, hardened against malformed DOS/PE headers, corrupted sections, and oversized binaries without memory exhaustion.
- **URL Analysis Hardening (`scanners/url_scanner.py`):** RFC scheme validation, canonical normalization, default port stripping, backslash path rejection, 19-feature vector extraction, session caching.
- **Message URL Analysis (`scanners/text_analyzer.py`):** Boundary-aware link extraction, canonical deduplication, social engineering heuristics, ReDoS-safe linear time evaluation, and strict delegation to canonical URL analysis.
- **Detection Decision & Risk Engine (`detection_engine/`):** Multi-criteria evidence fusion, dynamic weight normalization, deterministic heuristic rules, confidence calculation, circular-import-safe module boundaries, and explainability trees.
- **Device Scanner (`scanners/device_scanner.py`):** User-authorized directory and drive traversal, junction/reparse-point loop safety, safe file metadata extraction, streaming chunked SHA-256 fingerprinting with race detection, cooperative cancellation, structured `DeviceScanResult`.
- **Incremental Scan State (`scanners/incremental_state.py`):** Deterministic change classification (`NEW_FILE`, `UNCHANGED_FILE`, `CHANGED_FILE`, `REMOVED_FILE`, `UNAVAILABLE_FILE`), analytical/model version invalidation tags, SQLite scan state persistence, and skipping deep analysis for verified unchanged files.
- **Windows Protection Service Foundation (`service/`):** Lightweight resident background service managing endpoint state, deterministic lifecycle (`start`, `stop`, `pause`, `resume`), state transitions (`STOPPED`, `STARTING`, `RUNNING`, `PAUSED`, `DEGRADED`, `FAILED`), worker pool coordination, bounded recovery, canonical `SecurityEvent` schema, bounded intake queue (`SecurityEventQueue`) with burst/saturation drop telemetry, `EventDispatcher` routing, and decoupled `AnalysisOrchestrationBoundary` handoff.
- **Event-Driven File Protection (`scanners/file_watcher.py`, `service/file_pipeline.py`):** Real-time Windows filesystem event monitoring (`watchdog` bridge `FilesystemEventSource`), canonical path normalization (`FilesystemEventNormalizer`), temporary/editor file filtering (`FileEventFilter`), sliding-window debouncing (`FileEventDebouncer`), bounded queue backpressure (`SecurityEventQueue`), incremental scan state integration (`FileProtectionPipeline`), pre/post-inspection race condition hardening, and direct delegation to the existing `ThreatDetector` static analysis pipeline.
- **Online Threat Intelligence Integration (Day 11, `threat_intelligence/`):** Extensible `BaseThreatClient` abstraction, client adapters for VirusTotal v3, URLhaus API v1, and AbuseIPDB API v2 with sliding-window rate limiting and bounded HTTP timeouts. Strict indicator validation (`indicator_validator.py`) with RFC 1918 private/loopback/link-local/unspecified IP shielding, thread-safe in-memory TTL caching (`threat_cache.py`), and unified 9-stage local-first threat lookup (`threat_lookup.py`) with 8 explicit outcome states and multi-provider conflict resolution.
- **Scheduled Feed Synchronization & Dashboard Integration (Day 12, `threat_intelligence/sync/`, `dashboard/`):** Decoupled `ThreatSyncService` importing upstream feeds into local SQLite, feed adapters for URLhaus and AbuseIPDB, explicit `UNSUPPORTED_OPERATION` modeling for VirusTotal bulk feeds, non-blocking lock preventing overlapping runs, thread-safe `ThreatSyncScheduler` lifecycle, parameterized idempotent batch upserts (`upsert_feed_records`), and live feed controls on the Streamlit command center dashboard.
- **Central Threat Intelligence Service & Secure Synchronization (Day 13, `backend/`, `threat_intelligence/`):** Hardened FastAPI central intelligence REST API (`/api/v1`), constant-time API key verification (`hmac.compare_digest`), role-based authorization (`read`, `contribute`, `admin`), in-memory sliding-window rate limiting (60–300 RPM default), strict RFC 1918 IP shielding, candidate contribution anti-poisoning policy (forces `CANDIDATE` / `PENDING`), administrative review endpoint (`APPROVE`, `REJECT`), client `CentralACTISFeedAdapter`, and total offline scanning isolation.
- **Grounded AI Security Assistant & Explainable Threat Analysis (Day 14, `assistant/`, `dashboard/`):** Read-only security assistant providing explainable detection breakdowns, multi-factor scoring provenance (Intel 35%, ML 30%, Rules 20%), candidate indicator anti-poisoning caveats, deterministic target disambiguation, secret masking (`mask_sensitive_strings`), and safe defensive incident response recommendations without arbitrary shell or file modifications. Integrated with the Streamlit dashboard via session conversation history and native Markdown.
- **Security Hardening & Adversarial Robustness (Day 15, `tests/`):** Comprehensive boundary verification against malformed PE binaries, oversized files (>50MB), malformed/adversarial URLs, non-string/None inputs, regex resource safety, private IP and local directory leakage prevention across all provider lookups, prompt injection rejection, queue saturation burst testing (500–1,000 events), and SQLite multi-threaded transaction concurrency.
- **Final Integration, Demonstration & Release Verification (Day 16, `scripts/`, `tests/`):** Comprehensive end-to-end integration across all 15 core subsystems, reproducible safe offline demonstration workflow (`scripts/demo_actis.py`) covering 7 representative flows (Demos A–G), and 13 release acceptance tests (`tests/test_release_integration.py`).
- **Windows Service Integration & Native Windows Notifications (Day 17, `service/`, `scripts/`, `notifications/`):** Production Windows Service Control Manager (SCM) deployment tooling (`install_windows_service.ps1`, `status_windows_service.ps1`, `uninstall_windows_service.ps1`), standalone host lifecycle routing via CLI (`main.py --service`, `main.py --service-status`), graceful worker cleanup on failure, and native Windows desktop toast notifications (`notifications/windows_toast.py`) with non-blocking async dispatch (<50ms), automated secret/credential redaction, rate limiting flood protection, and silent test mode.
- **Enhanced PE Static Analysis & Heuristics (Day 18, `scanners/`, `detection_engine/`):** Standard Mandiant import hashing (`imphash`), threat family categorization across 10 dangerous API categories, section entropy dispersion analysis, and 7 new heuristic detection rules targeting process hollowing, token impersonation, dynamic API resolving, and anti-analysis.
- **Non-PE File Fallback Analysis Subsystem (Day 19, `scanners/`, `detection_engine/`):** Purely read-only static analysis for non-PE files including bounded streaming cryptographic hashing (SHA-256, MD5) with 64KB buffer chunks, safe archive metadata inspection (ZIP, TAR, GZIP, and graceful 7z handling) without disk extraction or zip bombs (50MB / 5,000 entries / 100:1 ratio limits), static script heuristics (PowerShell, Batch, VBScript, Python) with comment filtering and snippet masking, and 12 dedicated non-PE detection rules.
- **Week 5 Integration Audit & Pipeline Hardening (Day 20, `service/`, `scanners/`, `tests/`):** Comprehensive integration audit and hardening connecting PE analysis and non-PE fallback routines with resident Windows file protection pipeline and event debouncer. Added 0-byte file write stabilization, directory target rejection, rename previous-path state pruning, content-based script sniffing for disguised extensions, 24-file mixed-directory synthetic benchmark (100% success, 38.57ms avg latency, 6.4 MB peak memory), and 17 regression/edge-case tests.
- **Threat Caching & High-Performance Lookup Subsystem (Day 21, `threat_intelligence/`, `detection_engine/`, `reports/`, `scripts/`):** Thread-safe bounded in-memory caching (`LRUTTLCache`) with LRU capacity eviction and TTL expiration, hardened `ThreatIntelligenceCache` with indicator invalidation and injectable clock, scan cache integration in `ThreatDetector` with cache invalidation hooks in `register_indicator()` and `upsert_feed_records()`, and comparative benchmark (Cold: 37.17ms/file, 26.9 files/s; Warm: 10.57ms/file, 94.6 files/s, 3.52x speedup; Sustained loop: 106.9 files/s, 88.57% hit ratio).
- **Explainability Tree & Risk Weight Validation (Day 22, `detection_engine/`):** Bounded hierarchical explainability tree (`ExplainabilityTree`, `ExplainabilityNode`) detailing exact decision rationales, mathematical evidence-to-score calculation traceability (`ScoreTraceability`), sensitive credential/token masking, strict `RiskScoringWeights` validation (NaN, infinity, non-numeric, range constraints), dynamic weight normalization, sub-millisecond tree generation (<5ms for 50 signals), and 23 automated tests.
- **Evidence Fusion Audit & Edge-Case Hardening (Day 23, `detection_engine/`, `tests/`):** Systematic test-backed audit of the full evidence-fusion pipeline. Added deterministic duplicate signal deduplication keyed by `(source, signal_id)` in `DetectionEvidence` preserving highest-contribution signal, strict whitelist mitigation override precedence clamping scores to 0.0 with full before/after traceability, bounded explainability tree node count safety limits (<= 100), and 35 new comprehensive edge-case audit tests.
- **Advanced URL De-obfuscation & Safe Redirect Analysis (Day 24, `scanners/`, `detection_engine/`, `tests/`):** Standards-aware URL normalization and de-obfuscation with `URLAnalysisResult` contract preserving original and normalized URLs, zero-width character stripping/tracking, IDN/Punycode translation with mixed-script homoglyphs, numeric IP decoders (dword decimal, octal, hex), userinfo deception handling, bounded double percent-encoding and encoded delimiter analysis. Safe bounded redirect inspector (`RedirectInspector`) with strict SSRF defense (`SSRFValidator`) inspecting loopback, private IPv4/IPv6, link-local, cloud metadata, CGNAT, broadcast, and internal domains with full DNS resolution pre-validation. 8 dedicated URL heuristic rules, explainability tree nodes, and 58 unit/integration tests.
- **Safe MIME Parsing & Message Threat Analysis (Day 25, `scanners/`, `detection_engine/`, `tests/`):** Standards-compliant, bounded MIME message parsing (`SafeMIMEParser`) leveraging standard library `email.parser.BytesParser` with strict resource limits (10MB raw, 64KB headers, 50 parts, 10 nesting levels, 1MB decoded text, 100 URLs, 5s deadline), path traversal sanitization on attachment filenames, and safe fallback for plain text / SMS. Streaming HTML link extraction (`SafeHTMLURLParser`) with zero script execution, link display-text mismatch detection (`is_domain_mismatch`), metadata-only attachment policy (zero attachment execution), 9 deterministic message-level heuristic rules (`RULE_MSG_*`), explainability tree node integration, and 45 new deterministic tests.
- **Phishing & Message Analysis Verification Benchmark (Day 26, `benchmarks/`, `reports/benchmarks/`, `tests/fixtures/`, `tests/`):** Deterministic, reproducible offline verification benchmark framework evaluating the canonical ACTIS detection pipeline against a versioned (`v1.0.0`) synthetic corpus (140 samples across 9 balanced attack and legitimate scenarios). Comprehensive metrics engine computing confusion matrix, precision (0.8155), recall (0.9655), F1 (0.8842), balanced accuracy (0.7965), specificity (0.6275), accuracy (0.8406), FPR (0.3725), FNR (0.0345), coverage (98.6%), per-rule telemetry, embedded URL tracking, and monotonic latency profiling. Generates privacy-preserving JSON and Markdown verification reports with explicit baseline preservation. Fixed explainability tree node limitation handling (`NodeStatus.LIMITATION`), eliminating edge-case crashes.
- **Automated Test Infrastructure (`tests/`):** 715 unit, integration, adversarial security, service lifecycle, notification, PE analysis, non-PE fallback, pipeline hardening, deep TI caching, explainability tree, evidence fusion audit, URL de-obfuscation/redirect, safe MIME/message analysis, and benchmark framework tests passing with 100% success rate (+23 new tests for Day 26).

*(Note: ACTIS is a defensive cybersecurity platform and release candidate prototype, not a commercial antivirus or EDR product. Resident Windows Service integration is supported via standard Windows SCM facilities; real SCM registration requires administrative privileges and is fully removable via documented scripts.)*

---

## 📦 Project Structure

```text
ACTIS/
├── assets/                   # Official branding assets (logos, icons, favicons)
├── config/                   # Type-safe configuration, environment loader, logging
├── data/                     # Local SQLite databases, training datasets
├── models/                   # Serialized ML model artifacts (*.pkl) and JSON metadata
├── service/                  # Windows Protection Service & file protection pipeline (lifecycle, state, workers, queue, dispatcher, debouncer, windows_host)
├── scanners/                 # Event/input providers (URL, text, MIME parser, PE static analyzer, device scanner, file watcher)
├── detection_engine/         # Decision engine, risk engine, heuristic rule engine, explainability tree
├── threat_intelligence/      # Local indicator lookup, external API clients, sync manager, feed adapters
├── reports/                  # SQLite threat database schemas, query interfaces, reports
├── notifications/            # Alert formatting, user dispatch queue, and native Windows desktop toast notifications
├── dashboard/                # Streamlit web command center UI
├── assistant/                # Grounded AI security assistant & explainable analysis (Day 14)
├── backend/                  # Central FastAPI intelligence sharing service
├── scripts/                  # Service management scripts (install, status, uninstall), demo (`demo_actis.py`), doc generator
├── tests/                    # Automated unit, integration, adversarial, service, notification, and message suites
├── docs/                     # Architectural source of truth, roadmaps, and generated reports
│   ├── architecture/         # System design, module contracts, workflows, security rules
│   ├── roadmap/              # Authoritative daily execution roadmaps
│   └── generated/            # Empirical repository status, schema refs, test telemetry
└── main.py                   # Unified application CLI and launcher
```

---

## 🧪 Testing & Verification

ACTIS maintains comprehensive test coverage across all implemented modules.

### Run Automated Tests
```bash
pytest tests/ -v
```

**Current Verification Status:**
- **692 tests collected**
- **692 tests passed (100% success rate)**
- **0 failures / 0 errors / 4 warnings**

### Run Safe Offline System Demonstration
ACTIS includes a deterministic, safe, 100% offline demonstration script that exercises 7 representative security flows (benign URL, synthetic phishing URL, malformed PE static analysis, threat intel lifecycle, grounded AI assistant, multi-format reporting, incremental scan state) inside an isolated sandbox with zero mutation of user databases or files:

```bash
python scripts/demo_actis.py
```

---

## 🔒 Privacy & Operational Principles

1. **Indicator Sharing Only:** Only verified threat indicators (cryptographic hashes, malicious URLs, domains) are submitted to threat networks — user documents, private files, and personal data are never uploaded.
2. **Offline-First Functionality:** ACTIS operates with full analytical capability in completely offline or air-gapped environments using local machine learning models and SQLite threat databases. External API feeds serve as an optional enrichment layer.
3. **Transparent Explainability:** Every threat evaluation provides understandable, itemized reasoning detailing why a risk score was assigned and what defensive action is advised.
