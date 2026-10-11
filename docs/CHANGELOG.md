# ACTIS Changelog

All notable changes to the ACTIS (Automated Cyber Threat Intelligence System) project are documented in this file in accordance with the ACTIS Daily Micro-Commit & Documentation Protocol.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [v0.1.0] — Foundation (Release Candidate 1)

Milestone Scope: Complete core defensive architecture, configuration, logging, database schemas, static PE analysis, URL/message analysis, device scanning, resident Windows service foundation, file watcher pipeline, threat intel integration, scheduled sync, central TI API, grounded AI assistant, security hardening, and release demonstration.

### 2026-10-11 — Day 16: Final Integration, Demonstration & Release Verification

Conducted comprehensive system integration, release acceptance testing, and safe demonstration workflow verification across all 15 core subsystems of the ACTIS platform. Validated that all subsystems interface safely, deterministically, and in full alignment with documented defensive contracts. Implemented and verified:
1. **System Integration Audit:** Completed and verified integration matrix across all 15 subsystem boundaries: scanners -> orchestrator -> decision engine -> risk engine -> threat intel -> sync service -> central TI backend -> reporting -> grounded AI assistant -> dashboard.
2. **Safe End-to-End System Demonstration Workflow (`scripts/demo_actis.py`):** Implemented an automated, 100% offline demonstration runner exercising 7 representative security scenarios inside an isolated sandbox with zero mutation of user databases or filesystem assets:
   - *DEMO A (Benign URL Inspection):* Real lexical feature extraction (19 features), normalization, Random Forest inference, and LOW/MEDIUM risk classification.
   - *DEMO B (Synthetic Phishing URL Detection):* Lexical heuristic rules, brand keyword lure detection, and HIGH severity classification with itemized explanations.
   - *DEMO C (Safe Static Malformed PE Inspection):* Non-executing static inspection of corrupt PE headers with graceful error handling and immediate artifact cleanup.
   - *DEMO D (Threat Intelligence Provenance & Anti-Poisoning):* Differentiating verified `CONFIRMED` intelligence from client `CANDIDATE` submissions and `UNKNOWN` indicators, avoiding the negative-evidence trap.
   - *DEMO E (Grounded AI Security Assistant):* Truthful evidence-backed explanations of recorded detections, absence-of-evidence safety warnings, prompt injection resistance, and automated credential masking.
   - *DEMO F (Structured Security Audit Reporting):* Validated generation and schema compliance of multi-format reports (JSON, CSV, Markdown) in an isolated export directory.
   - *DEMO G (Incremental Scan State Optimization):* Demonstrating change classification (`NEW_FILE` vs `UNCHANGED_FILE`) and deep scan suppression for unchanged binaries.
3. **Release Acceptance Test Suite (`tests/test_release_integration.py`):** Added 13 focused end-to-end integration tests verifying core analysis entry points, structured result contracts, missing intelligence negative-evidence trap protection, candidate indicator anti-poisoning lifecycle, external provider timeout outcome states, local analysis resilience during central backend outages, sensitive path and private IP shielding, grounded AI assistant explanations, safe malformed binary handling without execution, isolated report generation and cleanup, and demo script execution.
4. **URL Parser Robustness Hardening (`scanners/url_scanner.py`):** Hardened `validate_url` to explicitly reject illegal backslashes / filesystem path separators, validate port integers during initial parsing, and guard `normalize_url` against `ValueError` when processing unusual host:port inputs.
5. **Configuration and Startup Verification:** Verified environment loading, path resolution, database schema idempotency, and offline resilience when optional services (external TI providers, central REST server) are unavailable.
6. **Release Readiness Audit:** Completed 6-dimension evaluation (Correctness, Security, Reliability, Reproducibility, Documentation, Hygiene) with zero critical blockers, establishing the ACTIS Milestone Month 1 Release Candidate (`v0.1.0-rc1`).

Expanded the automated test suite from 417 to 430 passing tests (+13 tests in `tests/test_release_integration.py`), maintaining 100% test pass rate with zero failures.

---

### 2026-10-11 — Day 15: Security Hardening, Adversarial Robustness & Broad Threat Coverage Testing

Audited, hardened, and verified the ACTIS platform against malformed and adversarial inputs, false-positive biases, credential/privacy leaks, and resource exhaustion. Preserved existing read-only contracts, multi-criteria risk scoring policies, and offline autonomy. Implemented and verified:
1. **Malformed PE Binary Hardening:** Resilient static analysis of truncated DOS headers, invalid PE signatures, corrupted section offsets, unexpected section counts, non-ASCII section names, random binary noise, and empty files without unhandled exceptions or crashing.
2. **Oversized Binary Protection:** Enforced `MAX_FILE_SIZE_BYTES` (50 MB) boundary pre-checks before deep PE parsing, preventing excessive memory allocation.
3. **Adversarial URL Input Hardening:** Bounded URL parsing (max 4,096 chars), control character and null byte rejection (`[\x00-\x1f\x7f]`), unsupported scheme rejection, embedded credential and port preservation, and 19-feature vector morphological extraction resilience across malformed and non-string inputs.
4. **ReDoS Immunity & Message Resource Safety:** Linear-time regex evaluation across urgency, credential lure, and financial lure keyword patterns; untrusted message boundary processing completing in < 1.0s even under pathological repetition.
5. **Local File Path Privacy Isolation:** Verified that raw local file paths (e.g. `C:\Users\SensitiveUser\...`) and file binary contents are never transmitted upstream to external threat intelligence providers (VirusTotal, URLhaus, AbuseIPDB) or the Central ACTIS API; lookups strictly use minimum required indicators (cryptographic hashes, canonical domains, URLs).
6. **Automated Structured Logging Credential Redaction:** Implemented `SecretMaskingFilter` and `mask_sensitive_strings` in `config/config.py`, automatically masking API keys, bearer tokens, passwords, and authorization secrets (`****`) across all console and rotating file logs.
7. **Comprehensive Special-Purpose IP Shielding:** Extended `is_safe_public_ip` in `threat_intelligence/indicator_validator.py` to explicitly reject IPv4/IPv6 unspecified addresses (`0.0.0.0`, `::`) alongside RFC 1918 private IPv4, loopback (`127.0.0.1`, `::1`), link-local (`169.254.1.1`, `fe80::1`), unique-local (`fc00::1`), and multicast addresses across all external lookup and central sync paths.
8. **Circular Import Resolution:** Eliminated cyclic dependency between `detection_engine` and `threat_intelligence` packages by lazily resolving `threat_lookup` in `ThreatDetector`, enabling clean isolated package imports.
9. **AI Security Assistant Instruction Boundaries:** Verified prompt injection immunity, absence-of-evidence safety caveats ("missing intelligence does not mean safe"), candidate anti-poisoning caveats, and strict denial of command execution or database mutation requests.
10. **Security Event Queue Saturation Stress Testing:** Verified bounded queue capacity (10,000 items), drop telemetry tracking under producer bursts (500–1,000 events), producer/consumer thread safety, and cancellation handling.
11. **SQLite Multithreaded Concurrency Integrity:** Verified concurrent worker read/write transactions under timeout and foreign-key enforcement without locks or corruption.

Expanded the automated test suite from 360 to 417 passing tests (+57 comprehensive tests in `tests/test_adversarial_security.py` and `tests/test_privacy_safeguards.py`), achieving 100% test pass rate with zero failures.

---

### 2026-10-10 — Day 14: Grounded AI Security Assistant and Explainable Threat Analysis

Audited, hardened, and integrated the Day 14 AI Security Assistant (`assistant/security_assistant.py`, `dashboard/app.py`) providing evidence-grounded, explainable threat intelligence and detection analysis. Enforced strict read-only security boundaries: zero arbitrary OS shell execution, zero automated file deletion or quarantine, zero modification of Windows Defender or endpoint settings, and zero transmission of private files or user documents. Implemented robust natural language intent routing for:
1. **Recent Detections:** Real-time queries for recent detections and high-risk security events derived strictly from SQLite detection history (`scans.db`), with truthful distinction between an empty database and a verified clean workstation.
2. **Explain Flagged Target:** Multi-factor evidence breakdown explaining why a file, URL, domain, or message was flagged, displaying recorded timestamps, risk scores, severity classifications, and itemized weighted scoring contributions (Threat Intel 35%, ML Inference 30%, Heuristic Rules 20%). Added candidate indicator anti-poisoning caveats explicitly distinguishing `CONFIRMED` intelligence from unverified `CANDIDATE` reports.
3. **Indicator Lookup:** Querying local threat intelligence indicators (`threat_database.py`), accurately reflecting status (`CONFIRMED`, `SUSPICIOUS`, `CANDIDATE`, `REPORTED`, `FALSE_POSITIVE`) and confidence, with strict safety caveats stating that missing indicators are not automatically safe.
4. **Scan Statistics:** Deriving aggregate metrics from SQLite scan history (scans, detections, average risk scores, risk distribution).
5. **Detection Methodology:** Plain-English architectural explanations grounded in verified repository capabilities (ML Random Forest, static PE header parsing, RFC-compliant URL analysis, multi-criteria risk engine, background Windows service).
6. **Defensive Guidance:** Safe, non-destructive incident response recommendations (isolation, credential rotation, independent verification) without autonomous remediation.
7. **Disambiguation & Absence-of-Evidence Safety:** Exact and prefix target matching with candidate disambiguation when multiple targets match, avoiding silent arbitrary selection. Truthful missing target handling refusing to claim unrecorded targets are safe.
8. **Sensitive Data Minimization & Secret Masking:** Automated credential sanitization (`mask_sensitive_strings`) preventing leakage of API keys, tokens, or private paths.
9. **Provider Abstraction & Offline Isolation:** Pluggable `BaseAssistantProvider` interface with default `DeterministicAssistantProvider` and configurable `ExternalLLMProvider` fallback, ensuring complete local functionality when external AI providers are unavailable or disabled.
10. **Dashboard Integration:** Streamlit conversational interface (`dashboard/app.py`) featuring session history (`st.session_state["assistant_history"]`), native markdown formatting, clear history controls, and offline status indicator.

Expanded the automated test suite from 333 to 360 passing tests (+27 comprehensive tests in `tests/test_security_assistant.py`), achieving 100% test pass rate with zero failures.

#### Commits

| Commit | Type | Description | Files | Verification |
|--------|------|-------------|-------|--------------|
| `b22965f` | feat | Implement grounded security assistant with evidence breakdown and read-only boundaries | `assistant/security_assistant.py`, `assistant/__init__.py` | Passed (360 tests) |
| `5e6e55f` | feat | Integrate grounded security assistant with session history and native markdown | `dashboard/app.py` | Passed (360 tests) |
| `332e3cf` | test | Add comprehensive test suite for grounded security assistant and safety boundaries | `tests/test_security_assistant.py` | Passed (360 tests) |
| `56151d9` | docs | Document Day 14 grounded AI security assistant and update roadmap | `README.md`, `docs/quickstart.md`, `docs/architecture/project-structure.md`, `docs/roadmap/README.md`, `docs/roadmap/month-1.md`, `docs/CHANGELOG.md` | Passed (360 tests) |
| `331edd8` | docs | Reconcile architectural documentation and test baselines with Day 14 | `docs/architecture/*`, `docs/generated/*` | Passed (360 tests) |

---

### 2026-10-10 — Day 13: Central Threat Intelligence Service and Secure ACTIS Synchronization

Implemented a hardened, central Threat Intelligence REST API service (`backend/`) and secure client synchronization subsystem extending the unified ACTIS architecture. Defined versioned API contracts (`/api/v1/health`, `/api/v1/indicators`, `/api/v1/indicators/{indicator_type}/{indicator_value}`, `/api/v1/sync/pull`, `/api/v1/contributions`, and `/api/v1/admin/indicators/{indicator_id}/review`). Implemented constant-time API key verification (`hmac.compare_digest`), role-based authorization (`read`, `contribute`, `admin`), in-memory sliding-window rate limiting per client identity (default 60–300 RPM), and defensive payload bounds. Enforced strict RFC 1918 private/loopback/link-local IP shielding via `is_safe_public_ip` and indicator normalization on all retrieval, synchronization, and contribution pathways. Implemented an anti-poisoning candidate contribution policy: submitted indicators are strictly assigned `status="CANDIDATE"`, `review_status="PENDING"`, and `source_type="CLIENT_CONTRIBUTION"`, preventing unauthorized self-promotion to `CONFIRMED`. Added an administrative review endpoint for state transitions (`APPROVE`, `REJECT`). Implemented the client-side `CentralACTISFeedAdapter` extending `BaseFeedAdapter` in `threat_intelligence/sync/feed_adapter.py` and updated `SyncManager`, allowing ACTIS endpoint nodes to synchronize verified threat intelligence into their local SQLite database (`upsert_feed_records`) while maintaining total outage isolation: local file scanning and background Windows monitoring run 100% autonomously without external or central connectivity dependencies. Updated the Streamlit dashboard (`dashboard/app.py`) to reflect Central ACTIS Threat Network synchronization. Expanded the automated test suite from 303 to 333 passing tests (+30 comprehensive tests in `tests/test_central_ti_service.py`), achieving 100% pass rate with zero network dependencies (100% mocked transport).

#### Commits

| Commit | Type | Description | Files | Verification |
|--------|------|-------------|-------|--------------|
| `6f7995c` | feat | Implement central threat intelligence API and candidate contribution state machine | `backend/models.py`, `backend/database.py`, `backend/api.py`, `config/` | Passed (333 tests) |
| `9abcfda` | feat | Add central ACTIS feed adapter and client synchronization | `threat_intelligence/sync/feed_adapter.py`, `threat_intelligence/sync_manager.py`, `threat_intelligence/sync/sync_service.py`, `dashboard/app.py` | Passed (333 tests) |
| `d7fcfed` | test | Cover central threat intelligence API authentication and synchronization | `tests/test_central_ti_service.py` | Passed (333 tests) |
| `04691b3` | docs | Document central threat intelligence service architecture and contracts | `docs/architecture/unified-architecture.md`, `docs/CHANGELOG.md` | Passed (333 tests) |

---

### 2026-10-10 — Day 12: Scheduled Threat Intelligence Synchronization & Dashboard Integration

Implemented a robust, decoupled, and tested Threat Intelligence synchronization service importing supported upstream threat feeds into the local SQLite threat database, isolating provider failures, preserving provenance, and ensuring imported indicators are immediately queryable by the unified analysis pipeline. Built feed adapters implementing `BaseFeedAdapter` for **URLhaus** (recent payload URLs feed with automatic tagging and status parsing) and **AbuseIPDB** (configurable blacklist query with confidence thresholding and RFC 1918 shielding). Modeled the **VirusTotal** bulk feed limitation explicitly as `UNSUPPORTED_OPERATION` rather than creating synthetic feeds or misrepresenting enterprise endpoints. Built the core `ThreatSyncService` with in-memory deduplication, failure isolation (per-provider error trapping), structured outcome telemetry (`SyncRunResult`, `ProviderSyncResult`), and non-blocking concurrency locking preventing overlapping sync runs. Extended SQLite persistence (`reports/threat_database.py`) with `threat_sync_runs` and `threat_feed_status` tables, and implemented parameterized, idempotent batch upserts (`upsert_feed_records`) into existing `indicators` and `threats` tables without creating duplicates or clearing historical data on empty feeds. Implemented `ThreatSyncScheduler` with thread-safe lifecycle control, configurable interval, graceful shutdown, and explicit manual trigger (`trigger_sync_now()`), ensuring background threads are never started on module import. Integrated live feed synchronization metrics and manual synchronization controls into the Streamlit dashboard (`dashboard/app.py`), preserving strict read-only detection boundaries. Expanded the automated test suite from 279 to 303 passing tests (+24 tests in `tests/test_threat_sync.py`), achieving 100% test pass rate with zero network dependencies.

#### Commits

| Commit | Type | Description | Files | Verification |
|--------|------|-------------|-------|--------------|
| `f12bf62` | feat | Implement scheduled threat intelligence synchronization service and feed adapters | `threat_intelligence/sync/`, `reports/threat_database.py`, `config/` | Passed (303 tests) |
| `030c44f` | feat | Integrate feed synchronization status and controls into dashboard | `dashboard/app.py` | Passed (303 tests) |
| `b6818cb` | test | Cover threat feed adapters synchronization and pipeline integration | `tests/test_threat_sync.py`, `tests/test_file_protection_integration.py`, `detection_engine/threat_detector.py` | Passed (303 tests) |
| `5b12719` | docs | Document scheduled threat intelligence synchronization and sync status | `docs/architecture/unified-architecture.md`, `docs/CHANGELOG.md` | Passed (303 tests) |

---

### 2026-10-10 — Unified ACTIS Architecture Adoption & Validation

Adopted and validated the authoritative Unified ACTIS Architecture, establishing the Core + Extensions model across the repository without unnecessary rewrites. Conducted a complete repository audit verifying previous milestones (Days 1–11: 267 baseline tests passing). Unified structured detection contracts across input modalities by ensuring `ThreatDetector.analyze_file()` evaluates the canonical `DetectionDecisionEngine` and exports structured `DetectionResult` metadata, matching `analyze_url()`. Introduced the formal `AnalysisOrchestrator` (`detection_engine/orchestrator.py`) implementing `IAnalysisOrchestrationBoundary` to serve as the single authoritative pipeline coordinator for file, URL, and message scanning, as well as Windows Protection Service security events. Created `docs/architecture/unified-architecture.md` specifying Core vs Extension boundaries, structured contracts, evidence provenance, and verified component status. Added 12 dedicated compliance and integration tests (`tests/test_unified_architecture.py`) verifying multi-modal ingestion, contract symmetry, event handoffs, scanner delegation, and failure isolation, expanding the test suite to 279 passing tests (0 failures).

#### Commits

| Commit | Type | Description | Files | Verification |
|--------|------|-------------|-------|--------------|
| `8060ed5` | feat | Adopt unified analysis orchestrator and symmetric detection contracts | `detection_engine/orchestrator.py`, `detection_engine/threat_detector.py`, `detection_engine/__init__.py` | Passed (279 tests) |
| `e8e523b` | test | Add validation suite for unified architecture compliance | `tests/test_unified_architecture.py` | Passed (279 tests) |

---

### 2026-10-10 — Day 11: Online Threat Intelligence Integration

Implemented a fully working, tested external threat-intelligence lookup pipeline integrating seamlessly with existing ACTIS analysis, detection, and risk-assessment infrastructure. Built the extensible provider abstraction (`BaseThreatClient`) with indicator capability reporting, configurable bounded HTTP timeouts, sliding-window rate-limiting, and secret-masked representation (`***`). Implemented comprehensive client adapters for **VirusTotal v3** (SHA-256 hashes, URLs, domains with 4 req/min throttling), **URLhaus API v1** (malicious URLs and payload SHA-256 hashes with JSON payload encoding), and **AbuseIPDB API v2** (IPv4 and IPv6 public address reputation scoring). Built strict defensive indicator validation (`indicator_validator.py`) with canonical normalization, URL fragment stripping, and strict RFC 1918 private/loopback/link-local IP shielding to prevent enterprise network leakage. Developed a thread-safe, TTL-based threat intelligence cache (`ThreatIntelligenceCache`) that rejects caching transient network failures or timeouts. Implemented a 9-stage local-first threat lookup orchestrator (`ThreatLookup`) that prioritizes local SQLite indicator databases before querying external feeds, tracks 8 explicit outcome states (`FOUND_MALICIOUS`, `FOUND_SUSPICIOUS`, `FOUND_BENIGN`, `NOT_FOUND`, `PROVIDER_UNAVAILABLE`, `REQUEST_TIMEOUT`, `INVALID_RESPONSE`, `QUERY_SKIPPED`), and provides multi-provider aggregation with conflict resolution (`aggregate_findings`). Integrated normalized external intelligence into `ThreatDetector` and `RiskEngine` without altering existing scoring contracts or introducing duplicate risk engines. Expanded the automated test suite from 229 to 267 passing tests (100% pass rate) with zero live network dependencies (100% mocked transport).

#### Commits

| Commit | Type | Description | Files | Verification |
|--------|------|-------------|-------|--------------|
| `0effbb3` | feat | Define external threat intelligence provider contract | `detection_engine/threat_intel_contract.py`, `threat_intelligence/provider_base.py`, `threat_intelligence/__init__.py` | Passed (235 tests) |
| `6b4e1fb` | feat | Add provider configuration and timeout handling | `config/settings.py`, `config/defaults.py`, `config/config.py`, `config/validator.py`, `.env.example` | Passed (235 tests) |
| `632a3fe` | feat | Add indicator validation for external lookups | `threat_intelligence/indicator_validator.py`, `threat_intelligence/__init__.py` | Passed (235 tests) |
| `de90f3c` | feat | Implement external threat intelligence provider adapters | `threat_intelligence/api_clients.py`, `threat_intelligence/__init__.py` | Passed (235 tests) |
| `3c568e2` | feat | Add threat intelligence caching layer | `threat_intelligence/threat_cache.py`, `threat_intelligence/__init__.py` | Passed (235 tests) |
| `f453ff9` | feat | Integrate provider lookup with local intelligence | `threat_intelligence/threat_lookup.py`, `threat_intelligence/__init__.py` | Passed (235 tests) |
| `9f77010` | feat | Integrate normalized evidence with detection pipeline | `detection_engine/threat_detector.py` | Passed (235 tests) |
| `2d38f44` | feat | Add bounded provider failure and offline fallback handling | `threat_intelligence/api_clients.py`, `threat_intelligence/provider_base.py` | Passed (235 tests) |
| `d712aa3` | test | Cover provider adapter response handling | `tests/test_threat_providers.py`, `threat_intelligence/indicator_validator.py` | Passed (256 tests) |
| `788ea97` | test | Cover detection pipeline and threat intelligence integration | `detection_engine/threat_intel_contract.py`, `tests/test_threat_intel_pipeline.py`, `threat_intelligence/provider_base.py`, `threat_intelligence/threat_cache.py`, `threat_intelligence/threat_lookup.py` | Passed (267 tests) |
| `d58cc4d` | docs | Update threat intelligence architecture status and roadmap | `docs/architecture/reference/actis-threat-intelligence-integration.md`, `docs/roadmap/README.md`, `docs/roadmap/month-1.md` | Passed (267 tests) |

---

### 2026-10-09 — Day 10: Event-Driven File Protection

Implemented the event-driven file protection layer for ACTIS, connecting Windows filesystem events directly to the ACTIS Protection Service, event filtering and debouncing, Day 8 incremental scan state tracking, and the existing `ThreatDetector` static analysis and multi-criteria risk engine. Built the native Windows filesystem event monitor bridge (`FilesystemEventSource` using `watchdog.Observer`) with thread-safe lifecycle control, non-blocking callback bridge, and support for `FILE_CREATED`, `FILE_MODIFIED`, `FILE_MOVED`, and `FILE_DELETED` events. Implemented path normalization (`FilesystemEventNormalizer`) resolving canonical absolute paths, standard separators, and Windows case-folding. Created safe event filtering (`FileEventFilter`) discarding directory-only notifications, inaccessible targets, and temporary/editor swap patterns (`.tmp`, `~$*`, `.crdownload`, `.part`). Implemented time-window debouncing and duplicate suppression (`FileEventDebouncer`) coalescing burst file modifications into single logical scan requests with file-settling and size stability checks. Added high-watermark tracking and throttled backpressure logging to bounded intake queues (`SecurityEventQueue`). Integrated event processing with incremental scan state (`FileProtectionPipeline` + `IncrementalStateManager`), safely skipping deep analysis for verified unchanged files while analyzing new and modified files. Hardened the pipeline against filesystem race conditions (`compute_file_fingerprint`, stat comparison) explicitly handling `DISAPPEARED`, `INACCESSIBLE`, and `CHANGED_DURING_ANALYSIS` states. Connected verified files to the canonical `ThreatDetector` static analysis pipeline (PE header parsing, Shannon entropy, static rules, Random Forest ML, multi-criteria risk scoring, SQLite logging) without duplicating detection logic. Expanded automated test suite from 200 to 229 passing tests (100% pass rate).

#### Commits

| Commit | Type | Description | Files | Verification |
|--------|------|-------------|-------|--------------|
| `c165969` | feat | Add filesystem event source integration | `scanners/file_watcher.py` | Passed (200 tests) |
| `3f5c507` | feat | Normalize ACTIS filesystem events | `service/file_normalizer.py`, `service/__init__.py` | Passed (200 tests) |
| `603d9cc` | feat | Add filesystem event filtering | `service/file_filter.py`, `service/__init__.py` | Passed (200 tests) |
| `2ab558f` | feat | Implement filesystem event debouncing | `service/debouncer.py`, `service/__init__.py` | Passed (200 tests) |
| `72b2eba` | feat | Add bounded protection event queue | `service/events.py` | Passed (200 tests) |
| `d0ff9d3` | feat | Integrate filesystem events with protection service | `service/protection_service.py`, `service/health.py`, `service/config.py` | Passed (200 tests) |
| `281b380` | feat | Connect event processing with incremental scan state | `service/file_pipeline.py`, `service/__init__.py` | Passed (200 tests) |
| `6f74ec2` | feat | Connect changed files to ACTIS analysis pipeline | `service/file_pipeline.py` | Passed (200 tests) |
| `38debd5` | feat | Harden event processing against filesystem races | `service/file_pipeline.py`, `service/__init__.py` | Passed (200 tests) |
| `55852db` | test | Add filesystem event and debounce coverage | `tests/test_file_protection_events.py` | Passed (217 tests) |
| `4ce21ab` | test | Add event burst and queue stability coverage | `tests/test_file_protection_burst.py` | Passed (222 tests) |
| `acf96f4` | test | Add event-to-analysis integration coverage | `tests/test_file_protection_integration.py` | Passed (229 tests) |
| `0646444` | docs | Document ACTIS event-driven file protection workflow | `README.md`, `docs/architecture/*` | Passed (229 tests) |

---

### 2026-10-09 — Day 9: Windows Protection Service Foundation

Built the foundation of the ACTIS Windows Protection Service, establishing the lightweight resident protection layer introduced by the post-Day-7 architectural evolution. Implemented deterministic service lifecycle management (`start`, `stop`, `pause`, `resume`, `is_running`, `get_state`), synchronized state transitions (`STOPPED`, `STARTING`, `RUNNING`, `PAUSED`, `DEGRADED`, `FAILED`), worker pool lifecycle coordination with non-blocking queue waiting, thread cancellation, and bounded failure recovery policy (`restart_failed_workers`). Established the canonical security event intake contract (`SecurityEvent`, `SecurityEventType`, `SecurityEventQueue`), decoupling event intake from downstream analysis. Implemented the `EventDispatcher` subscription router and `AnalysisOrchestrationBoundary` handoff interface, strictly ensuring that detection, ML models, and heuristic rules remain outside the service layer. Built the Windows Service Control Manager (SCM) host bridge (`WindowsServiceHost`, `create_windows_host`) for future administrative service deployment and safe interactive/standalone console hosting. Expanded automated test suite from 162 to 200 passing tests (100% pass rate).

#### Commits

| Commit | Type | Description | Files | Verification |
|--------|------|-------------|-------|--------------|
| `a9078e0` | feat | Add ACTIS protection service lifecycle contract | `service/lifecycle.py`, `service/config.py`, `config/settings.py`, `config/defaults.py`, `config/config.py`, `service/__init__.py` | Passed (162 tests) |
| `a0b8ec2` | feat | Implement protection service state management | `service/state.py`, `service/__init__.py` | Passed (162 tests) |
| `47b0e34` | feat | Add controlled protection service worker lifecycle | `service/workers.py`, `service/__init__.py` | Passed (162 tests) |
| `658a7a9` | feat | Add protection service event boundary contract | `service/events.py`, `service/__init__.py` | Passed (162 tests) |
| `524988d` | feat | Add service-to-analysis orchestration boundary | `service/dispatcher.py`, `service/__init__.py` | Passed (162 tests) |
| `21cb05f` | feat | Add protection service health state | `service/health.py`, `service/protection_service.py`, `service/__init__.py` | Passed (162 tests) |
| `2de26b4` | feat | Harden protection service failure handling | `service/workers.py`, `service/protection_service.py`, `service/windows_host.py`, `service/__init__.py` | Passed (162 tests) |
| `77ba8cb` | test | Add protection service lifecycle coverage | `tests/test_protection_service_lifecycle.py` | Passed (176 tests) |
| `721f3d3` | test | Add worker failure and shutdown regression coverage | `tests/test_protection_service_workers.py`, `service/workers.py`, `service/protection_service.py` | Passed (185 tests) |
| `cb8de71` | test | Add security event boundary validation coverage | `tests/test_protection_service_events.py` | Passed (200 tests) |
| `932f05d` | docs | Document ACTIS protection service architecture | `docs/architecture/system-architecture.md`, `docs/architecture/module-architecture.md`, `docs/architecture/project-structure.md`, `docs/architecture/architecture-evolution.md`, `README.md` | Passed (200 tests) |

---

### 2026-10-09 — Day 8: Device Scanner & Incremental Scan State Foundation

Implemented the safe, user-authorized Device Scanner and incremental scan state infrastructure for ACTIS. Features safe recursive filesystem traversal with Windows junction/reparse-point loop avoidance (`TraversalSafetyHelper`), safe file metadata inspection (`FileMetadata`), streaming chunked SHA-256 fingerprinting with race-condition detection (`FileFingerprint`), incremental scan state tracking (`IncrementalStateManager`, `FileScanState`) across five change states (`NEW_FILE`, `UNCHANGED_FILE`, `CHANGED_FILE`, `REMOVED_FILE`, `UNAVAILABLE_FILE`), analytical model version invalidation, SQLite scan state persistence (`file_scan_states`), canonical file analysis pipeline integration (`scan_file` -> `ThreatDetector.analyze_file`), skipping deep analysis for verified unchanged files while re-analyzing modified ones, and strongly-typed `DeviceScanResult` with cooperative cancellation support (`ScanCancellationToken`). Expanded automated test suite to 162 passing tests (100% pass rate).

---

### 2026-09-14 — Week 1 Day 6: Detection Engine & ML Model Integration Foundation

Implemented the central analytical intelligence layer of ACTIS, establishing the structured detection decision pipeline, heterogeneous evidence models, ML prediction contracts, rule evaluation results, threat intelligence evidence representations, deterministic mathematical risk scoring with dynamic active-layer normalization, five-tier risk classification with safety overrides, internal decision confidence calculation, grounded explanation generation, and model manager integration. Expanded automated test suite to 128 passing unit tests (100% pass rate).

#### Commits

| Commit | Type | Description | Files | Verification |
|--------|------|-------------|-------|--------------|
| `c2b046e` | feat | Add detection result contract | `detection_engine/detection_contract.py`, `detection_engine/__init__.py` | Passed (109 tests) |
| `7ce0550` | feat | Add structured detection evidence model | `detection_engine/evidence_model.py`, `detection_engine/__init__.py` | Passed (109 tests) |
| `4b1b29f` | feat | Add ML prediction result contract | `detection_engine/ml_prediction_contract.py`, `detection_engine/__init__.py` | Passed (109 tests) |
| `ad3c831` | feat | Add rule evaluation result contract | `detection_engine/rule_engine.py`, `detection_engine/__init__.py` | Passed (109 tests) |
| `8372c3f` | feat | Add threat intelligence evidence contract | `detection_engine/threat_intel_contract.py`, `detection_engine/__init__.py` | Passed (109 tests) |
| `2065654` | feat | Implement deterministic risk scoring engine | `detection_engine/risk_engine.py`, `detection_engine/__init__.py` | Passed (109 tests) |
| `f9482ae` | feat | Add risk classification thresholds and override logic | `detection_engine/risk_engine.py`, `detection_engine/__init__.py` | Passed (109 tests) |
| `ef7d2e2` | feat | Add detection explanation and confidence calculation | `detection_engine/explanation_generator.py`, `detection_engine/__init__.py` | Passed (109 tests) |
| `bb84daa` | feat | Add model manager abstraction interface | `detection_engine/model_manager.py`, `detection_engine/__init__.py` | Passed (109 tests) |
| `93aff4d` | feat | Implement unified detection decision engine | `detection_engine/decision_engine.py`, `detection_engine/__init__.py` | Passed (109 tests) |
| `56307dd` | test | Add detection engine validation suite | `tests/test_detection_engine.py` | Passed (120 tests) |
| `e1e3821` | test | Add risk engine edge case coverage | `tests/test_risk_engine_day6.py`, `detection_engine/risk_engine.py` | Passed (128 tests) |
| `bfbb6ee` | docs | Document detection engine workflow | `docs/detection_engine_workflow.md`, `SUMMARY.md` | Passed (128 tests) |

---

### 2026-09-14 — Week 1 Day 5: Safe Windows PE Static File Analysis Foundation

Implemented the safe, non-destructive, read-only Windows Portable Executable (PE) static analysis foundation. Built streaming multi-algorithm file hashing (SHA-256, MD5, SHA-1), fast pre-parser binary PE signature detection, core header metadata extraction, section metrics with W+X risk flagging, import table and threat API heuristics, Shannon entropy analysis, and the formal strongly-typed `PEStaticFeatures` feature contract cleanly separating threat-intelligence identifiers from ML features. Hardened against malformed/corrupted files and expanded automated test coverage to 109 passing unit tests.

#### Commits

| Commit | Type | Description | Files | Verification |
|--------|------|-------------|-------|--------------|
| `5490a6d` | feat | Add safe file hashing utilities | `scanners/file_feature_extractor.py` | Passed (91 tests) |
| `2472bd7` | feat | Add Windows PE file detection | `scanners/file_feature_extractor.py` | Passed (91 tests) |
| `0bc56ea` | feat | Add PE metadata extraction foundation | `scanners/file_feature_extractor.py` | Passed (91 tests) |
| `75e6a83` | feat | Add PE section feature extraction | `scanners/file_feature_extractor.py` | Passed (91 tests) |
| `00e0392` | feat | Add PE import feature extraction | `scanners/file_feature_extractor.py` | Passed (91 tests) |
| `b6a4ed5` | feat | Add PE entropy feature extraction | `scanners/file_feature_extractor.py` | Passed (91 tests) |
| `4caed0e` | feat | Add structured PE feature contract | `scanners/pe_feature_contract.py`, `scanners/file_feature_extractor.py` | Passed (91 tests) |
| `f24885e` | fix | Harden PE analysis against malformed files | `scanners/file_feature_extractor.py` | Passed (91 tests) |
| `9549fbe` | test | Add PE static analysis test suite | `tests/test_static_pe.py`, `scanners/file_feature_extractor.py` | Passed (109 tests) |
| `ef285cd` | docs | Document ACTIS static file analysis workflow | `docs/static_pe_analysis.md`, `SUMMARY.md` | Passed (109 tests) |

---

### 2026-09-09 — Week 1 Day 3: Windows PE Malware Dataset Inspection & Data Preparation Foundation

Established the authentic data ingestion, schema validation, metadata identifier isolation, quality audit, and label normalization foundation for the Windows PE malware dataset (`data/malware_dataset.csv`, 62,485 samples, 15 PE structural features, 2 metadata identifiers, 1 label). Enforced zero data leakage, target binarization (`is_malware`), and added 25 automated unit tests (91 total suite tests).

#### Commits

| Commit | Type | Description | Files | Verification |
|--------|------|-------------|-------|--------------|
| `1d0f2d6` | feat | Define Windows PE malware dataset schema contract | `detection_engine/malware_dataset_schema.py` | Passed (66 tests) |
| `0afd272` | feat | Implement raw malware dataset loading with identifier isolation | `detection_engine/malware_dataset_loader.py` | Passed (66 tests) |
| `39db203` | feat | Implement dataset schema validation and integrity verification | `detection_engine/malware_dataset_loader.py` | Passed (66 tests) |
| `26d4b3d` | feat | Implement feature matrix extraction and label binarization | `detection_engine/malware_dataset_loader.py` | Passed (66 tests) |
| `a2ec5b3` | feat | Implement dataset quality inspection and diagnostic reporting | `detection_engine/malware_dataset_loader.py` | Passed (66 tests) |
| `ef9c7ac` | feat | Implement class distribution and balance analysis | `detection_engine/malware_dataset_loader.py` | Passed (66 tests) |
| `ffda49d` | test | Add unit tests for malware dataset schema contracts | `tests/test_malware_dataset.py` | Passed (74 tests) |
| `6e5b5b0` | test | Add unit tests for dataset loading and identifier isolation | `tests/test_malware_dataset.py`, `detection_engine/malware_dataset_loader.py` | Passed (80 tests) |
| `92362fe` | test | Add unit tests for schema validation and edge case errors | `tests/test_malware_dataset.py` | Passed (84 tests) |
| `4177478` | test | Add unit tests for feature preparation, quality inspection, and class balance | `tests/test_malware_dataset.py` | Passed (91 tests) |
| `54ec9c9` | docs | Document Windows PE malware dataset and data preparation foundation | `docs/ml_malware_dataset.md`, `SUMMARY.md` | Passed (91 tests) |

---

### 2026-09-08 — Week 1 Day 2: Configuration & Documentation Governance Framework

Established the authoritative ACTIS documentation framework (`docs/architecture/`, `docs/roadmap/`, `docs/generated/`) and centralized configuration management foundation. Decoupled operational settings, paths, and credentials with strict secret protection and full backward compatibility.

#### Commits

| Commit | Type | Description | Files | Verification |
|--------|------|-------------|-------|--------------|
| `b96763b` | chore | Establish ACTIS configuration foundation (dataclass schema) | `config/settings.py` | Passed (24 tests) |
| `2ab1ac5` | chore | Add environment configuration support (typed parsers, .env) | `config/env_loader.py` | Passed (24 tests) |
| `ab13ae7` | chore | Add ACTIS project path configuration (dynamic paths) | `config/paths.py` | Passed (24 tests) |
| `408e3b6` | chore | Add runtime configuration defaults (baseline operational limits) | `config/defaults.py` | Passed (24 tests) |
| `8790268` | chore | Add configuration validation (weights, risk thresholds, bounds) | `config/validator.py` | Passed (24 tests) |
| `b715e14` | chore | Add environment example (.env.example templates with placeholders) | `.env.example`, `config/.env.example` | Passed (24 tests) |
| `db26f3a` | chore | Protect environment secrets (harden .gitignore for keys/tokens) | `.gitignore` | Passed (24 tests) |
| `4a47393` | test | Add configuration loading tests (defaults, paths, env parsing) | `tests/test_config_loading.py` | Passed (28 tests) |
| `8951436` | test | Add configuration validation tests (weights, thresholds, strict mode) | `tests/test_config_validation.py` | Passed (35 tests) |
| `6345d10` | docs | Document ACTIS configuration usage (architecture guide & reference) | `docs/configuration.md` | Passed (35 tests) |
| `6b58e0e` | chore | Wire centralized configuration into config entrypoint | `config/config.py`, `config/__init__.py` | Passed (35 tests) |
| `4b45465` | docs | Initialize ACTIS changelog with Week 1 Day 2 record | `docs/CHANGELOG.md` | Passed (35 tests) |
| `bba3b6d` | docs | Define architecture source of truth and AI rules | `docs/architecture/README.md` | Passed (35 tests) |
| `dd71ba0` | docs | Document system architecture | `docs/architecture/system-architecture.md` | Passed (35 tests) |
| `c57a297` | docs | Document module architecture | `docs/architecture/module-architecture.md` | Passed (35 tests) |
| `5282b7f` | docs | Document project structure | `docs/architecture/project-structure.md` | Passed (35 tests) |
| `277263b` | docs | Document detection workflow | `docs/architecture/detection-workflow.md` | Passed (35 tests) |
| `b29297a` | docs | Document data flow and privacy boundaries | `docs/architecture/data-flow.md` | Passed (35 tests) |
| `1839ad5` | docs | Document threat intelligence workflow | `docs/architecture/threat-intelligence-workflow.md` | Passed (35 tests) |
| `5daaced` | docs | Document ML workflow and model contracts | `docs/architecture/ml-workflow.md` | Passed (35 tests) |
| `dd0a25d` | docs | Document scanning workflow and safety controls | `docs/architecture/scanning-workflow.md` | Passed (35 tests) |
| `0766636` | docs | Define ACTIS security boundaries | `docs/architecture/security-boundaries.md` | Passed (35 tests) |
| `6cec39f` | docs | Establish four-month roadmap overview | `docs/roadmap/README.md` | Passed (35 tests) |
| `f62f777` | docs | Define day-by-day roadmap for month 1 foundation | `docs/roadmap/month-1.md` | Passed (35 tests) |
| `e0af4ec` | docs | Define day-by-day roadmap for month 2 scanners and detection | `docs/roadmap/month-2.md` | Passed (35 tests) |
| `dbee27d` | docs | Define day-by-day roadmap for month 3 real-time and threat intel | `docs/roadmap/month-3.md` | Passed (35 tests) |
| `4f35035` | docs | Define day-by-day roadmap for month 4 productization and release | `docs/roadmap/month-4.md` | Passed (35 tests) |
| `3f12abd` | docs | Establish current-state generated documentation framework | `docs/generated/*.md` | Passed (35 tests) |
| `9735199` | docs | Add database ML test references and changelog to generated documentation | `docs/generated/*.md` | Passed (35 tests) |
| `cad6618` | docs | Synchronize changelogs with complete documentation framework history | `docs/CHANGELOG.md`, `docs/generated/CHANGELOG.md` | Passed (35 tests) |
| `82e7b4c` | feat | Create documentation generator core repository inspector | `scripts/generate_docs.py` | Passed (35 tests) |
| `4b23a40` | feat | Add Git history and working tree analyzer to documentation generator | `scripts/generate_docs.py` | Passed (35 tests) |
| `41b928d` | feat | Add Python AST module inspector to documentation generator | `scripts/generate_docs.py` | Passed (35 tests) |
| `cef2cbc` | feat | Add ML models and dataset analyzer to documentation generator | `scripts/generate_docs.py` | Passed (35 tests) |
| `bedf771` | feat | Add database schema analyzer to documentation generator | `scripts/generate_docs.py` | Passed (35 tests) |
| `23c7d4c` | feat | Add test suite inventory analyzer to documentation generator | `scripts/generate_docs.py` | Passed (35 tests) |
| `263a383` | feat | Add reproducible roadmap progress calculator to documentation generator | `scripts/generate_docs.py` | Passed (35 tests) |
| `831c017` | feat | Add markdown report writers for project and module status | `scripts/generate_docs.py` | Passed (35 tests) |
| `bd64d60` | feat | Add markdown report writers for database, ML, and test references | `scripts/generate_docs.py` | Passed (35 tests) |
| `963163d` | test | Add automated unit tests for documentation generator | `scripts/generate_docs.py`, `tests/test_doc_generator.py` | Passed (55 tests) |
| `2e3152b` | chore | Execute documentation generator to synchronize generated documentation | `docs/generated/*.md` | Passed (55 tests) |
| `d54e1ea` | docs | Update main changelog with documentation progress system records | `docs/CHANGELOG.md` | Passed (55 tests) |

---

### 2026-09-08 — Week 1 Day 1: Architecture & Project Foundation

Established initial project foundation, architectural specifications, initial validation suite, contracts, and repository structure.

#### Commits

| Commit | Type | Description | Files | Verification |
|--------|------|-------------|-------|--------------|
| `8d4611d` | docs | Define ACTIS architecture | `docs/architecture.md`, `README.md` | Verified |
| `2e2a0f0` | chore | Initialize ACTIS project structure (validate tool) | `tools/validate_structure.py` | Passed |
| `a6e14e8` | chore | Add initial configuration example | `config/.env.example` | Verified |
| `0174f37` | chore | Add ACTIS logging infrastructure (rotating file handler) | `config/config.py` | Passed |
| `88e2788` | docs | Define database and ML contracts | `docs/contracts.md` | Verified |
| `e55fbf1` | test | Add initial ACTIS validation suite | `tests/test_week1_validation.py` | Passed |
| `e78460e` | chore | Ignore model binaries (models/*.pkl) | `.gitignore` | Verified |
| `38363f6` | chore | Commit remaining workspace files | Multiple workspace components | Passed |
| `8beb805` | chore | Remove accidental file, runtime DB, and Android dataset from tracking | `.gitignore`, Git index | Passed |
