# ACTIS Roadmap — Foundation & Evolution (Days 1 – 16)

**Milestone Version**: `v0.1.0 — Foundation & Evolution`  
**Status**: Authoritative Execution Plan  

---

## 1. Roadmap Architecture Overview

The ACTIS development progression is structured into:
1. **COMPLETED: Days 1–7** (Architecture, Configuration, Logging, SQLite Database, Phishing ML, Unified Detection Engine, URL & Message Scanner Hardening).
2. **CURRENT BREAKTHROUGH: Post-Day-7 Architectural Evolution** (Transition from scanner collection to an event-driven Windows protection platform).
3. **NEXT: Days 8–16** (Targeted implementation of the event-driven platform).

---

## 2. Completed Foundation: Days 1–7

### Day 1: Architecture Planning & Repository Foundation (`COMPLETED`)
- Defined approved ACTIS system architecture and initialized repository structure.
- Established strict read-only security boundaries and `.gitignore` hygiene.

### Day 2: Configuration Management (`COMPLETED`)
- Built strongly-typed `AppConfig`, path resolver, environment loader, and constraint validator.
- 11 unit tests passing under `pytest`.

### Day 3: Logging Infrastructure & Audit Trails (`COMPLETED`)
- Established enterprise structured logging, rotating file handlers, and credential sanitization in `config/logger.py`.

### Day 4: Database Contracts & Schema Planning (`COMPLETED`)
- Defined SQLite WAL-mode tables (`threats`, `indicators`, `scans`, `detections`, `scan_items`) in `reports/threat_database.py`.

### Day 5: ML Contracts & Phishing Model Foundation (`COMPLETED`)
- Formalized 19-feature morphological Random Forest phishing model contract (`models/phishing_model_metadata.json`).
- Built schema enforcement in `detection_engine/model_manager.py`.

### Day 6: Unified Detection Decision Engine & Risk Fusion (`COMPLETED`)
- Built `DetectionDecisionEngine` combining ML, heuristics, and threat intelligence into normalized scores.
- Implemented dynamic weight normalization, confidence scoring, and itemized explainability.

### Day 7: URL & Message Scanner Hardening (`COMPLETED`)
- Hardened `scanners/url_scanner.py`: RFC validation, canonical normalization, 19-feature vector extraction, session caching.
- Hardened `scanners/text_analyzer.py`: Boundary-aware URL extraction, canonical deduplication, social engineering heuristics.
- **Architectural Mandate:** Strict delegation of all URL analysis to the single canonical URL scanning path (`scan_url_logic`).

### Day 8: Device Scanner + Incremental Scan State (`COMPLETED`)
- Built safe, user-authorized recursive filesystem traversal with Windows junction/reparse-point loop safety (`TraversalSafetyHelper`).
- Implemented safe file metadata collection (`FileMetadata`) and streaming chunked SHA-256 fingerprinting with race-condition detection (`FileFingerprint`).
- Built incremental scan state management (`IncrementalStateManager`, `FileScanState`) with change classification (`NEW_FILE`, `UNCHANGED_FILE`, `CHANGED_FILE`, `REMOVED_FILE`, `UNAVAILABLE_FILE`).
- Persisted scan state to SQLite (`file_scan_states`).
- Integrated with canonical file analysis pipeline (`scan_file` -> `ThreatDetector.analyze_file`), reusing verdicts and skipping deep analysis for unchanged files while re-analyzing modified files.
- Returned strongly-typed `DeviceScanResult` with cooperative cancellation support (`ScanCancellationToken`).
- 162 automated unit and integration tests passing with 100% success rate.

---

## 3. Post-Day-7 Architectural Breakthrough

Introduced following the completion of Day 7, this architectural shift recognizes that **ACTIS cannot remain merely a collection of independent scanners**. Scanners and sensors are input providers; the platform is evolving into a Windows-oriented, event-driven cyber protection platform featuring:
- A lightweight resident **Protection Service**
- An **Event/Input Layer** translating stimuli into typed security events
- A centralized **Analysis Orchestrator** standardizing feature extraction and model execution
- Shared **Threat Intelligence** infrastructure
- The **Detection Engine** as the multi-criteria intelligence core
- The **Risk Engine** providing evidence-driven, explainable classifications

---

## 4. Revised Execution Plan: Days 8–16

### Day 8: Device Scanner + Incremental Scan State (`COMPLETED`)
- Safe user-authorized filesystem scanning, incremental scan state tracking, privacy-preserving file fingerprints (SHA-256 + mtime/size), junction/reparse-point loop protection, cancellation token support, and skipping unchanged files.
- Components: `scanners/device_scanner.py`, `scanners/incremental_state.py`, `tests/test_device_scanner.py`, `tests/test_incremental_state.py`.

### Day 9: Windows Protection Service Foundation (`COMPLETED`)
- **Delivered:** Lightweight resident Protection Service foundation, deterministic lifecycle (`start`, `stop`, `pause`, `resume`), state machine (`STOPPED`, `STARTING`, `RUNNING`, `PAUSED`, `DEGRADED`, `FAILED`), worker pool coordination, bounded recovery policy, canonical `SecurityEvent` schema and validation, thread-safe bounded intake queue (`SecurityEventQueue`), `EventDispatcher` subscription router, decoupled `AnalysisOrchestrationBoundary` handoff, and Windows Service Control Manager host bridge (`WindowsServiceHost`).
- **Constraint Verified:** Real-time filesystem event monitoring (`watchdog` file watcher) was NOT implemented today and remains scheduled for Day 10.
- **Components:** `service/lifecycle.py`, `service/state.py`, `service/workers.py`, `service/events.py`, `service/dispatcher.py`, `service/health.py`, `service/protection_service.py`, `service/windows_host.py`, `tests/test_protection_service_lifecycle.py`, `tests/test_protection_service_workers.py`, `tests/test_protection_service_events.py`.
- **Baseline:** 200 automated unit and integration tests passing with 100% success rate.

### Day 10: Event-Driven File Protection (`COMPLETED`)
- **Delivered:** Real-time Windows filesystem event monitoring (`watchdog` bridge `FilesystemEventSource`), canonical path normalization (`FilesystemEventNormalizer`), temporary and editor swap file filtering (`FileEventFilter`), sliding-window debouncing (`FileEventDebouncer`), bounded event queue (`SecurityEventQueue`) with peak tracking and backpressure, incremental scan state integration (`FileProtectionPipeline`), pre/post-inspection race condition hardening, and direct delegation to the existing `ThreatDetector` static analysis pipeline.
- **Constraint Verified:** Clipboard monitoring, online threat intelligence, notifications, and AI assistant were NOT implemented today.
- **Components:** `scanners/file_watcher.py`, `service/file_normalizer.py`, `service/file_filter.py`, `service/debouncer.py`, `service/file_pipeline.py`, `tests/test_file_protection_events.py`, `tests/test_file_protection_burst.py`, `tests/test_file_protection_integration.py`.
- **Baseline:** 229 automated unit and integration tests passing with 100% success rate.

### Day 11: Online Threat Intelligence (`COMPLETED`)
- **Delivered:** Working external threat-intelligence provider architecture, `BaseThreatClient` abstraction, comprehensive client adapters for VirusTotal v3, URLhaus API v1, and AbuseIPDB API v2 with sliding-window rate limiting and bounded HTTP timeouts. Strict canonical indicator validation (`indicator_validator.py`) with RFC 1918 private IP shielding and URL fragment stripping. Thread-safe in-memory TTL caching (`threat_cache.py`) that strictly avoids caching transient outages or timeouts. Unified 9-stage local-first threat lookup (`threat_lookup.py`) with 8 explicit outcome states (`FOUND_MALICIOUS`, `FOUND_SUSPICIOUS`, `FOUND_BENIGN`, `NOT_FOUND`, `PROVIDER_UNAVAILABLE`, `REQUEST_TIMEOUT`, `INVALID_RESPONSE`, `QUERY_SKIPPED`) and multi-provider conflict resolution. End-to-end integration with the Detection Decision Engine and Risk Engine without altering existing scoring contracts.
- **Constraints Verified:** Zero full-file uploads, API keys masked in logs and representations, no external network dependencies during unit tests (100% mocked transport). Day 12 central intelligence sharing was NOT implemented.
- **Components:** `threat_intelligence/provider_base.py`, `threat_intelligence/api_clients.py`, `threat_intelligence/indicator_validator.py`, `threat_intelligence/threat_cache.py`, `threat_intelligence/threat_lookup.py`, `detection_engine/threat_intel_contract.py`, `tests/test_threat_providers.py`, `tests/test_threat_intel_pipeline.py`.
- **Baseline:** 267 automated unit and integration tests passing with 100% success rate.


### Day 12: Scheduled Threat Intelligence Synchronization & Dashboard (`COMPLETED`)
- **Delivered:** Periodic background sync scheduler (`threat_intelligence/sync/sync_service.py`), lock-safe synchronization lifecycle, feed adapters (`URLhausFeedAdapter`, `AbuseIPDBFeedAdapter`), idempotent database upserts, telemetry tracking, and Streamlit command center sync management integration (`dashboard/app.py`).
- **Constraints Verified:** Local threat scanning remains 100% autonomous; synchronization errors do not impact local file or URL inspections.
- **Components:** `threat_intelligence/sync/sync_service.py`, `threat_intelligence/sync/feed_adapter.py`, `threat_intelligence/sync/threat_database_sync.py`, `dashboard/app.py`, `tests/test_threat_intel_sync.py`.
- **Baseline:** 303 automated unit and integration tests passing with 100% success rate.

### Day 13: Central Threat Intelligence Service & Secure Synchronization (`COMPLETED`)
- **Delivered:** Versioned central FastAPI service (`backend/api.py`), central SQLite persistence (`backend/database.py`), Pydantic v1 schemas with bounded pagination (`backend/models.py`), constant-time HMAC API key authentication, sliding-window rate limiting, anti-poisoning candidate workflow (`CANDIDATE` / `PENDING`), administrative review endpoint (`/api/v1/admin/indicators/{id}/review`), client feed adapter (`CentralACTISFeedAdapter`), and dashboard central service telemetry integration.
- **Constraints Verified:** Local protection engine remains 100% autonomous and offline-functional. Central service is an intelligence exchange channel only; zero remote code execution, zero personal file transmission. Candidate indicators cannot pollute client detection databases without explicit admin review.
- **Components:** `backend/api.py`, `backend/database.py`, `backend/models.py`, `threat_intelligence/sync/feed_adapter.py`, `dashboard/app.py`, `tests/test_central_ti_service.py`.
- **Baseline:** 333 automated unit and integration tests passing with 100% success rate (30 new tests added).

### Day 14: Grounded AI Security Assistant and Explainable Threat Analysis (`COMPLETED`)
- **Delivered:** Read-only security assistant (`assistant/security_assistant.py`), deterministic intent routing (recent detections, explain target, indicator lookup, scan statistics, methodology, safe defensive guidance), multi-factor scoring explainability (Intel 35%, ML 30%, Rules 20%), candidate anti-poisoning caveats, disambiguated target matching, absence-of-evidence safety warnings (missing != safe), secret masking (`mask_sensitive_strings`), provider abstraction (`BaseAssistantProvider`, `DeterministicAssistantProvider`, `ExternalLLMProvider`), dashboard session conversation history (`dashboard/app.py`), and offline indicator badge.
- **Constraints Verified:** Strictly read-only; zero arbitrary OS shell execution, zero automated file deletion/quarantine, zero prompt injection escalation, zero personal file transmission to external LLM providers.
- **Components:** `assistant/security_assistant.py`, `assistant/__init__.py`, `dashboard/app.py`, `tests/test_security_assistant.py`.
- **Baseline:** 360 automated unit and integration tests passing with 100% success rate (27 new tests added).

### Day 15: Security Hardening, Adversarial Robustness & Broad Threat Coverage Testing (`COMPLETED`)
- **Delivered:** Comprehensive adversarial input hardening across all intake channels (malformed PE headers, truncated files, oversized binaries bounded at 50MB, random noise), malformed and adversarial URL validation, ReDoS-safe linear time message evaluation. Strict privacy safeguards preventing local file paths or document contents from leaking to external intelligence APIs. Automated structured logging credential masking (`SecretMaskingFilter`), special-purpose IP shielding (`is_safe_public_ip` covering RFC 1918, loopback, link-local, unspecified, and multicast), circular-import-safe module boundaries (`detection_engine` / `threat_intelligence`), assistant prompt injection immunity, `SecurityEventQueue` capacity saturation burst stress-testing (500–1,000 events) with backpressure drop telemetry, and isolated SQLite multi-threaded transaction concurrency testing.
- **Constraints Verified:** Strictly read-only; zero dynamic execution of inspected binaries, zero automated file deletion/quarantine, zero unrestricted AI shell execution, zero complete user file uploads.
- **Components:** `tests/test_adversarial_security.py`, `tests/test_privacy_safeguards.py`, `config/config.py`, `detection_engine/threat_detector.py`, `threat_intelligence/indicator_validator.py`.
- **Baseline:** 417 automated unit, integration, and security tests passing with 100% success rate (+57 new tests added).

### Day 16: Final Integration + Demo + Release (`PLANNED`)
- **Goals:** Complete system integration, reproducible deployment verification, documentation finalization, demonstration scripts, and milestone release preparation.

