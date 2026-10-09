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

### Day 9: Windows Protection Service Foundation
- **Goals:** Define lightweight resident service architecture, startup/resume lifecycle management, event intake loop, service-to-orchestrator queueing boundary, and state persistence.
- **Components:** `service/protection_service.py`, `service/event_queue.py`.

### Day 10: Event-Driven File Protection
- **Goals:** File creation and modification event hooks (`watchdog`), write-stability debounce filtering, task enqueuing, and automatic handoff to the Analysis Orchestrator for new/modified files.
- **Components:** `scanners/file_watcher.py`, `service/file_event_handler.py`.

### Day 11: Online Threat Intelligence
- **Goals:** External threat intelligence connectors (VirusTotal v3), safe read-only API client abstractions, rate-limiting, timeout controls, and normalized reputation results.
- **Components:** `threat_intelligence/api_clients.py`, `threat_intelligence/threat_lookup.py`.

### Day 12: Central ACTIS Threat Intelligence
- **Goals:** Central ACTIS Threat Intelligence REST API, client-server synchronization protocol, federated sharing of verified indicators, and state machine transition enforcement (`CONFIRMED`, `SUSPICIOUS`, `CANDIDATE`).
- **Components:** `backend/api.py`, `threat_intelligence/sync_manager.py`.

### Day 13: Dashboard + Notification Layer
- **Goals:** Streamlit cybersecurity command center UI, detection visualization, scan history queries, telemetry charts, and native Windows desktop alert notifications.
- **Components:** `dashboard/app.py`, `notifications/notifier.py`.

### Day 14: AI Security Assistant
- **Goals:** Offline-grounded natural language security assistant, plain-English detection explanations, security state summarization, operating strictly through controlled SQLite read interfaces with **NO unrestricted OS shell access**.
- **Components:** `assistant/security_assistant.py`.

### Day 15: Security Hardening + Broad Threat Coverage Testing
- **Goals:** Security boundary verification, false positive rate auditing, malformed input stress-testing, adversarial sample evaluation, privacy review, and end-to-end reliability benchmarks.
- **Components:** `tests/test_adversarial_security.py`, `tests/test_privacy_safeguards.py`.

### Day 16: Final Integration + Demo + Release
- **Goals:** Complete system integration, reproducible deployment verification, documentation finalization, demonstration scripts, and milestone release preparation.
