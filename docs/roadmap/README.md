# ACTIS Development Roadmap & Post-Day-7 Evolution

**Authoritative Roadmap Specification**  
**Milestone:** Post-Day-7 Architectural Evolution  
**Status:** Approved Roadmap Direction  

This directory defines the authoritative development roadmap for **ACTIS — Automated Cyber Threat Intelligence System**.

---

## 1. Roadmap Evolution & Structure

Following the completion of Day 7, ACTIS underwent a major architectural breakthrough: evolving from a collection of isolated scanning tools into a **Windows-oriented, event-driven cyber protection platform**.

The roadmap is strictly structured into three distinct chronological phases:

```text
┌────────────────────────────────────────────────────────────────────────┐
│ COMPLETED: DAYS 1 – 7 (Core Foundation & Ingestion Hardening)          │
│ • Architecture, Configuration, Logging, SQLite Database Schemas       │
│ • Machine Learning Contracts & 19-Feature Phishing Random Forest Model │
│ • Static Windows PE Feature Extraction & Safe Binary Parsing           │
│ • Unified Detection Decision Engine & Multi-Criteria Risk Engine       │
│ • URL & Message Scanner Hardening (Deduplication & Single Pipeline)   │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ CURRENT BREAKTHROUGH: POST-DAY-7 ARCHITECTURE EVOLUTION                │
│ • Shift to Windows-Oriented, Event-Driven Cyber Protection Platform    │
│ • Separation of Event Ingest from Centralized Analysis Orchestrator   │
│ • Specification of Resident Protection Service & Shared Threat Intel   │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ NEXT: DAYS 8 – 16 (Targeted System Evolution)                          │
│ • Day 8: Device Scanner + Incremental Scan State                       │
│ • Day 9: Windows Protection Service Foundation                         │
│ • Day 10: Event-Driven File Protection                                 │
│ • Day 11: Online Threat Intelligence                                   │
│ • Day 12: Central ACTIS Threat Intelligence                            │
│ • Day 13: Dashboard + Notification Layer                               │
│ • Day 14: AI Security Assistant                                        │
│ • Day 15: Security Hardening + Broad Threat Coverage Testing           │
│ • Day 16: Final Integration + Demo + Release                           │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Phase 1: Completed Foundation (Days 1–8)

- **Day 1: Architecture Planning & Repository Foundation** — Repository topology, safe structure validation, and non-destructive policies established.
- **Day 2: Configuration Management** — Strongly typed `AppConfig`, environment variable validation, dynamic project path anchoring (11 passing tests).
- **Day 3: Logging Infrastructure & Audit Trails** — Rotating file handlers, structured JSON log formatting, sensitive credential sanitization.
- **Day 4: Database Contracts & Schema Planning** — SQLite WAL mode persistence for `threats`, `indicators`, `scans`, `detections`, and `scan_items`.
- **Day 5: ML Contracts & Phishing Model Foundation** — 19-feature morphological Random Forest phishing model and metadata contract verification.
- **Day 6: Detection Engine & Risk Engine Integration** — Unified `DetectionDecisionEngine` combining ML, heuristics, and threat intelligence into normalized scores with explainability.
- **Day 7: URL & Message Scanner Hardening** — Boundary-aware link extraction, canonical deduplication, safe heuristics, and strict delegation to the canonical URL analysis pipeline.
- **Day 8: Device Scanner + Incremental Scan State** — Safe recursive filesystem traversal, Windows junction/reparse-point loop safety, safe file metadata extraction, streaming chunked SHA-256 fingerprinting with race detection, incremental scan state tracking (`NEW_FILE`, `UNCHANGED_FILE`, `CHANGED_FILE`, `REMOVED_FILE`, `UNAVAILABLE_FILE`), SQLite persistence (`file_scan_states`), canonical analysis pipeline delegation, and cooperative cancellation.

*Current Baseline Verification:* 162 automated unit and integration tests passing with 100% success rate.

---

## 3. Phase 2: Post-Day-7 Architectural Breakthrough

Introduced after Day 7, this architectural refinement formalizes:
1. **Scanners as Input Providers:** Scanners and sensors feed typed security events into the platform without duplicating detection algorithms.
2. **Analysis Orchestrator:** Canonical analytical pipeline standardizing feature extraction, ML scoring, and heuristic evaluation per target domain.
3. **Resident Protection Service:** Dedicated background service for event intake, write-completion debouncing, and non-blocking job queueing.
4. **Shared Threat Intelligence:** Unified local and remote threat reputation feeds shared across all analysis workflows.

Detailed design is documented in [`docs/architecture/architecture-evolution.md`](../architecture/architecture-evolution.md).

---

## 4. Phase 3: Revised Roadmap Execution (Days 8–16)

### Day 8: Device Scanner + Incremental Scan State (`COMPLETED`)
- **Delivered:** Safe user-authorized filesystem scanning, incremental scan state tracking, privacy-preserving file fingerprints (SHA-256 + mtime/size), junction/reparse-point loop protection, cancellation token support, and skipping unchanged files.
- **Constraint Verified:** Resident Windows Protection Service was NOT implemented today.
- **Components:** `scanners/device_scanner.py`, `scanners/incremental_state.py`, `tests/test_device_scanner.py`, `tests/test_incremental_state.py`.

### Day 9: Windows Protection Service Foundation (`COMPLETED`)
- **Delivered:** Lightweight resident Protection Service foundation, deterministic lifecycle (`start`, `stop`, `pause`, `resume`), state transitions (`STOPPED`, `STARTING`, `RUNNING`, `PAUSED`, `DEGRADED`, `FAILED`), worker pool coordination, bounded failure recovery, canonical `SecurityEvent` schema and validation, thread-safe bounded intake queue (`SecurityEventQueue`), `EventDispatcher` subscription router, decoupled `AnalysisOrchestrationBoundary` handoff, and Windows Service Control Manager host bridge (`WindowsServiceHost`).
- **Constraint Verified:** Real-time filesystem event monitoring (`watchdog` file watcher) was NOT implemented today and remains scheduled for Day 10.
- **Components:** `service/lifecycle.py`, `service/state.py`, `service/workers.py`, `service/events.py`, `service/dispatcher.py`, `service/health.py`, `service/protection_service.py`, `service/windows_host.py`, `tests/test_protection_service_lifecycle.py`, `tests/test_protection_service_workers.py`, `tests/test_protection_service_events.py`.
- **Baseline:** 200 automated unit and integration tests passing with 100% success rate.

### Day 10: Event-Driven File Protection (`PLANNED`)
- **Goals:** File creation and modification event hooks (`watchdog`), write-stability debounce filtering, task enqueuing, and automatic handoff to the Analysis Orchestrator for new/modified files.

### Day 11: Online Threat Intelligence
- **Goals:** External threat intelligence connectors (VirusTotal v3), safe read-only API client abstractions, rate-limiting, timeout controls, and normalized reputation results.

### Day 12: Central ACTIS Threat Intelligence
- **Goals:** Central ACTIS Threat Intelligence REST API, client-server synchronization protocol, federated sharing of verified indicators, and state machine transition enforcement (`CONFIRMED`, `SUSPICIOUS`, `CANDIDATE`).

### Day 13: Dashboard + Notification Layer
- **Goals:** Streamlit cybersecurity command center UI, detection visualization, scan history queries, telemetry charts, and native Windows desktop alert notifications.

### Day 14: AI Security Assistant
- **Goals:** Offline-grounded natural language security assistant, plain-English detection explanations, security state summarization, operating strictly through controlled SQLite read interfaces with **NO unrestricted OS shell access**.

### Day 15: Security Hardening + Broad Threat Coverage Testing
- **Goals:** Security boundary verification, false positive rate auditing, malformed input stress-testing, adversarial sample evaluation, privacy review, and end-to-end reliability benchmarks.

### Day 16: Final Integration + Demo + Release
- **Goals:** Complete system integration, reproducible deployment verification, documentation finalization, demonstration scripts, and milestone release preparation.

---

## 5. Authoritative Development Rules

1. **Strict Day-by-Day Sequencing:** Work strictly within the scope of the currently assigned development day.
2. **No Working Ahead:** Do not implement tasks assigned to future days.
3. **Preserve Read-Only Security Boundaries:** Never introduce code execution, automatic file deletion, or covert surveillance.
4. **Atomic Conventional Commits:** Maintain verifiable Git history with verified identity.
