# ACTIS System Architecture

**Authoritative Architecture Document**  
**Milestone:** Post-Day-7 Architectural Evolution  
**Status:** Approved Target Architecture  

---

## Architectural Philosophy & Evolution

ACTIS (Automated Cyber Threat Intelligence System) is an intelligent, non-intrusive, read-only endpoint cybersecurity and threat intelligence platform designed specifically for Windows desktop environments.

Following the Day 7 milestone, ACTIS evolved beyond a collection of independent scanning utilities into a **Windows-oriented, event-driven cyber protection platform**. In this target architecture:
1. **Sensors and scanners are input mechanisms and event providers**, not isolated detection engines.
2. A **lightweight resident Protection Service** manages system-level telemetry and event intake.
3. A **centralized Analysis Orchestrator** standardizes feature extraction and coordinates analytical pipelines without code duplication.
4. The **Detection Engine remains the centralized intelligence core**, synthesizing multi-layered evidence rather than relying on any single fragile signal.
5. The **Risk Engine provides evidence-driven, explainable risk classifications** across standard lifecycle states (`CONFIRMED`, `SUSPICIOUS`, `CANDIDATE`, `REPORTED`, `FALSE_POSITIVE`).

---

## High-Level Target Topology

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

## Core Architectural Principles

1. **ACTIS is NOT simply a collection of scanners:**
   Scanners and sensors are input mechanisms. Core intelligence belongs exclusively in the shared analysis, threat intelligence, and detection pipelines.
2. **Event-driven design:**
   ACTIS responds reactively to security events (e.g. newly created files, dropped binaries, modified files, copied/submitted URLs, messages, and user-initiated on-demand scan tasks).
3. **Lightweight Resident Protection Service:**
   The resident Windows service manages endpoint state, event intake, debouncing, and job queueing. It does not block operating system threads with heavy ML or file parsing tasks.
4. **Centralized Analysis Orchestrator:**
   A single canonical pipeline coordinates feature extraction, machine learning evaluation, and rule execution per target type, preventing sensors from duplicating detection logic.
5. **Detection Engine as Intelligence Core:**
   The Detection Engine combines evidence from multiple independent sources (local threat intelligence, machine learning inference, deterministic heuristic rules, and external threat feeds) rather than trusting a single heuristic or probabilistic model.
6. **Evidence-driven Risk Classification:**
   Statistical ML probabilities are evidence, not ground truth. Risk scoring is itemized, explainable, and categorized into verified lifecycle states (`CONFIRMED`, `SUSPICIOUS`, `CANDIDATE`, `REPORTED`, `FALSE_POSITIVE`).
7. **Privacy-first architecture:**
   Personal user files and document contents are **never** uploaded to central clouds or third-party APIs. Only cryptographic hashes, public domain names, URLs, and derived structural features are analyzed.
8. **Safe-by-design:**
   Strictly read-only, non-destructive operation. ACTIS never executes inspected files, deletes user files automatically, modifies system settings, or encrypts user data.
9. **Explainability:**
   Every detection includes itemized evidence trees, rule matches, model probabilities, confidence scores, and plain-English reasoning.

---

## Central Intelligence & Threat Sharing Network

```text
                  +----------------------------------------------+
                  |                 ACTIS Client                 |
                  +-----------------------+----------------------+
                                          |
                                          v
                  +----------------------------------------------+
                  |      Local Threat Intelligence Database      |
                  |                   (SQLite)                   |
                  +-----------------------+----------------------+
                                          |
                      (Push Verified / Pull Shared Intel)
                                          |
                                          v
                  +----------------------------------------------+
                  |    Central ACTIS Threat Intelligence API     |
                  |                (FastAPI REST)                |
                  +-----------------------+----------------------+
                                          |
                                          v
                  +----------------------------------------------+
                  |      Shared Verified Threat Intelligence     |
                  |      (CONFIRMED, SUSPICIOUS, CANDIDATE)      |
                  +-----------------------+----------------------+
                                          |
                     +--------------------+--------------------+
                     |                                         |
                     v                                         v
       +---------------------------+             +---------------------------+
       |       ACTIS Client 1      |     ...     |       ACTIS Client N      |
       +---------------------------+             +---------------------------+
```

---

## Layered Component Breakdown

### 1. Windows Resident Layer (`ACTIS Protection Service`)
- **Status:** `IMPLEMENTED` (Completed in Day 9 Foundation).
- **Responsibilities:**
  - Manages Windows resident service lifecycle (`start`, `stop`, `pause`, `resume`).
  - Enforces deterministic state transitions (`STOPPED`, `STARTING`, `RUNNING`, `PAUSED`, `DEGRADED`, `FAILED`).
  - Coordinates background worker pools with graceful cancellation, thread safety, and bounded recovery.
  - Ingests canonical `SecurityEvent` objects via thread-safe bounded queue (`SecurityEventQueue`).
  - Dispatches security events to the Analysis Orchestrator without executing detection or ML logic inside the service layer.
  - Provides Windows Service Control Manager (SCM) host adapter (`WindowsServiceHost`).
  - *Boundary:* Real-time filesystem monitoring hooks are deferred to Day 10.

### 2. Event & Input Layer (`scanners/`)
- **Status:** Core Foundation & Device Scanner `IMPLEMENTED`; Advanced Sensors `PROTOTYPE / NOT YET MILESTONE-COMPLETE`.
- **Role:** Translates raw inputs and system events into strongly-typed security event objects.
  - *URL Ingest (`url_scanner.py`):* `IMPLEMENTED` (Validates, normalizes, extracts 19 morphological features).
  - *Message Ingest (`text_analyzer.py`):* `IMPLEMENTED` (Parses links, detects urgency, deduplicates, delegates to URL scanner).
  - *Static PE Ingest (`file_feature_extractor.py`):* `IMPLEMENTED` (Extracts 15 static PE features, SHA-256, MD5, byte entropy).
  - *Device Scanner (`device_scanner.py`):* `IMPLEMENTED` (Completed in Day 8: user-authorized recursive crawler, junction loop protection, streaming SHA-256, structured scan results).
  - *Incremental Scan State (`incremental_state.py`):* `IMPLEMENTED` (Completed in Day 8: SQLite change classification, state persistence, skip unchanged files).
  - *File Watcher (`file_watcher.py`):* `PROTOTYPE / NOT YET MILESTONE-COMPLETE` (Filesystem change monitor; scheduled for Day 10).
  - *Clipboard Monitor (`clipboard_scanner.py`):* `PROTOTYPE / NOT YET MILESTONE-COMPLETE` (URL clipboard monitor).

### 3. Analysis Orchestrator
- **Status:** Day 7 Foundation `IMPLEMENTED`; Formal Centralization `PLANNED`.
- **Role:** Coordinates the analytical pipeline for each incoming event. Dispatches feature vectors to models, triggers heuristic rules, and queries threat intelligence without sensor-level duplication.

### 4. Detection Engine & Risk Engine (`detection_engine/`)
- **Status:** `IMPLEMENTED` (Unified Decision Engine, Risk Engine, Rule Engine, Threat Detector).
- **Role:** Fuses multi-source evidence into a normalized composite risk score (0–100) and severity band (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).

### 5. Shared Threat Intelligence (`threat_intelligence/`, `reports/`)
- **Status:** Local TI `IMPLEMENTED`; Online TI & Central Sync `PROTOTYPE / NOT YET MILESTONE-COMPLETE`.
- **Role:** Provides local SQLite indicator lookups, optional external enrichment (VirusTotal v3), and client synchronization with the central ACTIS Threat Intelligence API.

### 6. User & System Presentations
- **Status:** `PROTOTYPE / NOT YET MILESTONE-COMPLETE` (Scheduled for Days 13–14).
  - *Command Dashboard (`dashboard/app.py`):* Streamlit interactive UI.
  - *Notification System (`notifications/notifier.py`):* Desktop alerts and telemetry banners.
  - *Audit Reporting (`reports/report_generator.py`):* `IMPLEMENTED` (JSON, CSV, Markdown reports).
  - *AI Security Assistant (`assistant/security_assistant.py`):* Grounded offline security explainer.
