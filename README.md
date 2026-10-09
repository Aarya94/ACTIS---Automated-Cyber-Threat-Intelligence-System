# ACTIS — Automated Cyber Threat Intelligence System

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

### Implemented Baseline Foundation (Days 1–7)
- **Configuration Management (`config/`):** Strongly-typed `AppConfig`, environment loader, path resolver, constraint validation (11 passing tests).
- **Enterprise Logging (`config/logger.py`):** Rotating file logs, structured JSON formatters, credential sanitization.
- **Relational Threat Database (`reports/`):** SQLite schema with WAL mode (`threats`, `indicators`, `scans`, `detections`, `scan_items`), indexed queries, JSON/CSV/Markdown report generation.
- **Phishing Machine Learning Model (`models/`, `detection_engine/`):** 19-feature morphological Random Forest classifier with formal metadata contract validation.
- **Static Windows PE Extraction (`scanners/file_feature_extractor.py`):** Read-only PE header and section parsing (`pefile`), Shannon byte entropy, 64 KB chunked SHA-256 and MD5 hashing (21 passing tests).
- **URL Scanner Hardening (`scanners/url_scanner.py`):** RFC scheme validation, canonical normalization, default port stripping, 19-feature vector extraction, session caching.
- **Message Scanner Hardening (`scanners/text_analyzer.py`):** Boundary-aware link extraction, canonical deduplication, social engineering heuristics, and strict delegation to canonical URL analysis.
- **Detection Decision Engine (`detection_engine/`):** Multi-criteria evidence fusion, dynamic weight normalization, deterministic heuristic rules, confidence calculation, and explainability trees.
- **Automated Test Infrastructure (`tests/`):** 144 unit and integration tests passing with 100% success rate.

### Planned Subsystems in Target Architecture (Days 8–16)
- **Device Scanner with Incremental State (Day 8):** Recursive crawler with reparse-point junction protection and fingerprint caching.
- **Windows Protection Service (Day 9):** Lightweight resident background service managing endpoint state and event intake.
- **Event-Driven File Protection (Day 10):** Real-time filesystem hooks (`watchdog`) with write-stability debounce filtering.
- **Online Threat Intelligence Connectors (Day 11):** VirusTotal v3 client with rate limiting and offline fallback.
- **Central ACTIS Threat Intelligence API (Day 12):** FastAPI federated intelligence sharing service with anti-poisoning state machine.
- **Command Dashboard & Desktop Alerts (Day 13):** Streamlit user console and native Windows toast notifications.
- **AI Security Assistant (Day 14):** Safe, offline-grounded natural language security explainer.
- **Security Hardening & Broad Testing (Day 15):** Adversarial sample evaluation and stress testing.
- **Final Integration & Release (Day 16):** Milestone packaging, documentation finalization, and demonstration scripts.

*(Note: Prototype files for some of these future modules exist historically in the repository; they are being systematically hardened and integrated per the post-Day-7 roadmap and are not yet production-ready.)*

---

## 📦 Project Structure

```text
ACTIS/
├── config/                   # Type-safe configuration, environment loader, logging
├── data/                     # Local SQLite databases, training datasets
├── models/                   # Serialized ML model artifacts (*.pkl) and JSON metadata
├── scanners/                 # Event/input providers (URL, text, PE static analyzer)
├── detection_engine/         # Decision engine, risk engine, heuristic rule engine
├── threat_intelligence/      # Local indicator lookup, external API clients, sync manager
├── reports/                  # SQLite threat database schemas, query interfaces, reports
├── notifications/            # Alert formatting and user dispatch queue
├── dashboard/                # Streamlit web command center UI
├── assistant/                # Offline grounded security assistant
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
- **144 tests collected**
- **144 tests passed (100% success rate)**
- **0 failures / 0 errors**

---

## 🔒 Privacy & Operational Principles

1. **Indicator Sharing Only:** Only verified threat indicators (cryptographic hashes, malicious URLs, domains) are submitted to threat networks — user documents, private files, and personal data are never uploaded.
2. **Offline-First Functionality:** ACTIS operates with full analytical capability in completely offline or air-gapped environments using local machine learning models and SQLite threat databases. External API feeds serve as an optional enrichment layer.
3. **Transparent Explainability:** Every threat evaluation provides understandable, itemized reasoning detailing why a risk score was assigned and what defensive action is advised.
