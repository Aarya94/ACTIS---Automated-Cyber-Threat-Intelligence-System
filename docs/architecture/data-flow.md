# ACTIS Data Flow & Privacy Boundaries

**Authoritative Architecture Document**  
**Milestone:** Post-Day-7 Architectural Evolution  
**Status:** Approved Target Architecture  

---

## 1. Event-Driven Data Flow Lifecycle

In the post-Day-7 event-driven architecture, data traverses from operating system stimuli through the resident protection layer into the centralized analysis orchestrator, detection engine, and persistence layers:

```text
  [Windows OS / User Space]
             │
             ▼
  ┌────────────────────────────────────────────────────────┐
  │         ACTIS Protection Service (Resident)            │
  │ - System event intake & debouncing                     │
  │ - File-write completion stability verification         │
  │ - Non-blocking event queueing                          │
  └──────────────────────────┬─────────────────────────────┘
                             │
                             ▼
  ┌────────────────────────────────────────────────────────┐
  │                 Event / Input Layer                    │
  │ - FileSecurityEvent    (Path, timestamp, trigger)      │
  │ - UrlSecurityEvent     (Normalized URL, source)        │
  │ - MessageSecurityEvent (Extracted links, urgency)      │
  │ - OnDemandScanEvent    (Target path, recursive flag)   │
  └──────────────────────────┬─────────────────────────────┘
                             │
                             ▼
  ┌────────────────────────────────────────────────────────┐
  │                 Analysis Orchestrator                  │
  │ - Canonical URL Normalization & Feature Extraction     │
  │ - Safe Read-Only Static PE Inspection & Byte Entropy   │
  │ - Hash Computation (SHA-256, MD5)                      │
  └─────────────┬───────────────────────────┬──────────────┘
                │                           │
                ▼                           ▼
  ┌───────────────────────────┐ ┌──────────────────────────┐
  │ Threat Intelligence Layer │ │  Analytical Inference    │
  │ - Local SQLite Database   │ │ - Phishing RF Model      │
  │ - Online TI (Optional VT) │ │ - Malware PE RF Model    │
  │ - Central ACTIS TI Sync   │ │ - Deterministic Rules    │
  └─────────────┬─────────────┘ └───────────┬──────────────┘
                │                           │
                └─────────────┬─────────────┘
                              │
                              ▼
  ┌────────────────────────────────────────────────────────┐
  │            Detection & Decision Engine                 │
  │ - Multi-Criteria Evidence Fusion                       │
  │ - Dynamic Weight Normalization                         │
  │ - Categorical State Classification                     │
  │   (CONFIRMED, SUSPICIOUS, CANDIDATE, FALSE_POSITIVE)   │
  └───────────────────────────┬────────────────────────────┘
                              │
                              ▼
  ┌────────────────────────────────────────────────────────┐
  │             Persistence & User Presentation            │
  │ - Local SQLite Database (threats, scans, detections)   │
  │ - Audit Exporters (JSON, CSV, Markdown)                │
  │ - User Desktop Alerts & Streamlit Command Dashboard    │
  │ - Grounded AI Security Assistant Explanations          │
  └────────────────────────────────────────────────────────┘
```

---

## 2. Data Objects in Motion

### 2.1 File Security Events & Executables
- **Ingestion:** Generated when a file is created, downloaded, modified, or queued by an on-demand scan.
- **Debounce & Stabilization:** The Protection Service applies write-stability checks (e.g. verifying file handles are released) before dispatching the event.
- **Inspection:** Inspected strictly in read-only binary mode (`open(path, 'rb')`). Cryptographic hashes (SHA-256, MD5), byte entropy distributions, and static PE headers are parsed entirely in memory.
- **Privacy Boundary:** **ACTIS NEVER uploads complete user files or documents to any external server or third-party API.** Only cryptographic hashes (SHA-256/MD5) are queried externally. Personal documents (PDFs, Word documents, spreadsheets, images) are never exfiltrated.

### 2.2 URL Security Events & Domains
- **Ingestion:** Acquired via direct user query, clipboard URL hook, or extracted from messages/documents.
- **Normalization:** Enforces canonical lowercase scheme and hostname, removes default ports (80, 443), strips trailing punctuation and balanced boundary delimiters, while preserving meaningful query parameters and path structures.
- **Privacy Boundary:** Local and private network IP ranges (e.g., `127.0.0.1`, `localhost`, `10.*`, `192.168.*`) are recognized locally and never queried against external threat feeds.

### 2.3 Message Security Events & Communications
- **Ingestion:** Plaintext messages, emails, or chat transcripts submitted by the user.
- **Processing:** Analyzed in-memory for social engineering urgency patterns and embedded web links. Extracted URLs are canonically deduplicated and passed to the Analysis Orchestrator.
- **Privacy Boundary:** **Raw message text is NEVER stored in the database or transmitted externally.** Only extracted URLs and computed suspicion metrics are preserved in local audit telemetry.

### 2.4 Indicators of Compromise (IoCs)
- **Ingestion:** Extracted from confirmed local detections, external feeds, or administrative synchronization.
- **Types:** `sha256`, `md5`, `url`, `domain`, `ip`.
- **Validation:** Strict syntactic validation (hexadecimal hashes, RFC-compliant hostnames and IPs).

### 2.5 Detection Records & Telemetry
- Persisted locally in SQLite (`scans`, `detections`, `scan_items`).
- Stores scan session timestamps, itemized evidence breakdowns, confidence ratings, and rule IDs.
- Stored exclusively in local user application directories, protected by operating system user permissions.

### 2.6 Incremental Scan States & File Fingerprints
- **Ingestion & Metadata:** Discovered files are inspected for non-content filesystem metadata (`file_size`, `mtime`, `ctime`, accessibility) via `FileMetadata`.
- **Change Detection:** `IncrementalStateManager` compares metadata and analytical model versions against persistent SQLite records (`file_scan_states`).
  - **`UNCHANGED_FILE`**: If size and modification timestamps match, and analyzer/model versions are compatible (`is_version_compatible`), deep file analysis is skipped, the cached verdict is reused, and `last_scanned_at` is updated.
  - **`NEW_FILE` / `CHANGED_FILE`**: A streaming 64 KB chunked SHA-256 fingerprint is computed with pre/post-stat race detection (`FILE_CHANGED_DURING_HASH`), followed by canonical file analysis.
- **Privacy & Safety:** Scan states store only canonical paths, sizes, timestamps, hashes, versions, and risk verdicts. Raw file contents are never persisted.

---

## 3. Explicit Privacy Safeguards

1. **Zero Full-File Uploads:** Neither the local client nor the central threat sharing backend ever transmits, accepts, or stores user binaries or document payloads.
2. **Offline-First Functionality:** ACTIS operates with complete detection fidelity in fully offline or air-gapped environments. External reputation feeds are strictly an optional secondary enrichment layer.
3. **No Keylogging or Screen Capture:** ACTIS does not hook keyboard drivers, record keystrokes, capture screens, or monitor user input. The clipboard sensor inspects strictly text that matches standard URL syntax.
4. **Credential Isolation:** `.env` credentials, API tokens, and local secret keys are strictly excluded from logging, audit reports, and repository version control.
