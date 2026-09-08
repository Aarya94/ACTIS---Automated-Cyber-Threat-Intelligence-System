# ACTIS Data Flow & Privacy Boundaries

This document defines how data objects traverse ACTIS, how sensitive telemetry is handled, and the strict privacy boundaries enforced throughout the system.

---

## Data Ingestion & Transformation Lifecycle

```text
  [User Space]                     [ACTIS Engine]                     [Persistence / Egress]
  
  Raw URL / Clipboard ----------> Morphological Extraction ----------> Feature Vector (19 floats)
                                                                               |
  Raw Text / Message -----------> Regex & Urgency Parser -----------> Extracted Links & Heuristics
                                                                               |
  Local File -------------------> Binary Stream (Read-Only) ---------> SHA-256 / MD5 Hash
                                 PE Header Parser (pefile) ---------> Structural Metadata (15 floats)
                                                                               |
                                                                               v
                                                                   Detection Orchestrator
                                                                               |
                                    +------------------------------------------+
                                    |
                                    v
                            [Evaluation Pipeline]
                            - Local SQLite DB Lookup
                            - ML Random Forest Inference
                            - Rule Heuristic Evaluation
                            - Normalized Risk Engine
                                    |
                                    v
                            [Composite Detection Object]
                            - Target Identifier (Hash/URL)
                            - Risk Score (0-100) & Severity
                            - Detailed Evidence Breakdown Tree
                                    |
                                    +--------------------+---------------------+
                                    |                                         |
                                    v                                         v
                         [Local Storage]                         [Optional Central Sync]
                         - reports/threat_database.db             - Central FastAPI Endpoint
                           (scans, detections, items)               (Canonical Indicators ONLY:
                         - Sanitized Report Exporter                 SHA-256, URL, Domain)
                           (JSON, CSV, Markdown)
```

---

## Data Objects in Motion

### 1. URLs & Domains
- **Ingestion**: Acquired via direct CLI arguments, dashboard text boxes, clipboard polling, or message parser extraction.
- **Normalization**: Stripped of trailing slashes, normalized to lowercase schemes/hostnames, fragments removed.
- **Privacy Boundary**: Internal company Intranet URLs (e.g. `http://localhost`, `192.168.*`, `.internal`) are handled locally and flagged as private IP spaces.

### 2. Text Messages & Communications
- **Ingestion**: Raw text supplied directly by the user to the Message Scanner.
- **Processing**: Regex extracts embedded HTTP/HTTPS links. Heuristic dictionaries calculate urgency and credential solicitation metrics.
- **Privacy Boundary**: **Raw message content is NEVER persisted to the threat database or transmitted externally.** Only extracted URLs and computed suspicion scores are stored in scan telemetry.

### 3. Files & Executables
- **Ingestion**: Targeted via path selection, background file watcher notifications, or device directory crawler.
- **Processing**: Inspected statically in read-only binary mode (`open(path, 'rb')`). Cryptographic hashes (SHA-256, MD5) and PE header attributes are computed entirely in memory.
- **Privacy Boundary**: **ACTIS NEVER uploads complete personal user files to any server or external API.** Only cryptographic hashes (SHA-256/MD5) are used for external threat reputation lookups. Personal documents (PDFs, Word documents, images, spreadsheets) are NEVER uploaded or exposed to third-party endpoints.

### 4. Indicators of Compromise (IoCs)
- **Ingestion**: Extracted from confirmed threats, external feeds, or administrative ingestion.
- **Types**: `sha256`, `md5`, `url`, `domain`, `ip`.
- **Validation**: Enforced syntax validation (hexadecimal regex for hashes, standard RFC validation for IP addresses and URLs).

### 5. Detection Records & Scan History
- Persisted locally in SQLite (`scans`, `detections`, `scan_items`).
- Stores scan timestamps, files scanned, detected threat types, and itemized evidence breakdowns.
- Excluded from Git tracking and protected with operating system user-level permissions.

---

## Explicit Privacy & Data Protection Safeguards

1. **Zero Full-File Uploads**: Neither the local client nor the central backend ever transmits or accepts full user executable binaries or document payloads.
2. **Offline-First Functionality**: ACTIS operates with 100% functionality in air-gapped or offline environments. External API enrichment is strictly an optional layer.
3. **No Keylogging or Screen Capture**: ACTIS does not install keyboard hooks, collect keystrokes, or take screen captures. The clipboard scanner examines only text matching URL syntax.
4. **Credential Isolation**: Local `.env` files and API keys are strictly excluded from logging, reports, and Git commits.
