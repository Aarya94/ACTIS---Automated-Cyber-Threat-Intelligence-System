# ACTIS Scanning Workflow & Safety Controls

**Authoritative Architecture Document**  
**Milestone:** Post-Day-7 Architectural Evolution  
**Status:** Approved Target Architecture  

---

## 1. Scanner Subsystems & Ingestion Layer

In the post-Day-7 architecture, **scanners and sensors act strictly as event/input providers**. They do not implement independent detection logic. Instead, they capture input, validate and normalize syntax, and delegate analysis to the **centralized Analysis Orchestrator**.

| Ingestion Mechanism | Input Domain | Status | Operational Role |
|---|---|---|---|
| **URL Scanner** | Web links, query strings | `IMPLEMENTED` | Canonical normalization, 19-feature extraction, session caching, orchestrator delegation. |
| **Message Scanner** | Plaintext, emails, chats | `IMPLEMENTED` | Boundary cleanup, social engineering urgency heuristics, deduplication, strict delegation to URL scanner. |
| **Static PE Extractor** | Windows PE executables | `IMPLEMENTED` | Safe read-only binary parsing (`pefile`), 15 static PE features, SHA-256, MD5, byte entropy. |
| **Device Scanner** | Filesystem trees, volumes | `IMPLEMENTED` | Recursive crawler with cooperative cancellation, junction/reparse-point loop safety, safe metadata, streaming chunked SHA-256 fingerprinting, incremental scan state, and canonical analysis pipeline delegation. |
| **File Watcher** | Real-time file drops | `IMPLEMENTED` | Filesystem change events (`watchdog`) with normalization, temporary-file filtering, debounce window, bounded queue, incremental state check, race protection, and canonical analysis delegation. (Completed Day 10) |
| **Clipboard Monitor** | Windows clipboard buffer | `PROTOTYPE / NOT YET MILESTONE-COMPLETE` | Background URL hook with strict privacy filtering. |

---

## 2. Canonical Delegation Architecture

### 2.1 The Single Canonical URL Scanning Path
Day 7 established the architectural mandate that there must be **strictly ONE canonical analysis path** per target domain. The Message Scanner does NOT duplicate:
- Feature extraction
- Phishing model invocation
- Threat intelligence queries
- Risk calculation
- Categorical classification

Instead, the Message Scanner identifies candidate URLs, strips boundary noise, performs canonical deduplication, and passes each unique canonical URL to the common URL analysis logic:

```text
Message / Text Input
         │
         ▼
Text Parsing & Regex Extraction
         │
         ▼
Boundary Punctuation & Balanced Parenthesis Cleanup
         │
         ▼
Canonical Normalization & Order-Preserving Deduplication
         │
         ▼
┌────────────────────────────────────────────────────────┐
│            COMMON URL ANALYSIS PIPELINE                │
│  (Validation -> Normalization -> TI -> ML -> Rules)    │
└────────────────────────┬───────────────────────────────┘
                         │
                         ▼
Per-URL Typed DetectionResult Models
                         │
                         ▼
MessageScanResult Aggregation (Max Risk + SE Urgency)
```

---

## 3. In-Depth Operational Workflows

### A. URL Scanning Workflow (`scanners/url_scanner.py`)
1. **Input Validation & Sanitization:** Validates length ($\le 4096$ chars), checks supported schemes (`http`, `https`), detects control characters/newlines, and handles `None` or empty strings without exceptions.
2. **Canonical Normalization:** Normalizes scheme and hostname to lowercase, strips outer whitespace, quotes, and brackets, removes default ports (`:80`, `:443`) while preserving custom ports, query parameters, and fragments.
3. **Session Caching:** Queries local thread-safe session cache to eliminate redundant analysis for repeated URLs.
4. **Local Threat Intelligence:** Queries exact normalized URL, domain, and hostname against local SQLite indicators.
5. **Morphological Feature Extraction:** Computes the verified 19 morphological features in deterministic order matching the Random Forest model contract.
6. **Machine Learning Inference:** Invokes the phishing model (`models/phishing_model.pkl`) to obtain probabilistic threat evidence.
7. **Safe Heuristic Rules:** Evaluates deterministic lexical signals (IP hostnames, suspicious TLDs, excessive subdomains, `@` tricks, excessive length >150 chars, percent-encoding density, non-standard service ports).
8. **Detection Decision Engine:** Fuses evidence into a typed `DetectionResult` with confidence rating, five-tier risk level, and explainable evidence breakdown.

### B. Message Scanning Workflow (`scanners/text_analyzer.py`)
1. **Boundary-Aware URL Extraction:** Discovers URLs using regex while safely stripping trailing sentence delimiters (`.`, `,`, `;`, `!`) and unmatched brackets, while preserving balanced Wikipedia-style parenthetical links (`/wiki/Phishing_(security)`).
2. **Canonical URL Deduplication:** Normalizes extracted links and deduplicates repeated instances (e.g. 100 repeated URLs are analyzed strictly once).
3. **Delegation to Canonical URL Scanner:** Iterates solely over unique canonical URLs and delegates to `scan_url_logic`.
4. **Social Engineering Heuristics:** In-memory analysis of urgency cues ("immediate action required", "account suspended"), credential prompts ("verify password"), and financial lures.
5. **Message-Level Aggregation:** Produces a structured `MessageScanResult` combining URL detection outcomes with social engineering scores.
6. **Privacy-Preserving Audit:** Raw message text is NEVER logged or transmitted externally.

### C. File & Static PE Scanning Workflow (`scanners/file_feature_extractor.py`)
1. **Size Verification:** Validates file size against `MAX_FILE_SIZE_BYTES` (default 100 MB). Over-limit files are parsed for streaming cryptographic hashes only.
2. **Cryptographic Hashing:** Reads file in 64 KB chunks to generate SHA-256 and MD5 hashes.
3. **Static PE Parsing:** Opens Windows PE binaries (`.exe`, `.dll`, `.sys`) in read-only binary mode (`'rb'`) to parse COFF headers, Optional headers, section tables, and import directories via `pefile`.
4. **Byte Entropy Calculation:** Computes Shannon entropy per section to detect encrypted or packed payloads ($\text{entropy} > 7.2$).
5. **Heuristic Rule Evaluation:** Flags known packer sections (`UPX0`, `UPX1`, `.aspack`), missing digital signatures, and high-risk API imports (`VirtualAllocEx`, `WriteProcessMemory`).
6. **Malware ML Inference:** Evaluates the 15-feature Windows PE Random Forest model (`models/malware_model.pkl`).

### D. Device Scanner & Incremental Scan State Workflow (`scanners/device_scanner.py`, `scanners/incremental_state.py`)
1. **User-Authorized Discovery:** Scans user-specified directory, persistence paths (Quick Scan), or system drives (Full Scan).
2. **Reparse Point & Loop Guardrails:** `TraversalSafetyHelper` detects `FILE_ATTRIBUTE_REPARSE_POINT` (0x0400) and tracks directory `(dev, ino)` pairs to prevent circular traversal and junction looping.
3. **Safe Metadata Extraction:** `collect_file_metadata` retrieves size, timestamps (`mtime`, `ctime`), and accessibility without buffering contents.
4. **Incremental Scan State Verification:** `IncrementalStateManager` queries persistent SQLite storage (`file_scan_states`).
   - **`UNCHANGED_FILE`**: If size and modification timestamps match previous verified state and analytical model versions match (`is_version_compatible`), deep file analysis is skipped, the previous verdict is reused, and the scan timestamp is refreshed.
   - **`NEW_FILE` / `CHANGED_FILE`**: Proceeds to safe analysis.
   - **`REMOVED_FILE` / `UNAVAILABLE_FILE`**: Records state accordingly; missing files can be pruned via `prune_missing_files()`.
5. **Streaming Chunked Fingerprinting:** Reads file in 64 KB chunks to compute SHA-256 safely. Compares file metadata before and after streaming to detect race conditions (`FILE_CHANGED_DURING_HASH`).
6. **Canonical Pipeline Delegation:** Eligible files pass into canonical `scan_file` -> `ThreatDetector.analyze_file` (PE static extraction, heuristic rules, Random Forest ML model, risk engine, and SQLite logging).
7. **State Persistence & Structured Reporting:** Constructs updated `FileScanState` with versioning tags, persists to SQLite, and returns a strongly-typed `DeviceScanResult`.
8. **Cooperative Cancellation:** `ScanCancellationToken` allows callers to interrupt ongoing scans at any time without data corruption or lingering file locks.

### E. Event-Driven File Protection (`scanners/file_watcher.py`, `service/file_pipeline.py`) — *Completed Day 10*
1. **Event Capture & Bridging:** `FilesystemEventSource` monitors user-authorized paths using native Windows notifications via `watchdog.Observer`, converting OS events into non-blocking callback notifications.
2. **Path Normalization:** `FilesystemEventNormalizer` standardizes absolute path resolution, slashes, and Windows case-folding.
3. **Filtering:** `FileEventFilter` ignores directory events, inaccessible paths, and temporary/editor swap patterns (`.tmp`, `~$*`, `.crdownload`, `.part`).
4. **Debouncing & Deduplication:** `FileEventDebouncer` coalesces rapid write sequences (configurable window, default 0.5s) and checks file size stability before analysis.
5. **Bounded Intake Queue:** `SecurityEventQueue` buffers events with bounded capacity, high-watermark tracking, and throttled drop logging under burst pressure.
6. **Incremental State Integration:** `FileProtectionPipeline` verifies file metadata against `IncrementalStateManager`. If size, modification time, and model versions match, the file is classified as `UNCHANGED` and expensive analysis is skipped.
7. **Filesystem Race Hardening:** Verifies file existence and streams pre/post-fingerprints (`compute_file_fingerprint`, stat comparison) to catch files that disappeared (`DISAPPEARED`), became inaccessible (`INACCESSIBLE`), or mutated during analysis (`CHANGED_DURING_ANALYSIS`).
8. **Canonical Pipeline Delegation:** Eligible new or changed files pass into canonical `scan_file` -> `ThreatDetector.analyze_file` without duplicating detection logic.
9. **State Persistence:** Results are persisted to SQLite via `IncrementalStateManager.record_file_scan()`.

### F. Clipboard URL Scanner — *Target: Post-Day 10*
1. **Clipboard Monitoring:** Inspects clipboard string content on change notifications.
2. **Strict Regex Filter:** Discards any text not conforming to standard URL syntax to protect passwords and personal clips.
3. **Deduplication:** Maintains an in-memory cache of recently inspected URLs to avoid redundant analysis.

---

## 4. Strict Safety & Non-Destructive Principles

ACTIS enforces non-negotiable safety guardrails across all scanning modules:
- **Static Analysis Only:** Files are analyzed as raw data bytes; **they are NEVER executed, debugged, or injected into running processes.**
- **No Automatic Deletion:** ACTIS **never automatically deletes user files.** All remediation guidance is presented as advisory recommendations for the user.
- **No File Modification:** Files are opened strictly with `'rb'` (read-only binary mode). No file headers, contents, or metadata are ever altered.
- **No System Tampering:** ACTIS does not disable Windows Defender, modify firewall configurations, or alter Windows registry security policies.
- **Strict Privacy:** Raw user messages, personal documents, and private credentials are never logged, persisted, or broadcast.
