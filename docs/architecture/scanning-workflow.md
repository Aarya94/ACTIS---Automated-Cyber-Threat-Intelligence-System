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
| **Device Scanner** | Filesystem trees, volumes | `PROTOTYPE / NOT YET MILESTONE-COMPLETE` | Recursive crawler with cancellation tokens and junction loop protection. Target: Day 8. |
| **File Watcher** | Real-time file drops | `PROTOTYPE / NOT YET MILESTONE-COMPLETE` | Filesystem change events (`watchdog`) with write-stability debounce. Target: Day 10. |
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

### D. Device Scanner (Crawler) — *Target: Day 8*
1. **Scan Modes:** Quick Scan (high-risk locations: Downloads, Desktop, Temp, Startup), Custom Scan (user path), or Full Drive Scan.
2. **Reparse Point Protection:** Tracks canonical device inodes and symbolic links to prevent infinite traversal loops caused by Windows directory junctions.
3. **Incremental State:** Tracks file timestamps and cryptographic fingerprints to avoid rescanning unchanged files.
4. **Cancellation Token:** Supports cooperative asynchronous interruption so users can cancel volume scans at any time.

### E. Background File Watcher — *Target: Day 10*
1. **Event Capture:** Observes file creation and modification events via Windows filesystem hooks (`watchdog`).
2. **Debounce Delay:** Enforces debounce intervals to allow file write operations to finalize before opening for read-only inspection.
3. **Orchestrator Handoff:** Dispatches settled file paths into the Analysis Orchestrator without blocking the OS event pump.

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
