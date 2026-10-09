# ACTIS Scanning Workflow & Safety Controls

This document details the operational execution patterns, data pipelines, and non-negotiable safety guardrails for all six ACTIS scanner subsystems.

---

## 1. Scanner Subsystems Overview

| Scanner | Input Domain | Status | Operational Pattern |
|---|---|---|---|
| **URL Scanner** | Web links, query strings | `IMPLEMENTED` | Lexical extraction, URL normalization, morphological ML scoring, TI feed check. |
| **Message Scanner** | Text messages, chat, email | `IMPLEMENTED` | Regex link parsing, social engineering urgency analysis, credential solicitation detection. |
| **File Scanner** | Single local binary/file | `IMPLEMENTED` | Read-only static inspection via `pefile` and `hashlib`. Extracts 15 PE features, hashes, entropy. |
| **Device Scanner** | Directory trees, drives | `IMPLEMENTED` | Multi-threaded recursive crawler with cancellation tokens and junction loop protection. |
| **File Watcher** | Target watch directories | `IMPLEMENTED` | Event-driven filesystem monitoring (`watchdog`) with write-stability debounce delays. |
| **Clipboard Scanner**| Windows clipboard buffer | `IMPLEMENTED` | Polling monitor extracting URL strings with duplicate deduplication and privacy filters. |

---

## 2. In-Depth Operational Workflows

### A. URL Scanning Workflow
1. **Input Validation & Sanitization**: Validates candidate length (<= 4096 chars), verifies supported schemes (`http`, `https`), detects illegal control characters, and handles `None`/empty inputs without application faults.
2. **Canonical Normalization**: Lowercases scheme and hostname, removes leading/trailing whitespace and enclosing quotes/brackets, strips default ports (`:80` for HTTP, `:443` for HTTPS) while preserving non-standard ports, and retains query strings and fragments without altering destination semantics.
3. **In-Memory Caching**: Checks session scan cache keyed by canonical URL to prevent redundant reprocessing.
4. **Local Threat Intelligence**: Checks exact normalized URL, hostname, and parent domain against local database IOCs (`indicators` table) offline.
5. **Morphological Feature Extraction**: Computes the exact 19 morphological features in strict schema order (`url_length`, character counts for dots, hyphens, slashes, `@`, redirection `//`, etc.) matching the trained classifier contract.
6. **Machine Learning Inference**: Invokes the Random Forest phishing classifier (`models/phishing_model.pkl`) to generate structured prediction probabilities and confidence scores.
7. **Safe Heuristic Rules**: Evaluates deterministic lexical indicators (raw IP hostname, suspicious TLDs, excessive subdomains, credential keywords in path, `@` destination tricks, excessive length >150 chars, percent-encoding density, non-standard service ports). Heuristics serve strictly as contributing evidence rather than sole verdict determinants.
8. **Detection Decision Fusion**: Routes all evidence signals into `DetectionDecisionEngine`, producing a typed `DetectionResult` with confidence, five-tier risk level, and human-readable explanation.

### B. Message Scanning Workflow
1. **Boundary-Aware URL Extraction**: Uses regex to discover URLs in text while safely stripping sentence punctuation (`.`, `,`, `;`, `!`) and outer brackets/parentheses (`(...)`, `[...]`), while preserving balanced internal parentheses (such as Wikipedia reference links).
2. **Canonical URL Deduplication**: Normalizes extracted URLs and deduplicates repeated instances and case variants (`https://example.com` vs `HTTPS://EXAMPLE.COM`). Tracks per-URL occurrence counts.
3. **Delegation to Canonical URL Scanner**: Iterates solely over unique canonical URLs and passes them to `scan_url_logic`. Guarantees zero duplication of model inference or threat intelligence queries.
4. **Social Engineering Heuristics**: Analyzes textual corpus for urgency cues ("immediate action required", "account suspended"), credential solicitation ("verify password", "login credentials"), and financial lure patterns ("wire transfer", "cryptocurrency").
5. **Message-Level Aggregation**: Combines maximum URL threat score with social engineering probability into a structured `MessageScanResult`.
6. **Privacy-Preserving Audit**: Retains structural counts and risk indicators without permanently logging or transmitting private communication content.


### C. File & Static PE Scanning Workflow
1. **Size Verification**: Validates file size against `MAX_FILE_SIZE_BYTES` (default 100 MB). Files exceeding the limit are parsed for streaming cryptographic hashes only to avoid memory exhaustion.
2. **Cryptographic Hashing**: Reads file in 64 KB chunks to generate canonical SHA-256 and MD5 hashes.
3. **Static PE Parsing**: For Windows Portable Executable binaries (`.exe`, `.dll`, `.sys`), uses `pefile` to extract COFF headers, Optional headers, section characteristics, and imports in read-only binary mode.
4. **Byte Entropy Calculation**: Computes Shannon entropy per section to identify encrypted or packed payloads (entropy > 7.2).
5. **Heuristic Rule Evaluation**: Flags known packer section names (`UPX0`, `UPX1`, `.aspack`), missing digital signatures, and process injection API imports (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`).
6. **Malware ML Inference**: Evaluates the 15-feature Windows PE Random Forest model (`models/malware_model.pkl`).

### D. Device Scanner (Crawler)
1. **Scan Modes**: Quick Scan (high-risk persistence points: Downloads, Desktop, Temp, Startup), Custom Scan (user path), or Full Drive Scan.
2. **Reparse Point Protection**: Tracks canonical device inodes and symbolic links to prevent infinite traversal loops caused by Windows directory junctions.
3. **Cancellation Token**: Supports cooperative asynchronous interruption so users can cancel long-running volume scans at any time.

### E. Background File Watcher
1. **Event Capture**: Listens for `FileCreatedEvent` and `FileModifiedEvent` via the Windows filesystem API (`ReadDirectoryChangesW` via `watchdog`).
2. **Debounce Delay**: Enforces `WATCHDOG_DEBOUNCE_SECONDS` (default 2.0s) to allow file writes to complete before opening the file for read-only hashing.
3. **Async Dispatch**: Queues settled files into the File Scanner pipeline without blocking the OS event pump.

### F. Clipboard URL Scanner
1. **Clipboard Sniffing**: Inspects clipboard string content on change notifications.
2. **Regex Filter**: Discards any text that does not match standard URL syntax (protecting passwords, personal text, or document clips).
3. **Deduplication**: Maintains a circular LRU cache of recently inspected URLs to prevent repetitive analysis of the same link.

---

## 3. Strict Safety & Non-Destructive Principles

ACTIS enforces non-negotiable safety guardrails across all scanning modules:

- **Static Analysis Only**: Suspicious files are analyzed as raw data bytes; **they are NEVER executed, debugged, or injected into running processes.**
- **No Automatic Deletion**: ACTIS **never automatically deletes user files.** All remediation guidance is presented as advisory recommendations for the user.
- **No File Modification**: Files are opened strictly with `'rb'` (read-only binary mode). No file headers, contents, or metadata are ever altered.
- **No System Tampering**: ACTIS does not disable Windows Defender, modify firewall configurations, or alter Windows registry security policies.
- **Strict Privacy**: Raw user messages, personal documents, and private credentials are never logged, persisted, or broadcast.
