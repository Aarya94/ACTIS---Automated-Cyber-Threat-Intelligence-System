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
1. **Input Normalization**: Trims whitespace, validates RFC URL syntax, parses protocol, hostname, port, and query components.
2. **Morphological Feature Extraction**: Computes length, symbol counts (dots, hyphens, slashes, ampersands), and sub-domain counts.
3. **Local DB & External TI Lookup**: Hashes normalized URL and domain to check known malicious listings.
4. **ML Inference**: Invokes the 19-feature Random Forest phishing model (`models/phishing_model.pkl`).
5. **Rule Heuristics**: Checks for direct IP hostnames, typosquatting patterns, unencoded credentials, or excessive redirection symbols (`//`).
6. **Risk Engine Synthesis**: Evaluates evidence layers to produce a 0–100 score and explainability report.

### B. Message Scanning Workflow
1. **Link Extraction**: Employs URL-regex patterns to discover all embedded HTTP/HTTPS URLs.
2. **Social Engineering Heuristics**: Analyzes textual corpus for urgency cues ("immediate action required", "account suspended", "verify password", "wire transfer", "cryptocurrency wallet").
3. **Recursive Link Analysis**: Passes all extracted links to the URL Scanner.
4. **Combined Threat Assessment**: Returns maximum link risk score compounded by message-level social engineering probability.

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
