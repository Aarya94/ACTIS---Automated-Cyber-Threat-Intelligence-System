# ACTIS Security Boundaries & Operational Constraints

**CRITICAL POLICY DOCUMENT — AUTHORITATIVE FOR ALL DEVELOPERS AND AI CODING AGENTS**  
**Milestone:** Post-Day-7 Architectural Evolution  
**Status:** Binding Security Policy  

This document establishes the binding operational boundaries for ACTIS (Automated Cyber Threat Intelligence System). As ACTIS evolves into an event-driven, Windows-oriented cybersecurity platform, it remains fundamentally a **defensive, advisory, and read-only** system. It is explicitly **not** an autonomous administrative system with destructive or intrusive execution authority.

---

## 1. What ACTIS MAY Do (Authorized Defensive Capabilities)

ACTIS is authorized to perform the following defensive cybersecurity functions:

1. **Resident Event Intake & Debouncing:** Run a lightweight resident background service that monitors file and URL events, debounces write locks, and queues analysis tasks without blocking operating system threads.
2. **Scan User-Authorized Filesystem Locations:** Read local files, directories, and storage volumes specified by the user or preconfigured in standard user-space scan targets.
3. **Analyze URLs & Web Addresses:** Parse, normalize, compute morphological metrics, and query threat reputation for links submitted by the user or copied to the clipboard.
4. **Analyze Raw Messages & Text:** Inspect email, chat, or document text snippets in-memory for social engineering urgency triggers and extract embedded web links.
5. **Perform Safe Static File Analysis:** Open local files strictly in read-only binary mode (`'rb'`) to compute cryptographic hashes (SHA-256, MD5) and calculate byte entropy.
6. **Inspect Windows PE Binary Metadata:** Parse Portable Executable headers, section tables, import address tables, and export structures via `pefile` without executing underlying code.
7. **Query Threat Intelligence Feeds:** Query local SQLite indicator tables and authorized external reputation APIs (e.g. VirusTotal v3, AbuseIPDB, URLhaus) using read-only requests.
8. **Calculate Multi-Criteria Risk Scores:** Synthesize ML probabilities, deterministic heuristic rules, and threat intelligence matches into a normalized 0–100 risk score.
9. **Notify and Warn Users:** Format and present actionable security alerts and explainable evidence breakdowns via console badges, desktop notifications, and dashboard telemetry.
10. **Explain Security Findings:** Provide plain-English conversational summaries of why a file, URL, or indicator was flagged, referencing grounded local database records.
11. **Observe Real-Time Filesystem Events Safely:** Passive event intake via Windows filesystem hooks (`watchdog`), path normalization, temporary file filtering, and debouncing without modifying, renaming, deleting, or locking user files.

---

## 2. What ACTIS MUST NOT Do (Strict Prohibitions)

The following actions are **STRICTLY FORBIDDEN** across all components of ACTIS. No module, update, patch, script, or AI coding agent may introduce or enable any of these capabilities:

1. **MUST NOT Execute Suspicious Files:** ACTIS must NEVER run, debug, dynamically execute, simulate, or inject any suspicious executable, script, or binary. Dynamic sandbox execution is outside ACTIS endpoint scope.
2. **MUST NOT Delete User Files Automatically:** ACTIS must NEVER automatically delete user files, quarantine files destructively, or alter directory contents. All remediation must be presented to the user as advisory guidance.
3. **MUST NOT Modify User Files:** ACTIS must NEVER write to, modify, overwrite, sanitize, patch, or alter files being analyzed. Analysis is strictly read-only.
4. **MUST NOT Encrypt User Files:** ACTIS must NEVER encrypt, lock, or restrict access to user documents, partitions, or system files.
5. **MUST NOT Disable Antivirus or Security Controls:** ACTIS must NEVER disable, terminate, modify, or interfere with Windows Defender, third-party antivirus suites, Windows Firewall, or User Account Control (UAC).
6. **MUST NOT Secretly Capture Screens or Inputs:** ACTIS must NEVER take unauthorized screenshots, record video, install global keyboard hooks, or log user keystrokes. Clipboard inspection is strictly restricted to text matching standard URL syntax.
7. **MUST NOT Secretly Collect Personal Data:** ACTIS must NEVER harvest browsing history, browser cookies, saved credentials, contact lists, or personal documents.
8. **MUST NOT Upload Complete Personal Files:** ACTIS must NEVER upload whole user binaries, documents, photos, or data payloads to external servers or APIs. Only canonical cryptographic hashes (SHA-256/MD5), public domains, or URLs may be queried externally.
9. **MUST NOT Grant Unrestricted Shell Execution to AI Assistant:** The AI Security Assistant must NEVER possess unrestricted access to the Windows command prompt (`cmd.exe`), PowerShell, or arbitrary system subprocesses. The assistant is strictly read-only and queries local SQLite detection records.
10. **MUST NOT Introduce Remote Administration or Command Execution:** The Central Threat Intelligence API is strictly an intelligence exchange channel; it must NEVER implement remote shell execution, arbitrary payload downloads, remote file deletion, or endpoint takeover.

---

## 3. Central Threat Intelligence Service Security Boundaries

The Central Threat Intelligence REST API service (`backend/`) enforces strict defensive operational constraints:

1. **Mandatory Authentication & Constant-Time Verification:** All protected operations require API keys verified using constant-time string comparison (`hmac.compare_digest`) to prevent timing attacks.
2. **Granular Role-Based Authorization:** Operations enforce distinct permissions (`read`, `contribute`, `admin`). Endpoints reject unauthorized scopes with HTTP 403 Forbidden.
3. **Anti-Poisoning Candidate State Machine:** Submissions via `/api/v1/contributions` strictly enter as `status="CANDIDATE"` with `review_status="PENDING"`. Clients cannot self-promote indicators to `CONFIRMED`. Only authorized operators with the `admin` role may transition records to `CONFIRMED` (`APPROVED`).
4. **RFC 1918 Private & Loopback IP Shielding:** Ingestion and query endpoints enforce `is_safe_public_ip()`, rejecting RFC 1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), loopback (127.0.0.0/8), and link-local ranges with HTTP 422 to prevent leaking private network topologies.
5. **Sliding-Window Rate Limiting:** Enforces client-specific requests-per-minute (RPM) limits (60–300 RPM default) using an in-memory sliding window, rejecting bursts with HTTP 429 Too Many Requests.
6. **Bounded Request Payloads & Pagination:** Enforces maximum page size (200 records default) and strict payload size limits to protect against memory exhaustion.
7. **Offline Endpoint Autonomy:** Local file scanning, URL inspection, and background Windows protection run 100% autonomously without external or central connectivity dependencies. Outages or latency on the central API never degrade local threat protection.

---

## 4. Adversarial Robustness & Privacy Safeguards (Day 15 Hardening)

Verified defensive constraints established during Day 15 security hardening:

1. **Parser & Size Failure Isolation:** Local PE binary parsing strictly bounds file size checks before deep inspection (`MAX_FILE_SIZE_BYTES = 50 MB`). Parsing malformed DOS headers, out-of-bounds offsets, non-ASCII sections, or invalid signatures raises handled structured warnings and flags files without unhandled exceptions.
2. **Deterministic URL Ingestion & ReDoS Safety:** All URL and message text evaluations enforce maximum input length bounds (4,096 characters for URLs). Regex patterns operate in linear time without nested repetition, ensuring pathological inputs complete within bounded time (< 1.0s).
3. **Automated Structured Logging Redaction:** `config/config.py` enforces a global `SecretMaskingFilter` on all console and rotating file logger handlers. Sensitive API keys, bearer tokens, passwords, and authorization secrets matching `SECRET_PATTERN` are automatically masked (`****`) before emission.
4. **Special-Purpose IP Privacy Protection:** Ingestion and external query adapters strictly reject non-public routable IP addresses via `is_safe_public_ip()`. This includes RFC 1918 private IPv4 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), IPv4 loopback (127.0.0.0/8), IPv4 link-local (169.254.0.0/16), IPv4/IPv6 unspecified (0.0.0.0, ::), IPv6 loopback (::1), IPv6 link-local (fe80::/10), IPv6 unique-local (fc00::/7), and multicast addresses.
5. **Local File Path Isolation:** Local file paths (e.g. `C:\Users\SensitiveUser\...`) and raw binary contents are strictly quarantined locally. Outbound threat intelligence queries (VirusTotal, URLhaus, AbuseIPDB, Central ACTIS) transmit only cryptographic hashes, canonical domains, or normalized URLs.
6. **Queue Backpressure & Saturation Safety:** `SecurityEventQueue` enforces a strict capacity ceiling (default 10,000 items). Burst overload discards excess events gracefully with rate-limited logging, increments `dropped_count`, and prevents memory exhaustion or deadlock.
7. **SQLite Multithreaded Concurrency & Integrity:** Database operations across worker threads enforce connection isolation, timeout parameters (15.0s), and foreign-key integrity constraints without persistent table locks.

---

## 5. Enforcement & Governance Protocol

Any Pull Request, commit, or code change that violates any of the above prohibitions must be **immediately rejected**. AI coding agents receiving requests to build automatic file deleters, process killers, shell execution hooks, or live malware runners must decline the task, citing this document as the governing boundary.
