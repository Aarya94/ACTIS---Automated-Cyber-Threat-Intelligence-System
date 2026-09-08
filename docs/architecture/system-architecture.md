# ACTIS System Architecture

## Architectural Philosophy

ACTIS (Automated Cyber Threat Intelligence System) is designed as an intelligent, non-intrusive, read-only endpoint cybersecurity platform for Windows environments. Inspired by the concept of an intelligent computer security guardian, ACTIS operates strictly through rigorous, deterministic cybersecurity engineering, safe static analysis, layered machine learning inference, multi-criteria risk scoring, and verified threat intelligence sharing.

---

## High-Level Topology

```text
                                  +-------------------+
                                  |       USER        |
                                  +---------+---------+
                                            |
         +-----------------+----------------+-----------------+-----------------+
         |                 |                |                 |                 |
         v                 v                v                 v                 v
   +-----------+    +-------------+   +-----------+    +------------+    +--------------+    +-----------------+
   |    URL    |    |   Message   |   |   File    |    |   Device   |    |  Background  |    |  Clipboard URL  |
   |  Scanner  |    |   Scanner   |   |  Scanner  |    |  Scanner   |    | File Watcher |    |     Scanner     |
   +-----+-----+    +------+------+   +-----+-----+    +-----+------+    +------+-------+    +--------+--------+
         |                 |                |                |                  |                     |
         +-----------------+----------------+----------------+------------------+---------------------+
                                            |
                                            v
                              +---------------------------+
                              |     Detection Engine      |
                              +-------------+-------------+
                                            |
                  +-------------------------+-------------------------+
                  |                         |                         |
                  v                         v                         v
       +--------------------+    +--------------------+    +--------------------+
       |Threat Intelligence |    |  ML Models Engine  |    |  Rule-Based Engine |
       |     (Local DB)     |    | (Phishing/Malware) |    |  (Heuristics/YARA) |
       +----------+---------+    +----------+---------+    +----------+---------+
                  |                         |                         |
                  +-------------------------+-------------------------+
                                            |
                                            v
                              +---------------------------+
                              |   Decision / Risk Engine  |
                              |  (Multi-Criteria Fusion)  |
                              +-------------+-------------+
                                            |
                  +-------------------------+-------------------------+
                  |                         |                         |
                  v                         v                         v
       +--------------------+    +--------------------+    +--------------------+    +--------------------+
       |     Logging &      |    |    Notification    |    |  Streamlit Command |    | AI-Grounded Security|
       |  Audit Reporting   |    |       System       |    |      Dashboard     |    |     Assistant      |
       +--------------------+    +--------------------+    +--------------------+    +--------------------+
```

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

## Component Responsibilities

### 1. Ingestion & Scanners
- **URL Scanner**: Normalizes input web addresses, computes lexical and morphological features, and queries intelligence feeds.
- **Message Scanner (Text Analyzer)**: Dissects raw text messages (emails, chat transcripts, SMS), detects social engineering urgency patterns, extracts embedded links, and dispatches them to the URL scanner.
- **File Scanner**: Conducts safe, non-destructive static analysis of single files, extracting cryptographic hashes (SHA-256, MD5), byte entropy, and structural PE properties without executing code.
- **Device Scanner**: Coordinates multi-path scans (Quick Scan of high-risk user locations, Custom Scan of specific directories, or Full Volume Scans) with reparse-point loop protection and cancellation tokens.
- **Background File Watcher**: Observes user-designated folders in real time using filesystem events (`watchdog`) with write-stability debounce delays before inspection.
- **Clipboard URL Scanner**: Monitors the Windows clipboard for copied URL strings in the background with user privacy safeguards.

### 2. Detection Engine
- **Threat Intelligence Lookup**: Instantly verifies target hashes, domains, or URLs against the local SQLite database (`threats` and `indicators` tables) and optionally enriches via external APIs (VirusTotal, AbuseIPDB, URLhaus).
- **ML Models Engine**: Evaluates feature vectors using specialized, trained machine learning classifiers:
  - *Phishing Classifier*: 19-feature morphological Random Forest model.
  - *Malware Classifier*: 15-feature static PE header Random Forest model.
- **Rule-Based Engine**: Applies deterministic heuristic signatures (e.g., suspicious PE section entropy, known packer sections like UPX, high-risk Win32 API imports, suspicious Bitcoin addresses in text, unescaped IP URLs).

### 3. Decision / Risk Engine
- Fuses multi-source evidence (threat intel match, ML probability, heuristic rules, external enrichment) into a normalized `0–100` composite risk score.
- Categorizes risk into actionable bands: `CRITICAL` (80–100), `HIGH` (60–79), `MEDIUM` (35–59), and `LOW` (0–34).
- Produces deterministic, explainable evidence breakdowns detailing exactly why a target was flagged.

### 4. Presentation, Storage & Assistant
- **Logging & Reporting**: Persists structured scan sessions, detected items, and audit trails to SQLite and generates JSON/CSV/Markdown reports.
- **Notification System**: Formats and dispatches critical security alerts to the user.
- **Command Dashboard**: Provides an interactive Streamlit-based web console for telemetry, manual scans, threat lookup, and system health monitoring.
- **Security Assistant**: An offline-grounded natural language security assistant querying local database records and explainable threat details without unrestricted operating system shell access.
