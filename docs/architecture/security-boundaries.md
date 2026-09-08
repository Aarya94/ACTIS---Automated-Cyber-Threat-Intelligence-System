# ACTIS Security Boundaries & Operational Constraints

**CRITICAL POLICY DOCUMENT — AUTHORITATIVE FOR ALL DEVELOPERS AND AI CODING AGENTS**

This document establishes the binding operational boundaries for ACTIS (Automated Cyber Threat Intelligence System). ACTIS is engineered as a defensive, advisory, and read-only cybersecurity platform. It is explicitly **not** an autonomous administrative system with unrestricted endpoint execution authority.

---

## What ACTIS MAY Do (Authorized Capabilities)

ACTIS is explicitly authorized to perform the following defensive cybersecurity functions when explicitly initiated or configured by the user:

1. **Scan User-Authorized Filesystem Locations**: Read local files, directories, and storage volumes specified by the user or preconfigured in standard user-space quick scan paths.
2. **Analyze URLs & Web Addresses**: Parse, normalize, compute morphological metrics, and query reputation for links submitted by the user or copied to the clipboard.
3. **Analyze Raw Messages & Text**: Inspect email, chat, or document text snippets for social engineering urgency triggers and extract embedded web links.
4. **Perform Safe Static File Analysis**: Open local files in read-only binary mode (`'rb'`) to compute cryptographic hashes (SHA-256, MD5) and calculate byte entropy.
5. **Inspect Windows PE Binary Metadata**: Parse Portable Executable headers, section tables, import address tables, and export structures via `pefile` without executing the underlying code.
6. **Query Threat Intelligence Databases**: Query local SQLite indicator tables and authorized external reputation APIs (e.g. VirusTotal, AbuseIPDB, URLhaus).
7. **Calculate Multi-Criteria Risk Scores**: Synthesize ML probabilities, deterministic rules, and threat intelligence matches into a normalized 0–100 risk score.
8. **Notify and Warn Users**: Format and present actionable security alerts and explainable evidence breakdowns via console badges, desktop notifications, and dashboard telemetry.
9. **Explain Security Findings**: Provide plain-English conversational summaries of why a file, URL, or indicator was flagged, referencing grounded local database records.

---

## What ACTIS MUST NOT Do (Strict Prohibitions)

The following actions are **STRICTLY FORBIDDEN** across all components of ACTIS. No module, update, patch, script, or AI coding agent may introduce or enable any of these capabilities:

1. **MUST NOT Execute Suspicious Files**: ACTIS must NEVER run, debug, dynamically execute, simulate, or inject any suspicious executable, script, or binary. Dynamic sandbox execution is outside ACTIS endpoint scope.
2. **MUST NOT Delete User Files Automatically**: ACTIS must NEVER automatically delete user files, quarantine files destructively, or alter directory contents. All remediation must be presented to the user as advisory guidance.
3. **MUST NOT Modify User Files**: ACTIS must NEVER write to, modify, overwrite, sanitize, patch, or alter files being analyzed. Analysis is strictly read-only.
4. **MUST NOT Encrypt User Files**: ACTIS must NEVER encrypt, lock, or restrict access to user documents, partitions, or system files.
5. **MUST NOT Disable Antivirus or Security Controls**: ACTIS must NEVER disable, terminate, modify, or interfere with Windows Defender, third-party antivirus suites, Windows Firewall, or User Account Control (UAC).
6. **MUST NOT Secretly Capture Screens or Inputs**: ACTIS must NEVER take unauthorized screenshots, record video, install global keyboard hooks, or log user keystrokes. Clipboard inspection is strictly restricted to text matching standard URL syntax.
7. **MUST NOT Secretly Collect Personal Data**: ACTIS must NEVER harvest browsing history, browser cookies, saved credentials, contact lists, or personal documents.
8. **MUST NOT Upload Complete Personal Files**: ACTIS must NEVER upload whole user binaries, documents, photos, or data payloads to external servers or APIs. Only canonical cryptographic hashes (SHA-256/MD5), public domains, or URLs may be queried externally.
9. **MUST NOT Grant Unrestricted Shell Execution to AI Assistant**: The AI Security Assistant must NEVER possess unrestricted access to the Windows command prompt (`cmd.exe`), PowerShell, or arbitrary system subprocesses. The assistant is strictly read-only and queries local SQLite detection records.

---

## Enforcement & Agent Protocol

Any Pull Request, commit, or code change that violates any of the above prohibitions must be **immediately rejected**. AI coding agents receiving requests to build automatic file deleters, process killers, shell execution hooks, or live malware runners must decline the task, citing this document as the governing boundary.
