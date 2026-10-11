# ACTIS Roadmap — Month 2: Operational Reliability, Service & Detection Core

**Milestone Version**: `v0.2.0 — Detection Core`

Month 2 integrates production Windows Service Control Manager (SCM) deployment and operational reliability, introduces native Windows toast notifications, deepens the detection engine, refines static Windows PE parsing, integrates URL and message scanners into production workflows, and introduces the multi-threaded recursive device scanner with junction loop protection.

---

## Operational Foundations & Service Reliability

### Day 17: Windows Service Integration & Native Windows Notifications (`COMPLETED`)
- **Delivered**:
  1. *Windows Service Lifecycle Host (`service/windows_host.py`)*: SCM control code translation (`STOP`, `PAUSE`, `CONTINUE`, `INTERROGATE`), standalone execution host with SIGINT/SIGTERM handlers, worker cleanup on partial/failed startup, and CLI execution flags (`--service`, `--service-status`).
  2. *SCM Management Automation (`scripts/`)*: Safe PowerShell installers (`install_windows_service.ps1`, `status_windows_service.ps1`, `uninstall_windows_service.ps1`) supporting non-elevated `-DryRun` validation, path pre-checks, memory working set telemetry, and strict user data preservation (`data/`, `logs/`).
  3. *Native Windows Desktop Notifications (`notifications/windows_toast.py`, `notifications/notifier.py`)*: Non-blocking asynchronous dispatch (<50ms) using `ThreadPoolExecutor`, automated credential/secret redaction (`sanitize_notification_text`), sliding-window rate limiting per indicator, truth in advertising (unconfirmed != malware), and silent test mode.
  4. *Pipeline Handoff (`service/file_pipeline.py`)*: Automated notification trigger on file threat detection.
- **Components**: `service/windows_host.py`, `main.py`, `scripts/install_windows_service.ps1`, `scripts/status_windows_service.ps1`, `scripts/uninstall_windows_service.ps1`, `notifications/windows_toast.py`, `notifications/notifier.py`, `service/file_pipeline.py`, `tests/test_windows_service_host.py`, `tests/test_service_scripts.py`, `tests/test_windows_notifications.py`.
- **Baseline**: 461 automated tests passing with 100% success rate (+26 new tests for Day 17). Zero administrator privileges required for test suite.

---

## Week 5: Static File Analysis Refinement

### Days 29–31: Enhanced PE Section & Import Analysis (`COMPLETED` — Day 18)
- **Delivered**:
  1. *Standard Mandiant Import Hash (`imphash`)*: Computes standard Mandiant import hash with fallback for ordinals and headless synthetic binaries (`calculate_imphash`).
  2. *Threat Family API Categorization*: Structured classification of imported Windows APIs into 10 threat categories (`PROCESS_HOLLOWING`, `TOKEN_IMPERSONATION`, `DYNAMIC_RESOLUTION`, `ANTI_DEBUGGING`, `PERSISTENCE_SERVICE`, `KEYLOGGING_INPUT`, `NETWORK_DOWNLOAD`, `EXECUTION_COMMAND`, `MEMORY_PROTECTION`, `CRYPTOGRAPHY`).
  3. *Heuristic PE Security Rules (`detection_engine/rule_engine.py`)*:
     - `RULE_PE_PROCESS_HOLLOWING` (CRITICAL, 45.0): Unmapping API sequence or memory allocation + remote write + thread execution/context manipulation.
     - `RULE_PE_TOKEN_IMPERSONATION` (HIGH, 30.0): Process access token retrieval with privilege escalation adjustments.
     - `RULE_PE_DYNAMIC_API_RESOLVER` (HIGH, 25.0): Dynamic API loading (`LoadLibrary` + `GetProcAddress`) with minimal static imports (packing indicator).
     - `RULE_PE_ANTI_ANALYSIS` (MEDIUM, 20.0): Multiple anti-debugging or environment inspection APIs.
     - `RULE_PE_PERSISTENCE_APIS` (MEDIUM, 20.0): Windows service creation or registry run persistence APIs.
     - `RULE_PE_SECTION_ENTROPY_ANOMALY` (HIGH, 25.0): Anomalous section entropy dispersion across binary sections.
     - `RULE_PE_SECTION_UNPACKING_STUB` (HIGH, 25.0): Executable section with negligible disk size (<512B) expanding to large virtual memory (>=4096B).
  4. *Contract & Pipeline Integration*: Updated `PEImportFeature` dataclass with `imphash`, `api_categories_found`, and `to_dict()`; enriched `extract_features()` dictionary with `entropy_distribution`.
- **Files/Components**: `scanners/file_feature_extractor.py`, `scanners/pe_feature_contract.py`, `detection_engine/rule_engine.py`, `tests/test_static_pe.py`, `tests/test_detection_engine.py`.
- **Validation**: 472 automated tests passing with 100% success rate (+11 new unit and rule verification tests).
- **Not Included**: Live process memory inspection, driver loading, or code execution.

### Days 32–34: Non-PE File Fallback Analysis Subsystem (`COMPLETED` — Day 19)
- **Delivered**:
  1. *Non-PE Contract & Architecture (`scanners/non_pe_contract.py`)*: Formal dataclasses (`NonPEAnalysisResult`, `ArchiveMetadata`, `ScriptMetadata`) and enums (`NonPEFileType`, `NonPEAnalysisMethod`, `NonPEAnalysisStatus`) providing structured static analysis contracts without code execution.
  2. *Bounded Streaming Cryptographic Hashing (`scanners/non_pe_analyzer.py`)*: 64KB bounded chunk streaming for SHA-256 and MD5, eliminating high memory consumption on large files, with deterministic calculation, isolated state, and resource boundary enforcement.
  3. *Safe Archive Inspection (`scanners/non_pe_analyzer.py`)*: Format identification and metadata inspection for ZIP, TAR, and GZIP without filesystem extraction. Defense-in-depth limits: 50MB max archive size, 5,000 maximum entries, 500MB declared uncompressed size, and 100:1 compression ratio detection (ZIP bomb mitigation). Graceful fallback for unsupported archive types (7z) reporting format honestly without false negatives or crashes.
  4. *Static Script Heuristic Inspection (`scanners/non_pe_analyzer.py`)*: Purely read-only static analysis for PowerShell, Windows Batch, VBScript, and Python. Bounded scanning (up to 2MB), comment and documentation filtering to eliminate false positives, and evidence snippet truncation (100 chars max) with sensitive redaction. Pure static detection with zero `eval`, `exec`, or process execution.
  5. *Detection Engine Heuristic Rules (`detection_engine/rule_engine.py`)*: 12 dedicated non-PE static rules:
     - `RULE_ARCHIVE_ZIP_BOMB` (CRITICAL, 45.0): Excessive compression ratio or uncompressed expansion.
     - `RULE_ARCHIVE_DOUBLE_EXTENSION` (HIGH, 30.0): Files disguised with double extensions inside archives.
     - `RULE_ARCHIVE_EXECUTABLE_CONTENT` (MEDIUM, 20.0): Executable binaries concealed within archives.
     - `RULE_ARCHIVE_EXCESSIVE_ENTRIES` (MEDIUM, 20.0): Suspiciously high entry counts.
     - `RULE_ARCHIVE_ENCRYPTED_ENTRIES` (LOW, 10.0): Password-protected or encrypted archive entries.
     - `RULE_SCRIPT_POWERSHELL_DOWNLOAD_EXECUTE` (CRITICAL, 45.0): WebClient/Net.WebClient download and dynamic execution cradle.
     - `RULE_SCRIPT_SHADOW_COPY_DELETION` (CRITICAL, 45.0): Volume Shadow Copy or recovery deletion commands (`vssadmin delete shadows`, `bcdedit /set recoveryenabled no`).
     - `RULE_SCRIPT_POWERSHELL_ENCODED_COMMAND` (HIGH, 30.0): Obfuscated base64 PowerShell invocation (`-EncodedCommand`, `-enc`).
     - `RULE_SCRIPT_VBSCRIPT_DOWNLOAD_DROPPER` (HIGH, 30.0): MSXML2/WinHttp download and WScript/Shell execution.
     - `RULE_SCRIPT_BATCH_DOWNLOAD_EXECUTE` (HIGH, 25.0): Living-off-the-land download tools (`certutil -urlcache`, `bitsadmin`) combined with execution.
     - `RULE_SCRIPT_PYTHON_DYNAMIC_EXECUTION` (HIGH, 25.0): Combination of network/base64 decoding with dynamic execution primitives (`exec`, `eval`).
     - `RULE_SCRIPT_POWERSHELL_EXECUTION_BYPASS` (MEDIUM, 20.0): Execution policy bypass flags (`-ExecutionPolicy Bypass`, `-WindowStyle Hidden`).
  6. *Unified Pipeline Routing (`scanners/file_feature_extractor.py`, `detection_engine/threat_detector.py`)*: Seamless routing from `FileFeatureExtractor.extract_features` when files are not valid PE executables to `NonPEAnalyzer.analyze_non_pe_file`, populating `detected_format`, `analysis_method`, and `non_pe_features` across `ThreatDetector` and `RiskEngine`.
- **Files/Components**: `scanners/non_pe_contract.py`, `scanners/non_pe_analyzer.py`, `scanners/file_feature_extractor.py`, `detection_engine/rule_engine.py`, `detection_engine/threat_detector.py`, `tests/test_non_pe_analysis.py`.
- **Validation**: 496 automated tests passing with 100% success rate (+24 new unit and integration tests).
- **Security Boundaries**: Zero dynamic script execution, zero archive extraction to disk, zero unconstrained memory allocation.

### Day 35: Week 5 Integration Audit
- **Goal**: Full regression check for static file analysis routines.

---

## Week 6: Detection Engine Deep Integration

### Days 36–38: Threat Caching & High-Performance Lookup
- **Goal**: Implement high-throughput in-memory hash caching to avoid redundant SQLite queries during recursive directory scans.
- **Tasks**: Build thread-safe LRU hash cache with TTL expiration.
- **Files/Components**: `detection_engine/threat_detector.py`.
- **Validation**: Benchmark scan loop with repeated files.

### Days 39–41: Dynamic Weight Fine-Tuning & Explainability Tree
- **Goal**: Enhance Risk Engine explainability output with structured evidence trees detailing exact rule triggers and ML feature contributions.
- **Files/Components**: `detection_engine/risk_engine.py`, `tests/test_risk_engine.py`.

### Day 42: Week 6 Review & Test Expansion
- **Goal**: Verify end-to-end evidence fusion across synthetic edge cases.

---

## Week 7: URL & Message Scanner Production Integration

### Days 43–45: Advanced URL De-obfuscation & Redirection Handling
- **Goal**: Expand URL parser to resolve hex-encoded IP addresses, decimal IPs, octal IPs, and open-redirect query parameters.
- **Files/Components**: `scanners/url_scanner.py`, `tests/test_url_scanner.py`.

### Days 46–48: Social Engineering & Credential Harvesting Heuristics
- **Goal**: Enhance message text analysis with multi-language urgency triggers and credential harvesting regex.
- **Files/Components**: `scanners/text_analyzer.py`, `tests/test_text_analyzer.py`.

### Day 49: Week 7 Verification
- **Goal**: Regression validation across 100+ synthetic phishing URLs and SMS text samples.

---

## Week 8: Recursive Device Scanner

### Days 50–52: Multi-Threaded Directory Traversal Engine
- **Goal**: Implement recursive crawler supporting Quick Scan (user profiles), Custom Scan (arbitrary directory), and Full Drive Scan.
- **Tasks**: Multi-threaded file queue, thread pool execution, error isolation on inaccessible system paths.
- **Files/Components**: `scanners/device_scanner.py`.

### Days 53–55: Reparse-Point Loop Protection & Cancellation Tokens
- **Goal**: Protect filesystem crawler from infinite directory loops caused by Windows NTFS junctions and symbolic links.
- **Tasks**: Track visited `(device_id, inode)` pairs, implement cooperative cancellation tokens.
- **Files/Components**: `scanners/device_scanner.py`.

### Day 56: Month 2 Milestone Audit (`v0.2.0`)
- **Goal**: Verify full detection core and scanner subsystem integrity. Tag version `v0.2.0`.
