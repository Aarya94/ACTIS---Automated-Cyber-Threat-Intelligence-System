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

### Day 35: Week 5 Integration Audit & End-to-End File Pipeline Hardening (`COMPLETED` — Day 20)
- **Delivered**:
  1. *Filesystem Pipeline & Debounce Hardening (`service/file_pipeline.py`, `scanners/file_watcher.py`)*: Hardened `wait_until_file_stable` to allow 0-byte files to stabilize cleanly without timeout latency. Added directory target rejection in `process_file_event` returning `SKIPPED_UNSUPPORTED` to prevent spurious inaccessibility errors. Added automatic previous-path pruning on `FILE_RENAMED` events.
  2. *PE & Non-PE Analysis Fallback Hardening (`scanners/file_feature_extractor.py`, `scanners/non_pe_analyzer.py`)*: Added deterministic empty file handling with standard empty-digest hashes and `GENERIC_METADATA_ONLY` attribution. Added `OVERSIZED_FILE` categorization with `RESOURCE_LIMIT_EXCEEDED` method. Extended PE parser exception fallback to route corrupt PE headers and files disguised as `.exe` through `NonPEAnalyzer.analyze_non_pe_file()`. Added content-based heuristic sniffing for Batch, PowerShell, and VBScript scripts lacking typical extensions.
  3. *Deterministic Mixed-Directory Benchmark (`scripts/benchmark_mixed_directory.py`)*: Executed 24-file synthetic mixed-directory benchmark spanning PE binaries, corrupted PE headers, scripts, benign/bomb/camouflage archives, empty files, and 7z containers. Achieved 100% analysis success (24/24 files), 0.9259s total analysis time (38.57ms avg latency, 4.58ms median latency), 6.4 MB peak memory, and verified 5 security alert triggers through pipeline notifications.
  4. *Integration & Hardening Test Suite (`tests/test_file_pipeline_hardening.py`)*: Added 17 automated tests covering rapid modification debouncing, write stabilization, duplicate deduplication, file disappearance, rename state pruning, deletion state removal, directory filtering, swap file filtering, queue saturation drops, clean worker pool shutdown, analyzer error isolation, and end-to-end format routing.
- **Files/Components**: `service/file_pipeline.py`, `scanners/file_watcher.py`, `scanners/file_feature_extractor.py`, `scanners/non_pe_analyzer.py`, `scripts/benchmark_mixed_directory.py`, `tests/test_file_pipeline_hardening.py`.
- **Validation**: 513 automated tests passing with 100% success rate (+17 new unit and integration tests).
- **Security Boundaries**: Zero code execution, bounded memory queues, and safe threat notification dispatch.

---

## Week 6: Detection Engine Deep Integration

### Days 36–38: Threat Caching & High-Performance Lookup (`COMPLETED` — Day 21)
- **Delivered**:
  1. *Thread-Safe Bounded In-Memory Hash Cache (`detection_engine/threat_detector.py`)*: Built `LRUTTLCache` providing thread-safe (`threading.RLock`) bounded Least-Recently-Used capacity eviction (default 5,000 entries), configurable TTL expiration (default 300s), clock injection for deterministic testing, and dictionary interface compatibility. Replaced unbounded raw scan cache dictionaries in `ThreatDetector`.
  2. *Threat Intelligence Cache Hardening (`threat_intelligence/threat_cache.py`)*: Hardened `ThreatIntelligenceCache` with bounded capacity limits (`max_entries`), LRU eviction on saturation, injectable clock function, safe error boundaries, comprehensive telemetry (hits, misses, LRU evictions, TTL evictions, hit ratio), and indicator-level cache invalidation (`invalidate()`).
  3. *Pipeline Invalidation Integration (`threat_intelligence/threat_lookup.py`, `reports/threat_database.py`)*: Added `invalidate_indicator` to `ThreatLookup` and automated cache invalidation upon indicator registration (`register_indicator`) and feed batch upserts (`upsert_feed_records`), preventing stale benign/clean verdicts when new threats are discovered.
  4. *Benchmark Validation (`scripts/benchmark_threat_cache.py`)*: Executed cold vs warm repeated scan benchmark across 20 synthetic fixtures (PE, PowerShell, Batch, Logs). Cold pass: 37.17 ms/file, 26.9 files/sec; Warm pass: 10.57 ms/file, 94.6 files/sec (3.52x speedup, 100% cache hits); Sustained loop: 106.9 files/sec, 88.57% hit ratio across 100 scans with 2.06 MB peak memory.
  5. *Deep Caching & Failure Isolation Test Suite (`tests/test_threat_caching_deep.py`)*: Added 18 automated tests covering LRU eviction, TTL expiration with clock injection, indicator type collision prevention, case/whitespace normalization, transient provider failure rejection, safe write error isolation, multi-threaded concurrency, cache invalidation on SQLite registration, and scan cache hit bypassing.
- **Files/Components**: `threat_intelligence/threat_cache.py`, `threat_intelligence/threat_lookup.py`, `detection_engine/threat_detector.py`, `reports/threat_database.py`, `scripts/benchmark_threat_cache.py`, `tests/test_threat_caching_deep.py`.
- **Validation**: 531 automated tests passing with 100% success rate (+18 new unit and integration tests).

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
