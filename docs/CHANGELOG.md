# ACTIS Changelog

All notable changes to the ACTIS (Automated Cyber Threat Intelligence System) project are documented in this file in accordance with the ACTIS Daily Micro-Commit & Documentation Protocol.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [v0.1.0] — Foundation (Release Candidate 1)

Milestone Scope: Complete core defensive architecture, configuration, logging, database schemas, static PE analysis, URL/message analysis, device scanning, resident Windows service foundation, file watcher pipeline, threat intel integration, scheduled sync, central TI API, grounded AI assistant, security hardening, and release demonstration.

### 2026-10-13 — Day 24: Advanced URL De-obfuscation & Safe Redirect Analysis (Obfuscation Detection, SSRF Safeguards & Evidence Integration)

Implemented advanced URL de-obfuscation, standards-aware normalization, safe bounded redirect inspection, and comprehensive SSRF defense-in-depth protections while preserving existing detection architecture, risk scoring, evidence contracts, and explainability tree:
1. **Standards-Aware URL Normalization & De-obfuscation (`scanners/url_scanner.py`):**
   - Implemented `URLAnalysisResult` contract and `deobfuscate_and_analyze_url()` function preserving both original input and normalized URL representations.
   - Handled zero-width and invisible character stripping and tracking (`\u200b`, `\u200c`, `\u200d`, `\ufeff`, `\u202a`–`\u202e`, `\u2060`, `\u00a0`).
   - Bidirectional IDN and Punycode translation (`xn--...` <-> Unicode) with mixed-script homoglyph detection (e.g. Cyrillic characters mixed into Latin domains).
   - Alternative numeric IPv4 representation normalization (dword decimal integers, octal representations, hex-encoded IPs) converting to canonical dotted decimal.
   - Userinfo deception parsing (handling misleading usernames and multiple `@` characters) and trailing dot normalization.
   - Double percent-encoding (`%25xx`) and encoded delimiter analysis (`%2e`, `%2f`, `%40`, `%3a`, `%5c`) with bounded decoding passes preventing infinite recursion.
   - Maintained 100% backward compatibility for existing callers: `normalize_url()`, `extract_domain()`, `extract_url_features()`, and `validate_url()`.
2. **Safe Bounded Redirect Analysis & Strict SSRF Defense (`scanners/redirect_inspector.py`):**
   - Implemented `SSRFValidator` validating hostnames and all resolved IP addresses before any outbound connection attempt.
   - Rejects loopback (`127.0.0.0/8`, `::1`), private IPv4/IPv6 (RFC 1918 `10/8`, `172.16/12`, `192.168/16`, RFC 4193 `fc00::/7`), link-local (RFC 3927 `169.254/16`, RFC 4291 `fe80::/10`), cloud metadata endpoints (`169.254.169.254`, `100.100.100.200`, `fd00:ec2::254`, `metadata.google.internal`), CGNAT (`100.64.0.0/10`), broadcast, and internal domain patterns (`.local`, `.internal`, `.lan`, `.corp`, `.home`).
   - Implemented `RedirectInspector` enforcing bounded redirect chains (max 5 hops default), overall analysis deadline (5.0s default), per-request timeout (2.0s), cycle loop detection, and standards-aware relative location joining.
   - Uses non-intrusive HEAD/GET requests with 0-byte body reads; sends zero user credentials, cookies, or authorization tokens; zero JavaScript or payload execution.
3. **Deterministic URL Heuristic Rules (`detection_engine/rule_engine.py`):**
   - Added 8 dedicated heuristic rules integrated into the existing Rule Engine:
     - `RULE_URL_HOMOGLYPH_IDN` (HIGH, 30.0): Mixed-script homoglyphs or suspicious IDN homograph patterns.
     - `RULE_URL_ZERO_WIDTH_CHARS` (HIGH, 30.0): Hidden zero-width or formatting characters within the URL.
     - `RULE_URL_DOUBLE_ENCODING` (HIGH, 25.0): Double percent-encoding (`%25xx`) or encoded path separators.
     - `RULE_URL_IP_NUMERIC_OBFUSCATION` (HIGH, 30.0): Dword integer, octal, or hexadecimal IP address obfuscation.
     - `RULE_URL_USERINFO_OBFUSCATION` (MEDIUM, 20.0): Misleading userinfo component or multiple `@` characters.
     - `RULE_URL_SSRF_PROHIBITED` (CRITICAL, 45.0): Destination attempted to redirect to prohibited internal, loopback, or cloud metadata target.
     - `RULE_URL_REDIRECT_LOOP` (MEDIUM, 15.0): Circular redirect loop detected during hop inspection.
     - `RULE_URL_SUSPICIOUS_REDIRECT` (MEDIUM, 15.0): Excessive hops (>=4) or cross-domain redirection to suspicious TLDs.
4. **Detection Pipeline, Evidence Model & Explainability Integration:**
   - Enriched `ThreatDetector.analyze_url()` with optional `follow_redirects: bool` parameter, returning structured `url_analysis` and `redirect_hops` dictionaries.
   - Added `discarded_duplicates_count` property to `DetectionEvidence` in `detection_engine/evidence_model.py`.
   - Updated `ExplanationGenerator` adding dedicated `url_deobfuscation` and `redirect_inspection` nodes within the input analysis subtree.
5. **Comprehensive Automated Test Suite (`tests/test_url_deobfuscation_and_redirects.py`):**
   - Added 58 automated unit and integration tests across 3 comprehensive sections covering standard URLs, percent encoding, Unicode/IDN/homoglyphs, userinfo tricks, IP literals, redirect chains, relative locations, redirect loops, deadline/hop limits, SSRF boundaries, DNS rebinding simulations, evidence integration, whitelist safety, explainability score alignment, and full pipeline regression.
   - Full test suite baseline expanded to 647 passing tests (+58 new tests, 0 failures, 0 errors, 4 third-party warnings).

---

### 2026-10-12 — Day 23: Week 6 Review & Evidence Fusion Edge-Case Audit (Detection Reliability, Risk Consistency & Regression Hardening)

Conducted a systematic, test-backed audit of the complete evidence-fusion and detection-decision pipeline across contradictory, missing, duplicate, boundary, mitigation, override, and offline failure scenarios. Resolved verified defects without architecture rewrites or contract breakage:
1. **Evidence Deduplication Subsystem (`detection_engine/evidence_model.py`):**
   - Implemented duplicate signal detection and deduplication keyed by `(source, signal_id)` in both `DetectionEvidence.add_signal()` and `__post_init__()`.
   - Guaranteed signal idempotence by preserving the signal instance with higher weighted contribution (`confidence * weight`), preventing artificial score inflation from duplicate feed inputs or rule re-evaluations.
   - Added transparent discarded duplicate tracking (`discarded_duplicates: List[Dict[str, Any]]` and `discarded_duplicates_count` property) for complete auditability.
2. **Deterministic Whitelist Override Precedence (`detection_engine/decision_engine.py`):**
   - Enforced strict whitelist mitigation precedence: when `evidence.is_whitelisted` is True, `effective_score` is unconditionally clamped to `0.0`, `status` to `DetectionStatus.BENIGN`, and `level` to `SeverityLevel.INFORMATIONAL`.
   - Preserved pre-override raw score in `ScoreTraceability` (`pre_override_score`) and analysis metadata (`pre_override_score`) ensuring total mathematical auditability.
   - Fixed explainability tree synchronization under whitelist overrides: node `calc_override` explicitly documents `WHITELIST_OVERRIDE` with before/after score traceability.
3. **Bounded Explainability Tree Safety Truncation (`detection_engine/explanation_generator.py`):**
   - Hardened `ExplanationGenerator` signal iteration loops (static analysis, detection rules, threat intelligence findings) against `MAX_TOTAL_NODES` (100) exhaustion.
   - Added defensive overflow truncation notices if excessive signals are present, guaranteeing zero unhandled exceptions or memory exhaustion in high-volume edge cases.
4. **Comprehensive Evidence Fusion Edge-Case Audit Suite (`tests/test_evidence_fusion_audit.py`):**
   - Added 35 focused automated edge-case and reliability tests covering:
     - Contradictory evidence handling (high static + clean TI, high ML + low heuristic, high heuristic + benign ML).
     - Missing and unavailable evidence robustness (offline/unreachable TI providers, zero-signal empty evidence, partial inputs).
     - Duplicate and correlated signals (duplicate rule IDs, duplicate TI indicators, multi-source same-indicator fusion).
     - Risk-scoring mathematical boundaries (epsilon boundary checks around 20.0, 35.0, 60.0, 80.0, score clamping [0.0, 100.0]).
     - Mitigation and safety override precedence (whitelist override vs high raw score, mitigation discounts, multi-mitigation stacking).
     - Explainability and final-decision consistency (verdict-score alignment, tree traceability reconciliation, secret masking).
     - Provider failure isolation and offline analysis resilience (transient network drops, simulated HTTP 500/timeout, partial feed corruption).
     - Cross-module regression behavior across file and URL pipelines.
   - 589 automated tests passing with 100% success rate (+35 new tests, 0 failed, 0 errors, 4 third-party warnings).

---

### 2026-10-12 — Day 22: Dynamic Weight Fine-Tuning & Explainability Tree

Implemented a hierarchical explainability tree subsystem, exact evidence-to-score mathematical calculation traceability, validated and configurable risk-scoring weights, and end-to-end pipeline integration without altering existing threat detection contracts:
1. **Hierarchical Explainability Tree Subsystem (`detection_engine/explainability_tree.py`):**
   - Implemented `ExplainabilityTree` and `ExplainabilityNode` supporting bounded depth (<=5) and total node count (<=100) to ensure zero memory exhaustion.
   - Defined `NodeCategory` (`ROOT`, `INPUT_ANALYSIS`, `STATIC_ANALYSIS`, `RULE_ENGINE`, `MACHINE_LEARNING`, `THREAT_INTELLIGENCE`, `EVIDENCE_AGGREGATION`, `RISK_CALCULATION`, `FINAL_DECISION`, `FINDING`, `METRIC`, `LIMITATION`) and `NodeStatus` (`EVALUATED`, `NO_FINDINGS`, `NOT_EVALUATED`, `UNAVAILABLE`, `TIMED_OUT`, `CONFIRMED_THREAT`, `SUSPICIOUS`, `BENIGN`, `MUTUAL_CONFIRMATION`, `MITIGATED`, `OVERRIDDEN`).
   - Integrated recursive node lookup (`find_node()`, `find_nodes_by_category()`) and human-readable Unicode/ASCII branch rendering (`render_ascii()`).
   - Added automated redaction of sensitive credentials, API keys, and bearer tokens (`mask_sensitive_value()`) across node titles, descriptions, and metadata dictionaries.
2. **Evidence-to-Score Traceability (`detection_engine/explainability_tree.py`, `explanation_generator.py`):**
   - Built `ScoreTraceability` detailing active layer scores, configured weights, normalized weights, weighted contributions, mutual confirmation escalation (+25% boost), mitigation discounts, and safety overrides matching authoritative Risk Engine scores.
   - Ensured honest representation of unavailable or unsupported models/providers (`NodeStatus.UNAVAILABLE`), distinguishing absence of findings from verified clean verdicts.
3. **Validated Risk Scoring Weight Configuration (`detection_engine/risk_engine.py`):**
   - Refined `RiskScoringWeights` with strict type validation, rejection of NaN and infinite values, range validation `[0.0, 1.0]`, dynamic `normalized()` method, `from_dict(strict=True/False)` factory, `from_config()` integration, and safe default rollbacks.
4. **Empirical Weight Fine-Tuning Evaluation:**
   - Audited training datasets (`data/malware_dataset.csv`, `data/phishing_dataset.csv`). Formally documented that empirical weight tuning across all 4 layers is responsibly deferred pending a verified multi-layer ground-truth benchmark corpus, avoiding speculative overfitting while providing transparent validated configuration.
5. **Contract & Pipeline Integration (`detection_engine/detection_contract.py`, `decision_engine.py`, `threat_detector.py`):**
   - Added `explainability_tree` property to `DetectionResult` contract.
   - Integrated full tree generation in `DetectionDecisionEngine.evaluate()`, attaching serialized tree and ASCII views to `analysis_metadata`.
   - Exposed `explainability_tree` in `ThreatDetector.analyze_file()` and `analyze_url()` while preserving 100% backward compatibility for all legacy callers.
6. **Comprehensive Explainability & Traceability Test Suite (`tests/test_explainability_tree.py`):**
   - Added 23 automated tests covering tree structure, multi-branch routing, honest representation of unavailable ML/TI, secret redaction, mathematical traceability, strict weight validation, deterministic repeatability, end-to-end file/URL integration, and sub-millisecond performance (< 5.0 ms across 50 signals).
   - 554 automated tests passing with 100% success rate (+23 new tests, 0 failed, 0 errors, 4 third-party warnings).

---

### 2026-10-12 — Day 21: Threat Detection Engine Deep Integration: Threat Intelligence Caching

Audited and hardened the Threat Intelligence caching layer and integrated high-performance bounded LRU in-memory scan caching with the ACTIS threat detector and local database:
1. **Thread-Safe Bounded LRU Cache Subsystem (`threat_intelligence/threat_cache.py`):**
   - Implemented `LRUTTLCache` providing thread-safe (`threading.RLock`) bounded Least-Recently-Used capacity eviction (default 5,000 entries), configurable TTL expiration (default 300s), injectable clock (`clock: Callable[[], float]`), and full dict-interface compatibility (`__getitem__`, `__setitem__`, `__delitem__`, `__contains__`).
   - Hardened `ThreatIntelligenceCache` with explicit capacity limits (`max_entries`), LRU eviction on saturation, clock injection, safe error boundaries (never crashing detection upon cache failures), and comprehensive telemetry (`hits`, `misses`, `evictions_lru`, `evictions_ttl`, `hit_ratio`).
   - Reinforced strict exclusion of `UNAVAILABLE` verdicts from caching to ensure transient provider outages are never treated as durable or benign results.
2. **ThreatDetector Integration & Telemetry (`detection_engine/threat_detector.py`):**
   - Replaced unbounded raw scan cache dictionaries with `LRUTTLCache` instances for both file hashes and normalized URLs.
   - Added cache telemetry reporting (`get_cache_stats()`), hash invalidation (`invalidate_hash()`), and URL invalidation (`invalidate_url()`).
3. **Pipeline Invalidation Hooks (`threat_intelligence/threat_lookup.py`, `reports/threat_database.py`):**
   - Added `invalidate_indicator` to `ThreatLookup` for programmatic cache eviction.
   - Connected automatic cache invalidation in `register_indicator()` and `upsert_feed_records()` to guarantee newly identified threats instantly purge stale clean cache entries.
4. **Benchmark Verification (`scripts/benchmark_threat_cache.py`):**
   - Cold scan: 37.17 ms/file, 26.9 files/sec; Warm scan: 10.57 ms/file, 94.6 files/sec (3.52x speedup, 100% cache hits); Sustained loop: 106.9 files/sec, 88.57% hit ratio across 100 scans with 2.06 MB peak memory.
5. **Comprehensive Deep Caching Test Suite (`tests/test_threat_caching_deep.py`):**
   - Added 18 automated tests covering LRU eviction, TTL expiration with clock injection, indicator type collision prevention, case/whitespace normalization, transient provider failure rejection, safe write error isolation, multi-threaded concurrency, cache invalidation on SQLite registration, and scan cache hit bypassing.
   - 531 automated tests passing with 100% success rate (+18 new tests, 0 failed, 0 errors, 4 third-party warnings).

---

### 2026-10-12 — Day 20: Week 5 Integration Audit & End-to-End File Pipeline Hardening

Performed an end-to-end integration audit and hardening of static PE parsing and non-PE fallback analysis with the resident Windows file protection pipeline and filesystem event debouncer. Implemented and verified:
1. **Filesystem Event Handling & Stabilization Hardening (`service/file_pipeline.py`, `scanners/file_watcher.py`):**
   - Hardened `wait_until_file_stable` to allow 0-byte files to stabilize when size remains 0 across intervals and file is openable, eliminating 4-second timeout latency for empty files.
   - Enhanced `FileProtectionPipeline.process_file_event` with defensive directory validation, returning `SKIPPED_UNSUPPORTED` with clean diagnostic reasons if a directory event is received.
   - Added automatic incremental scan state pruning for the previous path on `FILE_RENAMED` events to prevent orphaned state records.
2. **Analysis Fallback & Format Routing Hardening (`scanners/file_feature_extractor.py`, `scanners/non_pe_analyzer.py`):**
   - Added deterministic empty file handling with standard cryptographic empty-digest hashes and `GENERIC_METADATA_ONLY` method attribution.
   - Added `OVERSIZED_FILE` categorization with `RESOURCE_LIMIT_EXCEEDED` method for files exceeding `MAX_FILE_SIZE_BYTES`.
   - Extended PE parser exception fallback to route both `pefile.PEFormatError` and general PE parser exceptions into `NonPEAnalyzer.analyze_non_pe_file()`.
   - Added content-based heuristic sniffing in `NonPEAnalyzer.detect_format` for Batch, PowerShell, and VBScript scripts lacking typical extensions or disguised with misleading extensions (e.g., `.exe`, `.txt`).
3. **Deterministic Mixed-Directory Benchmark (`scripts/benchmark_mixed_directory.py`):**
   - Created a synthetic fixture generator spanning 24 diverse file types (text, benign scripts, heuristic threat scripts, archives, corrupt archives, decompression bombs, PE binaries, corrupt PE headers, empty files, 7z containers, and generic binaries).
   - Achieved 100% analysis success (24/24 files analyzed) in 0.9259 seconds (38.57ms avg latency, 4.58ms median latency, 6.4 MB peak memory), correctly triggering 5 security alert notifications without code execution.
4. **Comprehensive Integration & Hardening Test Suite (`tests/test_file_pipeline_hardening.py`):**
   - Added 17 unit and integration tests covering rapid modification debouncing, write stabilization, duplicate deduplication, file disappearance, rename state pruning, deletion state removal, directory filtering, swap file filtering, queue saturation drops, clean worker pool shutdown, analyzer error isolation, and end-to-end format routing.
   - Verified 513 automated tests passing with 100% success rate (expanded from 496 baseline, 0 failed, 0 errors, 4 third-party warnings).

---

### 2026-10-11 — Day 19: Non-PE File Fallback Static Analysis Subsystem

Implemented safe static analysis for non-PE files including bounded streaming cryptographic hashing, safe archive inspection (ZIP, TAR, GZIP, and graceful 7z handling), static script heuristic inspection (PowerShell, Batch, VBScript, Python), and 12 dedicated non-PE detection rules without executing files or extracting contents to disk. Preserved existing Windows PE analysis pathways and zero-privilege offline operation. Implemented and verified:
1. **Non-PE Contracts & Data Architecture (`scanners/non_pe_contract.py`):**
   - Defined `NonPEFileType` enum (`UNKNOWN`, `ARCHIVE_ZIP`, `ARCHIVE_TAR`, `ARCHIVE_GZIP`, `ARCHIVE_7Z`, `SCRIPT_POWERSHELL`, `SCRIPT_BATCH`, `SCRIPT_VBSCRIPT`, `SCRIPT_PYTHON`, `GENERIC_TEXT`, `GENERIC_BINARY`).
   - Defined `NonPEAnalysisMethod` and `NonPEAnalysisStatus` distinguishing format detection, unsupported formats, parsing errors, incomplete analyses, and successful inspections.
   - Defined structured dataclasses `ArchiveMetadata`, `ScriptMetadata`, and `NonPEAnalysisResult` for standardized indicator delivery to the detection engine.
2. **Bounded Streaming Cryptographic Hashing (`scanners/non_pe_analyzer.py`):**
   - Implemented streaming file hashing (`compute_streaming_hashes`) with 64KB bounded buffer reads for SHA-256 and MD5, eliminating memory exhaustion on large files.
   - Enforced defensive boundary checks: isolated read state, permission error isolation, file truncation handling, and strict read-only operation.
3. **Safe Archive Metadata Inspection (`scanners/non_pe_analyzer.py`):**
   - Implemented safe metadata parsing for ZIP, TAR, and GZIP without filesystem extraction or execution.
   - Enforced defensive resource boundaries: 50MB maximum archive size, 5,000 maximum entries, 500MB declared uncompressed size limit, and 100:1 compression ratio detection (ZIP bomb mitigation).
   - Audited for concealed executables (`.exe`, `.dll`, `.bat`, etc.), camouflage double extensions (`.pdf.exe`), excessive entries, and encrypted items.
   - Built graceful fallback for unsupported formats (e.g., 7z) without crashes or false-negative verdicts.
4. **Static Script Heuristic Inspection (`scanners/non_pe_analyzer.py`):**
   - Built read-only static analysis for PowerShell, Windows Batch, VBScript, and Python scripts with zero execution (`eval`, `exec`, and subprocess strictly prohibited).
   - Comment and documentation filtering to eliminate false positives in benign scripts and documentation examples.
   - Safe evidence extraction with bounded snippet lengths (100 characters max) and credential/secret masking.
5. **Detection Engine Heuristic Rules (`detection_engine/rule_engine.py`):**
   - Added 12 dedicated non-PE static rules:
     - `RULE_ARCHIVE_ZIP_BOMB` (CRITICAL, +45.0)
     - `RULE_ARCHIVE_DOUBLE_EXTENSION` (HIGH, +30.0)
     - `RULE_ARCHIVE_EXECUTABLE_CONTENT` (MEDIUM, +20.0)
     - `RULE_ARCHIVE_EXCESSIVE_ENTRIES` (MEDIUM, +20.0)
     - `RULE_ARCHIVE_ENCRYPTED_ENTRIES` (LOW, +10.0)
     - `RULE_SCRIPT_POWERSHELL_DOWNLOAD_EXECUTE` (CRITICAL, +45.0)
     - `RULE_SCRIPT_SHADOW_COPY_DELETION` (CRITICAL, +45.0)
     - `RULE_SCRIPT_POWERSHELL_ENCODED_COMMAND` (HIGH, +30.0)
     - `RULE_SCRIPT_VBSCRIPT_DOWNLOAD_DROPPER` (HIGH, +30.0)
     - `RULE_SCRIPT_BATCH_DOWNLOAD_EXECUTE` (HIGH, +25.0)
     - `RULE_SCRIPT_PYTHON_DYNAMIC_EXECUTION` (HIGH, +25.0)
     - `RULE_SCRIPT_POWERSHELL_EXECUTION_BYPASS` (MEDIUM, +20.0)
6. **Pipeline Routing Integration (`scanners/file_feature_extractor.py`, `detection_engine/threat_detector.py`):**
   - Routed non-PE files from `FileFeatureExtractor.extract_features` to `NonPEAnalyzer.analyze_non_pe_file`, ensuring PE files continue through existing PE pipelines while non-PE files receive structured fallback analysis.
   - Threaded `detected_format`, `analysis_method`, and `non_pe_features` into `ThreatDetector.scan_file` and `RiskEngine.calculate_risk`.
7. **Test Suite Expansion:**
   - Added 24 automated tests in `tests/test_non_pe_analysis.py` covering streaming hashing, archive inspection, script heuristics, boundary handling, and full pipeline integration.
   - Maintained 100% pass rate across the full test suite: 496 passing tests (472 baseline + 24 new).

---

### 2026-10-11 — Day 18: Enhanced Windows PE Static Import, Dangerous API Sequence & Section Heuristic Analysis

Implemented standard Mandiant import hashing (`imphash`), 10-category threat family API mapping, and advanced section/import heuristic rules for static Windows PE analysis. Preserved all existing Day 1–17 architectures, offline resilience, and defensive read-only contracts. Implemented and verified:
1. **Mandiant Import Hashing (`calculate_imphash` in `scanners/file_feature_extractor.py`):**
   - Implemented standard Mandiant import hash algorithm: sequential import parsing, lowercase DLL name with `.dll`/`.sys`/`.ocx` extension stripping, lowercase function or `ordN` ordinal formatting, comma concatenation, and MD5 digest calculation.
   - Built deterministic fallback algorithm for synthetic or headless binaries where `pefile.PE.get_imphash()` is unavailable or returns non-MD5 objects.
2. **Threat Family API Categorization (`API_CATEGORIES` in `scanners/file_feature_extractor.py`):**
   - Categorized dangerous Windows APIs across 10 distinct threat families: `PROCESS_HOLLOWING`, `TOKEN_IMPERSONATION`, `DYNAMIC_RESOLUTION`, `ANTI_DEBUGGING`, `PERSISTENCE_SERVICE`, `KEYLOGGING_INPUT`, `NETWORK_DOWNLOAD`, `EXECUTION_COMMAND`, `MEMORY_PROTECTION`, and `CRYPTOGRAPHY`.
   - Populated `api_categories_found` in `extract_pe_import_features` and `extract_features` mapping threat categories to detected function imports.
3. **Advanced Heuristic PE Detection Rules (`detection_engine/rule_engine.py`):**
   - `RULE_PE_PROCESS_HOLLOWING` (CRITICAL, +45.0): Flags unmapping APIs (`NtUnmapViewOfSection`, `ZwUnmapViewOfSection`) or the combined sequence of memory allocation (`VirtualAllocEx`/`VirtualAlloc`), remote write (`WriteProcessMemory`), and thread execution/context manipulation (`SetThreadContext`, `ResumeThread`, `QueueUserAPC`, `CreateRemoteThread`).
   - `RULE_PE_TOKEN_IMPERSONATION` (HIGH, +30.0): Flags process token retrieval (`OpenProcessToken`) combined with privilege adjustment APIs (`AdjustTokenPrivileges`, `LookupPrivilegeValue*`, `DuplicateTokenEx`, `ImpersonateLoggedOnUser`).
   - `RULE_PE_DYNAMIC_API_RESOLVER` (HIGH, +25.0): Flags runtime dynamic API loading (`LoadLibrary*` + `GetProcAddress`) combined with small import footprint (<= 25 functions), characteristic of stealth loaders.
   - `RULE_PE_ANTI_ANALYSIS` (MEDIUM, +20.0): Flags presence of 2 or more anti-debugging/anti-analysis APIs.
   - `RULE_PE_PERSISTENCE_APIS` (MEDIUM, +20.0): Flags Windows service installation or registry run key persistence APIs.
   - `RULE_PE_SECTION_ENTROPY_ANOMALY` (HIGH, +25.0): Evaluates entropy dispersion across sections; flags binaries with packed entropy indicators or high standard deviation with high maximum entropy.
   - `RULE_PE_SECTION_UNPACKING_STUB` (HIGH, +25.0): Flags executable sections with negligible raw disk size (<512 bytes) expanding to large virtual memory (>= 4096 bytes).
4. **Contract & Pipeline Integration (`scanners/pe_feature_contract.py`):**
   - Updated `PEImportFeature` dataclass to include `imphash: str`, `api_categories_found: Dict[str, Tuple[str, ...]]`, and `to_dict() -> Dict[str, Any]`.
   - Wired `entropy_distribution` from `analyze_pe_entropy_distribution` directly into `FileFeatureExtractor.extract_features` return dictionary for direct consumption by `RuleEngine.evaluate_pe_file`.
5. **Test Suite Expansion:**
   - Added 11 new automated unit and integration tests across `tests/test_static_pe.py` and `tests/test_detection_engine.py`:
     - Tested deterministic `imphash` calculation on named functions and ordinals.
     - Tested threat family category mapping.
     - Tested structured `PEImportFeature` contract serialization.
     - Tested each new PE heuristic rule and verified benign PE binaries trigger zero spurious rules.
   - Verified 472 passing tests with 100% success rate (expanded from 461 baseline, 0 failed, 0 errors, 4 third-party warnings).

---

### 2026-10-11 — Day 17: Windows Service Integration, Operational Reliability & Native Windows Notifications

Implemented production Windows Service Control Manager (SCM) deployment tooling, operational reliability enhancements, and native Windows desktop toast notifications with async non-blocking dispatch, automated secret redaction, and flood protection. Preserved all existing Day 1–16 architectures and read-only defensive contracts. Implemented and verified:
1. **Windows Service Host & SCM Lifecycle Integration (`service/windows_host.py`, `main.py`):**
   - Enhanced `WindowsServiceHost` with explicit stop signaling (`request_stop`, `is_stop_requested`), resource cleanup on startup failures, and standalone execution entrypoint via `__main__`.
   - Wired `--service` (starts resident SCM service host loop with SIGINT/SIGTERM handlers) and `--service-status` (queries and outputs structured health telemetry JSON) into `main.py`.
2. **Safe Windows Service Management Tooling (`scripts/`):**
   - Created `scripts/install_windows_service.ps1`: validates Windows platform, verifies project paths (`venv\Scripts\python.exe`, `main.py`), validates Administrator elevation, prevents duplicate SCM registrations, registers `ACTISProtectionService` via `sc.exe`, and supports `-DryRun` for non-privileged CI/validation runs.
   - Created `scripts/status_windows_service.ps1`: non-privileged status inspector checking SCM registration, service state (Running/Stopped/Paused), process ID and memory usage via CIM/WMI, recent log history, and structured JSON output via `-AsJson`.
   - Created `scripts/uninstall_windows_service.ps1`: validates elevation, cleanly stops running service instances, unregisters the service via `sc.exe delete`, and explicitly preserves threat databases (`data/`) and logs (`logs/`).
3. **Native Windows Desktop Notifications (`notifications/windows_toast.py`, `notifications/notifier.py`):**
   - Implemented `WindowsToastNotifier`: asynchronous non-blocking notification dispatch powered by `ThreadPoolExecutor` (guaranteed dispatch time < 50ms, never blocking the scanning pipeline).
   - Automated secret and credential sanitization (`sanitize_notification_text`) scrubbing API keys, bearer tokens, passwords, and sensitive tokens from notification text; escaped XML characters for Windows toast templates.
   - Sliding-window cooldown rate limiting per target/indicator suppressing notification floods during burst operations.
   - Truth in advertising: unconfirmed or candidate threats are labeled as suspicious alerts, never mislabeled as confirmed malware.
   - Robust Windows execution: dynamic `powershell.exe` path resolution (`get_powershell_executable`), non-interactive execution, and error isolation preventing OS/subprocess exceptions from leaking.
   - Test mode support (`test_mode=True`): facilitates headless and automated test validation without spawning OS UI popups.
   - Integrated with `NotificationManager.notify_threat(...)` for `HIGH` and `CRITICAL` risk alerts.
4. **File Protection Pipeline Threat Notification Handoff (`service/file_pipeline.py`):**
   - Integrated `FileProtectionPipeline` to automatically trigger `notifier.notify_threat(...)` when static analysis classifies a changed or new binary with `is_threat=True`.
5. **Comprehensive Test Expansion:**
   - Added 26 automated unit and integration tests across 3 new test suites:
     - `tests/test_windows_service_host.py` (8 tests)
     - `tests/test_service_scripts.py` (6 tests)
     - `tests/test_windows_notifications.py` (12 tests)
   - Verified that ordinary tests require zero Administrator elevation.
   - Verified full regression test suite: 461 tests passed with 100% success rate (expanded from 435 baseline).

---

### 2026-10-11 — Day 16: Final Integration, Demonstration & Release Verification

Conducted comprehensive system integration, release acceptance testing, and safe demonstration workflow verification across all 15 core subsystems of the ACTIS platform. Validated that all subsystems interface safely, deterministically, and in full alignment with documented defensive contracts. Implemented and verified:
1. **System Integration Audit:** Completed and verified integration matrix across all 15 subsystem boundaries: scanners -> orchestrator -> decision engine -> risk engine -> threat intel -> sync service -> central TI backend -> reporting -> grounded AI assistant -> dashboard.
2. **Safe End-to-End System Demonstration Workflow (`scripts/demo_actis.py`):** Implemented an automated, 100% offline demonstration runner exercising 7 representative security scenarios inside an isolated sandbox with zero mutation of user databases or filesystem assets:
   - *DEMO A (Benign URL Inspection):* Real lexical feature extraction (19 features), normalization, Random Forest inference, and LOW/MEDIUM risk classification.
   - *DEMO B (Synthetic Phishing URL Detection):* Lexical heuristic rules, brand keyword lure detection, and HIGH severity classification with itemized explanations.
   - *DEMO C (Safe Static Malformed PE Inspection):* Non-executing static inspection of corrupt PE headers with graceful error handling and immediate artifact cleanup.
   - *DEMO D (Threat Intelligence Provenance & Anti-Poisoning):* Differentiating verified `CONFIRMED` intelligence from client `CANDIDATE` submissions and `UNKNOWN` indicators, avoiding the negative-evidence trap.
   - *DEMO E (Grounded AI Security Assistant):* Truthful evidence-backed explanations of recorded detections, absence-of-evidence safety warnings, prompt injection resistance, and automated credential masking.
   - *DEMO F (Structured Security Audit Reporting):* Validated generation and schema compliance of multi-format reports (JSON, CSV, Markdown) in an isolated export directory.
   - *DEMO G (Incremental Scan State Optimization):* Demonstrating change classification (`NEW_FILE` vs `UNCHANGED_FILE`) and deep scan suppression for unchanged binaries.
3. **Release Acceptance Test Suite (`tests/test_release_integration.py`):** Added 13 focused end-to-end integration tests verifying core analysis entry points, structured result contracts, missing intelligence negative-evidence trap protection, candidate indicator anti-poisoning lifecycle, external provider timeout outcome states, local analysis resilience during central backend outages, sensitive path and private IP shielding, grounded AI assistant explanations, safe malformed binary handling without execution, isolated report generation and cleanup, and demo script execution.
4. **URL Parser & Input Robustness Hardening (`scanners/`, `assistant/`, `detection_engine/`):** Hardened `validate_url` to explicitly reject illegal backslashes / filesystem path separators, validate port integers during initial parsing, and guard `normalize_url` against `ValueError` when processing unusual host:port inputs. Hardened `detect_pe_format`, `calculate_file_hashes`, and `FileFeatureExtractor.extract_features` against `None` and non-path inputs; hardened `scan_file` and `threat_detector.analyze_file` to reject directory targets with consistent failure contracts; hardened `TextAnalyzer.evaluate_social_engineering` and `clean_url_token` against non-string and `None` payloads; hardened `mask_sensitive_strings` and `SecurityAssistant.ask` against non-string query inputs.
5. **Configuration and Startup Verification:** Verified environment loading, path resolution, database schema idempotency, and offline resilience when optional services (external TI providers, central REST server) are unavailable.
6. **Release Readiness Audit:** Completed 6-dimension evaluation (Correctness, Security, Reliability, Reproducibility, Documentation, Hygiene) with zero critical blockers, establishing the ACTIS Milestone Month 1 Release Candidate (`v0.1.0-rc1`).

Expanded the automated test suite from 417 to 435 passing tests (+13 release integration tests, +5 input robustness security tests), maintaining 100% test pass rate with zero failures.

---

### 2026-10-11 — Day 15: Security Hardening, Adversarial Robustness & Broad Threat Coverage Testing

Audited, hardened, and verified the ACTIS platform against malformed and adversarial inputs, false-positive biases, credential/privacy leaks, and resource exhaustion. Preserved existing read-only contracts, multi-criteria risk scoring policies, and offline autonomy. Implemented and verified:
1. **Malformed PE Binary Hardening:** Resilient static analysis of truncated DOS headers, invalid PE signatures, corrupted section offsets, unexpected section counts, non-ASCII section names, random binary noise, and empty files without unhandled exceptions or crashing.
2. **Oversized Binary Protection:** Enforced `MAX_FILE_SIZE_BYTES` (50 MB) boundary pre-checks before deep PE parsing, preventing excessive memory allocation.
3. **Adversarial URL Input Hardening:** Bounded URL parsing (max 4,096 chars), control character and null byte rejection (`[\x00-\x1f\x7f]`), unsupported scheme rejection, embedded credential and port preservation, and 19-feature vector morphological extraction resilience across malformed and non-string inputs.
4. **ReDoS Immunity & Message Resource Safety:** Linear-time regex evaluation across urgency, credential lure, and financial lure keyword patterns; untrusted message boundary processing completing in < 1.0s even under pathological repetition.
5. **Local File Path Privacy Isolation:** Verified that raw local file paths (e.g. `C:\Users\SensitiveUser\...`) and file binary contents are never transmitted upstream to external threat intelligence providers (VirusTotal, URLhaus, AbuseIPDB) or the Central ACTIS API; lookups strictly use minimum required indicators (cryptographic hashes, canonical domains, URLs).
6. **Automated Structured Logging Credential Redaction:** Implemented `SecretMaskingFilter` and `mask_sensitive_strings` in `config/config.py`, automatically masking API keys, bearer tokens, passwords, and authorization secrets (`****`) across all console and rotating file logs.
7. **Comprehensive Special-Purpose IP Shielding:** Extended `is_safe_public_ip` in `threat_intelligence/indicator_validator.py` to explicitly reject IPv4/IPv6 unspecified addresses (`0.0.0.0`, `::`) alongside RFC 1918 private IPv4, loopback (`127.0.0.1`, `::1`), link-local (`169.254.1.1`, `fe80::1`), unique-local (`fc00::1`), and multicast addresses across all external lookup and central sync paths.
8. **Circular Import Resolution:** Eliminated cyclic dependency between `detection_engine` and `threat_intelligence` packages by lazily resolving `threat_lookup` in `ThreatDetector`, enabling clean isolated package imports.
9. **AI Security Assistant Instruction Boundaries:** Verified prompt injection immunity, absence-of-evidence safety caveats ("missing intelligence does not mean safe"), candidate anti-poisoning caveats, and strict denial of command execution or database mutation requests.
10. **Security Event Queue Saturation Stress Testing:** Verified bounded queue capacity (10,000 items), drop telemetry tracking under producer bursts (500–1,000 events), producer/consumer thread safety, and cancellation handling.
11. **SQLite Multithreaded Concurrency Integrity:** Verified concurrent worker read/write transactions under timeout and foreign-key enforcement without locks or corruption.

Expanded the automated test suite from 360 to 417 passing tests (+57 comprehensive tests in `tests/test_adversarial_security.py` and `tests/test_privacy_safeguards.py`), achieving 100% test pass rate with zero failures.

---

### 2026-10-10 — Day 14: Grounded AI Security Assistant and Explainable Threat Analysis

Audited, hardened, and integrated the Day 14 AI Security Assistant (`assistant/security_assistant.py`, `dashboard/app.py`) providing evidence-grounded, explainable threat intelligence and detection analysis. Enforced strict read-only security boundaries: zero arbitrary OS shell execution, zero automated file deletion or quarantine, zero modification of Windows Defender or endpoint settings, and zero transmission of private files or user documents. Implemented robust natural language intent routing for:
1. **Recent Detections:** Real-time queries for recent detections and high-risk security events derived strictly from SQLite detection history (`scans.db`), with truthful distinction between an empty database and a verified clean workstation.
2. **Explain Flagged Target:** Multi-factor evidence breakdown explaining why a file, URL, domain, or message was flagged, displaying recorded timestamps, risk scores, severity classifications, and itemized weighted scoring contributions (Threat Intel 35%, ML Inference 30%, Heuristic Rules 20%). Added candidate indicator anti-poisoning caveats explicitly distinguishing `CONFIRMED` intelligence from unverified `CANDIDATE` reports.
3. **Indicator Lookup:** Querying local threat intelligence indicators (`threat_database.py`), accurately reflecting status (`CONFIRMED`, `SUSPICIOUS`, `CANDIDATE`, `REPORTED`, `FALSE_POSITIVE`) and confidence, with strict safety caveats stating that missing indicators are not automatically safe.
4. **Scan Statistics:** Deriving aggregate metrics from SQLite scan history (scans, detections, average risk scores, risk distribution).
5. **Detection Methodology:** Plain-English architectural explanations grounded in verified repository capabilities (ML Random Forest, static PE header parsing, RFC-compliant URL analysis, multi-criteria risk engine, background Windows service).
6. **Defensive Guidance:** Safe, non-destructive incident response recommendations (isolation, credential rotation, independent verification) without autonomous remediation.
7. **Disambiguation & Absence-of-Evidence Safety:** Exact and prefix target matching with candidate disambiguation when multiple targets match, avoiding silent arbitrary selection. Truthful missing target handling refusing to claim unrecorded targets are safe.
8. **Sensitive Data Minimization & Secret Masking:** Automated credential sanitization (`mask_sensitive_strings`) preventing leakage of API keys, tokens, or private paths.
9. **Provider Abstraction & Offline Isolation:** Pluggable `BaseAssistantProvider` interface with default `DeterministicAssistantProvider` and configurable `ExternalLLMProvider` fallback, ensuring complete local functionality when external AI providers are unavailable or disabled.
10. **Dashboard Integration:** Streamlit conversational interface (`dashboard/app.py`) featuring session history (`st.session_state["assistant_history"]`), native markdown formatting, clear history controls, and offline status indicator.

Expanded the automated test suite from 333 to 360 passing tests (+27 comprehensive tests in `tests/test_security_assistant.py`), achieving 100% test pass rate with zero failures.

#### Commits

| Commit | Type | Description | Files | Verification |
|--------|------|-------------|-------|--------------|
| `b22965f` | feat | Implement grounded security assistant with evidence breakdown and read-only boundaries | `assistant/security_assistant.py`, `assistant/__init__.py` | Passed (360 tests) |
| `5e6e55f` | feat | Integrate grounded security assistant with session history and native markdown | `dashboard/app.py` | Passed (360 tests) |
| `332e3cf` | test | Add comprehensive test suite for grounded security assistant and safety boundaries | `tests/test_security_assistant.py` | Passed (360 tests) |
| `56151d9` | docs | Document Day 14 grounded AI security assistant and update roadmap | `README.md`, `docs/quickstart.md`, `docs/architecture/project-structure.md`, `docs/roadmap/README.md`, `docs/roadmap/month-1.md`, `docs/CHANGELOG.md` | Passed (360 tests) |
| `331edd8` | docs | Reconcile architectural documentation and test baselines with Day 14 | `docs/architecture/*`, `docs/generated/*` | Passed (360 tests) |

---

### 2026-10-10 — Day 13: Central Threat Intelligence Service and Secure ACTIS Synchronization

Implemented a hardened, central Threat Intelligence REST API service (`backend/`) and secure client synchronization subsystem extending the unified ACTIS architecture. Defined versioned API contracts (`/api/v1/health`, `/api/v1/indicators`, `/api/v1/indicators/{indicator_type}/{indicator_value}`, `/api/v1/sync/pull`, `/api/v1/contributions`, and `/api/v1/admin/indicators/{indicator_id}/review`). Implemented constant-time API key verification (`hmac.compare_digest`), role-based authorization (`read`, `contribute`, `admin`), in-memory sliding-window rate limiting per client identity (default 60–300 RPM), and defensive payload bounds. Enforced strict RFC 1918 private/loopback/link-local IP shielding via `is_safe_public_ip` and indicator normalization on all retrieval, synchronization, and contribution pathways. Implemented an anti-poisoning candidate contribution policy: submitted indicators are strictly assigned `status="CANDIDATE"`, `review_status="PENDING"`, and `source_type="CLIENT_CONTRIBUTION"`, preventing unauthorized self-promotion to `CONFIRMED`. Added an administrative review endpoint for state transitions (`APPROVE`, `REJECT`). Implemented the client-side `CentralACTISFeedAdapter` extending `BaseFeedAdapter` in `threat_intelligence/sync/feed_adapter.py` and updated `SyncManager`, allowing ACTIS endpoint nodes to synchronize verified threat intelligence into their local SQLite database (`upsert_feed_records`) while maintaining total outage isolation: local file scanning and background Windows monitoring run 100% autonomously without external or central connectivity dependencies. Updated the Streamlit dashboard (`dashboard/app.py`) to reflect Central ACTIS Threat Network synchronization. Expanded the automated test suite from 303 to 333 passing tests (+30 comprehensive tests in `tests/test_central_ti_service.py`), achieving 100% pass rate with zero network dependencies (100% mocked transport).

#### Commits

| Commit | Type | Description | Files | Verification |
|--------|------|-------------|-------|--------------|
| `6f7995c` | feat | Implement central threat intelligence API and candidate contribution state machine | `backend/models.py`, `backend/database.py`, `backend/api.py`, `config/` | Passed (333 tests) |
| `9abcfda` | feat | Add central ACTIS feed adapter and client synchronization | `threat_intelligence/sync/feed_adapter.py`, `threat_intelligence/sync_manager.py`, `threat_intelligence/sync/sync_service.py`, `dashboard/app.py` | Passed (333 tests) |
| `d7fcfed` | test | Cover central threat intelligence API authentication and synchronization | `tests/test_central_ti_service.py` | Passed (333 tests) |
| `04691b3` | docs | Document central threat intelligence service architecture and contracts | `docs/architecture/unified-architecture.md`, `docs/CHANGELOG.md` | Passed (333 tests) |

---

### 2026-10-10 — Day 12: Scheduled Threat Intelligence Synchronization & Dashboard Integration

Implemented a robust, decoupled, and tested Threat Intelligence synchronization service importing supported upstream threat feeds into the local SQLite threat database, isolating provider failures, preserving provenance, and ensuring imported indicators are immediately queryable by the unified analysis pipeline. Built feed adapters implementing `BaseFeedAdapter` for **URLhaus** (recent payload URLs feed with automatic tagging and status parsing) and **AbuseIPDB** (configurable blacklist query with confidence thresholding and RFC 1918 shielding). Modeled the **VirusTotal** bulk feed limitation explicitly as `UNSUPPORTED_OPERATION` rather than creating synthetic feeds or misrepresenting enterprise endpoints. Built the core `ThreatSyncService` with in-memory deduplication, failure isolation (per-provider error trapping), structured outcome telemetry (`SyncRunResult`, `ProviderSyncResult`), and non-blocking concurrency locking preventing overlapping sync runs. Extended SQLite persistence (`reports/threat_database.py`) with `threat_sync_runs` and `threat_feed_status` tables, and implemented parameterized, idempotent batch upserts (`upsert_feed_records`) into existing `indicators` and `threats` tables without creating duplicates or clearing historical data on empty feeds. Implemented `ThreatSyncScheduler` with thread-safe lifecycle control, configurable interval, graceful shutdown, and explicit manual trigger (`trigger_sync_now()`), ensuring background threads are never started on module import. Integrated live feed synchronization metrics and manual synchronization controls into the Streamlit dashboard (`dashboard/app.py`), preserving strict read-only detection boundaries. Expanded the automated test suite from 279 to 303 passing tests (+24 tests in `tests/test_threat_sync.py`), achieving 100% test pass rate with zero network dependencies.

#### Commits

| Commit | Type | Description | Files | Verification |
|--------|------|-------------|-------|--------------|
| `f12bf62` | feat | Implement scheduled threat intelligence synchronization service and feed adapters | `threat_intelligence/sync/`, `reports/threat_database.py`, `config/` | Passed (303 tests) |
| `030c44f` | feat | Integrate feed synchronization status and controls into dashboard | `dashboard/app.py` | Passed (303 tests) |
| `b6818cb` | test | Cover threat feed adapters synchronization and pipeline integration | `tests/test_threat_sync.py`, `tests/test_file_protection_integration.py`, `detection_engine/threat_detector.py` | Passed (303 tests) |
| `5b12719` | docs | Document scheduled threat intelligence synchronization and sync status | `docs/architecture/unified-architecture.md`, `docs/CHANGELOG.md` | Passed (303 tests) |

---

### 2026-10-10 — Unified ACTIS Architecture Adoption & Validation

Adopted and validated the authoritative Unified ACTIS Architecture, establishing the Core + Extensions model across the repository without unnecessary rewrites. Conducted a complete repository audit verifying previous milestones (Days 1–11: 267 baseline tests passing). Unified structured detection contracts across input modalities by ensuring `ThreatDetector.analyze_file()` evaluates the canonical `DetectionDecisionEngine` and exports structured `DetectionResult` metadata, matching `analyze_url()`. Introduced the formal `AnalysisOrchestrator` (`detection_engine/orchestrator.py`) implementing `IAnalysisOrchestrationBoundary` to serve as the single authoritative pipeline coordinator for file, URL, and message scanning, as well as Windows Protection Service security events. Created `docs/architecture/unified-architecture.md` specifying Core vs Extension boundaries, structured contracts, evidence provenance, and verified component status. Added 12 dedicated compliance and integration tests (`tests/test_unified_architecture.py`) verifying multi-modal ingestion, contract symmetry, event handoffs, scanner delegation, and failure isolation, expanding the test suite to 279 passing tests (0 failures).

#### Commits

| Commit | Type | Description | Files | Verification |
|--------|------|-------------|-------|--------------|
| `8060ed5` | feat | Adopt unified analysis orchestrator and symmetric detection contracts | `detection_engine/orchestrator.py`, `detection_engine/threat_detector.py`, `detection_engine/__init__.py` | Passed (279 tests) |
| `e8e523b` | test | Add validation suite for unified architecture compliance | `tests/test_unified_architecture.py` | Passed (279 tests) |

---

### 2026-10-10 — Day 11: Online Threat Intelligence Integration

Implemented a fully working, tested external threat-intelligence lookup pipeline integrating seamlessly with existing ACTIS analysis, detection, and risk-assessment infrastructure. Built the extensible provider abstraction (`BaseThreatClient`) with indicator capability reporting, configurable bounded HTTP timeouts, sliding-window rate-limiting, and secret-masked representation (`***`). Implemented comprehensive client adapters for **VirusTotal v3** (SHA-256 hashes, URLs, domains with 4 req/min throttling), **URLhaus API v1** (malicious URLs and payload SHA-256 hashes with JSON payload encoding), and **AbuseIPDB API v2** (IPv4 and IPv6 public address reputation scoring). Built strict defensive indicator validation (`indicator_validator.py`) with canonical normalization, URL fragment stripping, and strict RFC 1918 private/loopback/link-local IP shielding to prevent enterprise network leakage. Developed a thread-safe, TTL-based threat intelligence cache (`ThreatIntelligenceCache`) that rejects caching transient network failures or timeouts. Implemented a 9-stage local-first threat lookup orchestrator (`ThreatLookup`) that prioritizes local SQLite indicator databases before querying external feeds, tracks 8 explicit outcome states (`FOUND_MALICIOUS`, `FOUND_SUSPICIOUS`, `FOUND_BENIGN`, `NOT_FOUND`, `PROVIDER_UNAVAILABLE`, `REQUEST_TIMEOUT`, `INVALID_RESPONSE`, `QUERY_SKIPPED`), and provides multi-provider aggregation with conflict resolution (`aggregate_findings`). Integrated normalized external intelligence into `ThreatDetector` and `RiskEngine` without altering existing scoring contracts or introducing duplicate risk engines. Expanded the automated test suite from 229 to 267 passing tests (100% pass rate) with zero live network dependencies (100% mocked transport).

#### Commits

| Commit | Type | Description | Files | Verification |
|--------|------|-------------|-------|--------------|
| `0effbb3` | feat | Define external threat intelligence provider contract | `detection_engine/threat_intel_contract.py`, `threat_intelligence/provider_base.py`, `threat_intelligence/__init__.py` | Passed (235 tests) |
| `6b4e1fb` | feat | Add provider configuration and timeout handling | `config/settings.py`, `config/defaults.py`, `config/config.py`, `config/validator.py`, `.env.example` | Passed (235 tests) |
| `632a3fe` | feat | Add indicator validation for external lookups | `threat_intelligence/indicator_validator.py`, `threat_intelligence/__init__.py` | Passed (235 tests) |
| `de90f3c` | feat | Implement external threat intelligence provider adapters | `threat_intelligence/api_clients.py`, `threat_intelligence/__init__.py` | Passed (235 tests) |
| `3c568e2` | feat | Add threat intelligence caching layer | `threat_intelligence/threat_cache.py`, `threat_intelligence/__init__.py` | Passed (235 tests) |
| `f453ff9` | feat | Integrate provider lookup with local intelligence | `threat_intelligence/threat_lookup.py`, `threat_intelligence/__init__.py` | Passed (235 tests) |
| `9f77010` | feat | Integrate normalized evidence with detection pipeline | `detection_engine/threat_detector.py` | Passed (235 tests) |
| `2d38f44` | feat | Add bounded provider failure and offline fallback handling | `threat_intelligence/api_clients.py`, `threat_intelligence/provider_base.py` | Passed (235 tests) |
| `d712aa3` | test | Cover provider adapter response handling | `tests/test_threat_providers.py`, `threat_intelligence/indicator_validator.py` | Passed (256 tests) |
| `788ea97` | test | Cover detection pipeline and threat intelligence integration | `detection_engine/threat_intel_contract.py`, `tests/test_threat_intel_pipeline.py`, `threat_intelligence/provider_base.py`, `threat_intelligence/threat_cache.py`, `threat_intelligence/threat_lookup.py` | Passed (267 tests) |
| `d58cc4d` | docs | Update threat intelligence architecture status and roadmap | `docs/architecture/reference/actis-threat-intelligence-integration.md`, `docs/roadmap/README.md`, `docs/roadmap/month-1.md` | Passed (267 tests) |

---

### 2026-10-09 — Day 10: Event-Driven File Protection

Implemented the event-driven file protection layer for ACTIS, connecting Windows filesystem events directly to the ACTIS Protection Service, event filtering and debouncing, Day 8 incremental scan state tracking, and the existing `ThreatDetector` static analysis and multi-criteria risk engine. Built the native Windows filesystem event monitor bridge (`FilesystemEventSource` using `watchdog.Observer`) with thread-safe lifecycle control, non-blocking callback bridge, and support for `FILE_CREATED`, `FILE_MODIFIED`, `FILE_MOVED`, and `FILE_DELETED` events. Implemented path normalization (`FilesystemEventNormalizer`) resolving canonical absolute paths, standard separators, and Windows case-folding. Created safe event filtering (`FileEventFilter`) discarding directory-only notifications, inaccessible targets, and temporary/editor swap patterns (`.tmp`, `~$*`, `.crdownload`, `.part`). Implemented time-window debouncing and duplicate suppression (`FileEventDebouncer`) coalescing burst file modifications into single logical scan requests with file-settling and size stability checks. Added high-watermark tracking and throttled backpressure logging to bounded intake queues (`SecurityEventQueue`). Integrated event processing with incremental scan state (`FileProtectionPipeline` + `IncrementalStateManager`), safely skipping deep analysis for verified unchanged files while analyzing new and modified files. Hardened the pipeline against filesystem race conditions (`compute_file_fingerprint`, stat comparison) explicitly handling `DISAPPEARED`, `INACCESSIBLE`, and `CHANGED_DURING_ANALYSIS` states. Connected verified files to the canonical `ThreatDetector` static analysis pipeline (PE header parsing, Shannon entropy, static rules, Random Forest ML, multi-criteria risk scoring, SQLite logging) without duplicating detection logic. Expanded automated test suite from 200 to 229 passing tests (100% pass rate).

#### Commits

| Commit | Type | Description | Files | Verification |
|--------|------|-------------|-------|--------------|
| `c165969` | feat | Add filesystem event source integration | `scanners/file_watcher.py` | Passed (200 tests) |
| `3f5c507` | feat | Normalize ACTIS filesystem events | `service/file_normalizer.py`, `service/__init__.py` | Passed (200 tests) |
| `603d9cc` | feat | Add filesystem event filtering | `service/file_filter.py`, `service/__init__.py` | Passed (200 tests) |
| `2ab558f` | feat | Implement filesystem event debouncing | `service/debouncer.py`, `service/__init__.py` | Passed (200 tests) |
| `72b2eba` | feat | Add bounded protection event queue | `service/events.py` | Passed (200 tests) |
| `d0ff9d3` | feat | Integrate filesystem events with protection service | `service/protection_service.py`, `service/health.py`, `service/config.py` | Passed (200 tests) |
| `281b380` | feat | Connect event processing with incremental scan state | `service/file_pipeline.py`, `service/__init__.py` | Passed (200 tests) |
| `6f74ec2` | feat | Connect changed files to ACTIS analysis pipeline | `service/file_pipeline.py` | Passed (200 tests) |
| `38debd5` | feat | Harden event processing against filesystem races | `service/file_pipeline.py`, `service/__init__.py` | Passed (200 tests) |
| `55852db` | test | Add filesystem event and debounce coverage | `tests/test_file_protection_events.py` | Passed (217 tests) |
| `4ce21ab` | test | Add event burst and queue stability coverage | `tests/test_file_protection_burst.py` | Passed (222 tests) |
| `acf96f4` | test | Add event-to-analysis integration coverage | `tests/test_file_protection_integration.py` | Passed (229 tests) |
| `0646444` | docs | Document ACTIS event-driven file protection workflow | `README.md`, `docs/architecture/*` | Passed (229 tests) |

---

### 2026-10-09 — Day 9: Windows Protection Service Foundation

Built the foundation of the ACTIS Windows Protection Service, establishing the lightweight resident protection layer introduced by the post-Day-7 architectural evolution. Implemented deterministic service lifecycle management (`start`, `stop`, `pause`, `resume`, `is_running`, `get_state`), synchronized state transitions (`STOPPED`, `STARTING`, `RUNNING`, `PAUSED`, `DEGRADED`, `FAILED`), worker pool lifecycle coordination with non-blocking queue waiting, thread cancellation, and bounded failure recovery policy (`restart_failed_workers`). Established the canonical security event intake contract (`SecurityEvent`, `SecurityEventType`, `SecurityEventQueue`), decoupling event intake from downstream analysis. Implemented the `EventDispatcher` subscription router and `AnalysisOrchestrationBoundary` handoff interface, strictly ensuring that detection, ML models, and heuristic rules remain outside the service layer. Built the Windows Service Control Manager (SCM) host bridge (`WindowsServiceHost`, `create_windows_host`) for future administrative service deployment and safe interactive/standalone console hosting. Expanded automated test suite from 162 to 200 passing tests (100% pass rate).

#### Commits

| Commit | Type | Description | Files | Verification |
|--------|------|-------------|-------|--------------|
| `a9078e0` | feat | Add ACTIS protection service lifecycle contract | `service/lifecycle.py`, `service/config.py`, `config/settings.py`, `config/defaults.py`, `config/config.py`, `service/__init__.py` | Passed (162 tests) |
| `a0b8ec2` | feat | Implement protection service state management | `service/state.py`, `service/__init__.py` | Passed (162 tests) |
| `47b0e34` | feat | Add controlled protection service worker lifecycle | `service/workers.py`, `service/__init__.py` | Passed (162 tests) |
| `658a7a9` | feat | Add protection service event boundary contract | `service/events.py`, `service/__init__.py` | Passed (162 tests) |
| `524988d` | feat | Add service-to-analysis orchestration boundary | `service/dispatcher.py`, `service/__init__.py` | Passed (162 tests) |
| `21cb05f` | feat | Add protection service health state | `service/health.py`, `service/protection_service.py`, `service/__init__.py` | Passed (162 tests) |
| `2de26b4` | feat | Harden protection service failure handling | `service/workers.py`, `service/protection_service.py`, `service/windows_host.py`, `service/__init__.py` | Passed (162 tests) |
| `77ba8cb` | test | Add protection service lifecycle coverage | `tests/test_protection_service_lifecycle.py` | Passed (176 tests) |
| `721f3d3` | test | Add worker failure and shutdown regression coverage | `tests/test_protection_service_workers.py`, `service/workers.py`, `service/protection_service.py` | Passed (185 tests) |
| `cb8de71` | test | Add security event boundary validation coverage | `tests/test_protection_service_events.py` | Passed (200 tests) |
| `932f05d` | docs | Document ACTIS protection service architecture | `docs/architecture/system-architecture.md`, `docs/architecture/module-architecture.md`, `docs/architecture/project-structure.md`, `docs/architecture/architecture-evolution.md`, `README.md` | Passed (200 tests) |

---

### 2026-10-09 — Day 8: Device Scanner & Incremental Scan State Foundation

Implemented the safe, user-authorized Device Scanner and incremental scan state infrastructure for ACTIS. Features safe recursive filesystem traversal with Windows junction/reparse-point loop avoidance (`TraversalSafetyHelper`), safe file metadata inspection (`FileMetadata`), streaming chunked SHA-256 fingerprinting with race-condition detection (`FileFingerprint`), incremental scan state tracking (`IncrementalStateManager`, `FileScanState`) across five change states (`NEW_FILE`, `UNCHANGED_FILE`, `CHANGED_FILE`, `REMOVED_FILE`, `UNAVAILABLE_FILE`), analytical model version invalidation, SQLite scan state persistence (`file_scan_states`), canonical file analysis pipeline integration (`scan_file` -> `ThreatDetector.analyze_file`), skipping deep analysis for verified unchanged files while re-analyzing modified ones, and strongly-typed `DeviceScanResult` with cooperative cancellation support (`ScanCancellationToken`). Expanded automated test suite to 162 passing tests (100% pass rate).

---

### 2026-09-14 — Week 1 Day 6: Detection Engine & ML Model Integration Foundation

Implemented the central analytical intelligence layer of ACTIS, establishing the structured detection decision pipeline, heterogeneous evidence models, ML prediction contracts, rule evaluation results, threat intelligence evidence representations, deterministic mathematical risk scoring with dynamic active-layer normalization, five-tier risk classification with safety overrides, internal decision confidence calculation, grounded explanation generation, and model manager integration. Expanded automated test suite to 128 passing unit tests (100% pass rate).

#### Commits

| Commit | Type | Description | Files | Verification |
|--------|------|-------------|-------|--------------|
| `c2b046e` | feat | Add detection result contract | `detection_engine/detection_contract.py`, `detection_engine/__init__.py` | Passed (109 tests) |
| `7ce0550` | feat | Add structured detection evidence model | `detection_engine/evidence_model.py`, `detection_engine/__init__.py` | Passed (109 tests) |
| `4b1b29f` | feat | Add ML prediction result contract | `detection_engine/ml_prediction_contract.py`, `detection_engine/__init__.py` | Passed (109 tests) |
| `ad3c831` | feat | Add rule evaluation result contract | `detection_engine/rule_engine.py`, `detection_engine/__init__.py` | Passed (109 tests) |
| `8372c3f` | feat | Add threat intelligence evidence contract | `detection_engine/threat_intel_contract.py`, `detection_engine/__init__.py` | Passed (109 tests) |
| `2065654` | feat | Implement deterministic risk scoring engine | `detection_engine/risk_engine.py`, `detection_engine/__init__.py` | Passed (109 tests) |
| `f9482ae` | feat | Add risk classification thresholds and override logic | `detection_engine/risk_engine.py`, `detection_engine/__init__.py` | Passed (109 tests) |
| `ef7d2e2` | feat | Add detection explanation and confidence calculation | `detection_engine/explanation_generator.py`, `detection_engine/__init__.py` | Passed (109 tests) |
| `bb84daa` | feat | Add model manager abstraction interface | `detection_engine/model_manager.py`, `detection_engine/__init__.py` | Passed (109 tests) |
| `93aff4d` | feat | Implement unified detection decision engine | `detection_engine/decision_engine.py`, `detection_engine/__init__.py` | Passed (109 tests) |
| `56307dd` | test | Add detection engine validation suite | `tests/test_detection_engine.py` | Passed (120 tests) |
| `e1e3821` | test | Add risk engine edge case coverage | `tests/test_risk_engine_day6.py`, `detection_engine/risk_engine.py` | Passed (128 tests) |
| `bfbb6ee` | docs | Document detection engine workflow | `docs/detection_engine_workflow.md`, `SUMMARY.md` | Passed (128 tests) |

---

### 2026-09-14 — Week 1 Day 5: Safe Windows PE Static File Analysis Foundation

Implemented the safe, non-destructive, read-only Windows Portable Executable (PE) static analysis foundation. Built streaming multi-algorithm file hashing (SHA-256, MD5, SHA-1), fast pre-parser binary PE signature detection, core header metadata extraction, section metrics with W+X risk flagging, import table and threat API heuristics, Shannon entropy analysis, and the formal strongly-typed `PEStaticFeatures` feature contract cleanly separating threat-intelligence identifiers from ML features. Hardened against malformed/corrupted files and expanded automated test coverage to 109 passing unit tests.

#### Commits

| Commit | Type | Description | Files | Verification |
|--------|------|-------------|-------|--------------|
| `5490a6d` | feat | Add safe file hashing utilities | `scanners/file_feature_extractor.py` | Passed (91 tests) |
| `2472bd7` | feat | Add Windows PE file detection | `scanners/file_feature_extractor.py` | Passed (91 tests) |
| `0bc56ea` | feat | Add PE metadata extraction foundation | `scanners/file_feature_extractor.py` | Passed (91 tests) |
| `75e6a83` | feat | Add PE section feature extraction | `scanners/file_feature_extractor.py` | Passed (91 tests) |
| `00e0392` | feat | Add PE import feature extraction | `scanners/file_feature_extractor.py` | Passed (91 tests) |
| `b6a4ed5` | feat | Add PE entropy feature extraction | `scanners/file_feature_extractor.py` | Passed (91 tests) |
| `4caed0e` | feat | Add structured PE feature contract | `scanners/pe_feature_contract.py`, `scanners/file_feature_extractor.py` | Passed (91 tests) |
| `f24885e` | fix | Harden PE analysis against malformed files | `scanners/file_feature_extractor.py` | Passed (91 tests) |
| `9549fbe` | test | Add PE static analysis test suite | `tests/test_static_pe.py`, `scanners/file_feature_extractor.py` | Passed (109 tests) |
| `ef285cd` | docs | Document ACTIS static file analysis workflow | `docs/static_pe_analysis.md`, `SUMMARY.md` | Passed (109 tests) |

---

### 2026-09-09 — Week 1 Day 3: Windows PE Malware Dataset Inspection & Data Preparation Foundation

Established the authentic data ingestion, schema validation, metadata identifier isolation, quality audit, and label normalization foundation for the Windows PE malware dataset (`data/malware_dataset.csv`, 62,485 samples, 15 PE structural features, 2 metadata identifiers, 1 label). Enforced zero data leakage, target binarization (`is_malware`), and added 25 automated unit tests (91 total suite tests).

#### Commits

| Commit | Type | Description | Files | Verification |
|--------|------|-------------|-------|--------------|
| `1d0f2d6` | feat | Define Windows PE malware dataset schema contract | `detection_engine/malware_dataset_schema.py` | Passed (66 tests) |
| `0afd272` | feat | Implement raw malware dataset loading with identifier isolation | `detection_engine/malware_dataset_loader.py` | Passed (66 tests) |
| `39db203` | feat | Implement dataset schema validation and integrity verification | `detection_engine/malware_dataset_loader.py` | Passed (66 tests) |
| `26d4b3d` | feat | Implement feature matrix extraction and label binarization | `detection_engine/malware_dataset_loader.py` | Passed (66 tests) |
| `a2ec5b3` | feat | Implement dataset quality inspection and diagnostic reporting | `detection_engine/malware_dataset_loader.py` | Passed (66 tests) |
| `ef9c7ac` | feat | Implement class distribution and balance analysis | `detection_engine/malware_dataset_loader.py` | Passed (66 tests) |
| `ffda49d` | test | Add unit tests for malware dataset schema contracts | `tests/test_malware_dataset.py` | Passed (74 tests) |
| `6e5b5b0` | test | Add unit tests for dataset loading and identifier isolation | `tests/test_malware_dataset.py`, `detection_engine/malware_dataset_loader.py` | Passed (80 tests) |
| `92362fe` | test | Add unit tests for schema validation and edge case errors | `tests/test_malware_dataset.py` | Passed (84 tests) |
| `4177478` | test | Add unit tests for feature preparation, quality inspection, and class balance | `tests/test_malware_dataset.py` | Passed (91 tests) |
| `54ec9c9` | docs | Document Windows PE malware dataset and data preparation foundation | `docs/ml_malware_dataset.md`, `SUMMARY.md` | Passed (91 tests) |

---

### 2026-09-08 — Week 1 Day 2: Configuration & Documentation Governance Framework

Established the authoritative ACTIS documentation framework (`docs/architecture/`, `docs/roadmap/`, `docs/generated/`) and centralized configuration management foundation. Decoupled operational settings, paths, and credentials with strict secret protection and full backward compatibility.

#### Commits

| Commit | Type | Description | Files | Verification |
|--------|------|-------------|-------|--------------|
| `b96763b` | chore | Establish ACTIS configuration foundation (dataclass schema) | `config/settings.py` | Passed (24 tests) |
| `2ab1ac5` | chore | Add environment configuration support (typed parsers, .env) | `config/env_loader.py` | Passed (24 tests) |
| `ab13ae7` | chore | Add ACTIS project path configuration (dynamic paths) | `config/paths.py` | Passed (24 tests) |
| `408e3b6` | chore | Add runtime configuration defaults (baseline operational limits) | `config/defaults.py` | Passed (24 tests) |
| `8790268` | chore | Add configuration validation (weights, risk thresholds, bounds) | `config/validator.py` | Passed (24 tests) |
| `b715e14` | chore | Add environment example (.env.example templates with placeholders) | `.env.example`, `config/.env.example` | Passed (24 tests) |
| `db26f3a` | chore | Protect environment secrets (harden .gitignore for keys/tokens) | `.gitignore` | Passed (24 tests) |
| `4a47393` | test | Add configuration loading tests (defaults, paths, env parsing) | `tests/test_config_loading.py` | Passed (28 tests) |
| `8951436` | test | Add configuration validation tests (weights, thresholds, strict mode) | `tests/test_config_validation.py` | Passed (35 tests) |
| `6345d10` | docs | Document ACTIS configuration usage (architecture guide & reference) | `docs/configuration.md` | Passed (35 tests) |
| `6b58e0e` | chore | Wire centralized configuration into config entrypoint | `config/config.py`, `config/__init__.py` | Passed (35 tests) |
| `4b45465` | docs | Initialize ACTIS changelog with Week 1 Day 2 record | `docs/CHANGELOG.md` | Passed (35 tests) |
| `bba3b6d` | docs | Define architecture source of truth and AI rules | `docs/architecture/README.md` | Passed (35 tests) |
| `dd71ba0` | docs | Document system architecture | `docs/architecture/system-architecture.md` | Passed (35 tests) |
| `c57a297` | docs | Document module architecture | `docs/architecture/module-architecture.md` | Passed (35 tests) |
| `5282b7f` | docs | Document project structure | `docs/architecture/project-structure.md` | Passed (35 tests) |
| `277263b` | docs | Document detection workflow | `docs/architecture/detection-workflow.md` | Passed (35 tests) |
| `b29297a` | docs | Document data flow and privacy boundaries | `docs/architecture/data-flow.md` | Passed (35 tests) |
| `1839ad5` | docs | Document threat intelligence workflow | `docs/architecture/threat-intelligence-workflow.md` | Passed (35 tests) |
| `5daaced` | docs | Document ML workflow and model contracts | `docs/architecture/ml-workflow.md` | Passed (35 tests) |
| `dd0a25d` | docs | Document scanning workflow and safety controls | `docs/architecture/scanning-workflow.md` | Passed (35 tests) |
| `0766636` | docs | Define ACTIS security boundaries | `docs/architecture/security-boundaries.md` | Passed (35 tests) |
| `6cec39f` | docs | Establish four-month roadmap overview | `docs/roadmap/README.md` | Passed (35 tests) |
| `f62f777` | docs | Define day-by-day roadmap for month 1 foundation | `docs/roadmap/month-1.md` | Passed (35 tests) |
| `e0af4ec` | docs | Define day-by-day roadmap for month 2 scanners and detection | `docs/roadmap/month-2.md` | Passed (35 tests) |
| `dbee27d` | docs | Define day-by-day roadmap for month 3 real-time and threat intel | `docs/roadmap/month-3.md` | Passed (35 tests) |
| `4f35035` | docs | Define day-by-day roadmap for month 4 productization and release | `docs/roadmap/month-4.md` | Passed (35 tests) |
| `3f12abd` | docs | Establish current-state generated documentation framework | `docs/generated/*.md` | Passed (35 tests) |
| `9735199` | docs | Add database ML test references and changelog to generated documentation | `docs/generated/*.md` | Passed (35 tests) |
| `cad6618` | docs | Synchronize changelogs with complete documentation framework history | `docs/CHANGELOG.md`, `docs/generated/CHANGELOG.md` | Passed (35 tests) |
| `82e7b4c` | feat | Create documentation generator core repository inspector | `scripts/generate_docs.py` | Passed (35 tests) |
| `4b23a40` | feat | Add Git history and working tree analyzer to documentation generator | `scripts/generate_docs.py` | Passed (35 tests) |
| `41b928d` | feat | Add Python AST module inspector to documentation generator | `scripts/generate_docs.py` | Passed (35 tests) |
| `cef2cbc` | feat | Add ML models and dataset analyzer to documentation generator | `scripts/generate_docs.py` | Passed (35 tests) |
| `bedf771` | feat | Add database schema analyzer to documentation generator | `scripts/generate_docs.py` | Passed (35 tests) |
| `23c7d4c` | feat | Add test suite inventory analyzer to documentation generator | `scripts/generate_docs.py` | Passed (35 tests) |
| `263a383` | feat | Add reproducible roadmap progress calculator to documentation generator | `scripts/generate_docs.py` | Passed (35 tests) |
| `831c017` | feat | Add markdown report writers for project and module status | `scripts/generate_docs.py` | Passed (35 tests) |
| `bd64d60` | feat | Add markdown report writers for database, ML, and test references | `scripts/generate_docs.py` | Passed (35 tests) |
| `963163d` | test | Add automated unit tests for documentation generator | `scripts/generate_docs.py`, `tests/test_doc_generator.py` | Passed (55 tests) |
| `2e3152b` | chore | Execute documentation generator to synchronize generated documentation | `docs/generated/*.md` | Passed (55 tests) |
| `d54e1ea` | docs | Update main changelog with documentation progress system records | `docs/CHANGELOG.md` | Passed (55 tests) |

---

### 2026-09-08 — Week 1 Day 1: Architecture & Project Foundation

Established initial project foundation, architectural specifications, initial validation suite, contracts, and repository structure.

#### Commits

| Commit | Type | Description | Files | Verification |
|--------|------|-------------|-------|--------------|
| `8d4611d` | docs | Define ACTIS architecture | `docs/architecture.md`, `README.md` | Verified |
| `2e2a0f0` | chore | Initialize ACTIS project structure (validate tool) | `tools/validate_structure.py` | Passed |
| `a6e14e8` | chore | Add initial configuration example | `config/.env.example` | Verified |
| `0174f37` | chore | Add ACTIS logging infrastructure (rotating file handler) | `config/config.py` | Passed |
| `88e2788` | docs | Define database and ML contracts | `docs/contracts.md` | Verified |
| `e55fbf1` | test | Add initial ACTIS validation suite | `tests/test_week1_validation.py` | Passed |
| `e78460e` | chore | Ignore model binaries (models/*.pkl) | `.gitignore` | Verified |
| `38363f6` | chore | Commit remaining workspace files | Multiple workspace components | Passed |
| `8beb805` | chore | Remove accidental file, runtime DB, and Android dataset from tracking | `.gitignore`, Git index | Passed |
