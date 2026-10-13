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

> **Target Architecture Reference:** The canonical 13-stage end-to-end detection pipeline is documented in [Detection Workflow & Target Pipeline Architecture](../architecture/detection-workflow.md).

### Days 36–38: Threat Caching & High-Performance Lookup (`COMPLETED` — Day 21)
- **Architecture Role**: Fulfills **Pipeline Stage 8: Threat Intelligence Cache (TI Cache)**.
- **Delivered**:
  1. *Thread-Safe Bounded In-Memory Hash Cache (`detection_engine/threat_detector.py`)*: Built `LRUTTLCache` providing thread-safe (`threading.RLock`) bounded Least-Recently-Used capacity eviction (default 5,000 entries), configurable TTL expiration (default 300s), clock injection for deterministic testing, and dictionary interface compatibility. Replaced unbounded raw scan cache dictionaries in `ThreatDetector`.
  2. *Threat Intelligence Cache Hardening (`threat_intelligence/threat_cache.py`)*: Hardened `ThreatIntelligenceCache` with bounded capacity limits (`max_entries`), LRU eviction on saturation, injectable clock function, safe error boundaries, comprehensive telemetry (hits, misses, LRU evictions, TTL evictions, hit ratio), and indicator-level cache invalidation (`invalidate()`).
  3. *Pipeline Invalidation Integration (`threat_intelligence/threat_lookup.py`, `reports/threat_database.py`)*: Added `invalidate_indicator` to `ThreatLookup` and automated cache invalidation upon indicator registration (`register_indicator`) and feed batch upserts (`upsert_feed_records`), preventing stale benign/clean verdicts when new threats are discovered.
  4. *Benchmark Validation (`scripts/benchmark_threat_cache.py`)*: Executed cold vs warm repeated scan benchmark across 20 synthetic fixtures (PE, PowerShell, Batch, Logs). Cold pass: 37.17 ms/file, 26.9 files/sec; Warm pass: 10.57 ms/file, 94.6 files/sec (3.52x speedup, 100% cache hits); Sustained loop: 106.9 files/sec, 88.57% hit ratio across 100 scans with 2.06 MB peak memory.
  5. *Deep Caching & Failure Isolation Test Suite (`tests/test_threat_caching_deep.py`)*: Added 18 automated tests covering LRU eviction, TTL expiration with clock injection, indicator type collision prevention, case/whitespace normalization, transient provider failure rejection, safe write error isolation, multi-threaded concurrency, cache invalidation on SQLite registration, and scan cache hit bypassing.
- **Files/Components**: `threat_intelligence/threat_cache.py`, `threat_intelligence/threat_lookup.py`, `detection_engine/threat_detector.py`, `reports/threat_database.py`, `scripts/benchmark_threat_cache.py`, `tests/test_threat_caching_deep.py`.
- **Validation**: 531 automated tests passing with 100% success rate (+18 new unit and integration tests).

### Days 39–41: Dynamic Weight Fine-Tuning & Explainability Tree (`COMPLETED` — Day 22)
- **Architecture Role**: Delivers and verifies **Pipeline Stage 10 (Evidence Aggregation)**, **Stage 11 (Risk Engine)**, and **Stage 12 (Explainable Detection)**.
- **Delivered**:
  1. *Hierarchical Explainability Tree (`detection_engine/explainability_tree.py`)*: Built `ExplainabilityTree` and `ExplainabilityNode` supporting bounded depth (<=5) and node counts (<=100), recursive node discovery by category, sensitive token masking, and Unicode/ASCII branch rendering (`render_ascii()`).
  2. *Evidence-to-Score Traceability (`detection_engine/explainability_tree.py`, `explanation_generator.py`)*: Implemented `ScoreTraceability` detailing active layer scores, configured weights, normalized weights, weighted contributions, mutual confirmation escalation (+25% boost), mitigation discounts, and safety overrides matching authoritative Risk Engine scores.
  3. *Validated Weight Configuration (`detection_engine/risk_engine.py`)*: Refined `RiskScoringWeights` with strict type validation, rejection of NaN and infinite values, range validation `[0.0, 1.0]`, dynamic `normalized()` method, `from_dict(strict=True/False)` factory, `from_config()` integration, and safe default rollbacks.
  4. *Empirical Weight Fine-Tuning Evaluation*: Audited training datasets (`data/malware_dataset.csv`, `data/phishing_dataset.csv`). Formally documented that empirical weight tuning across all 4 layers is responsibly deferred pending a verified multi-layer ground-truth benchmark corpus, avoiding speculative overfitting while providing transparent validated configuration.
  5. *Pipeline & Contract Integration (`detection_engine/detection_contract.py`, `decision_engine.py`, `threat_detector.py`)*: Integrated `explainability_tree` property into `DetectionResult`, attached full tree and ASCII renderings to `analysis_metadata`, and exposed trees in file and URL detector outputs while preserving 100% backward compatibility for legacy callers.
  6. *Explainability & Traceability Test Suite (`tests/test_explainability_tree.py`)*: Added 23 automated tests covering tree structure, multi-branch routing, honest representation of unavailable ML/TI, secret redaction, mathematical traceability, strict weight validation, deterministic repeatability, end-to-end file/URL integration, and sub-millisecond performance (< 5.0 ms across 50 signals).
- **Files/Components**: `detection_engine/explainability_tree.py`, `detection_engine/risk_engine.py`, `detection_engine/explanation_generator.py`, `detection_engine/detection_contract.py`, `detection_engine/decision_engine.py`, `detection_engine/threat_detector.py`, `tests/test_explainability_tree.py`.
- **Validation**: 554 automated tests passing with 100% success rate (+23 new unit and integration tests).
- **Security Boundaries**: Zero dynamic code execution, strict sensitive token redaction, bounded tree depths, and safe handling of unavailable/unsupported models.

### Day 42: Week 6 Review & Evidence Fusion Edge-Case Audit (`COMPLETED` — Day 23)
- **Architecture Role**: Audits, hardens, and validates **Pipeline Stage 10 (Evidence Aggregation)**, **Stage 11 (Risk Engine)**, and **Stage 12 (Explainable Detection)** against contradictory, missing, duplicate, boundary, override, and failure edge cases.
- **Delivered**:
  1. *Duplicate Signal Deduplication & Audit Provenance (`detection_engine/evidence_model.py`)*: Upgraded `DetectionEvidence` container with automatic deduplication by `(source, signal_id)`. If identical findings are ingested (e.g. repeated rule execution, file watcher replay), the signal with higher weighted contribution is preserved, and dropped duplicates are audited in `discarded_duplicates` without artificial score inflation.
  2. *Safety Override Precedence & Score Consistency (`detection_engine/decision_engine.py`, `explainability_tree.py`, `explanation_generator.py`)*: Resolved P1 override discrepancy where whitelisted indicators could retain non-zero risk scores. Enforced that verified whitelists/false-positives strictly force authoritative risk score to `0.0`, status `BENIGN`, and level `INFORMATIONAL`, while preserving `pre_override_score` in metadata and tree traceability for full security auditing.
  3. *Explainability Tree Size & Resource Bounding (`detection_engine/explanation_generator.py`)*: Hardened branch rendering across static, rule, and TI finding loops. Added safety truncation nodes (`static_truncated`, `rule_truncated`, `ti_truncated`) ensuring tree node count strictly respects `MAX_TOTAL_NODES` (<=100) even when analyzing large or noisy evidence payloads.
  4. *Evidence Fusion Edge-Case Audit Test Suite (`tests/test_evidence_fusion_audit.py`)*: Added 35 automated tests verifying:
     - *Contradictory evidence*: ML high vs TI absent, ML low vs TI confirmed (CRITICAL floor min 90.0), static structural flags vs zero rules, rules vs ML unavailable, reputation discounts vs static anomalies, whitelist override precedence over confirmed malicious TI.
     - *Missing/unavailable evidence*: TI provider timeout, rate limiting (429), missing ML model artifacts (omitted without penalty), empty evidence collections (informative baseline uncertainty).
     - *Duplicate/correlated evidence*: Repeated rule signal deduplication, stronger finding preservation, distinct rules accumulating up to cap.
     - *Risk scoring boundaries*: 0.0, 100.0, clamped negatives/excesses, weight validation (rejection of NaN/Inf/zero sum), and exact epsilon transitions around canonical thresholds (20, 35, 60, 80).
     - *Explainability consistency*: Strict equality between tree `final_score` and `decision_result.risk_score`, recursive credential redaction, bounded tree size.
     - *Offline analysis resilience*: Local PE analysis succeeds and detects threats when external TI is offline.
- **Files/Components**: `detection_engine/evidence_model.py`, `detection_engine/decision_engine.py`, `detection_engine/explainability_tree.py`, `detection_engine/explanation_generator.py`, `tests/test_evidence_fusion_audit.py`.
- **Validation**: 589 automated tests passing with 100% success rate (+35 new audit tests, 0 failed, 0 errors, 4 third-party warnings).
- **Security Boundaries**: Complete non-destructive execution, strict sensitive token masking, zero score inflation on duplicate ingestion, and clear precedence rules for whitelist overrides.

---

## Week 7: URL & Message Scanner Production Integration

### Days 43–45: Advanced URL De-obfuscation & Redirection Handling (`COMPLETED` — Day 24)
- **Delivered**:
  1. *Standards-Aware URL Normalization & De-obfuscation (`scanners/url_scanner.py`)*: Standards-aware parsing with `URLAnalysisResult` contract preserving original and normalized URLs, zero-width character detection/stripping, IDN/Punycode translation with mixed-script homoglyph detection, numeric IP decoders (dword decimal integer, octal, hex) converted to canonical dotted decimal, userinfo deception handling, and bounded double percent-encoding / encoded delimiter analysis. 100% backward compatibility maintained.
  2. *Strict SSRF Defense & Bounded Redirect Inspection (`scanners/redirect_inspector.py`)*: `SSRFValidator` inspecting loopback, private IPv4/IPv6, link-local, cloud metadata, CGNAT, broadcast, and internal domains with full DNS resolution pre-validation on every hop. `RedirectInspector` with bounded hops (<=5), deadline (<=5.0s), cycle loop detection, relative location joining, non-intrusive HEAD/GET (0-byte body), zero credentials/cookies, zero browser JS or payload execution.
  3. *Deterministic Heuristic Rules (`detection_engine/rule_engine.py`)*: 8 dedicated rules: `RULE_URL_HOMOGLYPH_IDN`, `RULE_URL_ZERO_WIDTH_CHARS`, `RULE_URL_DOUBLE_ENCODING`, `RULE_URL_IP_NUMERIC_OBFUSCATION`, `RULE_URL_USERINFO_OBFUSCATION`, `RULE_URL_SSRF_PROHIBITED`, `RULE_URL_REDIRECT_LOOP`, `RULE_URL_SUSPICIOUS_REDIRECT`.
  4. *Evidence & Explainability Integration*: `discarded_duplicates_count` in `DetectionEvidence`, URL de-obfuscation and redirect inspection nodes in `ExplanationGenerator`, and redirect parameter in `ThreatDetector.analyze_url()`.
  5. *Test Suite*: 58 automated unit/integration tests in `tests/test_url_deobfuscation_and_redirects.py`.
- **Files/Components**: `scanners/url_scanner.py`, `scanners/redirect_inspector.py`, `detection_engine/rule_engine.py`, `detection_engine/evidence_model.py`, `detection_engine/explanation_generator.py`, `detection_engine/threat_detector.py`, `tests/test_url_deobfuscation_and_redirects.py`.
- **Baseline**: 647 automated tests passing with 100% success rate (+58 new tests for Day 24). Zero regressions.

### Days 46–48: Social Engineering & Safe MIME Parsing (`COMPLETED` — Day 25)
- **Architecture Role**: Extends ACTIS message analysis capabilities with safe standard-library MIME parsing, explainable social-engineering indicators, link display-text mismatch detection, metadata-only attachment policy, and unified integration into the ACTIS evidence, detection, risk, and explainability systems.
- **Delivered**:
  1. *Safe Bounded MIME Parsing Subsystem (`scanners/mime_parser.py`)*: Standards-compliant traversal using standard library `email.parser.BytesParser(policy=policy.default)` with graceful fallback to `Parser(policy=policy.default)`. Enforces strict configurable resource boundaries (10MB raw message, 64KB headers, 50 parts, 10 nesting levels, 1MB decoded text, 5MB part size, 100 extracted URLs, 5.0s deadline). Path traversal sanitization on attachment filenames (`sanitize_filename`).
  2. *Safe HTML Extraction & Display-Text Mismatch Detection (`scanners/mime_parser.py`)*: `SafeHTMLURLParser` streaming parser operating with zero JavaScript execution and zero browser rendering. Captures `<a href>` attributes and plain text URLs in non-script/non-style tags. `is_domain_mismatch()` detects deceptive anchor links where visible domain disagrees with actual destination while safely allowing shared registered base domains.
  3. *Attachment Metadata-Only Policy (`scanners/mime_parser.py`)*: Strict read-only metadata extraction (`filename`, `content_type`, `size_bytes`, `extension`, `is_suspicious_extension`). Zero attachment execution, zero disk execution, zero dynamic loading.
  4. *Deterministic Heuristic Rules (`detection_engine/rule_engine.py`)*: 9 dedicated rules: `RULE_MSG_URGENCY_PRESSURE`, `RULE_MSG_CREDENTIAL_HARVEST`, `RULE_MSG_FINANCIAL_LURE`, `RULE_MSG_IMPERSONATION`, `RULE_MSG_SECURITY_EVASION`, `RULE_MSG_SENSITIVE_INFO_PROMPT`, `RULE_MSG_DISPLAY_TEXT_MISMATCH`, `RULE_MSG_SUSPICIOUS_ATTACHMENT`, `RULE_MSG_MIME_DEFECT_ANOMALY`.
  5. *Pipeline & Explainability Integration*: Unified `ThreatDetector.analyze_message()` routing to `DetectionDecisionEngine.evaluate(input_type=InputType.MESSAGE)` with dedicated `message_structure` node in `ExplanationGenerator`. 100% backward compatibility maintained.
  6. *Automated Test Suite (`tests/test_message_analysis.py`)*: 45 deterministic, offline, adversarial unit and integration tests.
- **Files/Components**: `scanners/mime_parser.py`, `scanners/text_analyzer.py`, `detection_engine/rule_engine.py`, `detection_engine/threat_detector.py`, `detection_engine/explanation_generator.py`, `detection_engine/detection_contract.py`, `tests/test_message_analysis.py`.
- **Validation**: 692 automated tests passing with 100% success rate (+45 new tests for Day 25, 0 failures, 0 errors, 4 third-party warnings).
- **Security Boundaries**: Zero attachment execution, zero network calls during offline message analysis, remote redirect inspection disabled by default (`follow_redirects=False`), zero browser rendering, and strict privacy protections on message logs.

### Day 49: Week 7 Verification (`COMPLETED` — Day 26)
- **Goal**: Deterministic, offline verification benchmark framework evaluating Day 24 URL-analysis and Day 25 message-analysis pipelines across 140 synthetic message, email, and URL samples.
- **Delivered**:
  1. *Versioned Synthetic Corpus Subsystem (`benchmarks/message_analysis/dataset.py`, `tests/fixtures/phishing_benchmark/manifest.json`)*: 140 labeled samples across 9 scenarios (`credential_harvesting`, `impersonation_social_engineering`, `financial_manipulation`, `deceptive_links_url_obfuscation`, `mixed_phishing_indicators`, `legitimate_security_account`, `benign_financial_business`, `security_awareness_education`, `malformed_resource_limits`). Schema validation and SHA-256 manifest hashing.
  2. *Deterministic Evaluation Metrics Engine (`benchmarks/message_analysis/metrics.py`)*: Confusion matrix, precision (0.8155), recall (0.9655), F1 (0.8842), balanced accuracy (0.7965), specificity (0.6275), accuracy (0.8406), FPR (0.3725), FNR (0.0345), coverage (98.6%), per-rule telemetry, URL metrics, and monotonic latency profiling.
  3. *Canonical Pipeline Runner (`benchmarks/message_analysis/runner.py`)*: Evaluates canonical `ThreatDetector.analyze_message()`, enforces zero network calls, isolates per-sample exceptions, and maps verdicts cleanly (`PHISHING`, `BENIGN`, `ABSTAIN`).
  4. *Reproducible Reporting Engine (`benchmarks/message_analysis/report.py`)*: Generates `reports/benchmarks/message_analysis/latest.json` and `latest.md` with privacy safeguards (message redaction) and preserved `baseline.json` / `baseline.md`.
  5. *Explainability Tree Bug Fix (`detection_engine/explainability_tree.py`)*: Added `LIMITATION = "LIMITATION"` to `NodeStatus` enum, resolving uncaught exceptions during partial message analysis.
  6. *Automated Test Suite (`tests/test_message_analysis_benchmark.py`)*: 22 comprehensive deterministic tests.
- **Files/Components**: `benchmarks/message_analysis/dataset.py`, `benchmarks/message_analysis/metrics.py`, `benchmarks/message_analysis/runner.py`, `benchmarks/message_analysis/report.py`, `tests/fixtures/phishing_benchmark/manifest.json`, `detection_engine/explainability_tree.py`, `tests/test_message_analysis_benchmark.py`, `tests/test_explainability_tree.py`.
- **Validation**: 715 automated tests passing with 100% success rate (+23 new tests for Day 26, 0 failures, 0 errors, 4 third-party warnings).

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
