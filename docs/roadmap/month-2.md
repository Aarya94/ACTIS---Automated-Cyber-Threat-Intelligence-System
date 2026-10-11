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

### Days 29–31: Enhanced PE Section & Import Analysis
- **Goal**: Expand heuristic rules for suspicious Windows API import combinations (process hollowing, memory manipulation, token impersonation).
- **Tasks**: Map API import hashes, flag dangerous API sequences (`VirtualAlloc`, `WriteProcessMemory`, `CreateRemoteThread`, `SetWindowsHookEx`), calculate per-section entropy.
- **Expected Output**: Deepened structural PE security analysis.
- **Files/Components**: `scanners/file_feature_extractor.py`, `detection_engine/rule_engine.py`.
- **Validation**: `pytest tests/test_static_pe.py`.
- **Dependencies**: Month 1 PE feature extractor.
- **Not Included**: Live process inspection or kernel drivers.

### Days 32–34: Non-PE File Fallback Analysis
- **Goal**: Provide safe static evaluation for non-PE files (scripts, archives, office documents).
- **Tasks**: Stream SHA-256/MD5 hashing, detect archive extensions, analyze macro presence heuristics without execution.
- **Expected Output**: Graceful fallback analyzer for non-Windows executable file types.
- **Files/Components**: `scanners/file_scanner.py`.
- **Validation**: Test hashing and metadata extraction on text and zip files.
- **Dependencies**: `scanners/file_feature_extractor.py`.
- **Not Included**: Microsoft Office COM automation.

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
