# ACTIS Roadmap — Month 1: Foundation (Weeks 1 – 4)

**Milestone Version**: `v0.1.0 — Foundation`

Month 1 establishes the bedrock of ACTIS: architecture governance, configuration infrastructure, logging, local threat database contracts, the 19-feature URL phishing classifier, safe static PE feature extraction, heuristic rule engines, the 15-feature Windows PE malware model, and the initial detection fusion pipeline.

---

## Week 1: Architecture, Configuration, Data & Model Foundations

### Day 1: Architecture Planning & Repository Foundation
- **Goal**: Define approved ACTIS system architecture and initialize repository structure.
- **Tasks**: Draft `docs/architecture/`, define component topology, configure `.gitignore` for secrets and binaries.
- **Expected Output**: Architectural documents, initial directory scaffold, clean `.gitignore`.
- **Files/Components**: `docs/architecture/`, `tools/validate_structure.py`, `README.md`.
- **Validation**: `python tools/validate_structure.py`.
- **Dependencies**: None.
- **Not Included**: ML model training, scanner implementations, live database initialization.

### Day 2: Configuration Management (Current Completed Baseline)
- **Goal**: Implement centralized, type-safe configuration with typed environment variable parsing and validation.
- **Tasks**: Build `config/settings.py`, `config/env_loader.py`, `config/paths.py`, `config/defaults.py`, `config/validator.py`, `.env.example`.
- **Expected Output**: Strongly-typed `AppConfig`, path resolver, 11 automated config tests, comprehensive documentation.
- **Files/Components**: `config/`, `tests/test_config_loading.py`, `tests/test_config_validation.py`, `docs/configuration.md`.
- **Validation**: `pytest tests/test_config_*.py` (100% pass).
- **Dependencies**: Day 1 repository structure.
- **Not Included**: Live threat intelligence syncing, database queries.

### Day 3: Logging Infrastructure & Audit Trails
- **Goal**: Establish enterprise structured logging, file rotation, and audit trail records.
- **Tasks**: Build rotating file handlers, structured JSON log formatters, audit trail loggers in `config/logger.py`.
- **Expected Output**: Structured logging utility supporting console and rotating file logs (`logs/actis.log`).
- **Files/Components**: `config/logger.py`, `tests/test_logger.py`.
- **Validation**: `pytest tests/test_logger.py`.
- **Dependencies**: Day 2 configuration paths.
- **Not Included**: Real-time dashboard log streaming.

### Day 4: Database Contracts & Schema Planning
- **Goal**: Define and initialize SQLite schemas for indicators, threats, scans, and detections.
- **Tasks**: Create normalized tables (`threats`, `indicators`, `scans`, `detections`, `scan_items`), index definition, foreign keys.
- **Expected Output**: `reports/threat_database.py` with thread-safe SQLite connection context managers.
- **Files/Components**: `reports/threat_database.py`, `tests/test_threat_database.py`.
- **Validation**: `pytest tests/test_threat_database.py`.
- **Dependencies**: Day 2 database paths.
- **Not Included**: Cloud database synchronization, ORMs.

### Day 5: ML Contracts & Phishing Model Foundation
- **Goal**: Establish feature schema contracts and integrate the 19-feature Random Forest phishing model.
- **Tasks**: Formalize `models/phishing_model_metadata.json`, create `detection_engine/model_manager.py` schema validators.
- **Expected Output**: Working ML inference runtime predicting phishing probability from 19 URL morphological features.
- **Files/Components**: `detection_engine/model_manager.py`, `models/phishing_model_metadata.json`.
- **Validation**: Verify prediction against synthetic test feature vectors.
- **Dependencies**: Day 2 model paths.
- **Not Included**: Windows PE binary analysis, online URL lookups.

### Day 6: Initial Validation Suite Expansion
- **Goal**: Implement end-to-end unit and integration validation for Week 1 components.
- **Tasks**: Author `tests/run_week1_tests.py` covering directory structure, config load, DB creation, and ML metadata contracts.
- **Expected Output**: Unified Week 1 validation runner.
- **Files/Components**: `tests/run_week1_tests.py`, `tests/test_week1_validation.py`.
- **Validation**: `python tests/run_week1_tests.py` passing 100%.
- **Dependencies**: Days 1–5 implementations.
- **Not Included**: Complex scanner workflows.

### Day 7: Week 1 Review, Cleanup & Documentation
- **Goal**: Audit Week 1 deliverables, verify changelog integrity, tag internal milestone `v0.1.0-w1`.
- **Tasks**: Run full regression test suite, verify clean Git state, update `docs/CHANGELOG.md`.
- **Expected Output**: Fully verified Week 1 foundation.
- **Files/Components**: `docs/CHANGELOG.md`, `docs/generated/PROJECT_STATUS.md`.
- **Validation**: Clean `git status`, all tests passing.
- **Dependencies**: Days 1–6.
- **Not Included**: Any Week 2 code.

---

## Week 2: Static File Analysis & PE Feature Extraction

### Days 8–10: Safe Read-Only Binary File Processing
- **Goal**: Build file streaming hashing and entropy calculation routines.
- **Tasks**: Implement chunked SHA-256 and MD5 hashing, byte frequency distribution, and Shannon entropy computation.
- **Files/Components**: `scanners/file_feature_extractor.py`.
- **Not Included**: Live process execution, dynamic debugging.

### Days 11–13: PE Structural Header & Section Extraction
- **Goal**: Extract 15 static PE header features from Windows binaries using `pefile`.
- **Tasks**: Parse COFF headers, Optional headers, section tables, and import directories safely in memory.
- **Files/Components**: `scanners/file_feature_extractor.py`, `tests/test_static_pe.py`.
- **Not Included**: Malware model training (scheduled for Week 4).

### Day 14: Week 2 Review & Integration Validation
- **Goal**: Validate static PE feature extraction on benign and non-PE test samples.
- **Files/Components**: `tests/test_static_pe.py`.

---

## Week 3: Ingestion Scanners & Heuristic Rules

### Days 15–17: URL Scanner & Text Message Analyzer
- **Goal**: Build URL normalization, regex link extraction, and social engineering urgency detection.
- **Files/Components**: `scanners/url_scanner.py`, `scanners/text_analyzer.py`.

### Days 18–20: Rule-Based Heuristic Engine & Risk Engine
- **Goal**: Implement deterministic heuristic rules (PE injection APIs, packers, unescaped IPs) and dynamic weight risk fusion.
- **Files/Components**: `detection_engine/rule_engine.py`, `detection_engine/risk_engine.py`.

### Day 21: Week 3 Integration Review
- **Goal**: Verify evidence fusion across rules, preliminary scores, and risk bands.

---

## Week 4: Malware Model & Detection Pipeline Validation

### Days 22–24: Windows PE Malware Model Integration
- **Goal**: Integrate the 15-feature Windows PE Random Forest classifier (`models/malware_model.pkl`).
- **Files/Components**: `models/malware_model_metadata.json`, `detection_engine/model_manager.py`.

### Days 25–27: End-to-End Detection Orchestration
- **Goal**: Unify scanners, models, rules, and risk engine in `detection_engine/threat_detector.py`.
- **Files/Components**: `detection_engine/threat_detector.py`.

### Day 28: Month 1 Milestone Audit (`v0.1.0`)
- **Goal**: Complete regression test suite, verify zero leaks/untracked files, cut milestone tag `v0.1.0`.
