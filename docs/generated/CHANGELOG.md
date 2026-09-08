# ACTIS Changelog

All notable changes to the ACTIS (Automated Cyber Threat Intelligence System) project are documented in this file in accordance with the ACTIS Daily Micro-Commit & Documentation Protocol.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) and adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [v0.1.0] — Foundation (In Progress)

Milestone Scope: Architecture planning, configuration management, logging infrastructure, database/ML contracts, initial validation tests, and project foundations.

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
