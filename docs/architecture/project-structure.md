# ACTIS Project Structure

**Authoritative Architecture Document**  
**Milestone:** Post-Day-7 Architectural Evolution  
**Status:** Approved Target Architecture  

This document details the standardized filesystem organization of the ACTIS repository, explaining the purpose of each directory and noting its current implementation status relative to the Day 7 baseline.

---

## 1. Intended Repository Layout

```text
ACTIS/
├── data/                      # Local datasets, SQLite databases, indicators
├── models/                    # Serialized ML model artifacts (*.pkl) and JSON metadata
├── scanners/                  # Ingestion modules (URL, message, file, device, watcher, clipboard)
├── detection_engine/          # Core detection orchestration, ML managers, rules, risk engine
├── threat_intelligence/       # Indicator lookup, API connectors, client sync manager
├── reports/                   # SQLite database wrappers, scan schemas, report generators
├── notifications/             # Alert formatting and user dispatch queue
├── dashboard/                 # Streamlit web command center UI
├── assistant/                 # Offline grounded security assistant
├── backend/                   # Central FastAPI intelligence sharing service
├── config/                    # Centralized settings, environment loaders, path resolver, defaults
├── tests/                     # Automated unit, integration, and validation suites
├── logs/                      # Rotating application audit and execution logs
├── docs/                      # Architectural source of truth, roadmaps, and generated reports
│   ├── architecture/          # System design, module contracts, workflows, security rules
│   ├── roadmap/               # Chronological daily development plans
│   └── generated/             # Empirical repository status, schema refs, test telemetry
├── main.py                    # Unified application CLI and orchestrator entrypoint
├── requirements.txt           # Python dependency declarations
├── README.md                  # High-level project summary and quickstart
└── .gitignore                 # Exclusion rules for secrets, venv, pycache, binaries
```

---

## 2. Directory Descriptions & Verified Status

| Directory | Purpose | Current Status | Notes |
|---|---|---|---|
| `config/` | Strongly-typed configuration schema, paths, environment loader, defaults, and validator. | **IMPLEMENTED** | Fully complete, tested, and validated as of Day 2 (11 unit tests). |
| `reports/` | SQLite database schemas (`threat_database.py`, `scan_database.py`) and report generator. | **IMPLEMENTED** | Relational schemas, WAL mode, CRUD queries, JSON/CSV/MD exports operational. |
| `models/` | Trained model binaries (`phishing_model.pkl`, `malware_model.pkl`) and metadata JSON schemas. | **IMPLEMENTED** | Phishing RF model integrated; malware metadata contract verified. |
| `scanners/` | Input mechanisms (URL scanner, text analyzer, PE feature extractor, device scanner, incremental scan state). | **PARTIALLY IMPLEMENTED** | URL and message scanners hardened on Day 7; PE static extractor verified; Device Scanner and Incremental Scan State completed on Day 8; File watcher scheduled for Day 10. |
| `detection_engine/` | Fuses evidence from ML, heuristics, threat intelligence, and risk calculations. | **IMPLEMENTED** | Decision engine, risk engine, rule engine, threat detector unified on Day 6. |
| `threat_intelligence/`| Local indicator lookup, external API connector, and backend sync manager. | **PARTIALLY IMPLEMENTED** | Local SQLite lookup verified; external API client (VT) and sync manager exist as prototypes. |
| `notifications/` | Alert formatting and console/desktop dispatch (`notifier.py`). | **PROTOTYPE / NOT YET MILESTONE-COMPLETE** | Console alerts operational; native Windows desktop notifications scheduled for Day 13. |
| `dashboard/` | Interactive Streamlit command center (`app.py`). | **PROTOTYPE / NOT YET MILESTONE-COMPLETE** | Prototype operational; production UI and scan management scheduled for Day 13. |
| `assistant/` | Grounded security assistant (`security_assistant.py`) querying local SQLite records. | **PROTOTYPE / NOT YET MILESTONE-COMPLETE** | SQLite-grounded explainer operational; conversational interface scheduled for Day 14. |
| `backend/` | Central FastAPI intelligence sharing API (`api.py`, `database.py`, `models.py`). | **PROTOTYPE / NOT YET MILESTONE-COMPLETE** | Prototype REST API operational; client synchronization scheduled for Day 12. |
| `tests/` | Automated test suites (`pytest`). | **IMPLEMENTED** | 162 passing automated tests with 100% pass rate. |
| `logs/` | Runtime rotating log directory (`actis.log`). | **EXISTING** | Managed by `config/logger.py` with sanitization and rotation. |
| `docs/` | Authoritative documentation framework (`architecture/`, `roadmap/`, `generated/`). | **IMPLEMENTED** | Authoritative source of truth for ACTIS engineering. |

---

## 3. File Tracking and Hygiene Policies

1. **Never Track Secrets:** `.env`, `.env.*`, `*.pem`, `*.key`, and credentials must NEVER be committed.
2. **Never Track Runtime Databases:** `data/*.db` and `backend/*.db` are strictly excluded in `.gitignore`.
3. **Never Track Binary Model Weights:** Machine learning weights (`models/*.pkl`) are excluded from Git history; model architectures are documented via `models/*_metadata.json`.
4. **Never Track Ephemeral Logs:** `logs/*.log` are generated at runtime and ignored.
