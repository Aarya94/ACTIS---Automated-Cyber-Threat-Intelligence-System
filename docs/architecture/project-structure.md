# ACTIS Project Structure

This document details the standardized filesystem organization of the ACTIS repository, explaining the purpose of each directory and noting its current implementation status.

---

## Intended Repository Layout

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
│   ├── roadmap/               # Chronological 4-month / 16-week daily development plans
│   └── generated/             # Empirical repository status, schema refs, test telemetry
├── main.py                    # Unified application CLI and orchestrator entrypoint
├── requirements.txt           # Python dependency declarations
├── README.md                  # High-level project summary and quickstart
└── .gitignore                 # Exclusion rules for secrets, venv, pycache, binaries
```

---

## Directory Descriptions & Status

| Directory | Purpose | Current Status | Notes |
|---|---|---|---|
| `data/` | Local SQLite databases (`threat_intelligence.db`) and evaluation datasets (`phishing_dataset.csv`, `malware_dataset.csv`). | **EXISTING** | Datasets preserved locally on disk; databases gitignored. |
| `models/` | Trained model binaries (`phishing_model.pkl`, `malware_model.pkl`) and metadata JSON schemas. | **EXISTING** | Model binaries ignored by Git; JSON metadata contracts tracked. |
| `scanners/` | URL scanner, text analyzer, PE feature extractor, device scanner, file watcher, clipboard scanner. | **PARTIAL** | Core inspection logic implemented; integrated workflows scheduled for Month 2. |
| `detection_engine/` | Orchestrates evidence fusion between ML, heuristics, threat intelligence, and risk calculations. | **PARTIAL** | Components exist; multi-criteria end-to-end integration scheduled for Month 1 Week 4 and Month 2. |
| `threat_intelligence/`| Local indicator lookup, external threat API client (VirusTotal), and backend sync manager. | **PARTIAL** | Implemented as prototype; standalone `indicator_manager.py` and additional providers scheduled for Month 3. |
| `reports/` | SQLite database schemas (`threat_database.py`, `scan_database.py`) and report generator (`report_generator.py`). | **PARTIAL** | Schemas and JSON/CSV/MD exports implemented; formal schema hardening scheduled for Week 1 Day 4. |
| `notifications/` | Alert formatting and console/desktop dispatch (`notifier.py`). | **PARTIAL** | Console notifier implemented; Windows toast/audio alerts scheduled for Month 4 Week 14. |
| `dashboard/` | Interactive Streamlit command center (`app.py`) with Plotly visualization. | **PARTIAL** | Prototype dashboard operational; production polish scheduled for Month 4 Week 13. |
| `assistant/` | Grounded security assistant (`security_assistant.py`) querying local SQLite records. | **PARTIAL** | Offline SQLite-grounded explainer implemented; LLM integration scheduled for Month 4 Week 14. |
| `backend/` | Central FastAPI intelligence sharing API (`api.py`, `database.py`, `models.py`). | **PARTIAL** | Core REST endpoints implemented; peer synchronization testing scheduled for Month 3 Week 12. |
| `config/` | Strongly-typed configuration schema, paths, environment loader, defaults, and validator. | **IMPLEMENTED** | Fully complete, tested, and validated as of Week 1 Day 2. |
| `tests/` | Automated test suites (`pytest`). | **IMPLEMENTED** | 35 passing tests covering config, backend, risk engine, PE static analysis, scanners, and DB. |
| `logs/` | Runtime rotating log directory (`actis.log`). | **EXISTING** | Managed by `config/config.py` using `RotatingFileHandler`. |
| `docs/` | Authoritative documentation framework (`architecture/`, `roadmap/`, `generated/`). | **IMPLEMENTED** | Established in Week 1 Day 2. |

---

## File Tracking and Hygiene Policies

1. **Never Track Secrets**: `.env`, `.env.*`, `*.pem`, `*.key`, and credentials must NEVER be committed.
2. **Never Track Runtime Databases**: `data/*.db` and `backend/*.db` are strictly excluded in `.gitignore`.
3. **Never Track Binary Model Weights**: Machine learning weights (`models/*.pkl`) are excluded from Git history; model architectures are documented via `models/*_metadata.json`.
4. **Never Track Ephemeral Logs**: `logs/*.log` are generated at runtime and ignored.
