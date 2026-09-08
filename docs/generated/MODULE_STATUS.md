# ACTIS Module Status (Empirical Audit)

This document provides a factual classification of every major module in the repository, evaluating whether each component contains working code, prototypes, or planned interfaces.

---

## Subsystem Classification

| Subsystem / Module | Empirical Status | Verification Evidence | Notes / Remaining Work |
|---|---|---|---|
| **`config/`** | `IMPLEMENTED` | Tested via `tests/test_config_*.py` (11 passing tests) | Fully realized Week 1 Day 2 foundation. |
| **`models/`** | `IMPLEMENTED` | Artifacts on disk; metadata JSON contracts verified | Phishing RF (19 feats) & Malware RF (15 feats) models operational. |
| **`scanners/`** | `PARTIALLY IMPLEMENTED` | Prototype code in all 6 scanner files; tested via `test_url_scanner.py`, `test_text_analyzer.py`, `test_static_pe.py` | Full multi-scanner unified orchestrator scheduled for Month 2. |
| **`detection_engine/`** | `PARTIALLY IMPLEMENTED` | `risk_engine.py`, `rule_engine.py`, `model_manager.py` tested in `test_risk_engine.py` | Multi-engine pipeline integration scheduled across Months 1–2. |
| **`threat_intelligence/`** | `PARTIALLY IMPLEMENTED` | `threat_lookup.py`, `api_clients.py`, `sync_manager.py` implemented | Full external provider suite and standalone `indicator_manager.py` scheduled for Month 3. |
| **`reports/`** | `PARTIALLY IMPLEMENTED` | `threat_database.py`, `scan_database.py`, `report_generator.py` tested in `test_threat_database.py` | Formal schema migration and constraints scheduled for Week 1 Day 4. |
| **`notifications/`** | `PARTIALLY IMPLEMENTED` | `notifier.py` formatting logic implemented | Native Windows desktop toast alerts scheduled for Month 4 Week 14. |
| **`dashboard/`** | `PARTIALLY IMPLEMENTED` | `app.py` Streamlit UI operational with 13 functional sections | Polish and security hardening scheduled for Month 4 Week 13. |
| **`assistant/`** | `PARTIALLY IMPLEMENTED` | `security_assistant.py` queries local SQLite DB | Advanced conversational grounding scheduled for Month 4 Week 14. |
| **`backend/`** | `PARTIALLY IMPLEMENTED` | FastAPI endpoints tested via `tests/test_backend_api.py` (4 passing tests) | Peer synchronization testing scheduled for Month 3 Week 12. |
| **`tests/`** | `IMPLEMENTED` | 35 passing tests across 8 test suites | Expands continuously with each development day. |

---

## Status Classification Key

- **`IMPLEMENTED`**: Production-ready, type-safe, validated by automated unit tests.
- **`PARTIALLY IMPLEMENTED`**: Functional prototypes active in repository, but formal roadmap integration/refinement is scheduled for later weeks.
- **`PLANNED`**: Defined in architectural source-of-truth documents, awaiting roadmap realization.
- **`MISSING`**: Required by architecture but completely absent from source tree.
