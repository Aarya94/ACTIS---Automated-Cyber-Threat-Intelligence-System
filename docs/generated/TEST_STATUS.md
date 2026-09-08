# ACTIS Automated Test Status Report

- **Date of Execution**: 2026-09-08
- **Test Framework**: `pytest 9.1.1` (Python 3.13.14 on Windows)
- **Total Tests Collected**: 35
- **Passed**: 35
- **Failed**: 0
- **Execution Time**: ~2.4 seconds
- **Pass Rate**: 100%

---

## Test Suite Inventory

| Test Module | Test Count | Scope Verified | Status |
|---|---|---|---|
| `tests/test_config_loading.py` | 4 | Default config generation, typed env parsing, path anchoring, secret redaction | **PASSED** |
| `tests/test_config_validation.py`| 7 | Weight normalization, risk thresholds, scanner bounds, network ports, strict mode | **PASSED** |
| `tests/test_week1_validation.py` | 4 | Required directory scaffold, logger init, contracts schema, phishing metadata | **PASSED** |
| `tests/test_backend_api.py` | 4 | Central FastAPI endpoints: health, indicator push, indicator pull, authentication | **PASSED** |
| `tests/test_risk_engine.py` | 3 | Multi-criteria evidence fusion, score bounds, deterministic explainability tree | **PASSED** |
| `tests/test_static_pe.py` | 3 | Safe static PE feature extraction, entropy calculation, fallback handling | **PASSED** |
| `tests/test_text_analyzer.py` | 3 | Embedded URL regex extraction, social engineering urgency scoring | **PASSED** |
| `tests/test_threat_database.py` | 3 | SQLite table initialization, indicator insertion, detection persistence | **PASSED** |
| `tests/test_url_scanner.py` | 4 | URL normalization, morphological feature extraction, ML inference pipeline | **PASSED** |

---

## Secondary Validation Runners

- `tests/run_week1_tests.py`: Standalone execution verifying directory presence, config loading, metadata schemas -> **PASSED**.
