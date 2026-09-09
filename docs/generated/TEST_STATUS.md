# ACTIS Test Status & Verification Inventory

**Generated:** 2026-09-09 14:37:38 UTC  
**Source of Truth:** AST Test Discovery & Pytest Runner (`scripts/generate_docs.py`)  

This document inventories all automated test files, test classes, and test functions
present in the `tests/` directory. Per ACTIS quality requirements, test passes are
recorded only after confirmed execution.

---

## Test Suite Summary

- **Total Test Files:** `10`
- **Total Discovered Test Cases:** `66`
- **Test Framework:** `pytest` 8.x with `unittest` compatibility
- **Execution Command:** `pytest tests/ -v`

---

## Discovered Test Files

| Test File | Test Cases | Status |
|---|---|---|
| `tests/test_backend_api.py` | 4 tests | `PASSING` |
| `tests/test_config_loading.py` | 11 tests | `PASSING` |
| `tests/test_config_validation.py` | 11 tests | `PASSING` |
| `tests/test_doc_generator.py` | 20 tests | `PASSING` |
| `tests/test_risk_engine.py` | 3 tests | `PASSING` |
| `tests/test_static_pe.py` | 3 tests | `PASSING` |
| `tests/test_text_analyzer.py` | 3 tests | `PASSING` |
| `tests/test_threat_database.py` | 3 tests | `PASSING` |
| `tests/test_url_scanner.py` | 4 tests | `PASSING` |
| `tests/test_week1_validation.py` | 4 tests | `PASSING` |

---

## Test Functions Detail

### `tests/test_backend_api.py` (4 tests)

**Standalone Test Functions:**
- `test_health_endpoint()`
- `test_indicator_lookup()`
- `test_unauthenticated_submission()`
- `test_authenticated_submission_and_sync()`

### `tests/test_config_loading.py` (11 tests)

**Standalone Test Functions:**
- `test_default_config_instantiation()`
- `test_project_paths_resolution()`
- `test_typed_env_loader_helpers()`
- `test_secret_redaction_in_repr()`
- `test_testing_profile_uses_isolated_test_paths()`
- `test_production_profile_configuration()`
- `test_dynamic_get_config_reload()`
- `test_bounded_int_and_float_loader()`
- `test_path_env_loader()`
- `test_config_to_dict_redaction_and_structure()`
- `test_config_to_dict_unmasked()`

### `tests/test_config_validation.py` (11 tests)

**Standalone Test Functions:**
- `test_valid_default_config_passes_validation()`
- `test_invalid_log_level()`
- `test_weight_validation_sum_and_bounds()`
- `test_risk_threshold_ordering()`
- `test_scanner_limits_validation()`
- `test_server_network_validation()`
- `test_strict_mode_raises_configuration_error()`
- `test_invalid_environment_validation()`
- `test_database_settings_validation()`
- `test_app_name_validation()`
- `test_api_request_timeout_validation()`

### `tests/test_doc_generator.py` (20 tests)

**Class `TestRepoInspector`:**
- `test_audit_directories()`
- `test_get_root_files()`

**Class `TestGitAnalyzer`:**
- `test_branch_info()`
- `test_recent_commits()`
- `test_working_tree_status()`

**Class `TestCodebaseAnalyzer`:**
- `test_inspect_python_file()`
- `test_inspect_package()`
- `test_inspect_scaffolded_package()`

**Class `TestMlModelAnalyzer`:**
- `test_audit_models()`
- `test_audit_datasets()`

**Class `TestDatabaseAnalyzer`:**
- `test_audit_schema()`

**Class `TestTestSuiteAnalyzer`:**
- `test_audit_test_files()`

**Class `TestRoadmapCalculator`:**
- `test_progress_metrics()`

**Class `TestMarkdownReportBuilder`:**
- `test_generate_project_status()`
- `test_generate_module_status()`
- `test_generate_ml_reference()`
- `test_generate_database_reference()`
- `test_generate_test_status()`
- `test_generate_changelog()`

**Class `TestGeneratorCli`:**
- `test_cli_check_mode()`

### `tests/test_risk_engine.py` (3 tests)

**Standalone Test Functions:**
- `test_confirmed_threat_fast_track()`
- `test_benign_low_risk()`
- `test_combined_ml_and_heuristic_escalation()`

### `tests/test_static_pe.py` (3 tests)

**Standalone Test Functions:**
- `test_entropy_calculation()`
- `test_non_pe_static_analysis()`
- `test_pe_static_analysis_notepad()`

### `tests/test_text_analyzer.py` (3 tests)

**Standalone Test Functions:**
- `test_extract_urls_multiple_formats()`
- `test_social_engineering_detection()`
- `test_end_to_end_message_analysis()`

### `tests/test_threat_database.py` (3 tests)

**Standalone Test Functions:**
- `test_seed_indicators_present()`
- `test_register_and_lookup_custom_indicator()`
- `test_scan_session_lifecycle()`

### `tests/test_url_scanner.py` (4 tests)

**Standalone Test Functions:**
- `test_normalize_url()`
- `test_extract_url_features_length_and_types()`
- `test_rule_engine_url_heuristics()`
- `test_scan_url_logic_safe_and_phishing()`

### `tests/test_week1_validation.py` (4 tests)

**Standalone Test Functions:**
- `test_required_directories_present()`
- `test_config_and_logger_load()`
- `test_requirements_and_readme_exist()`
- `test_phishing_model_metadata_contract()`

---

## Test Verification Commands

```powershell
# Run entire test suite
pytest tests/ -v

# Run specific subsystem tests
pytest tests/test_config_loading.py -v
pytest tests/test_config_validation.py -v
pytest tests/test_threat_database.py -v
pytest tests/test_url_scanner.py -v
pytest tests/test_static_pe.py -v
```

---
*Report automatically generated by `scripts/generate_docs.py`.*
