# ACTIS Test Status & Verification Inventory

**Generated:** 2026-10-09 11:52:23 UTC  
**Source of Truth:** AST Test Discovery & Pytest Runner (`scripts/generate_docs.py`)  

This document inventories all automated test files, test classes, and test functions
present in the `tests/` directory. Per ACTIS quality requirements, test passes are
recorded only after confirmed execution.

---

## Test Suite Summary

- **Total Test Files:** `13`
- **Total Discovered Test Cases:** `144`
- **Test Framework:** `pytest` 8.x with `unittest` compatibility
- **Execution Command:** `pytest tests/ -v`

---

## Discovered Test Files

| Test File | Test Cases | Status |
|---|---|---|
| `tests/test_backend_api.py` | 4 tests | `PASSING` |
| `tests/test_config_loading.py` | 11 tests | `PASSING` |
| `tests/test_config_validation.py` | 11 tests | `PASSING` |
| `tests/test_detection_engine.py` | 14 tests | `PASSING` |
| `tests/test_doc_generator.py` | 20 tests | `PASSING` |
| `tests/test_malware_dataset.py` | 25 tests | `PASSING` |
| `tests/test_risk_engine.py` | 3 tests | `PASSING` |
| `tests/test_risk_engine_day6.py` | 8 tests | `PASSING` |
| `tests/test_static_pe.py` | 21 tests | `PASSING` |
| `tests/test_text_analyzer.py` | 9 tests | `PASSING` |
| `tests/test_threat_database.py` | 3 tests | `PASSING` |
| `tests/test_url_scanner.py` | 11 tests | `PASSING` |
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

### `tests/test_detection_engine.py` (14 tests)

**Class `TestDetectionContractsAndEvidence`:**
- `test_detection_result_clamping_and_properties()`
- `test_detection_evidence_aggregation_and_filtering()`

**Class `TestRuleEngineContractsAndEvaluation`:**
- `test_rule_match_to_evidence_signal()`
- `test_generic_rule_registry_execution()`

**Class `TestMLAndThreatIntelContracts`:**
- `test_ml_prediction_result_conversion()`
- `test_ml_prediction_unavailable_and_error()`
- `test_threat_intel_evidence_from_local_intel()`

**Class `TestDetectionDecisionEngineEndToEnd`:**
- `test_decision_engine_with_confirmed_malicious_ti()`
- `test_decision_engine_with_benign_evidence()`
- `test_decision_engine_empty_evidence_safe_fallback()`
- `test_decision_engine_combined_ml_and_rules()`
- `test_url_pipeline_with_local_threat_intel_match()`
- `test_url_pipeline_with_ml_prediction_and_heuristics()`
- `test_url_pipeline_model_unavailable_safe_fallback()`

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

### `tests/test_malware_dataset.py` (25 tests)

**Class `TestMalwareDatasetSchemaContracts`:**
- `test_schema_feature_columns_count()`
- `test_schema_expected_feature_names()`
- `test_schema_identifier_columns()`
- `test_schema_label_conventions()`
- `test_schema_all_expected_columns()`
- `test_schema_validate_columns_success()`
- `test_schema_validate_columns_missing_features()`
- `test_schema_validate_columns_missing_label()`

**Class `TestMalwareDatasetLoading`:**
- `test_load_malware_dataset_default_path()`
- `test_load_malware_dataset_explicit_path()`
- `test_load_malware_dataset_file_not_found()`
- `test_load_malware_dataset_empty_file()`
- `test_isolate_metadata_identifiers()`
- `test_isolate_metadata_identifiers_empty_identifiers()`

**Class `TestMalwareDatasetSchemaValidation`:**
- `test_validate_dataset_schema_success()`
- `test_validate_dataset_schema_missing_feature()`
- `test_validate_dataset_schema_missing_label()`
- `test_validate_dataset_schema_invalid_label_values()`

**Class `TestMalwareDatasetPreparationAndDiagnostics`:**
- `test_prepare_features_and_labels_shape_and_types()`
- `test_prepare_features_and_labels_inversion_logic()`
- `test_inspect_dataset_quality_clean()`
- `test_inspect_dataset_quality_with_nulls_and_duplicates()`
- `test_get_class_distribution_raw_labels()`
- `test_get_class_distribution_normalized_target()`
- `test_get_class_distribution_empty_dataframe()`

### `tests/test_risk_engine.py` (3 tests)

**Standalone Test Functions:**
- `test_confirmed_threat_fast_track()`
- `test_benign_low_risk()`
- `test_combined_ml_and_heuristic_escalation()`

### `tests/test_risk_engine_day6.py` (8 tests)

**Class `TestRiskScoringEdgeCases`:**
- `test_zero_signals_scoring()`
- `test_single_active_layer_dynamic_renormalization()`
- `test_custom_weights_and_zero_weight_layers()`
- `test_reputation_mitigation_subtraction()`

**Class `TestRiskClassificationThresholdBoundaries`:**
- `test_exact_threshold_transitions()`
- `test_whitelist_safety_override()`
- `test_confirmed_threat_override()`
- `test_deterministic_repeatability()`

### `tests/test_static_pe.py` (21 tests)

**Standalone Test Functions:**
- `test_pe_static_analysis_notepad()`

**Class `TestSafeFileHashing`:**
- `test_calculate_file_hashes_success()`
- `test_calculate_file_hashes_nonexistent_file()`
- `test_calculate_file_hashes_unsupported_algo()`

**Class `TestShannonEntropyCalculations`:**
- `test_entropy_empty_data()`
- `test_entropy_homogeneous_bytes()`
- `test_entropy_uniform_distribution()`
- `test_calculate_file_entropy()`
- `test_calculate_file_entropy_empty()`
- `test_analyze_pe_entropy_distribution()`

**Class `TestWindowsPEFileDetection`:**
- `test_detect_pe_synthetic_pe()`
- `test_detect_pe_text_file()`
- `test_detect_pe_random_binary()`
- `test_detect_pe_truncated_pe()`

**Class `TestPEMetadataAndSectionExtraction`:**
- `test_synthetic_pe_extraction()`
- `test_mocked_import_feature_extraction()`

**Class `TestStructuredPEFeatureContract`:**
- `test_structured_features_extraction()`

**Class `TestMalformedAndEdgeCaseHandling`:**
- `test_nonexistent_file()`
- `test_empty_file()`
- `test_corrupted_pe_signature()`
- `test_directory_passed_as_file()`

### `tests/test_text_analyzer.py` (9 tests)

**Standalone Test Functions:**
- `test_extract_urls_multiple_formats()`
- `test_social_engineering_detection()`
- `test_end_to_end_message_analysis()`
- `test_extract_urls_boundary_and_punctuation_handling()`
- `test_message_url_canonical_deduplication()`
- `test_100_repeated_urls_delegates_once_to_scanner()`
- `test_message_scanner_delegates_to_common_url_scanner_path()`
- `test_empty_none_and_no_url_messages()`
- `test_structured_message_scan_result_contract()`

### `tests/test_threat_database.py` (3 tests)

**Standalone Test Functions:**
- `test_seed_indicators_present()`
- `test_register_and_lookup_custom_indicator()`
- `test_scan_session_lifecycle()`

### `tests/test_url_scanner.py` (11 tests)

**Standalone Test Functions:**
- `test_normalize_url()`
- `test_extract_url_features_length_and_types()`
- `test_rule_engine_url_heuristics()`
- `test_scan_url_logic_safe_and_phishing()`
- `test_url_validation_valid_cases()`
- `test_url_validation_invalid_and_hostile_cases()`
- `test_canonical_normalization_hardening()`
- `test_extract_domain()`
- `test_feature_extraction_contract_and_dictionary()`
- `test_expanded_url_heuristics()`
- `test_scan_url_logic_safe_error_handling_and_caching()`

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
