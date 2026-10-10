# ACTIS Test Status & Verification Inventory

**Generated:** 2026-10-10 12:51:13 UTC  
**Source of Truth:** AST Test Discovery & Pytest Runner (`scripts/generate_docs.py`)  

This document inventories all automated test files, test classes, and test functions
present in the `tests/` directory. Per ACTIS quality requirements, test passes are
recorded only after confirmed execution.

---

## Test Suite Summary

- **Total Test Files:** `27`
- **Total Discovered Test Cases:** `334`
- **Test Framework:** `pytest` 8.x with `unittest` compatibility
- **Execution Command:** `pytest tests/ -v`

---

## Discovered Test Files

| Test File | Test Cases | Status |
|---|---|---|
| `tests/test_backend_api.py` | 4 tests | `PASSING` |
| `tests/test_branding_assets.py` | 6 tests | `PASSING` |
| `tests/test_central_ti_service.py` | 30 tests | `PASSING` |
| `tests/test_config_loading.py` | 11 tests | `PASSING` |
| `tests/test_config_validation.py` | 11 tests | `PASSING` |
| `tests/test_detection_engine.py` | 14 tests | `PASSING` |
| `tests/test_device_scanner.py` | 10 tests | `PASSING` |
| `tests/test_doc_generator.py` | 20 tests | `PASSING` |
| `tests/test_file_protection_burst.py` | 5 tests | `PASSING` |
| `tests/test_file_protection_events.py` | 17 tests | `PASSING` |
| `tests/test_file_protection_integration.py` | 7 tests | `PASSING` |
| `tests/test_incremental_state.py` | 8 tests | `PASSING` |
| `tests/test_malware_dataset.py` | 25 tests | `PASSING` |
| `tests/test_protection_service_events.py` | 15 tests | `PASSING` |
| `tests/test_protection_service_lifecycle.py` | 15 tests | `PASSING` |
| `tests/test_protection_service_workers.py` | 9 tests | `PASSING` |
| `tests/test_risk_engine.py` | 3 tests | `PASSING` |
| `tests/test_risk_engine_day6.py` | 8 tests | `PASSING` |
| `tests/test_static_pe.py` | 21 tests | `PASSING` |
| `tests/test_text_analyzer.py` | 9 tests | `PASSING` |
| `tests/test_threat_database.py` | 3 tests | `PASSING` |
| `tests/test_threat_intel_pipeline.py` | 11 tests | `PASSING` |
| `tests/test_threat_providers.py` | 21 tests | `PASSING` |
| `tests/test_threat_sync.py` | 24 tests | `PASSING` |
| `tests/test_unified_architecture.py` | 12 tests | `PASSING` |
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

### `tests/test_branding_assets.py` (6 tests)

**Standalone Test Functions:**
- `test_branding_directory_and_assets_exist()`
- `test_authoritative_master_logo_integrity()`
- `test_derived_branding_variants_integrity()`
- `test_readme_and_docs_image_references_resolve()`
- `test_dashboard_branding_asset_resolution()`
- `test_summary_table_of_contents_link_resolves()`

### `tests/test_central_ti_service.py` (30 tests)

**Class `TestCentralAPIAuthenticationAndHealth`:**
- `test_health_v1_and_legacy_endpoints()`
- `test_client_info_with_valid_key()`
- `test_bearer_authorization_header_supported()`
- `test_missing_credentials_returns_401()`
- `test_invalid_key_returns_403()`
- `test_rate_limiting_enforced_when_exceeded()`

**Class `TestCentralAPIIndicatorRetrieval`:**
- `test_lookup_existing_seed_indicator()`
- `test_lookup_nonexistent_indicator()`
- `test_lookup_private_ip_is_shielded()`
- `test_paged_query_with_envelope_and_filters()`
- `test_authenticated_post_sync_pull()`

**Class `TestCandidateContributionAndAntiPoisoning`:**
- `test_readonly_client_cannot_contribute()`
- `test_contribute_candidate_indicator_forces_candidate_status()`
- `test_contribute_private_ip_rejected_with_422()`
- `test_contribute_malformed_hash_rejected_with_422()`
- `test_admin_review_promotes_candidate_to_confirmed()`

**Class `TestCentralACTISFeedAdapter`:**
- `test_adapter_fetch_success_with_mocked_central_service()`
- `test_adapter_shields_private_ips_from_central_response()`
- `test_adapter_timeout_isolation()`
- `test_adapter_connection_error_isolation()`
- `test_adapter_auth_failure_401()`
- `test_adapter_rate_limit_429()`
- `test_adapter_malformed_json_resilience()`
- `test_adapter_disabled_does_not_execute()`

**Class `TestCentralDatabasePersistenceAndClientSync`:**
- `test_central_feed_records_persisted_idempotently_in_local_db()`
- `test_sync_manager_pull_verified_intelligence()`
- `test_sync_manager_push_verified_threat()`

**Class `TestUnifiedPipelineCentralTIIntegration`:**
- `test_central_record_retrieved_by_local_threat_lookup()`
- `test_central_record_evaluated_by_threat_detector_analysis()`
- `test_local_scanning_functions_when_central_backend_is_offline()`

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

### `tests/test_device_scanner.py` (10 tests)

**Class `TestDeviceScannerTraversalAndSafety`:**
- `test_traversal_empty_directory()`
- `test_traversal_nested_directories()`
- `test_traversal_missing_and_invalid_path()`
- `test_traversal_only_executables_filter()`
- `test_traversal_reparse_point_and_symlink_safety()`
- `test_collect_file_metadata_safe()`
- `test_streaming_fingerprint_chunked()`
- `test_streaming_fingerprint_oversized()`
- `test_streaming_fingerprint_changed_during_hash()`
- `test_scan_cooperative_cancellation()`

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

### `tests/test_file_protection_burst.py` (5 tests)

**Class `TestQueueBurstAndBackpressure`:**
- `test_bounded_queue_burst_drops_excess()`
- `test_queue_cancellation_and_safe_draining()`
- `test_queue_drain_partial_limit()`

**Class `TestDebouncerBurstReduction`:**
- `test_debouncer_reduces_burst_on_multiple_paths()`

**Class `TestProtectionServiceBurstStability`:**
- `test_concurrent_event_burst_dispatch()`

### `tests/test_file_protection_events.py` (17 tests)

**Class `TestFilesystemEventSource`:**
- `test_initialization_valid_and_invalid_paths()`
- `test_start_and_stop_lifecycle()`
- `test_repeated_start_stop_is_idempotent()`
- `test_file_creation_event_detection()`
- `test_file_modification_event_detection()`
- `test_file_deletion_event_detection()`

**Class `TestFilesystemEventNormalizer`:**
- `test_normalize_filesystem_path()`
- `test_normalizer_mappings()`
- `test_normalizer_converts_to_security_event()`

**Class `TestFileEventFilter`:**
- `test_filter_directories()`
- `test_filter_temporary_files()`
- `test_temporary_files_allowed_when_policy_disabled()`
- `test_filter_excluded_segments()`
- `test_filter_monitored_roots()`

**Class `TestFileEventDebouncer`:**
- `test_debounce_coalesces_rapid_modifications()`
- `test_file_deletion_cancels_pending_debounced_writes()`
- `test_wait_until_file_stable_helper()`

### `tests/test_file_protection_integration.py` (7 tests)

**Class `TestFileProtectionPipelineDirect`:**
- `test_pipeline_classifies_new_file_and_analyzes()`
- `test_pipeline_handles_disappearing_file()`
- `test_pipeline_handles_file_deletion_and_pruning()`
- `test_pipeline_handles_oversized_file()`
- `test_pipeline_unsupported_non_executables_filter()`
- `test_pipeline_race_condition_modification_during_analysis()`

**Class `TestEndToEndProtectionServiceIntegration`:**
- `test_full_filesystem_to_analysis_pipeline_integration()`

### `tests/test_incremental_state.py` (8 tests)

**Class `TestIncrementalScanState`:**
- `test_file_scan_state_serialization_roundtrip()`
- `test_sqlite_persistence_crud()`
- `test_change_detection_new_vs_unchanged_vs_modified()`
- `test_change_detection_removed_file()`
- `test_change_detection_version_incompatibility()`
- `test_state_persistence_across_manager_instances()`
- `test_prune_missing_files()`
- `test_device_scanner_incremental_integration_end_to_end()`

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

### `tests/test_protection_service_events.py` (15 tests)

**Class `TestSecurityEventContract`:**
- `test_valid_event_creation()`
- `test_string_type_conversion()`
- `test_invalid_type_raises_error()`
- `test_missing_source_rejected()`
- `test_missing_target_for_file_events_rejected()`
- `test_system_events_allow_empty_target()`
- `test_to_dict_and_from_dict_roundtrip()`
- `test_from_dict_invalid_data_rejected()`

**Class `TestSecurityEventQueue`:**
- `test_queue_put_and_get()`
- `test_queue_capacity_drop()`

**Class `TestEventDispatcher`:**
- `test_specific_and_wildcard_dispatch()`
- `test_handler_error_isolation()`
- `test_orchestrator_stub_integration()`

**Class `TestProtectionServiceEndToEndIntake`:**
- `test_end_to_end_event_intake_flow()`
- `test_reject_event_submission_when_service_stopped()`

### `tests/test_protection_service_lifecycle.py` (15 tests)

**Class `TestServiceStateManager`:**
- `test_initial_state()`
- `test_valid_transitions()`
- `test_invalid_transition_raises_error()`
- `test_invalid_transition_without_raise()`
- `test_record_error_and_reset()`

**Class `TestProtectionServiceLifecycle`:**
- `test_config()`
- `test_initial_service_state()`
- `test_service_start_and_stop()`
- `test_repeated_start_is_idempotent()`
- `test_repeated_stop_is_idempotent()`
- `test_start_after_stop()`
- `test_pause_and_resume()`
- `test_pause_when_stopped_fails()`
- `test_startup_failure_transitions_to_failed()`

**Class `TestWindowsHostBridging`:**
- `test_scm_control_pause_continue_stop()`

### `tests/test_protection_service_workers.py` (9 tests)

**Class `TestServiceWorker`:**
- `test_worker_initial_status()`
- `test_worker_start_and_clean_stop()`
- `test_worker_pause_and_resume()`
- `test_worker_failure_handling()`

**Class `TestWorkerManager`:**
- `test_manager_starts_and_stops_workers()`
- `test_manager_restart_failed_workers()`

**Class `TestProtectionServiceFailureRecovery`:**
- `test_service_degrades_when_single_worker_fails_in_pool()`
- `test_service_fails_when_all_workers_fail()`
- `test_service_bounded_recovery_policy()`

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

### `tests/test_threat_intel_pipeline.py` (11 tests)

**Standalone Test Functions:**
- `test_local_first_lookup_known_malicious()`
- `test_local_not_found_queries_external_provider()`
- `test_caching_layer_bypasses_repeated_external_calls()`
- `test_cache_does_not_cache_transient_failures()`
- `test_conflicting_provider_findings_resolution()`
- `test_duplicate_findings_deduplication()`
- `test_threat_detector_url_analysis_with_external_ti()`
- `test_provider_failure_isolation_in_detection()`
- `test_secret_masking_in_repr_and_config()`
- `test_url_scanner_scan_url_logic_regression()`
- `test_text_analyzer_regression()`

**Class `MockProvider`:**

### `tests/test_threat_providers.py` (21 tests)

**Class `TestIndicatorValidator`:**
- `test_sha256_normalization_and_validation()`
- `test_malformed_sha256_rejection()`
- `test_url_canonical_normalization()`
- `test_private_and_loopback_ip_shielding()`
- `test_public_ip_acceptance()`

**Class `TestVirusTotalClient`:**
- `test_is_configured_and_disabled_state()`
- `test_lookup_hash_malicious_confirmed()`
- `test_lookup_hash_suspicious()`
- `test_lookup_hash_clean()`
- `test_lookup_not_found_404()`
- `test_lookup_rate_limit_429()`
- `test_lookup_auth_failure_401()`
- `test_lookup_timeout_isolation()`
- `test_lookup_malformed_json_resilience()`
- `test_lookup_url_base64_identifier()`

**Class `TestURLhausClient`:**
- `test_urlhaus_malicious_hit()`
- `test_urlhaus_no_results()`
- `test_urlhaus_timeout()`

**Class `TestAbuseIPDBClient`:**
- `test_private_ip_boundary_enforced()`
- `test_public_ip_malicious()`
- `test_public_ip_clean()`

### `tests/test_threat_sync.py` (24 tests)

**Class `TestFeedAdapters`:**
- `test_urlhaus_adapter_fetch_success()`
- `test_urlhaus_adapter_rejects_malformed_urls()`
- `test_urlhaus_adapter_timeout_isolation()`
- `test_urlhaus_adapter_rate_limit_429()`
- `test_urlhaus_adapter_malformed_json()`
- `test_abuseipdb_adapter_fetch_success()`
- `test_abuseipdb_adapter_shields_private_ips()`
- `test_abuseipdb_adapter_unconfigured_error()`
- `test_virustotal_adapter_reports_enterprise_limitation()`

**Class `TestThreatDatabaseSyncPersistence`:**
- `test_upsert_feed_records_new_indicators()`
- `test_upsert_feed_records_idempotent_duplicate()`
- `test_upsert_feed_records_updates_confidence_and_status()`
- `test_upsert_feed_records_empty_feed_does_not_delete()`
- `test_feed_status_tracking_in_db()`
- `test_sync_run_history_in_db()`

**Class `TestSyncServiceAndScheduler`:**
- `test_sync_service_sync_all_success()`
- `test_sync_service_partial_success_when_one_fails()`
- `test_sync_service_prevents_overlapping_runs()`
- `test_scheduler_lifecycle()`
- `test_scheduler_disabled_does_not_start()`
- `test_scheduler_manual_trigger()`

**Class `TestUnifiedPipelineTIIntegration`:**
- `test_imported_feed_record_retrieved_by_threat_lookup()`
- `test_imported_feed_record_analyzed_by_threat_detector()`
- `test_unknown_indicator_remains_unknown_when_not_in_feed()`

### `tests/test_unified_architecture.py` (12 tests)

**Standalone Test Functions:**
- `test_file_analysis_contract_symmetry()`
- `test_url_analysis_contract_symmetry()`
- `test_message_analysis_ingestion()`
- `test_handle_security_event_file_created()`
- `test_handle_security_event_url_accessed()`
- `test_handle_security_event_message_received()`
- `test_handle_security_event_disappeared_file()`
- `test_single_file_scanner_delegation()`
- `test_url_scanner_logic_delegation()`
- `test_text_analyzer_delegates_urls_to_scanner()`
- `test_orchestrator_invalid_url_isolation()`
- `test_orchestrator_nonexistent_file_isolation()`

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
