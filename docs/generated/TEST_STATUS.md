# ACTIS Test Status & Verification Inventory

**Generated:** 2026-10-12 16:06:29 UTC
**Source of Truth:** AST Test Discovery & Pytest Runner (`scripts/generate_docs.py`)

This document inventories all automated test files, test classes, and test functions
present in the `tests/` directory. Per ACTIS quality requirements, test passes are
recorded only after confirmed execution.

---

## Test Suite Summary

- **Total Test Files:** `39`
- **Total Discovered Test Cases:** `562`
- **Test Framework:** `pytest` 8.x with `unittest` compatibility
- **Execution Command:** `pytest tests/ -v`

---

## Discovered Test Files

| Test File | Test Cases | Status |
|---|---|---|
| `tests/test_adversarial_security.py` | 29 tests | `PASSING` |
| `tests/test_backend_api.py` | 4 tests | `PASSING` |
| `tests/test_branding_assets.py` | 6 tests | `PASSING` |
| `tests/test_central_ti_service.py` | 30 tests | `PASSING` |
| `tests/test_config_loading.py` | 11 tests | `PASSING` |
| `tests/test_config_validation.py` | 11 tests | `PASSING` |
| `tests/test_detection_engine.py` | 23 tests | `PASSING` |
| `tests/test_device_scanner.py` | 10 tests | `PASSING` |
| `tests/test_doc_generator.py` | 20 tests | `PASSING` |
| `tests/test_evidence_fusion_audit.py` | 22 tests | `PASSING` |
| `tests/test_explainability_tree.py` | 23 tests | `PASSING` |
| `tests/test_file_pipeline_hardening.py` | 17 tests | `PASSING` |
| `tests/test_file_protection_burst.py` | 5 tests | `PASSING` |
| `tests/test_file_protection_events.py` | 17 tests | `PASSING` |
| `tests/test_file_protection_integration.py` | 7 tests | `PASSING` |
| `tests/test_incremental_state.py` | 8 tests | `PASSING` |
| `tests/test_malware_dataset.py` | 25 tests | `PASSING` |
| `tests/test_non_pe_analysis.py` | 24 tests | `PASSING` |
| `tests/test_privacy_safeguards.py` | 16 tests | `PASSING` |
| `tests/test_protection_service_events.py` | 15 tests | `PASSING` |
| `tests/test_protection_service_lifecycle.py` | 15 tests | `PASSING` |
| `tests/test_protection_service_workers.py` | 9 tests | `PASSING` |
| `tests/test_release_integration.py` | 13 tests | `PASSING` |
| `tests/test_risk_engine.py` | 3 tests | `PASSING` |
| `tests/test_risk_engine_day6.py` | 8 tests | `PASSING` |
| `tests/test_security_assistant.py` | 27 tests | `PASSING` |
| `tests/test_service_scripts.py` | 6 tests | `PASSING` |
| `tests/test_static_pe.py` | 23 tests | `PASSING` |
| `tests/test_text_analyzer.py` | 9 tests | `PASSING` |
| `tests/test_threat_caching_deep.py` | 18 tests | `PASSING` |
| `tests/test_threat_database.py` | 3 tests | `PASSING` |
| `tests/test_threat_intel_pipeline.py` | 11 tests | `PASSING` |
| `tests/test_threat_providers.py` | 21 tests | `PASSING` |
| `tests/test_threat_sync.py` | 24 tests | `PASSING` |
| `tests/test_unified_architecture.py` | 12 tests | `PASSING` |
| `tests/test_url_scanner.py` | 11 tests | `PASSING` |
| `tests/test_week1_validation.py` | 4 tests | `PASSING` |
| `tests/test_windows_notifications.py` | 13 tests | `PASSING` |
| `tests/test_windows_service_host.py` | 9 tests | `PASSING` |

---

## Test Functions Detail

### `tests/test_adversarial_security.py` (29 tests)

**Class `TestMalformedPEFiles`:**
- `test_empty_file_handling()`
- `test_truncated_dos_header()`
- `test_invalid_dos_magic()`
- `test_pe_offset_out_of_bounds()`
- `test_pe_offset_below_dos_header()`
- `test_invalid_pe_signature()`
- `test_truncated_pe_header_body()`
- `test_random_bytes_with_exe_extension()`

**Class `TestOversizedFileBoundaries`:**
- `test_file_size_limit_constant()`
- `test_oversized_file_rejection()`

**Class `TestMalformedURLs`:**
- `test_extremely_long_url_rejected()`
- `test_null_byte_in_url_rejected()`
- `test_unsupported_schemes_rejected()`
- `test_missing_and_invalid_hostname()`
- `test_embedded_credentials_and_ports()`
- `test_multiple_at_symbols()`
- `test_url_feature_extraction_never_crashes()`

**Class `TestMessageAndRegexSafety`:**
- `test_large_message_processing()`
- `test_nested_quotes_and_brackets_url_cleaning()`
- `test_pathological_repetition_does_not_redos()`

**Class `TestClassificationAndFalsePositiveSafety`:**
- `test_benign_pe_with_no_findings_is_low_risk()`
- `test_missing_intelligence_does_not_bias_classification()`
- `test_single_weak_heuristic_does_not_force_critical()`
- `test_confirmed_threat_intel_enforces_critical_floor()`

**Class `TestAdversarialInputRobustness`:**
- `test_none_and_invalid_type_in_file_feature_extractor()`
- `test_directory_path_in_file_scanner_and_detector()`
- `test_none_input_in_file_scanner_and_threat_detector()`
- `test_none_and_non_string_in_text_analyzer_social_engineering()`
- `test_none_and_non_string_in_security_assistant()`

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

### `tests/test_detection_engine.py` (23 tests)

**Class `TestDetectionContractsAndEvidence`:**
- `test_detection_result_clamping_and_properties()`
- `test_detection_evidence_aggregation_and_filtering()`

**Class `TestRuleEngineContractsAndEvaluation`:**
- `test_rule_match_to_evidence_signal()`
- `test_generic_rule_registry_execution()`
- `test_pe_process_hollowing_rule_unmap()`
- `test_pe_process_hollowing_rule_sequence()`
- `test_pe_token_impersonation_rule()`
- `test_pe_dynamic_api_resolver_rule()`
- `test_pe_anti_analysis_rule()`
- `test_pe_persistence_apis_rule()`
- `test_pe_section_entropy_anomaly_rule()`
- `test_pe_section_unpacking_stub_rule()`
- `test_pe_benign_executable_no_severe_rules()`

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

### `tests/test_evidence_fusion_audit.py` (22 tests)

**Class `TestContradictoryEvidence`:**
- `test_case_a_ml_high_threat_intel_absent()`
- `test_case_b_ml_low_threat_intel_confirmed_critical()`
- `test_case_c_static_structural_findings_rules_clean()`
- `test_case_d_rules_suspicious_ml_unavailable()`
- `test_case_e_reputation_mitigation_conflicts_with_suspicious_static()`
- `test_case_f_whitelist_override_precedence_over_confirmed_malicious()`

**Class `TestMissingAndUnavailableEvidence`:**
- `test_ti_provider_timeout_not_treated_as_clean()`
- `test_ti_rate_limiting_handled_safely()`
- `test_ml_model_missing_omitted_without_penalty()`
- `test_empty_evidence_collection_produces_informative_uncertainty()`

**Class `TestDuplicateAndCorrelatedEvidence`:**
- `test_duplicate_rule_signals_suppressed_to_prevent_score_inflation()`
- `test_duplicate_signal_retains_stronger_finding_on_conflict()`
- `test_distinct_rules_accumulate_legitimately()`

**Class `TestRiskScoringBoundaries`:**
- `test_numeric_boundaries_clamping()`
- `test_weights_safety_and_rejections()`
- `test_classification_threshold_boundaries()`
- `test_mutual_confirmation_boost_trigger_and_cap()`
- `test_mitigation_adjustment_clamped_at_zero()`

**Class `TestExplainabilityConsistency`:**
- `test_tree_score_and_classification_strictly_equal_detection_result()`
- `test_sensitive_credential_redaction_in_explainability_nodes()`
- `test_explainability_tree_node_count_strictly_bounded()`

**Class `TestOfflineAndFailureRecovery`:**
- `test_local_pe_analysis_completes_when_external_ti_offline()`

### `tests/test_explainability_tree.py` (23 tests)

**Class `TestExplainabilityTreeStructureAndContracts`:**
- `test_tree_generation_for_simple_benign_target()`
- `test_multiple_independent_findings_in_branches()`
- `test_unavailable_ml_model_representation()`
- `test_confirmed_threat_intelligence_provenance()`
- `test_tree_depth_and_node_count_bounds()`
- `test_sensitive_token_redaction_in_explanations()`

**Class `TestMathematicalTraceability`:**
- `test_traceability_exact_score_match()`
- `test_reputation_mitigation_traceability()`
- `test_ascii_rendering_completeness()`

**Class `TestRiskScoringWeightsValidation`:**
- `test_valid_default_weights()`
- `test_rejects_nan_and_infinite_weights()`
- `test_rejects_negative_weights()`
- `test_rejects_out_of_range_weights()`
- `test_rejects_non_numeric_types()`
- `test_rejects_all_zero_weights()`
- `test_normalized_method()`
- `test_from_dict_strict_mode()`
- `test_from_dict_non_strict_mode()`
- `test_scoring_with_custom_validated_weights()`

**Class `TestEndToEndPipelineIntegration`:**
- `test_detector_analyze_url_produces_explainability_tree()`
- `test_detector_analyze_file_produces_explainability_tree()`
- `test_repeatable_identical_explanations()`
- `test_submillisecond_tree_generation_performance()`

### `tests/test_file_pipeline_hardening.py` (17 tests)

**Class `TestFileEventLifecycleAndDebouncing`:**
- `test_rapid_modifications_coalesced_by_debouncer()`
- `test_file_stability_check_helper()`
- `test_duplicate_events_for_same_path_deduplicated_by_state()`
- `test_pipeline_handles_disappeared_file_cleanly()`
- `test_pipeline_handles_file_renamed_and_prunes_old_path()`
- `test_pipeline_handles_file_deletion_and_state_removal()`
- `test_directory_event_mistakenly_presented_as_file()`
- `test_temporary_files_filtered_before_pipeline()`

**Class `TestQueueSchedulingAndWorkerSafety`:**
- `test_bounded_queue_saturation_drops_cleanly()`
- `test_worker_pool_clean_shutdown_during_pending_work()`
- `test_analyzer_exception_isolated_in_pipeline()`

**Class `TestEndToEndPERoutingAndEvidenceConsistency`:**
- `test_routing_valid_pe_uses_pe_parser()`
- `test_routing_corrupt_pe_header_falls_back_to_non_pe()`
- `test_routing_script_disguised_as_exe_detected_via_content()`
- `test_routing_empty_file_has_valid_hashes_and_generic_method()`
- `test_routing_unsupported_7z_reports_honestly()`
- `test_pipeline_dispatches_notification_for_malicious_script()`

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

### `tests/test_non_pe_analysis.py` (24 tests)

**Class `TestStreamingCryptographicHashing`:**
- `test_hashing_empty_file()`
- `test_hashing_chunk_boundaries()`
- `test_hashing_determinism_and_content_isolation()`
- `test_hashing_missing_and_invalid_inputs()`

**Class `TestArchiveInspection`:**
- `test_zip_benign_safe_inspection_no_extraction()`
- `test_zip_with_executable_content_flagged()`
- `test_zip_double_extension_camouflage_flagged()`
- `test_zip_bomb_compression_ratio_detection()`
- `test_tar_archive_safe_inspection()`
- `test_gzip_archive_safe_inspection()`
- `test_7z_unsupported_graceful_fallback_no_crash()`
- `test_corrupted_archive_handled_gracefully()`

**Class `TestStaticScriptHeuristics`:**
- `test_powershell_download_and_execute_cradle()`
- `test_powershell_encoded_command()`
- `test_powershell_execution_bypass_and_hidden()`
- `test_batch_certutil_download()`
- `test_batch_shadow_copy_deletion()`
- `test_vbscript_download_dropper()`
- `test_python_dynamic_execution_with_network_decode()`
- `test_benign_script_with_comments_not_flagged()`
- `test_clean_benign_python_script()`

**Class `TestNonPEPipelineIntegration`:**
- `test_pe_routing_preserves_pe_pipeline()`
- `test_non_pe_scan_file_integration_malicious_script()`
- `test_non_pe_scan_file_integration_benign_text()`

### `tests/test_privacy_safeguards.py` (16 tests)

**Class `TestLocalFilePathPrivacy`:**
- `test_file_analysis_never_sends_path_to_providers()`

**Class `TestCredentialAndSecretMasking`:**
- `test_mask_sensitive_strings_helper()`
- `test_assistant_output_masks_sensitive_tokens()`
- `test_logger_redacts_sensitive_credentials()`
- `test_independent_threat_intelligence_import()`

**Class `TestPrivateAndSpecialPurposeIPProtection`:**
- `test_special_purpose_ips_rejected_by_validator()`
- `test_public_ips_accepted_by_validator()`
- `test_abuseipdb_shields_private_ips_without_network_call()`
- `test_virustotal_shields_private_ips_without_network_call()`

**Class `TestAssistantSecurityBoundaries`:**
- `test_assistant_rejects_command_execution()`
- `test_assistant_rejects_rule_override_injection()`
- `test_missing_intelligence_includes_defensive_caveat()`

**Class `TestEventQueueSaturationAndStress`:**
- `test_queue_capacity_bound_and_drop_telemetry()`
- `test_burst_of_500_events_multithreaded()`
- `test_queue_cancellation_rejects_subsequent_puts()`

**Class `TestSQLiteConcurrencyAndTransactionSafety`:**
- `test_concurrent_reads_and_writes_in_isolated_db()`

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

### `tests/test_release_integration.py` (13 tests)

**Class `TestCoreAnalysisAndResultContracts`:**
- `test_url_analysis_entry_point_and_contract()`
- `test_file_analysis_entry_point_and_contract()`

**Class `TestNegativeEvidenceProtection`:**
- `test_missing_intelligence_not_reported_as_safe_in_lookup()`
- `test_missing_intelligence_in_assistant_explains_uncertainty()`

**Class `TestCandidateIndicatorProtection`:**
- `test_candidate_indicator_retains_candidate_status()`

**Class `TestProviderTimeoutHandling`:**
- `test_provider_timeout_produces_documented_outcome()`

**Class `TestLocalAnalysisResilience`:**
- `test_local_analysis_resilient_to_central_backend_outage()`

**Class `TestPrivacySafeguards`:**
- `test_local_filepath_rejected_from_indicator_validation()`
- `test_private_ip_rejected_from_external_indicator_validation()`

**Class `TestGroundedAssistantExplanations`:**
- `test_assistant_explains_recorded_detection_accurately()`

**Class `TestMalformedFileHandling`:**
- `test_malformed_truncated_binary_handled_safely()`

**Class `TestReportingAndCleanup`:**
- `test_reports_generate_in_isolated_dir_and_clean_up()`

**Class `TestDemonstrationExecution`:**
- `test_demo_script_runs_successfully()`

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

### `tests/test_security_assistant.py` (27 tests)

**Class `TestAssistantRecentDetections`:**
- `test_recent_detections_with_records()`
- `test_recent_detections_empty_db_no_false_safety()`

**Class `TestAssistantCriticalDetections`:**
- `test_critical_detections_filtering()`
- `test_critical_detections_empty_response()`

**Class `TestAssistantStatistics`:**
- `test_statistics_formatting()`
- `test_statistics_database_error_handling()`

**Class `TestAssistantTargetExplanation`:**
- `test_explain_known_detection_exact_match()`
- `test_explain_disambiguation_when_multiple_targets_match()`
- `test_explain_known_threat_intelligence_indicator()`
- `test_explain_candidate_threat_intelligence_notice()`
- `test_explain_unknown_target_does_not_claim_safe()`

**Class `TestAssistantTargetExtraction`:**
- `test_extract_sha256()`
- `test_extract_md5()`
- `test_extract_url()`
- `test_extract_ip()`
- `test_extract_domain()`
- `test_extract_filename()`
- `test_extract_quoted_target()`

**Class `TestAssistantMethodologyAndRecommendations`:**
- `test_methodology_accuracy()`
- `test_recommendations_non_destructive()`

**Class `TestAssistantSafetyAndBoundaries`:**
- `test_secret_masking_function()`
- `test_secret_masking_in_fallback_query()`
- `test_prompt_injection_resistance()`
- `test_query_length_bounding()`

**Class `TestAssistantProviderIntegration`:**
- `test_deterministic_provider_is_default()`
- `test_external_llm_provider_fallback_when_unconfigured()`
- `test_external_llm_provider_fallback_on_exception()`

### `tests/test_service_scripts.py` (6 tests)

**Class `TestServiceScriptsIntegrity`:**
- `test_scripts_exist_and_readable()`
- `test_scripts_contain_no_hardcoded_credentials()`
- `test_scripts_contain_no_defender_tampering()`

**Class `TestServiceScriptsExecution`:**
- `test_install_script_dry_run()`
- `test_status_script_json_output()`
- `test_uninstall_script_dry_run_or_uninstalled()`

### `tests/test_static_pe.py` (23 tests)

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
- `test_calculate_imphash_deterministic_and_ordinals()`

**Class `TestStructuredPEFeatureContract`:**
- `test_structured_features_extraction()`
- `test_structured_features_with_imports_contract()`

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

### `tests/test_threat_caching_deep.py` (18 tests)

**Class `MockClock`:**

**Class `DummyMockProvider`:**

**Class `TestLRUTTLCache`:**
- `test_lru_eviction_when_capacity_reached()`
- `test_ttl_expiration_with_injected_clock()`
- `test_dict_interface_compatibility()`
- `test_invalidate_and_clear()`

**Class `TestThreatIntelligenceCache`:**
- `test_cache_hit_avoids_repeated_lookup()`
- `test_indicator_type_prevents_key_collisions()`
- `test_normalization_produces_consistent_keys()`
- `test_expired_entries_follow_defined_policy()`
- `test_provider_failures_are_never_cached()`
- `test_cache_write_failure_isolation()`
- `test_indicator_invalidation()`
- `test_cache_capacity_lru_retention()`

**Class `TestCacheConcurrency`:**
- `test_concurrent_read_write_under_load()`

**Class `TestThreatDetectorScanCache`:**
- `test_threat_detector_hash_cache_hit_bypasses_deep_analysis()`
- `test_threat_detector_url_cache_hit()`
- `test_threat_detector_invalidate_and_clear()`

**Class `TestOfflineOutageResilience`:**
- `test_outage_does_not_falsely_declare_clean()`
- `test_database_registration_invalidates_cache()`

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

### `tests/test_windows_notifications.py` (13 tests)

**Class `TestNotificationSanitization`:**
- `test_sanitize_empty_text()`
- `test_sanitize_xml_special_characters()`
- `test_sanitize_redacts_api_keys_and_tokens()`
- `test_sanitize_bounds_length()`

**Class `TestWindowsToastNotifier`:**
- `test_notifier()`
- `test_toast_dispatch_is_non_blocking()`
- `test_test_mode_records_history()`
- `test_rate_limiting_suppresses_rapid_duplicate_toasts()`
- `test_notify_threat_event_labeling()`
- `test_powershell_failure_isolated_safely()`

**Class `TestNotificationManagerIntegration`:**
- `test_notification_manager_triggers_toast_for_high_risk()`
- `test_notification_manager_skips_toast_for_low_risk()`

**Class `TestFileProtectionPipelineNotificationHandoff`:**
- `test_pipeline_dispatches_notification_on_threat()`

### `tests/test_windows_service_host.py` (9 tests)

**Class `TestWindowsServiceHostLifecycle`:**
- `test_host()`
- `test_host_initialization()`
- `test_request_stop_sets_event()`
- `test_scm_control_handlers()`
- `test_run_standalone_graceful_stop()`
- `test_run_standalone_startup_failure()`
- `test_run_standalone_fails_when_service_enters_failed_state()`

**Class `TestServiceCliRouting`:**
- `test_main_service_status_flag()`
- `test_main_service_flag_dispatches_run_standalone()`

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
