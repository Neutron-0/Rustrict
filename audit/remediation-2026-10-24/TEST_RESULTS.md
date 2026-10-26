# Rustrict — Post-Remediation Test Results & Execution Matrix
**Date:** 2026-10-24  
**Workspace:** `D:\Vault\Rustrict`  
**Target:** `x86_64-pc-windows-msvc`  
**Toolchain:** `rustc 1.97.1` / `cargo 1.97.1`  
**Overall Status:** 100% PASS (187 passed; 0 failed; 0 ignored across 23 test binaries)

---

## 1. Summary of Execution

```
cargo test --all-targets
```

- **Total Test Binaries Executed:** 23
- **Total Tests Passed:** 187
- **Total Tests Failed:** 0
- **Total Tests Ignored:** 0
- **Total Filtered Out:** 0
- **Clippy Lint Status:** 0 warnings (`cargo clippy --all-targets -- -D warnings` - code 0)
- **Formatting Status:** Clean (`cargo fmt --check` - code 0)

---

## 2. Test Execution Breakdown by Binary

### 1. `rustrict` (lib test) — `src/lib.rs`
- `gateway::admin::curl_util::tests::test_find_curl_resolves_existing_executable` ... **ok**
- `gateway::admin::curl_util::tests::test_auto_clean_file_lifecycle` ... **ok**
- **Result:** `ok. 2 passed; 0 failed; 0 ignored`

### 2. `rustrict` (main test) — `src/main.rs`
- **Result:** `ok. 0 passed; 0 failed; 0 ignored`

### 3. `tests/test_assessment.rs`
- `test_cidr_containment_and_normalization` ... **ok**
- `test_fault_profile_simulation_metrics` ... **ok**
- `test_port_argument_parsing` ... **ok**
- `test_scope_manager_boundaries_and_exclusions` ... **ok**
- `test_report_export_markdown_json_sarif` ... **ok**
- **Result:** `ok. 5 passed; 0 failed; 0 ignored`

### 4. `tests/test_avm_admin.rs`
- `test_avm_digest_auth_failure` ... **ok**
- `test_avm_digest_auth_success` ... **ok**
- `test_avm_ipv4_and_ipv6_capability_classification` ... **ok**
- `test_avm_md5_rfc_vectors` ... **ok**
- `test_avm_lockout_prevention` ... **ok**
- `test_avm_identity_verification_and_mismatch` ... **ok**
- `test_avm_service_description_parsing` ... **ok**
- `test_avm_soap_success_and_fault_handling` ... **ok**
- `test_avm_missing_hostfilter_service` ... **ok**
- `test_avm_per_device_pause_and_resume` ... **ok**
- `test_avm_tls_cert_error_rejection` ... **ok**
- `test_avm_preserves_unrelated_hosts_and_settings` ... **ok**
- `test_avm_multi_target_policy_enforcement_and_recovery` (New Regression) ... **ok**
- `test_avm_unsafe_control_url_rejection` ... **ok**
- `test_avm_network_wide_policy_lifecycle` ... **ok**
- `test_avm_unsupported_autonomous_recovery` ... **ok**
- `test_avm_curl_transport_payload_isolation_and_cleanup` (New Regression) ... **ok**
- `test_avm_asynchronous_policy_verification_success` ... **ok**
- `test_avm_asynchronous_policy_verification_timeout` ... **ok**
- **Result:** `ok. 19 passed; 0 failed; 0 ignored`

### 5. `tests/test_dhcp.rs`
- `test_dhcp_option12_parsing` ... **ok**
- **Result:** `ok. 1 passed; 0 failed; 0 ignored`

### 6. `tests/test_diagnostics.rs`
- `test_endpoint_sanitization` ... **ok**
- `test_device_inventory_support_on_unifi_and_avm` ... **ok**
- `test_read_only_diagnostics_report_connected_and_read_only_enforcement` ... **ok**
- `test_read_only_diagnostics_report_disconnected` ... **ok**
- `test_no_provider_fallback_on_query_failure` ... **ok**
- `test_diagnostics_sanitizes_errors` ... **ok**
- `test_inventory_normalization_and_distinction_of_live_vs_cached` ... **ok**
- **Result:** `ok. 7 passed; 0 failed; 0 ignored`

### 7. `tests/test_fixes.rs`
- `test_bitrate_overflow_protection` ... **ok**
- `test_extract_html_title_with_unicode_and_case` ... **ok**
- `test_llmnr_ptr_response_parsing` ... **ok**
- `test_scan_range_bounded_protection` ... **ok**
- `test_mdns_parsing_with_question_echo` ... **ok**
- `test_soap_prefixed_tags` ... **ok**
- `test_persistent_state_both_directions_serialization` ... **ok**
- `test_check_environment_diagnostics` ... **ok**
- **Result:** `ok. 8 passed; 0 failed; 0 ignored`

### 8. `tests/test_gateway.rs`
- `test_gateway_host_entry_construction` ... **ok**
- `test_ssdp_header_parsing` ... **ok**
- `test_soap_extract_missing_tag` ... **ok**
- `test_soap_extract_tag_value` ... **ok**
- **Result:** `ok. 4 passed; 0 failed; 0 ignored`

### 9. `tests/test_mikrotik_admin.rs`
- `test_mikrotik_auth_failure` ... **ok**
- `test_mikrotik_auth_success` ... **ok**
- `test_mikrotik_capability_discovery` ... **ok**
- `test_mikrotik_identity_verification_and_mismatch` ... **ok**
- `test_mikrotik_apply_and_resume_device_policy` ... **ok**
- `test_mikrotik_adjust_policy_duration_lifecycle` ... **ok**
- `test_mikrotik_autonomous_watchdog_installation_and_idempotency` ... **ok**
- `test_mikrotik_rejection_when_autonomous_recovery_unsupported` ... **ok**
- `test_mikrotik_ipv6_honesty_check` (New Regression) ... **ok**
- `test_mikrotik_partial_transaction_failure_and_rollback` ... **ok**
- `test_mikrotik_resume_all_preserves_unrelated_rules` ... **ok**
- `test_mikrotik_tls_cert_error_rejection` ... **ok**
- `test_mikrotik_lockout_prevention` ... **ok**
- `test_mikrotik_ipv4_and_ipv6_policy_planning` ... **ok**
- `test_mikrotik_router_reboot_autonomous_expiration` ... **ok**
- `test_mikrotik_multi_target_policy_enforcement_and_recovery` (New Regression) ... **ok**
- `test_mikrotik_unsupported_resource_handling` ... **ok**
- `test_mikrotik_uninstall_watchdog_preserves_unrelated_schedulers` ... **ok**
- `test_mikrotik_wired_and_wireless_forward_chain_isolation` ... **ok**
- **Result:** `ok. 19 passed; 0 failed; 0 ignored`

### 10. `tests/test_openwrt_admin.rs`
- `test_openwrt_auth_failure` ... **ok**
- `test_openwrt_api_timeout` ... **ok**
- `test_openwrt_auth_success` ... **ok**
- `test_openwrt_identity_verification` ... **ok**
- `test_openwrt_autonomous_watchdog_installation` ... **ok**
- `test_openwrt_rejection_when_autonomous_recovery_unsupported` ... **ok**
- `test_openwrt_adjust_policy_duration_lifecycle` ... **ok**
- `test_openwrt_apply_and_resume_device_policy` ... **ok**
- `test_openwrt_lockout_prevention` ... **ok**
- `test_openwrt_reconcile_expired_timed_policy` ... **ok**
- `test_openwrt_network_wide_policy_lifecycle` ... **ok**
- `test_openwrt_multi_target_policy_enforcement_and_recovery` (New Regression) ... **ok**
- `test_openwrt_resume_not_found` ... **ok**
- `test_openwrt_interrupted_transaction_rollback` ... **ok**
- `test_openwrt_resume_all_preserves_unrelated_rules` ... **ok**
- `test_openwrt_unsupported_firmware_rejection` ... **ok**
- `test_openwrt_ipv4_and_ipv6_policy_planning` ... **ok**
- `test_openwrt_router_reboot_autonomous_expiration` ... **ok**
- `test_protected_credentials_and_zeroization` ... **ok**
- **Result:** `ok. 19 passed; 0 failed; 0 ignored`

### 11. `tests/test_persistence.rs`
- `test_recovery_metadata_and_preflight_rejection` ... **ok**
- `test_safe_startup_reconciliation_marks_active_as_unknown` ... **ok**
- `test_schema_versioning_and_malformed_state_handling` ... **ok**
- `test_windows_path_handling_with_spaces` ... **ok**
- `test_atomic_write_and_replace` ... **ok**
- `test_secret_sanitization_on_disk` ... **ok**
- `test_engine_integration_persists_audit_records_and_updates` ... **ok**
- **Result:** `ok. 7 passed; 0 failed; 0 ignored`

### 12. `tests/test_policy_engine.rs`
- `test_engine_audit_record_logging` ... **ok**
- `test_engine_duplicate_policy_rejection` ... **ok**
- `test_engine_disconnected_fails_closed` ... **ok**
- `test_engine_lockout_prevention_delegation` ... **ok**
- `test_engine_plan_policy_dry_run` ... **ok**
- `test_engine_policy_apply_and_resume` ... **ok**
- `test_engine_reconcile_policies` ... **ok**
- `test_engine_unsupported_capability_rejection` ... **ok**
- **Result:** `ok. 8 passed; 0 failed; 0 ignored`

### 13. `tests/test_policy_views.rs`
- `test_policy_views_confirmation_states` ... **ok**
- `test_policy_views_detail_rendering` ... **ok**
- `test_policy_views_recovery_status_mapping` ... **ok**
- `test_policy_views_sanitizes_output` ... **ok**
- `test_policy_views_unified_entry_conversion` ... **ok**
- `test_policy_views_unsupported_recovery_handling` ... **ok**
- **Result:** `ok. 6 passed; 0 failed; 0 ignored`

### 14. `tests/test_reliability.rs`
- `test_secret_sanitization_in_persistent_state` ... **ok**
- `test_engine_persistence_error_tracking` ... **ok**
- `test_atomic_write_resilience_and_cleanup` ... **ok**
- `test_schema_versioning_and_corrupt_files` ... **ok**
- `test_multi_instance_concurrent_sync` ... **ok**
- **Result:** `ok. 5 passed; 0 failed; 0 ignored`

### 15. `tests/test_router_admin.rs`
- `test_capability_classification_baseline` ... **ok**
- `test_operation_plan_request_construction` ... **ok**
- `test_mock_router_admin_provider_lifecycle` ... **ok**
- `test_mock_router_timed_policy_expiration` ... **ok**
- `test_mock_router_lockout_prevention` ... **ok**
- `test_mock_router_reconcile_policies` ... **ok**
- `test_scope_exclusion_integration` ... **ok**
- `test_startup_disconnected_and_explicit_mock_connection` (New Regression) ... **ok**
- **Result:** `ok. 8 passed; 0 failed; 0 ignored`

### 16. `tests/test_smb.rs`
- `test_smb_probe_command_formatting` ... **ok**
- **Result:** `ok. 1 passed; 0 failed; 0 ignored`

### 17. `tests/test_ssh_admin.rs`
- `test_ssh_command_argument_validation_and_injection_resistance` ... **ok**
- `test_ssh_remote_command_timeout_and_exit_code` ... **ok**
- `test_ssh_public_key_authentication_failure` ... **ok**
- `test_ssh_lockout_prevention` ... **ok**
- `test_ssh_non_root_user_privilege_rejection` ... **ok**
- `test_ssh_client_discovery` ... **ok**
- `test_ssh_host_key_strict_checking_and_mismatch_rejection` ... **ok**
- `test_ssh_router_identity_verification_and_mismatch` ... **ok**
- `test_ssh_transport_capabilities_distinction` ... **ok**
- `test_ssh_watchdog_failed_installation_fails_closed` ... **ok**
- `test_ssh_apply_resume_and_preservation_of_unrelated_rules` ... **ok**
- `test_ssh_transaction_rollback_on_commit_error` ... **ok**
- `test_ssh_adjust_policy_duration_lifecycle` ... **ok**
- `test_ssh_watchdog_update_and_removal_preserves_unrelated_jobs` ... **ok**
- `test_ssh_router_reboot_autonomous_recovery` ... **ok**
- `test_ssh_watchdog_dedicated_location_and_markers` ... **ok**
- **Result:** `ok. 16 passed; 0 failed; 0 ignored`

### 18. `tests/test_target_resolution.rs`
- `test_fresh_rescan_prunes_unmanaged_but_preserves_blocked` ... **ok**
- `test_resolve_all` ... **ok**
- `test_resolve_deduplication` ... **ok**
- `test_resolve_mixed_id_and_ip` ... **ok**
- `test_resolve_unknown_ip` ... **ok**
- `test_resolve_by_ip` ... **ok**
- `test_non_destructive_upsert` ... **ok**
- `test_resolve_invalid_syntax` ... **ok**
- `test_resolve_ambiguous_ip` ... **ok**
- `test_resolve_unknown_id` ... **ok**
- `test_resolve_by_id` ... **ok**
- `test_persistent_state_roundtrip` ... **ok**
- **Result:** `ok. 12 passed; 0 failed; 0 ignored`

### 19. `tests/test_tls.rs`
- `test_x509_cn_extraction` ... **ok**
- **Result:** `ok. 1 passed; 0 failed; 0 ignored`

### 20. `tests/test_unifi_admin.rs`
- `test_unifi_auth_failure` ... **ok**
- `test_unifi_auth_success` ... **ok**
- `test_unifi_lockout_prevention` ... **ok**
- `test_unifi_capability_discovery` ... **ok**
- `test_unifi_connected_client_inventory` ... **ok**
- `test_unifi_partial_transaction_failure_and_rollback` ... **ok**
- `test_unifi_api_timeout_handling` ... **ok**
- `test_unifi_identity_verification_and_mismatch` ... **ok**
- `test_unifi_preserves_unrelated_rules` ... **ok**
- `test_unifi_adjust_policy_duration` ... **ok**
- `test_unifi_missing_trafficrules_resource` ... **ok**
- `test_unifi_network_wide_policy_lifecycle` ... **ok**
- `test_unifi_reconcile_policies_cleans_legacy_expired_rules` ... **ok**
- `test_unifi_apply_and_resume_device_policy` ... **ok**
- `test_unifi_permission_denied` ... **ok**
- `test_unifi_site_selection_and_discovery` ... **ok**
- `test_unifi_temporary_policy_rejected_without_autonomous_recovery` ... **ok**
- `test_unifi_tls_cert_error_rejection` ... **ok**
- `test_unifi_curl_transport_payload_isolation_and_cleanup` (New Regression) ... **ok**
- **Result:** `ok. 19 passed; 0 failed; 0 ignored`

### 21. `tests/test_unified_admin.rs`
- `test_registry_explicit_provider_selection_and_status` ... **ok**
- `test_registry_disconnect_behavior_fails_closed` ... **ok**
- `test_registry_duplicate_policy_rejection` ... **ok**
- `test_registry_lockout_prevention_for_gateway_and_controller` ... **ok**
- `test_registry_registration_and_inventory` ... **ok**
- `test_registry_unrecognized_provider_rejected` ... **ok**
- `test_registry_policy_lifecycle_metadata_enrichment` ... **ok**
- **Result:** `ok. 7 passed; 0 failed; 0 ignored`

### 22. `tests/test_verification.rs`
- `test_blackhole_mac_spec_and_properties` ... **ok**
- `test_blocked_vs_limited_arp_frame_crafting` ... **ok**
- `test_scope_manager_persistence_and_enforcement` ... **ok**
- `test_token_bucket_shaping_and_refill` ... **ok**
- `test_subnet_scanner_rfc3021_and_range_clamping` ... **ok**
- **Result:** `ok. 5 passed; 0 failed; 0 ignored`

### 23. `tests/unit_tests.rs`
- `test_bitrate_parsing` ... **ok**
- `test_craft_arp_reply` ... **ok**
- `test_oui_vendor_lookup` ... **ok**
- `test_eapol_frame_detection` ... **ok**
- `test_mac_address_formatting` ... **ok**
- `test_craft_deauth_frame` ... **ok**
- `test_token_bucket` ... **ok**
- **Result:** `ok. 7 passed; 0 failed; 0 ignored`
