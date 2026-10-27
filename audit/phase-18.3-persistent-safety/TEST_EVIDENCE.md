# Rustrict Phase 18.3 — Automated Test Evidence & Verification Matrix

**Date:** 2026-10-27  
**Platform:** Native Windows 11 MSVC (`x86_64-pc-windows-msvc`)  
**Compilers Tested:**
- Stable: `rustc 1.97.1` (x86_64-pc-windows-msvc)
- MSRV: `rustc 1.88.0` (x86_64-pc-windows-msvc)
**Total Binaries:** 27  
**Total Passed Tests:** 295  
**Failed:** 0  
**Ignored:** 0  

---

## 1. Test Targets & Count Breakdown

| Binary Target | Output Test Executable | Tests Passed | Status |
| :--- | :--- | :---: | :---: |
| `src/lib.rs` (unittests) | `rustrict-*.exe` | 34 | PASS |
| `src/main.rs` (unittests) | `rustrict-*.exe` | 0 | PASS |
| `tests/test_assessment.rs` | `test_assessment-*.exe` | 5 | PASS |
| `tests/test_avm_admin.rs` | `test_avm_admin-*.exe` | 20 | PASS |
| `tests/test_cli_confirmation.rs` | `test_cli_confirmation-*.exe` | 10 | PASS |
| `tests/test_dhcp.rs` | `test_dhcp-*.exe` | 1 | PASS |
| `tests/test_diagnostics.rs` | `test_diagnostics-*.exe` | 15 | PASS |
| `tests/test_fixes.rs` | `test_fixes-*.exe` | 8 | PASS |
| `tests/test_gateway.rs` | `test_gateway-*.exe` | 4 | PASS |
| `tests/test_mikrotik_admin.rs` | `test_mikrotik_admin-*.exe` | 20 | PASS |
| `tests/test_openwrt_admin.rs` | `test_openwrt_admin-*.exe` | 21 | PASS |
| `tests/test_persistence.rs` | `test_persistence-*.exe` | 9 | PASS |
| `tests/test_policy_engine.rs` | `test_policy_engine-*.exe` | 13 | PASS |
| `tests/test_policy_views.rs` | `test_policy_views-*.exe` | 7 | PASS |
| `tests/test_protocol_integration.rs` | `test_protocol_integration-*.exe` | 17 | PASS |
| `tests/test_provider_contracts.rs` | `test_provider_contracts-*.exe` | 6 | PASS |
| `tests/test_reliability.rs` | `test_reliability-*.exe` | 9 | PASS |
| `tests/test_router_admin.rs` | `test_router_admin-*.exe` | 12 | PASS |
| `tests/test_safe_networking.rs` | `test_safe_networking-*.exe` | 10 | PASS |
| `tests/test_smb.rs` | `test_smb-*.exe` | 2 | PASS |
| `tests/test_ssh_admin.rs` | `test_ssh_admin-*.exe` | 17 | PASS |
| `tests/test_target_resolution.rs` | `test_target_resolution-*.exe` | 12 | PASS |
| `tests/test_tls.rs` | `test_tls-*.exe` | 2 | PASS |
| `tests/test_unifi_admin.rs` | `test_unifi_admin-*.exe` | 19 | PASS |
| `tests/test_unified_admin.rs` | `test_unified_admin-*.exe` | 10 | PASS |
| `tests/test_verification.rs` | `test_verification-*.exe` | 5 | PASS |
| `tests/unit_tests.rs` | `unit_tests-*.exe` | 7 | PASS |
| **Total Passed Tests** | | **295** | **100% PASS** |

---

## 2. Unit Test Suite Breakdown (`src/lib.rs` - 34 tests)

1. `core::restoration::tests::test_restoration_mixed_valid_and_invalid_records` ... ok
2. `core::restoration::tests::test_restoration_missing_packet_injection_dependency_results_in_zero_activation` ... ok
3. `core::restoration::tests::test_restoration_empty_records` ... ok
4. `core::restoration::tests::test_restoration_repeated_startup_shutdown_idempotency` ... ok
5. `gateway::admin::curl_util::tests::test_read_bounded_pipe_exceeding_limit` ... ok
6. `core::restoration::tests::test_restoration_forwarding_failure_results_in_zero_activation_and_preserves_records` ... ok
7. `gateway::admin::curl_util::tests::test_read_bounded_pipe_within_limit` ... ok
8. `monitor::nic::tests::test_csv_parser_with_quotes_and_commas` ... ok
9. `gateway::admin::curl_util::tests::test_find_curl_resolves_existing_executable` ... ok
10. `monitor::nic::tests::test_nic_sample_health_saturation_thresholds` ... ok
11. `monitor::nic::tests::test_parse_link_speed_units` ... ok
12. `monitor::nic::tests::test_parse_statistics_csv_missing_and_nonnumeric_values` ... ok
13. `monitor::nic::tests::test_resolve_adapter_precedence_and_ambiguity` ... ok
14. `monitor::nic::tests::test_zero_duration_sampling_rejected` ... ok
15. `platform::windows::tests::test_cleanup_forwarding_interface_disappeared_reports_failure` ... ok
16. `platform::windows::tests::test_cleanup_forwarding_multiple_interfaces_mixed_initial_states` ... ok
17. `core::restoration::tests::test_restoration_preserves_persistent_state_unmodified` ... ok
18. `platform::windows::tests::test_cleanup_forwarding_query_verification_failure_preserves_mutation_state` ... ok
19. `platform::windows::tests::test_cleanup_forwarding_repeated_cleanup_is_idempotent` ... ok
20. `platform::windows::tests::test_cleanup_forwarding_setter_failure_preserves_mutation_state_for_retry` ... ok
21. `platform::windows::tests::test_forwarding_not_touched_when_initially_enabled` ... ok
22. `platform::windows::tests::test_forwarding_mutation_and_restoration_when_initially_disabled` ... ok
23. `gateway::admin::curl_util::tests::test_auto_clean_file_lifecycle` ... ok
24. `monitor::nic::tests::test_missing_statistics_reported_unavailable_not_zero_normal` ... ok
25. `monitor::nic::tests::test_nic_sample_health_error_counter_decrease_treated_as_reset` ... ok
26. `monitor::nic::tests::test_disconnected_adapter_reports_unavailable` ... ok
27. `monitor::nic::tests::test_nic_counter_reset_treated_as_invalidation_and_degraded` ... ok
28. `monitor::nic::tests::test_nic_sample_health_degraded_on_packet_errors` ... ok
29. `monitor::nic::tests::test_nic_sample_health_missing_tx_discards_never_claims_normal` ... ok
30. `monitor::nic::tests::test_nic_sample_health_missing_rx_errors_never_claims_normal` ... ok
31. `monitor::nic::tests::test_sampling_interval_timestamp_captures_inter_snapshot_duration` ... ok
32. `monitor::nic::tests::test_nic_sample_health_normal_complete_stats` ... ok
33. `monitor::nic::tests::test_powershell_bounded_timeout_terminates_and_reaps_process` ... ok
34. `monitor::nic::tests::test_powershell_bounded_successful_command` ... ok

---

## 3. Safe Networking Test Suite Breakdown (`tests/test_safe_networking.rs` - 10 tests)

1. `test_hermetic_scanner_emits_zero_arp_probes` ... ok
2. `test_safe_ip_forwarding_tracks_mutations_and_cleans_up` ... ok
3. `test_safe_ip_forwarding_untouched_if_already_enabled` ... ok
4. `test_safe_ip_forwarding_fails_closed_when_disabling_fails` ... ok
5. `test_link_speed_parser_units` ... ok
6. `test_nic_health_telemetry_missing_stats_does_not_claim_normal` ... ok
7. `test_hermetic_cli_scan_emits_zero_probes` ... ok
8. `test_cli_dispatch_preserves_isolated_environment` ... ok
9. `test_persistent_block_fail_closed_on_forwarding_failure` ... ok
10. `test_cleanup_forwarding_report_structured_visibility` ... ok

---

## 4. Static Analysis and Tooling Invariants

1. **`cargo fmt --check`**: Clean, zero formatting diffs across the entire workspace.
2. **`cargo clippy --all-targets -- -D warnings`**: Clean, 0 warnings, 0 errors.
3. **MSRV Verification (`cargo +1.88.0 test --all-targets`)**: 100% identical 295 passed tests.
