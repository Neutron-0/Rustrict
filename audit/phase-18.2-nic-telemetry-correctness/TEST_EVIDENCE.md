# Phase 18.2 Test Evidence & Verification Records

## 1. Automated Test Suite Results

### Full Suite Summary
- **Stable Toolchain:** `rustc 1.97.1 (8bab26f4f 2026-07-14)`
- **MSRV Toolchain:** `rustc 1.88.0 (6b00bc388 2025-06-23)`
- **Host OS:** Windows 11 Enterprise (Build 26100)
- **Target Architecture:** `x86_64-pc-windows-msvc`
- **Total Test Binaries:** 27
- **Total Passed Tests:** **282 passed; 0 failed; 0 ignored**

### Complete Target-by-Target Breakdown (Derived from Raw Test Output)

| Test Target Binary | Type | Passed | Failed | Status |
| :--- | :--- | :---: | :---: | :---: |
| `unittests src\lib.rs` | Unit | 23 | 0 | PASS |
| `unittests src\main.rs` | Unit | 0 | 0 | PASS |
| `tests\test_assessment.rs` | Integration | 5 | 0 | PASS |
| `tests\test_avm_admin.rs` | Integration | 20 | 0 | PASS |
| `tests\test_cli_confirmation.rs` | Integration | 10 | 0 | PASS |
| `tests\test_dhcp.rs` | Integration | 1 | 0 | PASS |
| `tests\test_diagnostics.rs` | Integration | 15 | 0 | PASS |
| `tests\test_fixes.rs` | Integration | 8 | 0 | PASS |
| `tests\test_gateway.rs` | Integration | 4 | 0 | PASS |
| `tests\test_mikrotik_admin.rs` | Integration | 20 | 0 | PASS |
| `tests\test_openwrt_admin.rs` | Integration | 21 | 0 | PASS |
| `tests\test_persistence.rs` | Integration | 9 | 0 | PASS |
| `tests\test_policy_engine.rs` | Integration | 13 | 0 | PASS |
| `tests\test_policy_views.rs` | Integration | 7 | 0 | PASS |
| `tests\test_protocol_integration.rs` | Integration | 17 | 0 | PASS |
| `tests\test_provider_contracts.rs` | Integration | 6 | 0 | PASS |
| `tests\test_reliability.rs` | Integration | 9 | 0 | PASS |
| `tests\test_router_admin.rs` | Integration | 12 | 0 | PASS |
| `tests\test_safe_networking.rs` | Integration | 8 | 0 | PASS |
| `tests\test_smb.rs` | Integration | 2 | 0 | PASS |
| `tests\test_ssh_admin.rs` | Integration | 17 | 0 | PASS |
| `tests\test_target_resolution.rs` | Integration | 12 | 0 | PASS |
| `tests\test_tls.rs` | Integration | 2 | 0 | PASS |
| `tests\test_unifi_admin.rs` | Integration | 19 | 0 | PASS |
| `tests\test_unified_admin.rs` | Integration | 10 | 0 | PASS |
| `tests\test_verification.rs` | Integration | 5 | 0 | PASS |
| `tests\unit_tests.rs` | Unit | 7 | 0 | PASS |
| **Total** | | **282** | **0** | **100% PASS** |

---

## 2. Unit Tests in `src/lib.rs` (23 Tests)

```text
running 23 tests
test gateway::admin::curl_util::tests::test_read_bounded_pipe_within_limit ... ok
test gateway::admin::curl_util::tests::test_read_bounded_pipe_exceeding_limit ... ok
test gateway::admin::curl_util::tests::test_find_curl_resolves_existing_executable ... ok
test monitor::nic::tests::test_parse_statistics_csv_missing_and_nonnumeric_values ... ok
test monitor::nic::tests::test_csv_parser_with_quotes_and_commas ... ok
test monitor::nic::tests::test_nic_sample_health_saturation_thresholds ... ok
test monitor::nic::tests::test_parse_link_speed_units ... ok
test monitor::nic::tests::test_resolve_adapter_precedence_and_ambiguity ... ok
test monitor::nic::tests::test_zero_duration_sampling_rejected ... ok
test platform::windows::tests::test_forwarding_mutation_and_restoration_when_initially_disabled ... ok
test platform::windows::tests::test_forwarding_not_touched_when_initially_enabled ... ok
test gateway::admin::curl_util::tests::test_auto_clean_file_lifecycle ... ok
test monitor::nic::tests::test_nic_counter_reset_treated_as_invalidation_and_degraded ... ok
test monitor::nic::tests::test_nic_sample_health_degraded_on_packet_errors ... ok
test monitor::nic::tests::test_nic_sample_health_missing_tx_discards_never_claims_normal ... ok
test monitor::nic::tests::test_nic_sample_health_missing_rx_errors_never_claims_normal ... ok
test monitor::nic::tests::test_missing_statistics_reported_unavailable_not_zero_normal ... ok
test monitor::nic::tests::test_disconnected_adapter_reports_unavailable ... ok
test monitor::nic::tests::test_nic_sample_health_error_counter_decrease_treated_as_reset ... ok
test monitor::nic::tests::test_sampling_interval_timestamp_captures_inter_snapshot_duration ... ok
test monitor::nic::tests::test_nic_sample_health_normal_complete_stats ... ok
test monitor::nic::tests::test_powershell_bounded_timeout_terminates_and_reaps_process ... ok
test monitor::nic::tests::test_powershell_bounded_successful_command ... ok

test result: ok. 23 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.93s
```

---

## 3. Subprocess Termination & Reaping Verification

The test `test_powershell_bounded_timeout_terminates_and_reaps_process`:
- Spawns a PowerShell process that sleeps for 10 seconds: `powershell -NoProfile -Command "Start-Sleep -Seconds 10"`.
- Configures a timeout of 100 milliseconds.
- Captures the spawned OS Process ID (PID).
- Asserts that `run_command_bounded_with_pid` returns an error citing timeout.
- Queries Windows `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid)`.
- If the handle exists, calls `GetExitCodeProcess`. Asserts exit code is not `259` (`STILL_ACTIVE`).
- Proves zero abandoned zombie processes or runaway PowerShell instances.

---

## 4. Incomplete Telemetry Verification

The tests:
- `test_nic_sample_health_missing_rx_errors_never_claims_normal`
- `test_nic_sample_health_missing_tx_discards_never_claims_normal`
- `test_nic_sample_health_error_counter_decrease_treated_as_reset`

demonstrate that:
1. `rx_errors = None` with 0% utilization yields `NicHealthClassification::Degraded` with reason `"Incomplete telemetry"`.
2. `tx_discards = None` with 0% utilization yields `NicHealthClassification::Degraded`.
3. An error counter decrease from 10 to 5 sets `counter_reset_detected = true`, invalidates error telemetry, sets deltas to `None`, and classifies the adapter as `Degraded`.
4. Only when all four packet counters are present and zero does an adapter qualify for `NicHealthClassification::Normal`.
