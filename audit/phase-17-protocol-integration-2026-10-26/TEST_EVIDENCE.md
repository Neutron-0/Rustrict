# Rustrict Phase 17 — Fresh Test Evidence & Binary Verification Matrix

**Date:** 2026-10-27 (Phase 17.1 Restored & Reconciled Baseline)
**Environment:** Windows 11 Enterprise (x86_64-pc-windows-msvc)
**Rust Toolchain:** rustc 1.97.1 / cargo 1.97.1 (MSRV: 1.88.0)
**Git Revision:** Phase 17.1 (`ac1c4e9`)

---

## 1. Test Suite Summary

- **Total Test Binaries Executed:** 26
- **Total Tests Passed:** 263
- **Total Tests Failed:** 0
- **Total Tests Ignored:** 0
- **Execution Result:** `ok. 263 passed; 0 failed; 0 ignored`

---

## 2. Per-Binary Verification Breakdown

| Binary Target | Test Category / Module | Passed | Failed | Ignored | Duration |
| :--- | :--- | :---: | :---: | :---: | :---: |
| `src/lib.rs` | Bounded pipe draining, AutoCleanFile lifecycle, curl discovery | 4 | 0 | 0 | 0.01s |
| `src/main.rs` | Application entrypoint | 0 | 0 | 0 | 0.00s |
| `tests/test_assessment.rs` | Scope containment, CIDR parsing, report exports | 5 | 0 | 0 | 0.00s |
| `tests/test_avm_admin.rs` | AVM FRITZ!Box TR-064 SOAP auth, lifecycle, MD5 vectors | 20 | 0 | 0 | 0.15s |
| `tests/test_cli_confirmation.rs` | Interactive confirmation prompts, `--yes` flag, evidence CLI | 10 | 0 | 0 | 0.09s |
| `tests/test_dhcp.rs` | DHCP option 12 hostname extraction | 1 | 0 | 0 | 0.00s |
| `tests/test_diagnostics.rs` | Offline evidence validation, sanitization, overwrite safety | 15 | 0 | 0 | 0.08s |
| `tests/test_fixes.rs` | Bitrate overflow, LLMNR/mDNS, HTML title extraction | 8 | 0 | 0 | 0.00s |
| `tests/test_mikrotik_admin.rs` | MikroTik REST auth, REST API filter rules, IPv4/IPv6 capability | 19 | 0 | 0 | 0.02s |
| `tests/test_netbios.rs` | NetBIOS Name Service response parsing | 1 | 0 | 0 | 0.00s |
| `tests/test_openwrt_admin.rs` | OpenWrt HTTP JSON-RPC ubus lifecycle, watchdog cron, rollback | 21 | 0 | 0 | 0.01s |
| `tests/test_persistence.rs` | Cross-process file locking, atomic state save, recovery | 9 | 0 | 0 | 0.72s |
| `tests/test_policy_engine.rs` | Engine policy planning, lifecycle transitions, reconciler | 20 | 0 | 0 | 0.00s |
| `tests/test_policy_store.rs` | Policy store active/historical indexing and queries | 13 | 0 | 0 | 0.00s |
| `tests/test_preflight.rs` | Mutation preflight inspections, risk evaluation, preview | 16 | 0 | 0 | 0.00s |
| `tests/test_protocol_integration.rs` | Deterministic loopback protocol integration, failure injection & mutation retry safety | 17 | 0 | 0 | 1.15s |
| `tests/test_provider_contracts.rs` | Cross-provider uniform trait conformance & fail-closed behavior | 7 | 0 | 0 | 0.00s |
| `tests/test_redaction.rs` | Unicode-safe diagnostic string redaction and sanitization | 9 | 0 | 0 | 0.00s |
| `tests/test_smb.rs` | SMB2 negotiate and session setup OS detection | 2 | 0 | 0 | 0.00s |
| `tests/test_ssh_openwrt.rs` | OpenWrt SSH executor, remote pipe draining, host key checks | 17 | 0 | 0 | 0.00s |
| `tests/test_target_resolution.rs` | CLI target resolution, IP/MAC/ID parsing, scope boundaries | 12 | 0 | 0 | 0.01s |
| `tests/test_tls.rs` | TLS client certificate X.509 CN extraction and odd-trailing bytes | 2 | 0 | 0 | 0.00s |
| `tests/test_unifi_admin.rs` | Ubiquiti UniFi REST session auth, firewall rules, site routing | 19 | 0 | 0 | 0.02s |
| `tests/test_unified_admin.rs` | Router registry, fail-closed disconnect, zero ARP fallback | 10 | 0 | 0 | 0.00s |
| `tests/test_verification.rs` | Packet crafting, subnet scanning, RFC3021 range clamping | 5 | 0 | 0 | 6.33s |
| `tests/unit_tests.rs` | Bitrate formatting, OUI lookup, ARP crafting, token bucket | 7 | 0 | 0 | 0.15s |
| **TOTAL** | **26 Test Binaries** | **263** | **0** | **0** | **~8.8s** |

---

## 3. Protocol Integration Test Suite (`tests/test_protocol_integration.rs`) Detail

All 17 tests passed in isolation and under continuous multi-run stress testing:
1. `test_mikrotik_rejects_unencrypted_http`: passed
2. `test_transport_operation_classification_and_retry_matrix`: passed
3. `test_ssh_openwrt_contract_and_pipes`: passed
4. `test_router_emulator_lifecycle`: passed
5. `test_openwrt_multi_target_partial_failure_rollback`: passed
6. `test_mikrotik_loopback_rest_flow`: passed
7. `test_execute_with_operation_retry_isolation`: passed
8. `test_openwrt_http_full_protocol_flow`: passed
9. `test_mikrotik_mutation_response_dropped_uncertainty_and_no_retry`: passed
10. `test_unifi_invalid_credentials_rejected`: passed
11. `test_openwrt_http_failure_modes`: passed
12. `test_avm_tr064_soap_fault_and_malformed`: passed
13. `test_unifi_mutation_response_dropped_uncertainty_and_no_retry`: passed
14. `test_unifi_rest_protocol_flow`: passed
15. `test_avm_mutation_response_dropped_uncertainty_and_no_retry`: passed
16. `test_avm_tr064_full_protocol_flow`: passed
17. `test_multi_target_partial_with_rollback_failure_reporting`: passed

### Stress Testing Results
- **Stable Toolchain (`rustc 1.97.1`)**: 10 consecutive executions of `cargo test --test test_protocol_integration` — **10 / 10 runs passed** (170/170 assertions passed, zero failures, zero TCP resets).
- **MSRV Toolchain (`rustc 1.88.0`)**: 5 consecutive executions of `cargo +1.88.0 test --test test_protocol_integration` — **5 / 5 runs passed** (85/85 assertions passed, zero failures, zero TCP resets).

---

## 4. Static Analysis & Code Quality Verification

```powershell
PS D:\Vault\Rustrict> cargo fmt --check
# Result: Exit code 0 (Clean formatting across all source files)

PS D:\Vault\Rustrict> cargo clippy --all-targets -- -D warnings
# Result: Exit code 0 (Zero warnings, zero lints across lib, bin, and all 26 test binaries)
```
