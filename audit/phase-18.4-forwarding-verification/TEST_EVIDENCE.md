# Rustrict Phase 18.4 — Test Evidence & Verification Matrix

**Date:** 2026-10-27  
**Platform:** Native Windows 11 MSVC (`x86_64-pc-windows-msvc`)  
**Compilers Tested:**
- Stable: `rustc 1.97.1` (x86_64-pc-windows-msvc)
- MSRV: `rustc 1.88.0` (x86_64-pc-windows-msvc)
**Total Binaries:** 27  
**Total Passed Tests:** 306  
**Failed:** 0  
**Ignored:** 0  

---

## 1. Test Targets & Count Breakdown

| Binary Target | Output Test Executable | Tests Passed | Status |
| :--- | :--- | :---: | :---: |
| `src/lib.rs` (unittests) | `rustrict-*.exe` | 43 | PASS |
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
| `tests/test_safe_networking.rs` | `test_safe_networking-*.exe` | 12 | PASS |
| `tests/test_smb.rs` | `test_smb-*.exe` | 2 | PASS |
| `tests/test_ssh_admin.rs` | `test_ssh_admin-*.exe` | 17 | PASS |
| `tests/test_target_resolution.rs` | `test_target_resolution-*.exe` | 12 | PASS |
| `tests/test_tls.rs` | `test_tls-*.exe` | 2 | PASS |
| `tests/test_unifi_admin.rs` | `test_unifi_admin-*.exe` | 19 | PASS |
| `tests/test_unified_admin.rs` | `test_unified_admin-*.exe` | 10 | PASS |
| `tests/test_verification.rs` | `test_verification-*.exe` | 5 | PASS |
| `tests/unit_tests.rs` | `unit_tests-*.exe` | 7 | PASS |
| **Total Passed Tests** | | **306** | **100% PASS** |

---

## 2. Newly Added Unit Tests (`src/lib.rs` - 43 tests total, +9 new)

1. `core::scope::tests::test_cidr_network_and_broadcast_addresses`: Validates `/24`, `/31`, and `/32` network and broadcast classification under RFC 3021.
2. `core::scope::tests::test_scope_rejects_subnet_network_and_broadcast`: Validates rejection of network identifier, directed broadcast, global broadcast, multicast, loopback, and unspecified addresses.
3. `core::scope::tests::test_scope_conservative_overlapping_cidrs`: Validates conservative rejection of network/broadcast addresses across overlapping prefixes (`10.0.0.0/8` vs `10.1.2.0/24`).
4. `core::scope::tests::test_scope_preserves_31_and_32_valid_endpoints`: Validates that RFC 3021 `/31` endpoints and `/32` host routes are preserved as valid targets.
5. `platform::windows::tests::test_ensure_forwarding_setter_success_but_remains_disabled_fails`: Simulates setter returning success but OS state remaining `Disabled` (verification discrepancy failure).
6. `platform::windows::tests::test_ensure_forwarding_query_fails_after_setter`: Simulates postcondition verification query failure following setter invocation.
7. `platform::windows::tests::test_ensure_forwarding_previously_mutated_then_externally_disabled_queries_and_reenables`: Proves that stale internal flags are never trusted; queries OS state and re-enables/verifies.
8. `platform::windows::tests::test_original_state_enabled_later_changed_cleanup_restores_enabled`: Validates that an originally `Enabled` interface is restored to `Enabled` upon cleanup even if later altered.
9. `platform::windows::tests::test_cleanup_forwarding_with_retries_transient_failure_succeeds`: Validates bounded retry recovery on transient setter failures.

---

## 3. Newly Added Integration Tests (`tests/test_safe_networking.rs` - 12 tests total, +2 new)

1. `test_persistent_block_rejects_subnet_network_and_directed_broadcast_targets`: Verifies that persisted records for `192.168.1.0` and `192.168.1.255` on `/24` are rejected and never reach activator or spoofer, while valid targets are enforced and disk state remains unmodified.
2. `test_persistent_block_accepts_31_point_to_point_endpoints`: Verifies that RFC 3021 `/31` endpoints (`172.16.0.0` and `172.16.0.1`) are accepted as valid host targets during persistent block restoration.
