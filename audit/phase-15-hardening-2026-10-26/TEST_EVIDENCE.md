# Rustrict Phase 15 Hardening — Test Evidence

**Date:** 2026-10-26  
**Operating System:** Windows 10/11 (native x86_64-pc-windows-msvc)  
**Rust Toolchain:** `rustc 1.84.0` / stable  
**Total Tests Passing:** **196 passed**, 0 failed, 0 ignored  

---

## 1. Native Windows Verification Commands

All checks were executed natively in Windows PowerShell in `D:\Vault\Rustrict`:

1. `cargo fmt --check` $\to$ **Exit code 0** (code formatting strictly adheres to standard style)
2. `cargo check --all-targets` $\to$ **Exit code 0** (compilation successful across all targets)
3. `cargo clippy --all-targets -- -D warnings` $\to$ **Exit code 0** (zero linter warnings across all targets)
4. `cargo test --all-targets` $\to$ **Exit code 0** (196 tests passed)

---

## 2. Test Suite Breakdown by Binary

| Binary / Suite | Test File | Passed | Failed | Ignored | Focus Area |
| :--- | :--- | :---: | :---: | :---: | :--- |
| **Unit tests (lib)** | `src/lib.rs` | 2 | 0 | 0 | Native `curl.exe` discovery, `AutoCleanFile` zero-before-unlink |
| **Binary** | `src/main.rs` | 0 | 0 | 0 | CLI application entrypoint |
| **Assessment** | `tests/test_assessment.rs` | 5 | 0 | 0 | CIDR containment, scope boundaries, SARIF export |
| **AVM TR-064** | `tests/test_avm_admin.rs` | 20 | 0 | 0 | Digest auth, XML SOAP, HostFilter WAN block, rollback failure reporting |
| **DHCP** | `tests/test_dhcp.rs` | 1 | 0 | 0 | DHCP Option 12 hostname parsing |
| **Diagnostics** | `tests/test_diagnostics.rs` | 7 | 0 | 0 | Read-only inventory, secret sanitization, no-fallback behavior |
| **Fixes** | `tests/test_fixes.rs` | 8 | 0 | 0 | Bitrate bounds, LLMNR/mDNS echo parsing, serialization roundtrip |
| **Gateway** | `tests/test_gateway.rs` | 4 | 0 | 0 | Gateway host entry, SSDP headers, XML tag extraction |
| **MikroTik REST** | `tests/test_mikrotik_admin.rs` | 20 | 0 | 0 | HTTPS REST, address-list blocking, watchdog, rollback failure reporting |
| **OpenWrt** | `tests/test_openwrt_admin.rs` | 23 | 0 | 0 | ubus JSON-RPC, multi-target policies, autonomous watchdog |
| **Persistence** | `tests/test_persistence.rs` | 9 | 0 | 0 | Atomic replace, schema v2 migration, cross-process `fs2` lock contention |
| **Policy Engine** | `tests/test_policy_engine.rs` | 8 | 0 | 0 | Disconnected fail-closed, lockout protection, lifecycle tracking |
| **Policy Views** | `tests/test_policy_views.rs` | 6 | 0 | 0 | Active policy representation, status views |
| **Reliability** | `tests/test_reliability.rs` | 7 | 0 | 0 | DPAPI credential roundtrip, `ProtectedBuffer` memory zeroing |
| **Router Admin** | `tests/test_router_admin.rs` | 12 | 0 | 0 | Dry-run plans, timeout simulation, identity detection |
| **SMB** | `tests/test_smb.rs` | 1 | 0 | 0 | NetBIOS / SMB discovery |
| **SSH Admin** | `tests/test_ssh_admin.rs` | 16 | 0 | 0 | Argument injection resistance, host key pinning, cron watchdog |
| **Target Resolution**| `tests/test_target_resolution.rs` | 12 | 0 | 0 | IP/MAC/ID resolution, deduplication, persistent state |
| **TLS** | `tests/test_tls.rs` | 1 | 0 | 0 | X.509 CN extraction and identity validation |
| **UniFi REST** | `tests/test_unifi_admin.rs` | 19 | 0 | 0 | Traffic Rules API, session cookies, controller auth |
| **Unified Admin** | `tests/test_unified_admin.rs` | 10 | 0 | 0 | Registry fail-closed, preflight capability checks, zero mutation guarantee |
| **Verification** | `tests/test_verification.rs` | 5 | 0 | 0 | L2 blackhole MAC, token bucket shaper, subnet scan clamping |
| **Unit Tests** | `tests/unit_tests.rs` | 7 | 0 | 0 | Frame crafting (ARP/deauth), OUI vendor lookup |
| **TOTAL** | | **196** | **0** | **0** | **100% Passing** |

---

## 3. New Phase 15 Regression Tests

1. `test_cross_process_locking_contention_and_timeout`:
   - Validates that two concurrent processes competing for `policy_store.json.lock` properly detect contention, respect the bounded timeout, and handle Windows `ERROR_LOCK_VIOLATION` (OS error 33) cleanly.
2. `test_cross_process_concurrent_disjoint_writers`:
   - Validates that concurrent writers across separate threads/processes reliably serialize their updates without clobbering disjoint policy scopes.
3. `test_mikrotik_rollback_failure_reporting`:
   - Simulates a partial batch failure during multi-target enforcement on MikroTik REST, followed by simulated rollback failure. Asserts that `PolicyLifecycleState::PartialFailure` is returned and logged with dirty router state warning.
4. `test_avm_rollback_failure_reporting`:
   - Simulates multi-target AVM TR-064 failure with unrecoverable rollback failure, verifying `AdminError::RollbackFailed` details applied and failed targets.
5. `test_credential_hygiene_and_protected_buffer_zeroing`:
   - Verifies `ProtectedBuffer` and `ProtectedString` display `[REDACTED]`, volatile zeroing on drop, and memory zeroing on DPAPI decryption buffers.
6. `test_protected_credentials_file_roundtrip_with_zeroization`:
   - Verifies Windows DPAPI persistence roundtrip without leaving plaintext password strings on disk or unzeroed memory in heap.
7. `test_real_provider_failure_never_triggers_mock_or_arp_fallback`:
   - Proves registry fails completely closed when a real router endpoint is unreachable, refusing to fallback to `mock` or ARP spoofing.
8. `test_capability_preflight_fails_closed_before_mutation`:
   - Asserts that unsupported router operations (such as temporary policies on AVM without autonomous recovery) fail closed during preflight before mutating router rules.
9. `test_read_only_diagnostics_and_inventory_perform_zero_mutations`:
   - Asserts that diagnostic reports and inventory queries perform strictly zero mutations on router state.
