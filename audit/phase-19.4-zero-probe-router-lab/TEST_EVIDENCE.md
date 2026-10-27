# Rustrict Phase 19.4 — Test Evidence Report
## Zero-Probe Router-Lab Startup and Verification Suite

**Date:** 2026-10-27  
**Platform:** Native Windows 11 Enterprise (x86_64-pc-windows-msvc)  
**Rust Versions Verified:**
- Stable: `rustc 1.97.1-nightly` / current stable toolchain
- MSRV: `rustc 1.88.0 (873a06493 2025-05-10)`

---

### 1. Zero-Probe Regression Suite (`tests/test_router_lab_zero_probe.rs`)

The test suite exercises all 10 Phase 19.4 safety requirements under hermetic mocks with atomic counter verification:

```powershell
cargo test --test test_router_lab_zero_probe
```

```text
running 10 tests
test test_03_read_only_discovery_failure_fails_closed_without_active_fallback ... ok
test test_04_router_lab_environment_check_skips_enforcement_drivers ... ok
test test_10_clean_shutdown_and_eof_zero_forwarding_cleanup_and_zero_frames ... ok
test test_02_gateway_mac_unresolved_when_absent_from_cache ... ok
test test_09_existing_router_lab_allowlist_enforced_during_zero_probe_session ... ok
test test_01_read_only_resolver_retrieves_metadata_without_probes ... ok
test test_05_normal_application_mode_maintains_intended_active_behavior ... ok
test test_06_router_lab_provider_requests_do_not_occur_before_explicit_selection ... ok
test test_07_malformed_routes_ips_prefixes_and_adapters_fail_safely ... ok
test test_08_current_default_gateway_never_receives_unsolicited_startup_probe ... ok

test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.10s
```

#### Detailed Test Inventory:

1. **`test_01_read_only_resolver_retrieves_metadata_without_probes`**:
   - Injected Mock: Valid route (`Ethernet0|10.0.0.1`), IP (`10.0.0.42|24`), adapter (`00-50-56-C0-00-01`), cached ARP (`10.0.0.1 -> 00:0c:29:12:34:56`).
   - Verified: Name, IP, netmask, gateway, gateway MAC, local MAC, and NPF device path resolved accurately.
   - Verified: `send_arp_probe_count() == 0`, `icmp_ping_probe_count() == 0`, `raw_frame_send_count() == 0`.

2. **`test_02_gateway_mac_unresolved_when_absent_from_cache`**:
   - Injected Mock: Valid route/IP/adapter, empty ARP cache.
   - Verified: Interface resolution succeeds without error.
   - Verified: `iface.gateway_mac` is strictly `MacAddress::ZERO` (`is_zero() == true`).
   - Verified: Zero `SendARP` calls, zero `ping` calls.

3. **`test_03_read_only_discovery_failure_fails_closed_without_active_fallback`**:
   - Injected Mock: Route query fails with PowerShell error.
   - Verified: Returns `Err("Failed to query route...")`.
   - Verified: Fails closed immediately without invoking active resolver or issuing network probes.

4. **`test_04_router_lab_environment_check_skips_enforcement_drivers`**:
   - Injected Mock: `check_router_lab_environment()`.
   - Verified: `driver_check_count() == 0`.
   - Verified: `npcap_available == false`, `windivert_available == false`, details describe driver checks as skipped.
   - Verified: Ordinary `check_environment()` increments `driver_check_count()`.

5. **`test_05_normal_application_mode_maintains_intended_active_behavior`**:
   - Verified: `SystemArpCache` and `ActiveInterfaceResolver` contracts remain intact for normal operational mode.

6. **`test_06_router_lab_provider_requests_do_not_occur_before_explicit_selection`**:
   - Injected Mock: `RustrictCli::bootstrap_router_lab(&resolver)`.
   - Verified: `cli.router_registry().is_connected() == false`.
   - Verified: `cli.router_registry().active_provider_id() == None`.
   - Verified: Zero network packets or socket connections initiated towards gateway IP `172.16.0.1`.

7. **`test_07_malformed_routes_ips_prefixes_and_adapters_fail_safely`**:
   - Evaluated 6 subcases:
     - 7a. Missing route (empty string) $\rightarrow$ `Err("No default route...")`
     - 7b. Invalid gateway IP syntax $\rightarrow$ `Err("Invalid gateway IP...")`
     - 7c. Missing local IP $\rightarrow$ `Err("Could not query IP address...")`
     - 7d. Malformed/out-of-bounds prefix length ($> 32$) $\rightarrow$ `Err("Invalid prefix length...")`
     - 7e. Adapter query failure $\rightarrow$ `Err("Failed to query adapter info...")`
     - 7f. Zero/missing local MAC $\rightarrow$ `Err("Failed to query local MAC address...")`
   - Verified: All return actionable `Err`, none panic, zero network frames or probes emitted.

8. **`test_08_current_default_gateway_never_receives_unsolicited_startup_probe`**:
   - Injected Mock: Host default gateway set to `10.170.60.1` (production subnet).
   - Executed: `bootstrap_router_lab()`, followed by `help`, `router list`, `router capabilities`, `router status`.
   - Verified: Absolutely zero packets transmitted towards `10.170.60.1`. All counters remain 0.

9. **`test_09_existing_router_lab_allowlist_enforced_during_zero_probe_session`**:
   - Executed: Attempted active commands (`scan`, `block`, `limit`, `simulate`, `router pause`).
   - Verified: All commands rejected by default-deny admission. All counters remain 0.

10. **`test_10_clean_shutdown_and_eof_zero_forwarding_cleanup_and_zero_frames`**:
    - Executed: `cli.dispatch_command("exit")`, `cli.shutdown()`.
    - Verified: Zero forwarding mutation attempts, zero cleanup operations, zero raw L2 frame emissions.

---

### 2. Comprehensive Test Suite Totals

Executed `cargo test --all-targets` across the complete project workspace:

| Test Binary | Target | Tests Passed | Status |
| :--- | :--- | :---: | :---: |
| `rustrict` | `src/lib.rs` (unit tests) | 46 | OK |
| `rustrict` | `src/main.rs` (unit tests) | 0 | OK |
| `test_assessment` | `tests/test_assessment.rs` | 5 | OK |
| `test_avm_admin` | `tests/test_avm_admin.rs` | 20 | OK |
| `test_batched_readiness` | `tests/test_batched_readiness.rs` | 6 | OK |
| `test_cli_confirmation` | `tests/test_cli_confirmation.rs` | 10 | OK |
| `test_dhcp` | `tests/test_dhcp.rs` | 1 | OK |
| `test_diagnostics` | `tests/test_diagnostics.rs` | 15 | OK |
| `test_fixes` | `tests/test_fixes.rs` | 8 | OK |
| `test_gateway` | `tests/test_gateway.rs` | 4 | OK |
| `test_mikrotik_admin` | `tests/test_mikrotik_admin.rs` | 20 | OK |
| `test_openwrt_admin` | `tests/test_openwrt_admin.rs` | 21 | OK |
| `test_persistence` | `tests/test_persistence.rs` | 9 | OK |
| `test_policy_engine` | `tests/test_policy_engine.rs` | 13 | OK |
| `test_policy_views` | `tests/test_policy_views.rs` | 7 | OK |
| `test_protocol_integration` | `tests/test_protocol_integration.rs` | 17 | OK |
| `test_provider_contracts` | `tests/test_provider_contracts.rs` | 6 | OK |
| `test_reliability` | `tests/test_reliability.rs` | 9 | OK |
| `test_router_admin` | `tests/test_router_admin.rs` | 12 | OK |
| `test_router_lab_isolation` | `tests/test_router_lab_isolation.rs` | 16 | OK |
| `test_router_lab_zero_probe` | `tests/test_router_lab_zero_probe.rs` | 10 | OK |
| `test_safe_networking` | `tests/test_safe_networking.rs` | 12 | OK |
| `test_smb` | `tests/test_smb.rs` | 2 | OK |
| `test_ssh_admin` | `tests/test_ssh_admin.rs` | 17 | OK |
| `test_target_resolution` | `tests/test_target_resolution.rs` | 12 | OK |
| `test_tls` | `tests/test_tls.rs` | 2 | OK |
| `test_unifi_admin` | `tests/test_unifi_admin.rs` | 19 | OK |
| `test_unified_admin` | `tests/test_unified_admin.rs` | 10 | OK |
| `test_verification` | `tests/test_verification.rs` | 5 | OK |
| `unit_tests` | `tests/unit_tests.rs` | 7 | OK |
| **Total Passed** | **30 test targets (29 active suites)** | **341 / 341** | **100% OK** |

---

### 3. MSRV Rust 1.88.0 Toolchain Verification

Executed `cargo +1.88.0 test --all-targets`:
- **Result:** 341 / 341 tests passed.
- **Failures:** 0.
- **Ignored:** 0.

Executed `cargo +1.88.0 build --release`:
- **Result:** Exit code 0.
- **Binary:** `target\release\rustrict.exe` (3,037,696 bytes).
