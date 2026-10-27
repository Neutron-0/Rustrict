# Rustrict Phase 18.3 — Persistent Enforcement Safety, Startup/Shutdown Side-Effect Audit & Hardware Readiness

**Document Version:** 1.0.0  
**Date:** 2026-10-27  
**Baseline Git Revision:** `bd06f1c7fb90ac9716e514145d02df8aebd2520a`  
**Platform:** Native Windows 11 (MSVC), `rustc 1.97.1` (stable), `rustc 1.88.0` (MSRV)  
**Status:** Verification Complete — 295/295 Tests Passing (Stable & MSRV)

---

## 1. Executive Summary & Defect Remediation

Phase 18.3 addressed two critical release-blocking safety defects identified in the persistent enforcement and platform teardown subsystems:

1. **Persistent-Block Startup Restoration Defect (Release Blocker):**
   - *Previous behavior:* In `RustrictCli::new()`, saved blocked devices were restored from disk into the host table, and then unconditionally added to `ArpSpoofer` and `TrafficLimiter` even if `ensure_scoped_forwarding_enabled()` failed or was ignored. This created a severe safety defect where target traffic could be blackholed without routing transit, and invalid or corrupted persistent records could trigger packet injection without precondition validation.
   - *Remediation:* Created a dedicated restoration engine in `src/core/restoration.rs`. Enforced strict target validation (valid unicast IP, valid non-broadcast/non-multicast/non-zero MAC, exclusion of local host and gateway, subnet scope alignment) and precondition verification (scoped forwarding enablement, raw packet injection capability). If any precondition fails, the target is restored in memory with status `HostStatus::PersistedInactive(Direction)` and is **never** added to the spoofer or limiter. Saved records on disk are strictly preserved without deletion or overwrite, maintaining operator recoverability while failing closed.

2. **Unobservable and Non-Retryable Forwarding Cleanup:**
   - *Previous behavior:* In `ForwardingManager::cleanup_forwarding_with()`, `Set-NetIPInterface -Forwarding Disabled` errors were logged as warnings and discarded (`Ok(())` was returned regardless of outcome). If the interface disappeared or the PowerShell command failed, the mutation state `currently_mutated` was unconditionally cleared, making subsequent cleanup attempts impossible and leaving Windows interfaces permanently mutated. Furthermore, the disabled state was never verified after running the command.
   - *Remediation:* Redesigned `cleanup_forwarding_with()` to return a structured `ForwardingCleanupReport` tracking `restored_interfaces`, `untouched_interfaces`, and `failed_interfaces`. The disabled state is explicitly verified via `query_interface_forwarding_with` after setting. If any setter or query verification fails, or if an interface disappears while still marked mutated, `currently_mutated` is preserved as `true` so subsequent cleanup passes can retry. Both normal process termination and `console_ctrl_handler` now inspect the report, output detailed diagnostic warnings on failure, and exit with code 1.

---

## 2. Architectural Changes

### 2.1 Core Restoration Engine (`src/core/restoration.rs`)
- **`RestorationNetworkParams<'a>`**: Encapsulates adapter IP, MAC, alias name, gateway IP, and gateway MAC.
- **`validate_restored_target()`**: Strictly validates candidate targets:
  - Rejects broadcast, multicast, loopback, or unspecified IP addresses.
  - Rejects broadcast, multicast, or zero MAC addresses.
  - Rejects self (local controller IP or MAC) and gateway (router IP or MAC).
  - Rejects addresses falling outside the configured adapter subnet scope.
- **`ScopedForwardingEnabler` & `PersistentBlockActivator` traits**: Abstract platform operations allowing 100% hermetic unit testing without invoking live PowerShell or spawning driver threads.
- **`restore_persistent_blocks_with()`**:
  - Validates all persistent records prior to any network activation.
  - Checks preconditions: queries/enables scoped IP forwarding and verifies packet injection capabilities.
  - Injects into active enforcement only if all preconditions succeed.
  - If forwarding or preconditions fail, populates the host table with `HostStatus::PersistedInactive(dir)`, emits explicit operator warnings, and leaves the persistent disk store completely untouched.

### 2.2 Host Status Extensions (`src/types.rs`, `src/cli/table.rs`)
- Added `HostStatus::PersistedInactive(Direction)`:
  - Pretty-prints as `Persisted [Inactive] (Inbound)`, `Persisted [Inactive] (Outbound)`, or `Persisted [Inactive] (Both)` in yellow in the interactive CLI table.
  - In `src/spoofer/engine.rs`, `ArpSpoofer::add()` and tick loops explicitly treat `HostStatus::PersistedInactive` as a non-enforced status (zero ARP frames crafted or sent).
  - `ArpSpoofer::add()` now returns `Result<(), String>`, validating MAC and IP against broadcast, multicast, zero, gateway, and self before adding to the active target list.

### 2.3 Observable Forwarding Cleanup (`src/platform/windows.rs`)
- **`ForwardingCleanupReport`**:
  ```rust
  pub struct ForwardingCleanupReport {
      pub restored_interfaces: Vec<String>,
      pub untouched_interfaces: Vec<String>,
      pub failed_interfaces: Vec<(String, String)>,
  }
  ```
  Provides `is_success()` to confirm 100% safe restoration.
- **State Query Verification**:
  After `Set-NetIPInterface -Forwarding Disabled`, `query_interface_forwarding_with()` queries the interface to verify that `Forwarding` is indeed `Disabled`. If the query reports `Enabled` or fails, the interface is recorded in `failed_interfaces` and `currently_mutated` remains `true`.
- **Exit Code 1 on Teardown Failure**:
  Both `src/main.rs` (normal return) and `console_ctrl_handler` (Ctrl+C / console close) evaluate `report.is_success()`. If failures occurred, detailed diagnostics are printed to `stderr` and the process exits with code 1.

---

## 3. Comprehensive Audit of Startup & Shutdown Side Effects

As mandated by Phase 18.3 Section 3, all startup and shutdown code paths were audited and source-traced to catalog every implicit network action, Windows setting change, and driver activation:

| Execution Point | Subsystem / Function | Action / Side Effect | Scope & Targets | Trigger / Condition | Failure Mode & Safety Invariant |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Startup** | `network::scanner::find_default_gateway` | Windows `GetBestRoute2` / PowerShell `Get-NetRoute` / `Get-NetIPAddress` | Local Windows network stack | CLI launch / initialization | Read-only discovery. If fails, reports error and halts CLI setup. |
| **Startup** | `network::scanner::get_interface_friendly_name` | PowerShell `Get-NetAdapter` | Local adapter aliases | CLI launch | Read-only query. Defaults to adapter description or GUID if alias unresolvable. |
| **Startup** | `monitor::nic::sample_nic_health` | PowerShell `Get-NetAdapterStatistics` | Selected network adapter | Polled in background or on command | Read-only query bounded by child process timeout and process tree termination. Missing counters invalidate health (never falsely normal). |
| **Startup** | `core::restoration::restore_persistent_blocks_with` | State deserialization from `%ProgramData%\Rustrict\rustrict_state.json` | Local controller filesystem | `RustrictCli::new()` | File read only. Invalid records skipped with warning. Disk state is never overwritten or deleted on failure. |
| **Startup** | `platform::windows::ensure_scoped_forwarding_enabled` | PowerShell `Set-NetIPInterface -Forwarding Enabled` | Scoped active network interface | Restoring persistent blocks | **MUTATING**: Only executed if persisted blocks exist and are valid. If it fails, restoration halts immediately; targets marked `PersistedInactive`; zero packets sent. |
| **Startup** | `spoofer::engine::ArpSpoofer::start` | Npcap `pcap_open_live` / `pcap_sendpacket` worker thread | Raw Layer 2 Ethernet | Only if targets are actively added | Only invoked if preconditions pass. Validates targets. Zero packets sent for `PersistedInactive`. |
| **Startup** | `limiter::engine::TrafficLimiter::start` | WinDivert `WinDivertOpen` (`NETWORK_FORWARD`) | Windows network filtering layer | Only if targets actively limited/blocked | Only opened if targets added. Fails gracefully if WinDivert driver is missing or access is denied. |
| **Startup** | `PassiveIdentitySniffer::start` | Npcap promiscuous capture (UDP port 67/68) | Controller network interface | Non-hermetic live CLI launch | Read-only packet capture for DHCP Option 12. Never transmits packets. |
| **Runtime Rescan** | `RustrictCli::reconcile_hosts` | Forwarding check & spoofer re-sync | Active targets | Fresh rescan | If forwarding fails, all active spoofer/limiter entries are cleared and marked `PersistedInactive` (fail-closed). |
| **Shutdown** | `main.rs` (Normal Exit) | `platform::cleanup_forwarding()` | Mutated Windows network interfaces | Normal exit (`exit`, `quit`, EOF) | Executes `Set-NetIPInterface -Forwarding Disabled`, queries verification. Reports structured report. Exits 1 on failure. |
| **Shutdown** | `console_ctrl_handler` | `platform::cleanup_forwarding()` | Mutated Windows network interfaces | `CTRL_C_EVENT`, `CTRL_BREAK_EVENT`, `CTRL_CLOSE_EVENT` | Directly queries and disables forwarding via dedicated handler. Preserves state if fails. Exits 1 on failure. |
| **Shutdown** | `ArpSpoofer::stop` | ARP cache restoration packets (unicast ARP) | Active poisoned targets | Shutdown / target unblock | Sends restorative unicast ARP frames with real MAC addresses to unpoison target and gateway ARP caches before thread exit. |
| **Shutdown** | `TrafficLimiter::stop` | WinDivert handle closure (`WinDivertClose`) | Kernel WinDivert driver | Shutdown / target unlimit | Closes driver handle, restoring native kernel network transit immediately. |
| **Shutdown** | `AutoCleanFile::drop` | Temporary file deletion | Windows `%TEMP%` directory | RAII scope exit | Securely removes temporary curl argument files. |

---

## 4. Verification Evidence & Summary of Tests

A comprehensive verification suite was executed across native Windows MSVC using both the active stable compiler and the project MSRV:
- **Rust Stable:** `rustc 1.97.1` (`x86_64-pc-windows-msvc`)
- **Rust MSRV:** `rustc 1.88.0` (`x86_64-pc-windows-msvc`)
- **Total Test Binaries:** 27
- **Total Tests Passed:** 295 (Stable: 295/295, MSRV: 295/295)
- **Failures:** 0
- **Ignored:** 0

### Newly Added Unit Tests (`src/lib.rs` / `core::restoration` & `platform::windows`):
1. `test_restoration_empty_records`: Validates that empty persistent state completes cleanly with zero actions.
2. `test_restoration_forwarding_failure_results_in_zero_activation_and_preserves_records`: Confirms that if forwarding fails, zero targets are added to spoofer or limiter, targets are marked `PersistedInactive`, and disk state is preserved.
3. `test_restoration_missing_packet_injection_dependency_results_in_zero_activation`: Validates that missing raw injection capabilities prevent spoofer/limiter activation.
4. `test_restoration_mixed_valid_and_invalid_records`: Confirms that corrupt, gateway, self, or broadcast records are rejected while valid targets are classified.
5. `test_restoration_preserves_persistent_state_unmodified`: Proves that persistent state records on disk remain completely unmodified after restoration errors.
6. `test_restoration_repeated_startup_shutdown_idempotency`: Verifies repeated startup and teardown cycles without state corruption.
7. `test_cleanup_forwarding_setter_failure_preserves_mutation_state_for_retry`: Ensures setter failure preserves `currently_mutated = true`.
8. `test_cleanup_forwarding_query_verification_failure_preserves_mutation_state`: Ensures verification failure preserves mutation state.
9. `test_cleanup_forwarding_interface_disappeared_reports_failure`: Ensures disappeared interfaces are reported in `failed_interfaces`.
10. `test_cleanup_forwarding_repeated_cleanup_is_idempotent`: Confirms repeated cleanup calls do not corrupt state or re-mutate untouched interfaces.
11. `test_cleanup_forwarding_multiple_interfaces_mixed_initial_states`: Validates multi-interface environments with mixed initial forwarding states.

### Newly Added Integration Tests (`tests/test_safe_networking.rs`):
1. `test_persistent_block_fail_closed_on_forwarding_failure`: Verifies end-to-end fail-closed behavior on forwarding failure.
2. `test_cleanup_forwarding_report_structured_visibility`: Verifies structured report fields and success semantics across simulated platform states.
