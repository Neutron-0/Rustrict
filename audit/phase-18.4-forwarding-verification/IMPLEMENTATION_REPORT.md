# Rustrict Phase 18.4 — Verified Forwarding Preconditions, Target Address Validation & Stage 1 Release Gate Report

**Document Version:** 1.0.0  
**Date:** 2026-10-27  
**Baseline Git Revision:** `daa2a1cea9b4c46f0b970dbc892e95129ff33514` (Phase 18.3 Code) / `9e6c7da124110f6d3a1a5b712d9f66c109379879` (Phase 18.3 Docs HEAD)  
**Platform:** Native Windows 11 MSVC (`x86_64-pc-windows-msvc`), `rustc 1.97.1` (stable), `rustc 1.88.0` (MSRV)  
**Status:** Verification Complete — 306/306 Tests Passing (Stable & MSRV)

---

## 1. Executive Summary & Defect Remediation

Phase 18.4 focused on resolving safety and correctness gaps identified during deep source-level review of the forwarding precondition verification, teardown restoration, and target address admission subsystems:

1. **Forwarding Precondition Verification from Actual OS State:**
   - *Previous behavior:* `ForwardingManager::ensure_scoped_forwarding_enabled_with()` returned `Ok(true)` if `currently_mutated` was already marked true internally, without verifying the current state in Windows. Furthermore, after issuing `Set-NetIPInterface -Forwarding Enabled`, it did not query and verify that the postcondition state in the OS actually transitioned to `Enabled`. Non-terminating PowerShell errors could fail silently, and multiple observations could overwrite `original_enabled`.
   - *Remediation:*
     - Always queries the actual interface state before reporting readiness; never treats the internal flag as proof.
     - Sets forwarding to `Enabled` and queries the OS to verify postcondition `Enabled`. Fails closed if the query fails or the state remains `Disabled`.
     - In `SystemCommandRunner`, injects `$ErrorActionPreference = 'Stop'` to convert cmdlet failures into terminating errors with non-zero exit status and stderr propagation.
     - Preserves the initial interface state baseline captured at the first observation (`original_enabled`), never overwriting it on subsequent observations.
     - In `reconcile_hosts`, deactivates persistent enforcement if forwarding drops during runtime, and reactivates it only after forwarding is re-enabled and verified in the OS.

2. **Reliable Restoration of Original Forwarding Baseline with Bounded Retries:**
   - *Previous behavior:* Teardown unconditionally attempted to restore `Disabled`, disregarding whether the interface was originally `Enabled` prior to mutation. On failure, no bounded retries were performed.
   - *Remediation:*
     - Restores the captured `original_enabled` state (whether `Enabled` or `Disabled`).
     - Queries and verifies actual OS state post-restore; only clears `currently_mutated` if verification matches the target state.
     - Structured failure reporting captures expected original state, last known state, and alerts the operator that manual verification may be required.
     - Implemented `cleanup_forwarding_with_retries()` with bounded retries (3 attempts).
     - Both normal exit in `src/main.rs` and `console_ctrl_handler` enforce non-zero exit code 1 if cleanup fails.

3. **Subnet Network & Directed-Broadcast Target Rejection:**
   - *Previous behavior:* `Ipv4Addr::is_broadcast()` only checked `255.255.255.255`. A subnet's directed broadcast (e.g. `192.168.1.255` on `/24`) and network identifier (`192.168.1.0` on `/24`) were accepted as valid target host addresses.
   - *Remediation:*
     - Implemented shared address validation rule in `src/core/scope.rs`: `Ipv4Cidr` now exposes `network_address()`, `broadcast_address()`, `is_network_address()`, `is_directed_broadcast()`, and `is_valid_host_ip()`.
     - Conservative Overlapping CIDR Semantics: If an address constitutes a network identifier or directed broadcast for ANY configured CIDR prefix ($\le$ /30) containing it, it is rejected.
     - Correctly preserves RFC 3021 `/31` point-to-point links (both `0` and `1` are valid endpoints) and `/32` host routes.
     - Centralized in `ScopeManager::validate_target()` and integrated into `validate_restored_target()` and all CLI admission paths (`block`, `limit`, `unblock`, `unlimit`, `simulate`, `router pause`). Stored persistent disk state is preserved untouched on validation failure.

---

## 2. Comprehensive Startup Driver & Thread Initialization Audit

All startup components were inspected and verified against source code:

| Component | Constructor | Construction Behavior | Worker / Thread Behavior | Wire / Driver State |
| :--- | :--- | :--- | :--- | :--- |
| **`ArpSpoofer`** | `ArpSpoofer::new()` | Calls `RawL2Sender::open(iface)` (`pcap_open_live`) | Inactive (`running: false`, thread NOT spawned) | **Zero** frames sent, zero targets added until `add()` and `start()` called. |
| **`PassiveIdentitySniffer`** | `PassiveIdentitySniffer::new()` | Spawns background thread | Active promiscuous capture on UDP 67/68 | Strictly receives BOOTP/DHCP Option 12; **zero** packets transmitted. |
| **`TrafficLimiter`** | `TrafficLimiter::new()` | Instantiates empty rule/profile maps | Inactive (`running: false`, handle `None`) | Kernel `WinDivert` driver NOT opened until `limit()` or `block()` is called. |
| **`ForwardingManager`** | `ForwardingManager::new()` | Instantiates empty tracking mutex | Inactive | Zero commands executed until `ensure_scoped_forwarding_enabled` is called. |
| **`PersistentState`** | `PersistentState::load()` | Deserializes JSON state file | N/A (Data structure) | Fail-closed restoration; disk records never deleted or modified on error. |

---

## 3. Test Evidence Summary

- **Total Test Binaries:** 27
- **Total Passing Tests:** 306 (Stable: 306/306, MSRV 1.88.0: 306/306)
- **Unit Tests (`src/lib.rs`):** 43 passed (+9 new tests)
- **Safe Networking Tests (`test_safe_networking.rs`):** 12 passed (+2 new tests)
- **Failures / Errors:** 0
- **Clippy:** 0 warnings across all targets (`cargo clippy --all-targets -- -D warnings`)
- **Formatting:** Clean (`cargo fmt --check`)
