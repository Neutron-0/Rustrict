# Rustrict Phases 18.5–19.0 — Batched Release-Readiness Implementation Report

**Document Version:** 1.0.0  
**Date:** 2026-10-27  
**Implementation Baseline Commit:** `10dd09706d2796ebc62b34354719485a4edb92eb`  
**Previous Code Baseline:** `9106be33ceb4486e6fe2a272ea2773c71f0177ba` (Phase 18.4 Code)  
**Previous Documentation Baseline:** `ce3b57087f46fe7d7149052a05634e5e8bb744a6` (Phase 18.4 Docs)  
**Platform:** Native Windows 11 MSVC (`x86_64-pc-windows-msvc`), `rustc 1.97.1` (stable), `rustc 1.88.0` (MSRV)  
**Verification Outcome:** Complete Release Readiness — 315/315 Tests Passing (Stable & MSRV)

---

## 1. Executive Program Summary

The Batched Release-Readiness Program executed Phases 18.5 through 19.0 in a consolidated, single-session workflow to bring Rustrict to an independently verifiable, defensible release state:

1. **Batch 1 (Phase 18.5) — Secure Active-Target Admission Layer:**
   - Centralized all network target validation in `src/core/admission.rs` via `TargetAdmissionValidator`.
   - Immutable Controller and Gateway exclusions: controller IP/MAC and gateway IP/MAC are hard exclusions that cannot be targeted under any mode or configuration.
   - Concrete boundary enforcement: even when `strict_mode == false`, active local destructive operations (`block`, `limit`, `simulate`) strictly require an explicit authorized CIDR or interface subnet boundary and containment within it, preventing out-of-boundary / Internet destination targeting.
   - Preserves RFC 3021 `/31` point-to-point links and `/32` single-host endpoints while strictly rejecting `/0` to `/30` subnet network IDs and directed broadcast addresses.
   - Treated loaded persistent scope from `%ProgramData%\Rustrict\rustrict_state.json` as untrusted input: implemented `ScopeManager::sanitize()` to filter out malformed, loopback, multicast, broadcast, and invalid CIDRs, with automatic fallback to the local interface subnet boundary.

2. **Batch 2 (Phase 18.6) — Atomic Enforcement & Rollback Transactions:**
   - Resolved the partial-success and error-discard defect in `src/cli/prompt.rs`.
   - Before activating any target, prerequisites are validated upfront (Npcap injection readiness via `spoofer.has_sender()`, scoped forwarding enablement and verification via `ensure_scoped_forwarding_enabled`).
   - Transactional multi-target activation: iterates through validated targets. If target $k$ fails activation in `spoofer.add()`, all previously activated targets $1..k-1$ in the batch are immediately and atomically rolled back (`spoofer.remove()`, `limiter.unlimit()`).
   - In-memory `self.hosts` status is NEVER modified to `Blocked` or `Limited`, and `persistent_state` is NEVER modified or written to disk unless the entire transaction succeeds.
   - Teardown and rollback operations are verified to be idempotent.

3. **Batch 3 (Phase 18.7) — Startup, Shutdown, and Read-Only Router-Lab Mode:**
   - Introduced dedicated read-only router-lab mode via `--router-lab` CLI flag and `RustrictCli::new_router_lab()`.
   - In router-lab mode, zero Layer 2 packet injection sender is initialized (`ArpSpoofer::new_inactive`), sniffer is inactive (`PassiveIdentitySniffer::new_inactive`), and OS forwarding is untouched.
   - Persisted blocked devices from previous sessions are loaded into in-memory host inventory with `HostStatus::PersistedInactive(dir)` and enforcement is NOT activated.
   - Local destructive commands (`block`, `limit`, `simulate`) fail closed with clear error messages.
   - Read-only router administrative commands (`router providers`, `router status`, `router inventory`, `router devices`, `router preview`, `router export-evidence`, `router validate-evidence`) remain fully functional without requiring Npcap drivers or admin privilege bypasses.
   - Shutdown enforces bounded cleanup retries (`cleanup_forwarding_with_retries(3)`) and verifies OS postconditions.

4. **Batch 4 (Phase 18.8) — Router Provider Contracts & Operational Safety:**
   - Verified that all router providers (OpenWrt HTTP/SSH, MikroTik REST, AVM TR-064, UniFi REST) enforce bounded timeouts and zero automatic retries on mutating operations (`max_attempts == 1`).
   - Ensured credential redaction across diagnostic evidence bundles (`RouterEvidenceBundle`) and sanitized endpoint display.
   - Blocked concurrent or follow-up mutations whenever prior operations entered ambiguous or uncertain states.

5. **Batch 5 (Phase 18.9) — NIC Telemetry & Subprocess Diagnostics Verification:**
   - Verified bounded subprocess reaping and timeout enforcement in `WindowsPowershellNicProvider` and `run_powershell_bounded`.
   - Confirmed zero false-normals: telemetry missing RX/TX discard or error counters or exhibiting counter decreases is classified as `Unavailable` or `Degraded`, never `Normal`.

6. **Batch 6 (Phase 19.0) — Release Gate Audit & Verification:**
   - Reconciled commit hashes across all audit documentation, correcting the typographical SHA recorded in Phase 18.4 documentation (`9106be3999...` -> `9106be33ceb4486e6fe2a272ea2773c71f0177ba`).
   - Authored end-to-end regression test suite in `tests/test_batched_readiness.rs`.
   - Verified clean zero-warning builds under `cargo fmt --check`, `cargo check --all-targets`, `cargo clippy --all-targets -- -D warnings`, and full test execution under both stable Rust and MSRV Rust 1.88.0.

---

## 2. Architecture & Subsystem Changes

### 2.1 Centralized Target Admission (`src/core/admission.rs`)
- Implemented `TargetAdmissionValidator<'a>`:
  - Takes controller IP/MAC, gateway IP/MAC, and a reference to `ScopeManager`.
  - Distinguishes `AdmissionOperation::LocalEnforcement` from `AdmissionOperation::RouterPolicy`.
  - For `LocalEnforcement`: requires at least one authorized CIDR and strict containment within it.
  - Re-exports cleanly in `src/core/mod.rs` alongside `ScopeManager` and `RestorationNetworkParams`.

### 2.2 Untrusted Scope Sanitization (`src/core/scope.rs`)
- Added `ScopeManager::sanitize()`:
  - Purges CIDRs with `prefix == 0` or `prefix > 32`.
  - Filters out unspecified (`0.0.0.0`), loopback (`127.0.0.0/8`), broadcast (`255.255.255.255`), and multicast (`224.0.0.0/4`) network definitions.
  - Cleans invalid entries in `excluded_ips` and `excluded_macs`.

### 2.3 Transactional Enforcement in Prompt (`src/cli/prompt.rs`)
- Refactored `handle_limit`, `handle_block`, `handle_simulate`:
  - Check router-lab mode guard (`self.is_router_lab`).
  - Check injection readiness (`self.spoofer.has_sender()`).
  - Validate all targets using `self.admission_validator()`.
  - Execute activation transaction: record activated targets in a rollback buffer; if any target activation returns `Err`, loop through rollback buffer and revert spoofer/limiter entries, leaving `self.hosts` and `self.persistent_state` untouched.

### 2.4 Read-Only Router-Lab Entry Point (`src/main.rs`)
- Added `--router-lab` command line flag.
- When `--router-lab` is passed, skips Npcap/WinDivert driver warnings and constructs `RustrictCli::new_router_lab(iface)`.
