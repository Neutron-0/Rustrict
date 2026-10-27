# Rustrict Phase 17 — Technical Implementation Report: Protocol Integration Harness & Mutation Retry Safety

**Document Version:** 1.2.0
**Date:** 2026-10-27 (Phase 17.1 Restored & Reconciled Baseline)
**Engineering Phase:** Phase 17 & Phase 17.1
**Git Baseline:** `7bd9428`
**Target Codebase Revision:** Phase 17.1 (`ac1c4e9`)

---

## 1. Executive Summary

Phase 17 transitioned Rustrict from unit-level synthetic mocks and synthetic transports to a **deterministic loopback protocol simulation harness** exercising actual production adapters over real TCP loopback sockets (`127.0.0.1:0`) using native Windows networking, curl child processes, and OpenSSH pipelines.

Phase 17.1 eliminated an operational safety hazard introduced during initial transport hardening: blanket curl retries (`--retry 2`, `--retry-all-errors`, `--retry-connrefused`). Automatically retrying router mutation requests over an unreliable network can cause duplicate firewall rules, repeated state toggles, and corrupted state machines.

Key accomplishments across Phase 17 & 17.1:
1. **Loopback Protocol Simulation Harness** (`tests/support/router_emulator/`): Created an in-process, deterministic TCP server simulating OpenWrt (`ubus`), AVM FRITZ!Box (TR-064 SOAP), Ubiquiti UniFi (Network REST API), and MikroTik RouterOS (REST API). Hardened TCP socket teardown (`stream.shutdown(Shutdown::Write)` + bounded drain for peer FIN) to avoid Winsock 10053/10054 connection aborts without needing blanket mutation retries.
2. **Operation-Aware Transport Retry Policy** (`src/gateway/admin/plan.rs`, `src/gateway/admin/curl_util.rs`):
   - Defined `OperationSemantics` (`ReadOnly`, `StateChanging`, `Unknown`).
   - Mutations (`StateChanging`) and `Unknown` operations are strictly capped at `max_attempts() == 1` (zero retries).
   - Read-only requests permit at most 2 attempts (`max_attempts() == 2`), executed as isolated child processes to ensure stdout buffers are never corrupted or duplicated across attempts.
   - Removed blanket `--retry` parameters from AVM TR-064, UniFi Network REST, and MikroTik REST adapters.
3. **Ambiguous Outcome Representation & Conflict Blocking** (`src/gateway/admin/plan.rs`, `src/gateway/admin/engine.rs`):
   - Added `AdminError::is_ambiguous_outcome()` identifying transport drops, EOFs, timeouts, or 5xx responses that occur after mutation requests have been transmitted to the router.
   - Mapped ambiguous errors to `PolicyLifecycleState::Unknown` and persisted unconfirmed active policy state.
   - Enforced conflict detection (`PolicyScope::conflicts_with`): follow-up mutations on targets overlapping with any active `Unknown` or `PartialFailure` policy are immediately blocked with a fail-closed error until reconciled.
4. **Deterministic Failure Injection Matrix & Tests** (`tests/test_protocol_integration.rs`):
   - Added regression scenarios: `MutateThenDrop`, `MutateThenPartialResponse`, `MutateThenTimeout`, `MutateThenServerError`, `ReadOnlyDrop`, `MultiTargetPartialWithRollbackFail`.
   - Verified that adapters perform exactly 1 mutation attempt and never blindly retry when a mutation response is dropped.
   - Expanded protocol integration test suite from 11 to 17 tests; verified 10 consecutive runs on stable toolchain and 5 consecutive runs on MSRV 1.88.0 with zero failures.
5. **Interactive Mutation Confirmation & Diagnostic Verification**: Preserved preflight prompts (`[yes/N]`), non-interactive `--yes` mode, and offline evidence bundle validator (`router validate-evidence`).

---

## 2. Architecture & Components

### 2.1 Operation Semantics & Retry Classification
In `src/gateway/admin/plan.rs` and `src/gateway/admin/curl_util.rs`:
```rust
pub enum OperationSemantics {
    ReadOnly,
    StateChanging,
    Unknown,
}
```
- Each adapter inspects HTTP verbs and endpoint paths before issuing curl commands:
  - **AVM**: SOAP action name starting with `Get` or `X_AVM-DE_Get` -> `ReadOnly`. SOAP actions `DisallowWANAccessByIP` or `AllowWANAccessByIP` -> `StateChanging`.
  - **UniFi**: HTTP `GET` -> `ReadOnly`. HTTP `POST`, `PUT`, `DELETE` -> `StateChanging`.
  - **MikroTik**: HTTP `GET` -> `ReadOnly`. HTTP `POST`, `PUT`, `PATCH`, `DELETE` -> `StateChanging`.
- In `execute_with_operation_retry`, mutations are dispatched with `max_attempts() == 1` (zero retries). If the child process exits with curl error 52 (empty reply), 56 (connection reset), or 28 (timeout), the loop terminates immediately and returns the underlying error.

### 2.2 Ambiguous Outcome Handling
- When a mutation fails due to a dropped socket or timeout, `AdminError::is_ambiguous_outcome()` returns `true`.
- The execution engine transitions the policy lifecycle state to `PolicyLifecycleState::Unknown` rather than assuming the rule failed to apply.
- An `ActivePolicyStatus` is persisted with state `Unknown`.
- `PolicyExecutionEngine::apply_policy` evaluates existing unresolved policies before checking duplicate rules on the router. Any new policy whose scope overlaps with an active `Unknown` or `PartialFailure` policy is rejected immediately:
  ```text
  Router policy state for target ... is uncertain (Unknown). Refusing follow-up mutation until verified.
  ```

### 2.3 Router Protocol Emulator Hardening
- Previously, `curl.exe` on Windows would occasionally receive Winsock error 10054 (Connection reset by peer) if the server socket closed before the client read all data or completed the TLS handshake.
- In `tests/support/router_emulator/mod.rs`, the emulator now:
  - Checks if client headers indicate `Expect: 100-continue` and sends `HTTP/1.1 100 Continue\r\n\r\n`.
  - Distinguishes empty-body HTTP Digest 401 challenge probes from actual mutating bodies.
  - Performs `stream.shutdown(Shutdown::Write)` and drains peer FIN before closing the socket.
- This ensures deterministic behavior across hundreds of test executions on Windows without needing blanket transport retries.

---

## 3. Verification & Compliance Evidence

- **Linting & Code Quality**: `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings` passed with 0 errors and 0 warnings.
- **Test Suite Results**:
  - Baseline (Phase 16): 204 passing tests.
  - Phase 17 Baseline: 257 passing tests.
  - Phase 17.1 Suite: **263 passing tests** across 26 test binaries (100% pass rate, 0 failures, 0 ignored).
  - Protocol Integration Binary (`tests/test_protocol_integration.rs`): 17 tests passed.
  - Stress Testing: 10 consecutive runs on stable toolchain (`rustc 1.97.1`) and 5 consecutive runs on MSRV (`rustc 1.88.0`) executed with zero failures.
- **MSRV Compatibility**: Compatible with Rust MSRV 1.88.0 and current stable 1.97.1.
- **Documentation Recovery Note**: Restores documentation files inadvertently truncated during the initial Phase 17.1 commit sequence.
