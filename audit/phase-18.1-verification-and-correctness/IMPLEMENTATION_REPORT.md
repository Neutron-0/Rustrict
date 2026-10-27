# Phase 18.1 Implementation Report — Verification & Correctness Gap Closure

## Executive Summary

Phase 18.1 was executed to independently verify the codebase, resolve test-count discrepancies between GitHub Actions CI logs and documentation claims, correct confirmed correctness gaps in NIC telemetry diagnostics, enforce fail-closed network forwarding, and establish standalone CLI diagnostic execution independent of normal networking/probing startup.

All work strictly adheres to the native Windows MSVC toolchain constraints and declared MSRV (Rust 1.88.0). Zero physical routers were contacted, zero real ARP packets were broadcast in automated suites, and no network degradation was introduced.

---

## 1. Ground Truth Baseline & Test Count Resolution

### Confirmed Historical Discrepancy
- **Claimed Baseline (Phase 18 Report):** 275 tests.
- **Actual CI Output (GitHub Actions Run `40473746619`):** 270 passed tests across 27 test targets.
- **Root Cause Analysis:**
  - `tests/test_provider_contracts.rs` contained **6** `#[test]` definitions (claimed 8 in Phase 18 documentation; overestimate: +2).
  - `tests/test_reliability.rs` contained **9** `#[test]` definitions (claimed 12 in Phase 18 documentation; overestimate: +3).
  - Sum of discrepancies: +2 + 3 = +5 tests.
  - Actual baseline before Phase 18.1 edits: `275 - 5 = 270` passed tests.

### Phase 18.1 Test Count Evolution
- **`src/lib.rs` (unittests):** 13 -> 17 tests (+4 new unit tests in `src/monitor/nic.rs`).
- **`tests/test_safe_networking.rs`:** 6 -> 8 tests (+2 new hermetic integration tests).
- **All other 25 targets:** Preserved intact (251 tests).
- **Phase 18.1 Verified Total:** **276 passed tests across 27 test binaries** (100% pass rate on both Stable Rust and Rust 1.88.0 MSRV).

---

## 2. Corrected NIC Telemetry Diagnostics (`src/monitor/nic.rs`)

1. **Explicit Validity Signals & Invalidation:**
   - Updated `NicRawStats` to utilize `Option<u64>` for all counter fields (`received_bytes`, `sent_bytes`, `received_discarded`, `received_errors`, `outbound_discarded`, `outbound_errors`).
   - If counter values in `Get-NetAdapterStatistics` CSV are empty, nonnumeric, or absent, they are parsed as `None` rather than silently substituted with zero.
   - If telemetry for an active adapter is missing or incomplete, `NicHealthReport` records `telemetry_valid = false` and classifies the adapter as `NicHealthClassification::Unavailable` rather than fabricating zero throughput and classifying as `Normal`.

2. **Monotonic Counter Reset & Decreasing Metric Handling:**
   - Monotonic counter decreases (`rx1 < rx0` or `tx1 < tx0`) are detected as driver reinitialization or 32-bit counter wraparound.
   - Marked explicitly with `counter_reset_detected = true`, `telemetry_valid = false`, and classified as `NicHealthClassification::Degraded` with an informative diagnostic message.
   - Deltas and throughput rates are reported as `None` rather than silently saturating to zero and reporting false healthy states.

3. **Wall-Clock Time Elapsed Rate Calculation:**
   - Sample duration is computed using actual wall-clock elapsed time measured via `Instant::now()` (`let actual_elapsed = t_start.elapsed()`), preventing rate skew caused by sleep scheduling delays or timer jitter.
   - Sample interval duration is strictly validated: non-zero and at least 5ms required; zero or negative durations return explicit errors.

4. **Bounded PowerShell Subprocess Execution:**
   - PowerShell queries (`Get-NetAdapter`, `Get-NetAdapterStatistics`) are executed via `run_powershell_bounded` using standard subprocess worker threads with a default 5-second timeout, preventing unbounded process hangs if WMI or RPC queries stall.

5. **Disambiguated Adapter Matching:**
   - Implemented `resolve_adapter` with strict precedence:
     1. Exact interface index match.
     2. Exact name match (case-sensitive).
     3. Case-insensitive exact name match (with error if ambiguous).
     4. Substring match on name or description: if multiple adapters match (e.g. "Realtek"), returns an explicit error listing all matching candidates and requiring the operator to supply an exact interface name or index.
     5. Default: First adapter with status `"Up"`.
     6. Returns clear error if no matching adapter exists.

6. **Separation of Measured Telemetry from Heuristics:**
   - `NicHealthReport` separates raw measured telemetry deltas and utilization from the heuristic classification.
   - `Normal` classification explicitly diagnosticates that operational thresholds were not crossed during the sample window and includes a disclaimer that heuristic sampling does not guarantee hardware health.

---

## 3. Standalone CLI Diagnostics (`src/main.rs`, `src/cli/prompt.rs`)

1. **Pre-flight Dispatch Seam:**
   - Added early argument interception in `src/main.rs`: if `args[1]` is `"nic"` or `"adapter"`, dispatches directly to `run_nic_cli`.
   - Bypasses `platform::check_environment()` (no mandatory Admin elevation check).
   - Bypasses `platform::get_default_interface()` and kernel `SendARP` calls.
   - Bypasses WinDivert driver checks and network state mutations.
   - Exits cleanly with code 0 on success or code 1 on error.

2. **Supported CLI Grammar:**
   - `rustrict.exe nic list`: Enumerates all physical and virtual network adapters, interface indices, link speeds, and statuses without sampling.
   - `rustrict.exe nic [health|status|stats] [name|index]`: Samples 2-second telemetry window for default active adapter or named/indexed adapter.
   - `rustrict.exe nic <name|index>`: Shorthand syntax.
   - `rustrict.exe nic help`: Usage guidelines.

---

## 4. Fail-Closed Forwarding Architecture (`src/platform/windows.rs`, `src/cli/prompt.rs`)

1. **Disallow Unscoped Global Forwarding:**
   - Deprecated `enable_ip_forwarding()` with `#[deprecated]`. Calling it returns an immediate error disallowing unscoped global forwarding mutations.
   - System IPv4 forwarding changes are strictly scoped per-interface alias via `ensure_scoped_forwarding_enabled(iface_name)`.

2. **Thread-Isolated ForwardingManager:**
   - Encapsulated forwarding state inside `ForwardingManager`, exposing isolated test seams so concurrent unit and integration tests do not race on shared static state.

3. **Pre-Validation and Fail-Closed Mutation:**
   - In `handle_limit`, `handle_block`, and `handle_simulate`:
     1. Target IDs and addresses are resolved first.
     2. Scope boundaries and explicit exclusions are validated *before* touching forwarding or device state. If no in-scope targets remain, the operation exits cleanly with zero mutations.
     3. Scoped forwarding is enabled fail-closed: if `ensure_scoped_forwarding_enabled` fails, the operation aborts immediately with a clear red error message. Zero targets are added to the spoofer, zero limits are applied to WinDivert, and zero host states or persistent records are modified.
