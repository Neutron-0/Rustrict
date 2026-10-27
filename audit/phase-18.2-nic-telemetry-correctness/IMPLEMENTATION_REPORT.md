# Phase 18.2 Implementation Report — NIC Telemetry Correctness & Bounded Process Reaping

## Executive Summary

Phase 18.2 closes critical correctness and reliability gaps in Rustrict's read-only NIC health telemetry subsystem (`src/monitor/nic.rs`):

1. **Elimination of False "Normal" Health Classifications:**
   - Previous versions evaluated missing, malformed, or decreasing packet error/discard counters to zero deltas, allowing adapters with incomplete driver telemetry to be classified as `Normal`.
   - Phase 18.2 decouples throughput telemetry validity (`throughput_valid`) from packet error/discard telemetry validity (`error_telemetry_valid`).
   - Counter deltas are modeled as `Option<u64>`. When counter measurements are missing, malformed, unsupported, or decreasing (reset), the delta is `None`.
   - A `Normal` classification is strictly possible **only** when all error and discard counter measurements are verified valid (`Some(0)` deltas) and link utilization thresholds are not crossed.
   - If throughput counters are valid but error/discard counters are missing, throughput rates are preserved, but health classification is explicitly designated as `Degraded` with a diagnostic explanation that hardware error telemetry is missing.

2. **Genuine Subprocess Termination and Reaping on Timeout:**
   - Previous PowerShell execution relied on an unkillable worker thread and `mpsc::channel::recv_timeout()`, which returned to the caller on timeout while leaving the PowerShell subprocess running indefinitely in the OS process table. Additionally, unconsumed output in pipe buffers could deadlock child processes.
   - Implemented `run_command_bounded_with_pid` using `std::process::Command` with piped `stdout` and `stderr`.
   - Two background threads concurrently drain `stdout` and `stderr` to memory buffers, preventing OS pipe buffer deadlocks.
   - The main thread polls `child.try_wait()` with sleep backoff until the deadline.
   - On timeout, the child process is forcefully killed (`child.kill()`) and reaped (`child.wait()`), and reader threads are joined, ensuring zero abandoned or zombie processes.
   - Verified on native Windows by testing both successful commands and deliberately hung child processes (`Start-Sleep`), validating process termination and process exit status (`GetExitCodeProcess != 259`).

3. **Precise Inter-Snapshot Sampling Duration:**
   - Sampling timing now records `t_start = Instant::now()` immediately *after* the initial snapshot (snapshot 0) is retrieved from the provider.
   - Wall-clock duration `actual_elapsed = t_start.elapsed()` is recorded immediately *after* snapshot 1 completes.
   - This eliminates process spawn latency of snapshot 0 from skewing the inter-snapshot rate calculation.

4. **100% Hermetic Verification & Zero Probing:**
   - Automated tests never transmit ARP probes or interact with live network infrastructure.
   - The automated test suite grew from 276 to **282 tests across 27 test binaries** (100% pass rate on both Stable Rust 1.97.1 and MSRV Rust 1.88.0 on Windows MSVC).

---

## Subsystem Architecture & Changes

### 1. Counter Delta Computation (`compute_counter_delta`)

```rust
enum CounterDeltaResult {
    Valid(u64),
    Decreased { before: u64, after: u64 },
    Missing,
}
```

- When `s0` or `s1` is `None`, returns `CounterDeltaResult::Missing`.
- When `s1 < s0`, detects monotonic counter reset and returns `CounterDeltaResult::Decreased`.
- When `s1 >= s0`, returns `CounterDeltaResult::Valid(s1 - s0)`.

### 2. Dual-Validity Telemetry Model (`NicHealthReport`)

| Field | Type | Description |
| :--- | :--- | :--- |
| `throughput_valid` | `bool` | True if Rx and Tx byte counter deltas are valid (`Some(u64)`). |
| `error_telemetry_valid` | `bool` | True if Rx/Tx errors and discards are all present and valid (`Some(u64)`). |
| `telemetry_valid` | `bool` | Composite validity: true only when both throughput and error telemetry are complete. |
| `counter_reset_detected` | `bool` | True if any counter (byte or packet) decreased between snapshot 0 and snapshot 1. |
| `rx_errors_delta` | `Option<u64>` | Rx errors observed; `None` if missing, malformed, or counter reset. |
| `tx_errors_delta` | `Option<u64>` | Tx errors observed; `None` if missing, malformed, or counter reset. |
| `rx_discards_delta`| `Option<u64>` | Rx discards observed; `None` if missing, malformed, or counter reset. |
| `tx_discards_delta`| `Option<u64>` | Tx discards observed; `None` if missing, malformed, or counter reset. |

### 3. Classification Decision Matrix (`evaluate_health_classification`)

| Status / Speed | Utilization | Error/Discard Telemetry | Counter Decreases | Health Classification |
| :---: | :---: | :---: | :---: | :---: |
| Not `"Up"` or 0 bps | Any | Any | Any | `Unavailable` |
| Up / Valid bps | Any | Active errors/discards > 0 | None | `Degraded` |
| Up / Valid bps | Any | Any | Any counter reset | `Degraded` |
| Up / Valid bps | $\ge 90\%$ | Incomplete (`None`) | None | `Saturated` (with note: incomplete telemetry) |
| Up / Valid bps | $70\% - 89.9\%$ | Incomplete (`None`) | None | `Elevated` (with note: incomplete telemetry) |
| Up / Valid bps | $< 70\%$ | Incomplete (`None`) | None | **`Degraded`** (never `Normal`) |
| Up / Valid bps | $\ge 90\%$ | Complete (`Some(0)`) | None | `Saturated` |
| Up / Valid bps | $70\% - 89.9\%$ | Complete (`Some(0)`) | None | `Elevated` |
| Up / Valid bps | $< 70\%$ | Complete (`Some(0)`) | None | **`Normal`** |

---

## Verification & Test Counts

| Test Target | Baseline (Phase 18.1) | Phase 18.2 | Delta | Details |
| :--- | :---: | :---: | :---: | :--- |
| `src/lib.rs` (unittests) | 17 | 23 | +6 | +1 timeout & child process reaping<br>+1 successful bounded command<br>+1 complete normal health report<br>+1 inter-snapshot timestamp timing<br>+1 missing Rx errors -> Degraded<br>+1 missing Tx discards -> Degraded<br>+1 error counter decrease -> Reset/Degraded |
| `tests/test_safe_networking.rs` | 8 | 8 | 0 | Updated signature & validated incomplete telemetry -> Degraded |
| All other 25 integration binaries | 251 | 251 | 0 | All passed without modification |
| **Total Test Suite** | **276** | **282** | **+6** | **100% Passing (Stable & MSRV 1.88.0)** |
