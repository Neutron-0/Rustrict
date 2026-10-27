# Phase 18.1 Commit Manifest

## Planned Commits

1. **`fix(monitor): correct NIC telemetry parsing, counter decrease invalidation, and disambiguation`**
   - Updates `src/monitor/nic.rs`:
     - Explicit validity signals with `Option<u64>` on `NicRawStats` and `NicHealthReport`.
     - Detects monotonic counter resets and wraparounds; marks telemetry invalidated with `Degraded` classification.
     - Wall-clock elapsed duration computation via `Instant::now()` with validation.
     - Bounded PowerShell execution with subprocess timeouts.
     - Ambiguous adapter filter resolution error reporting.
     - Freestanding `run_nic_cli` handler.
     - Unit tests covering missing statistics, ambiguous matching, counter resets, and zero durations.

2. **`feat(cli): add standalone NIC diagnostics dispatch before network init`**
   - Updates `src/main.rs`:
     - Dispatches `nic` and `adapter` commands before environment checks, `get_default_interface()`, or kernel `SendARP`.
     - Read-only execution requiring no admin privileges or WinDivert initialization.
   - Updates `src/cli/prompt.rs`:
     - Delegates interactive `nic` command to `run_nic_cli`.

3. **`fix(platform): enforce fail-closed scoped forwarding and isolate test state`**
   - Updates `src/platform/windows.rs`:
     - Disallows unscoped global IP forwarding (`enable_ip_forwarding()` marked deprecated and returns error).
     - Introduces `ForwardingManager` encapsulating tracked forwarding state for thread isolation in concurrent tests.
   - Updates `src/cli/prompt.rs`:
     - Pre-validates scope and exclusions before checking forwarding.
     - Aborts `limit`, `block`, and `simulate` fail-closed if interface forwarding cannot be enabled, preventing unauthorized state changes or unrouted traffic blackholes.
   - Updates `tests/test_safe_networking.rs`:
     - Adds `test_unscoped_forwarding_is_disallowed`.
     - Adds `test_standalone_nic_dispatch_runs_hermetic_without_network`.
     - Updates existing tests for `ForwardingManager` isolation and `Option<u64>` counters.

4. **`docs(audit): record Phase 18.1 independent verification and 276-test baseline`**
   - Updates `README.md` with honest 276-test breakdown across 27 binaries and standalone CLI documentation.
   - Adds `audit/phase-18.1-verification-and-correctness/` reports.
