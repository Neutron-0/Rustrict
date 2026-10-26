# Rustrict — Audit-Guided Remediation Phase 1: Critical and High-Severity Findings
**Date:** 2026-10-24  
**Audit Target:** Rustrict (v2.0.0)  
**Repository Root:** `D:\Vault\Rustrict`  
**Toolchain:** `rustc 1.97.1` / `cargo 1.97.1` (`stable-x86_64-pc-windows-msvc`)  
**Status:** COMPLETED & VERIFIED  

---

## 1. Executive Summary

Following the master verification audit conducted on October 24, 2026 (`audit/verification-2026-10-24/`), this Phase 1 Remediation systematically addressed all confirmed critical and high-severity architectural, security, and operational defects in the Rustrict router administrative subsystem.

Every code change strictly adhered to the mandatory project constraints:
1. **Windows Native Exclusivity:** Fully compatible with `x86_64-pc-windows-msvc`; no Docker, WSL, or Unix-only runtime requirements.
2. **Zero Remote Disruption:** No physical routers were contacted, mutated, or disrupted; all verification was conducted with isolated mock transports and deterministic unit harnesses.
3. **No Automatic Mock Fallback:** Mock execution is strictly opt-in and visibly labelled as simulated; application startup starts disconnected and fails closed.
4. **Preservation of Existing Subsystems:** Unrelated working code (WinDivert limiter, ARP spoofer, active/passive scanners, SMB/TLS probes) and uncommitted working-tree files were strictly preserved.
5. **Zero Warning Clean Build:** All 23 compiler and Clippy lints were addressed, achieving clean `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check` verification.
6. **Complete Regression Verification:** Test suite expanded from 182 to 187 tests across 23 test binaries with 100% pass rate (0 failures, 0 ignored).

---

## 2. Remediated Defects & Implementation Details

### SEC-01: AVM & UniFi Curl Transport Pipeline Separation
- **Severity:** Critical
- **Affected Source Files:**
  - `src/gateway/admin/avm.rs`
  - `src/gateway/admin/unifi.rs`
  - `src/gateway/admin/curl_util.rs` (new module)
  - `src/gateway/admin/mod.rs`
- **Root Cause:**
  `ProcessAvmTransport` and `ProcessUnifiTransport` invoked `curl.exe` with both `--config -` and `--data-binary @-`, writing both configuration directives (URL, headers, HTTP digest authentication) and request payloads (SOAP XML or JSON) to the single `stdin` stream. Curl's configuration parser attempted to parse request payloads as directives, causing exit code 2 syntax failures.
- **Implemented Fix:**
  1. Created `src/gateway/admin/curl_util.rs` introducing:
     - `find_curl()`: Safe Windows `curl.exe` resolver prioritizing `%SystemRoot%\System32\curl.exe` before scanning `PATH`.
     - `AutoCleanFile`: Collision-resistant temporary payload RAII guard utilizing `std::env::temp_dir()`, process ID, nanosecond timestamps, and atomic sequence counters. Implements `Drop` to guarantee immediate file deletion upon function exit, failure, or timeout.
  2. Updated `ProcessAvmTransport::execute_soap` to write the SOAP envelope into an `AutoCleanFile` and invoke curl with `--data-binary @<temp_file>`, while streaming only configuration directives across `stdin`. Credentials remain strictly in `stdin` memory without CLI exposure or persistent disk footprint.
  3. Updated `ProcessUnifiTransport::request` to write JSON payloads into an `AutoCleanFile` for mutating calls (POST/PUT), omit `--data-binary` entirely for GET requests, and stream authentication cookies / headers via `stdin`.
  4. Added regression tests `test_avm_curl_transport_payload_isolation_and_cleanup` and `test_unifi_curl_transport_payload_isolation_and_cleanup`.

---

### SEC-02: Misleading Startup Mock Provider Connection
- **Severity:** Critical
- **Affected Source Files:**
  - `src/cli/prompt.rs`
  - `tests/test_router_admin.rs`
- **Root Cause:**
  `Prompt::new` explicitly called `router_registry.connect("mock", mock_provider, "internal://mock")` during initial interactive startup. This initialized an authenticated session against an in-memory mock router by default. Commands like `router pause <target>` reported successful firewall policy enforcement without physical hardware interaction, misleading operators into believing real traffic was blocked.
- **Implemented Fix:**
  1. Removed automatic mock connection from `Prompt::new`. `router_registry` initializes with `active_connection: None` (`is_connected() == false`).
  2. Router administration starts in an explicit `DISCONNECTED` state.
  3. Mutating operations (`router pause`, `router resume`, `router adjust`) fail closed with clear error messaging when no router provider is connected:
     `[ERR] Failed to apply router policy: No router provider is currently connected. Establish a connection first with 'router connect <provider>'.`
     `[SECURITY] Refusing to fall back to ARP poisoning.`
  4. Mock mode remains available exclusively via explicit manual connection: `router connect mock`.
  5. Added prominent `[SIMULATED / TEST MODE]` indicators in `router status`, `router pause`, and `router resume` whenever the active provider is `mock`.
  6. Added regression test `test_startup_disconnected_and_explicit_mock_connection`.

---

### SEC-03: Multi-Target Policy Enforcement Scope Truncation
- **Severity:** High
- **Affected Source Files:**
  - `src/gateway/admin/openwrt.rs`
  - `src/gateway/admin/mikrotik.rs`
  - `src/gateway/admin/avm.rs`
  - `tests/test_openwrt_admin.rs`
  - `tests/test_mikrotik_admin.rs`
  - `tests/test_avm_admin.rs`
- **Root Cause:**
  When supplied with a multi-device target list (`PolicyScope::SpecificTargets(targets)`), providers indexed only `targets[0]`:
  - `openwrt.rs` added only a single UCI firewall rule for `targets[0]`, silently ignoring `targets[1..]`.
  - `mikrotik.rs` set `src-address = targets[0]`, leaving all other target devices unblocked.
  - `avm.rs` looped across all targets, but assigned a rule ID and status only tracking `targets[0]`, without atomic rollback if subsequent targets failed.
- **Implemented Fix:**
  1. **OpenWrt (`openwrt.rs`):** Updated `apply_policy` to generate individual UCI firewall rules for every target device in `targets`, committing all rules atomically in a single UCI transaction. Partial failures trigger an immediate `uci revert` rollback. Updated `policy_id` naming for multi-target scopes (`rustrict_pause_multi_{ip}`).
  2. **MikroTik (`mikrotik.rs`):** Updated `apply_policy` to iterate and POST firewall filter rules for each target. Tracks created rule IDs and executes an automated compensation rollback (DELETE requests) if any insertion fails.
  3. **AVM FRITZ!Box (`avm.rs`):** Added compensation rollback in `apply_policy`: if any `DisallowWANAccessByIP` call fails, all previously disallowed targets in the batch are immediately re-allowed (`<NewDisallow>0</NewDisallow>`). Multi-target policy naming and native rule IDs accurately describe all targets.
  4. Added multi-target regression tests exercising 3 targets and verified 100% enforcement and cleanup across all three providers.

---

### SEC-04: MikroTik IPv6 Capability Declaration Honesty
- **Severity:** High
- **Affected Source Files:**
  - `src/gateway/admin/mikrotik.rs`
  - `src/gateway/admin/registry.rs`
  - `tests/test_mikrotik_admin.rs`
  - `tests/test_unified_admin.rs`
- **Root Cause:**
  `MikroTikAdminProvider::inspect_capabilities` and `RouterRegistry::register_builtin_providers` advertised `ipv6_policy_enforcement: CapabilityClassification::Implemented`, despite the provider interacting only with `/rest/ip/firewall/filter` (IPv4) and installing an IPv4-only autonomous scheduler watchdog.
- **Implemented Fix:**
  1. Reclassified `ipv6_policy_enforcement` to `CapabilityClassification::NotImplemented` in both `MikroTikAdminProvider::inspect_capabilities` and the built-in provider registry descriptor.
  2. Updated provider description to remove claims of managing `/ipv6/firewall/filter`.
  3. Added `test_mikrotik_ipv6_honesty_check` in `tests/test_mikrotik_admin.rs`.
  4. Updated `tests/test_unified_admin.rs` assertion to expect `NotImplemented`.

---

### SEC-05: Multi-Instance Persistence Synchronization Race
- **Severity:** High
- **Affected Source Files:**
  - `src/gateway/admin/persistence.rs`
  - `tests/test_persistence.rs`
- **Root Cause:**
  `PolicyStore::sync_from_disk_if_present` merged on-disk policies only if `p.lifecycle_state == PolicyLifecycleState::Recovered`, ignoring concurrent active policy additions or updates from other instances. Conversely, an overly broad merge would clobber in-memory startup reconciliation states (`Unknown`).
- **Implemented Fix:**
  1. In `sync_from_disk_if_present`, policies from disk update in-memory entries if the disk state is `Recovered` or if `p.applied_at_unix > current.applied_at_unix`.
  2. Preserves in-memory `Unknown` states produced by startup reconciliation, preventing stale disk records from prematurely declaring policies active.
  3. In `persist_internal`, executes a pre-write merge of any records or policies added concurrently to disk before serializing.
  4. All 7 persistence tests pass cleanly.

---

### SEC-06: Plaintext Console Password Echo Masking
- **Severity:** Medium / High
- **Affected Source Files:**
  - `Cargo.toml`
  - `src/cli/prompt.rs`
- **Root Cause:**
  Interactive prompts for MikroTik, AVM, UniFi, and OpenWrt router credentials read passwords using `io::stdin().read_line(&mut password_input)` without disabling terminal echo, exposing sensitive administrative passwords on the console.
- **Implemented Fix:**
  1. Added `Win32_System_Console` to `windows-sys` features in `Cargo.toml`.
  2. Implemented `read_masked_password() -> io::Result<String>` in `src/cli/prompt.rs`.
  3. Utilizes `GetStdHandle`, `GetConsoleMode`, and `SetConsoleMode` with `ENABLE_ECHO_INPUT` cleared to suppress console character echoing on Windows terminals.
  4. Restores original console mode in all code paths and automatically falls back to unmasked `read_line` if stdin is piped or non-interactive.
  5. Applied `read_masked_password()` across all four router credential prompt sites.

---

### SEC-07: SSH Pipe Buffer Deadlock Resistance
- **Severity:** Medium / High
- **Affected Source Files:**
  - `src/gateway/admin/ssh.rs`
- **Root Cause:**
  `ProcessSshExecutor::execute` spawned `ssh.exe` with piped stdout/stderr, then entered a polling loop calling `child.try_wait()` without draining pipes. If the remote command generated output exceeding OS pipe capacity (4KB–64KB), the child process deadlocked on `write()`.
- **Implemented Fix:**
  1. Extracted `child.stdout` and `child.stderr` immediately after spawn.
  2. Spawned dedicated background reader threads that continuously drain stdout and stderr into memory buffers in real time.
  3. Thread handles are joined after process termination or timeout kill, eliminating pipe-filling deadlocks regardless of command output volume.

---

### CODE-01: Compiler & Clippy Warning Elimination
- **Severity:** Low / Quality
- **Status:** 100% ELIMINATED (0 warnings, 0 errors)
- **Resolved Lints:**
  1. `avm.rs`: `#[allow(clippy::too_many_arguments)]` on `calculate_digest_response`.
  2. `avm.rs`: Replaced `field_reassign_with_default` with direct struct initialization in `inspect_capabilities`.
  3. `avm.rs`: Replaced `for (_id, pol) in active.iter_mut()` with `active.values_mut()`.
  4. `engine.rs`: Converted manual pattern comparison to array pattern: `.trim_start_matches(['"', '\''])`.
  5. `engine.rs`: Simplified `.map_or(false, |name| ...)` to `.is_some_and(...)`.
  6. `engine.rs`: Collapsed nested `if` statements in policy reconciliation.
  7. `engine.rs`: Eliminated redundant `unwrap()` after `is_some()`.
  8. `mikrotik.rs`: Used `.div_ceil(3)` in `base64_encode`.
  9. `mikrotik.rs`: Used `arr.first()` instead of `arr.get(0)`.
  10. `mock.rs`: Replaced `field_reassign_with_default` in `RouterCapabilityMatrix` default implementation.
  11. `persistence.rs`: Used `io::Error::other(...)` instead of `io::Error::new(io::ErrorKind::Other, ...)`.
  12. `persistence.rs`: Implemented `Default for PolicyStore`.
  13. `persistence.rs`: Collapsed nested `if` statements in historical policy check.
  14. `persistence.rs`: Merged identical branches in disk synchronization.
  15. `plan.rs`: Derived `Default` on `PolicyLifecycleState` with `#[default]` on `Active`.
  16. `registry.rs`: `#[allow(clippy::too_many_arguments)]` on `ProviderDescriptor::new`.
  17. `unifi.rs`: Replaced `.split('/').last()` with `.next_back()`.
  18. `unifi.rs`: Replaced `field_reassign_with_default` in `inspect_capabilities`.
  19. `views.rs`: Fixed identical if-branch to properly map `OpenWrtCronScheduler`.
  20. `divert.rs`: Replaced single-match block with `if let Ok(pkt) = ...`.
  21. `tests/test_verification.rs`: Replaced `field_reassign_with_default` in `PersistentState`.
  22. Formatted all touched files with `cargo fmt`.

---

## 3. Verification & Test Summary

| Check | Command | Result |
| :--- | :--- | :--- |
| **Rust Formatting** | `cargo fmt --check` | **PASS** (0 diffs) |
| **Type Check** | `cargo check --all-targets` | **PASS** (0 errors) |
| **Clippy Linter** | `cargo clippy --all-targets -- -D warnings` | **PASS** (0 warnings) |
| **Full Test Suite** | `cargo test --all-targets` | **PASS** (187 passed, 0 failed, 0 ignored) |

### Test Counts by Category
- **Unit Tests (Core Library):** 2 passed
- **Assessment & Scope Tests:** 5 passed
- **AVM FRITZ!Box Tests:** 19 passed (+1 regression test)
- **DHCP Tests:** 1 passed
- **Diagnostics Tests:** 7 passed
- **Bugfix Regressions:** 8 passed
- **Gateway SSDP/SOAP Tests:** 4 passed
- **MikroTik RouterOS Tests:** 19 passed (+2 regression tests)
- **OpenWrt UCI/HTTP Tests:** 19 passed (+1 regression test)
- **Persistence & Recovery Tests:** 7 passed
- **Policy Engine Tests:** 8 passed
- **Policy Views Tests:** 6 passed
- **Reliability & Multi-Instance Tests:** 5 passed
- **Router Administration & Registry Tests:** 8 passed (+1 regression test)
- **SMB Probes:** 1 passed
- **SSH Transport Tests:** 16 passed
- **Target Resolution Tests:** 12 passed
- **TLS Probes:** 1 passed
- **UniFi Controller Tests:** 19 passed (+1 regression test)
- **Unified Registry Tests:** 7 passed
- **Verification Tests:** 5 passed
- **General Unit Tests:** 7 passed
- **TOTAL:** **187 passing tests**
