# Rustrict Phase 19.1–19.3 — Implementation Report: Router-Lab Isolation, Native Windows Smoke Test, and Stage 1 Readiness

**Phase:** 19.1–19.3  
**Date:** 2026-10-27  
**Repository:** `D:\Vault\Rustrict`  
**Platform:** Native Windows 11 (MSVC x86_64), Rust Stable (1.97.1) / Rust MSRV (1.88.0)  
**Implementation Commit:** `326516b4894e091635aac6600daa99180c5e67c2`  
**Prior Implementation Baseline:** `10dd09706d2796ebc62b34354719485a4edb92eb`  
**Prior Documentation Baseline:** `b39578b77ee0aee90d56eeebec5048ce4c653ff9`  

---

## 1. Executive Summary

Phase 19.1–19.3 completes the operational isolation and safety containment program for Rustrict's physical router testing workflow. In previous iterations (Phases 18.5–18.7), `--router-lab` was introduced to disable selected local enforcement commands. However, comprehensive command-surface tracing revealed that secondary commands (`scan`, `ports`, `audit`, `add`, `scope`, `free`, `export`), router policy mutations (`router pause`, `router adjust`, `router resume`, `router refresh`), and in-memory mock connections could still be triggered or bypassed through direct handler invocations or flags. Furthermore, `src/main.rs` enforced Windows Administrator checks before inspecting the `--router-lab` flag, preventing least-privilege non-root execution.

This release establishes:
1. **Strict Default-Deny Command Policy**: An interactive dispatcher allowlist and defense-in-depth safety checks at every handler boundary. Destructive commands, local packet injection, port scanning, active ARP probes, router policy mutations, and mock connections are strictly rejected.
2. **Standard-User Execution**: Unprivileged execution is now supported in `--router-lab` mode. Administrator privileges are no longer demanded because raw packet injection drivers (Npcap), kernel filtering (WinDivert), and Windows OS forwarding setters are never initialized or touched.
3. **Robust EOF & Shutdown Semantics**: Resolved an interactive REPL loop bug where EOF on `stdin.read_line()` returned 0 bytes and caused an infinite loop; EOF now triggers clean shutdown and immediate process termination.
4. **Source-Level Side-Effect Instrumentation**: Added atomic counters across `RawL2Sender` (`raw_frame_send_count`), `ArpSpoofer` (`target_add_count`), `TrafficLimiter` (`limiter_activation_count`), and `ForwardingManager` (`forwarding_mutation_count`) proving mathematically that zero side effects occur in the read-only test path.
5. **Fresh Native Windows MSVC Runtime Smoke Test**: Verified `rustrict.exe nic list` and `nic health Wi-Fi` against live Windows network interfaces, capturing identical before-and-after OS forwarding and adapter states with `Compare-Object` (zero differences).
6. **Reconciled Stage 1 Operator Packet**: Replaced the hazardous instruction to run `router pause` cancellation on real hardware; Stage 1 runbook now strictly specifies read-only inquiries (`preview`, `status`, `capabilities`, `devices`, `diagnostics`, `export-evidence`, `validate-evidence`, `disconnect`).

---

## 2. Command Surface Audit & Categorization

A full trace of every command reachable in Rustrict CLI was conducted:

| Command | Category | Effects in Ordinary Mode | Effects in `--router-lab` Mode | Allowlist Status |
| :--- | :--- | :--- | :--- | :--- |
| `help`, `?` | Display | Displays full command list | Displays strictly read-only command list | **ALLOWED** |
| `clear`, `cls` | Display | Clears console screen | Clears console screen | **ALLOWED** |
| `hosts` | Inventory Display | Merges passive sniffer + renders host table | Renders inactive host inventory (sniffer inactive) | **ALLOWED** |
| `nic list`, `nic health`, `nic stats` | Query | Standalone read-only adapter queries | Read-only adapter queries | **ALLOWED** |
| `router providers` | Query | Lists registered provider descriptors | Lists registered provider descriptors | **ALLOWED** |
| `router status` | Query | Queries verified router identity & status | Queries verified router identity & status | **ALLOWED** |
| `router capabilities` | Query | Inspects router capabilities & evidence level | Inspects router capabilities & evidence level | **ALLOWED** |
| `router devices` | Query | Queries router client/station tables | Queries router client/station tables (read-only) | **ALLOWED** |
| `router diagnostics` | Query | Comprehensive read-only diagnostic checks | Comprehensive read-only diagnostic checks | **ALLOWED** |
| `router preview` | Compute | Computes dry-run preflight inspection | Computes dry-run preflight inspection (0 packets) | **ALLOWED** |
| `router inventory` | Display | Displays normalized inventory | Displays normalized inventory | **ALLOWED** |
| `router policies`, `router policy` | Display | Displays active/historical policy tables | Displays active/historical policy tables | **ALLOWED** |
| `router history`, `router records` | Display | Displays policy execution audit records | Displays policy execution audit records | **ALLOWED** |
| `router export-evidence` | File Write | Generates sanitized JSON evidence bundle | Generates sanitized JSON evidence bundle (0 mutation) | **ALLOWED** |
| `router validate-evidence` | File Read | Offline schema & secret validation | Offline schema & secret validation | **ALLOWED** |
| `router connect <ssh\|mikrotik\|...>` | Network Auth | Authenticates session with real router | Authenticates session with real router | **ALLOWED** |
| `router disconnect` | Network Disconnect | Disconnects provider without ARP fallback | Disconnects provider without ARP fallback | **ALLOWED** |
| `exit`, `quit` | Shutdown | Cleans up drivers and terminates process | Clean shutdown and process termination | **ALLOWED** |
| `router connect mock` | Prohibited | Connects in-memory mock provider | Blocked: cannot misrepresent simulated as physical | **DENIED** |
| `router pause` | Router Mutation | Commits firewall transit drop rules | Blocked: policy enforcement prohibited in lab mode | **DENIED** |
| `router resume` | Router Mutation | Revokes firewall drop rules | Blocked: policy revocation prohibited in lab mode | **DENIED** |
| `router adjust` | Router Mutation | Modifies expiration watchdog timers | Blocked: policy adjustment prohibited in lab mode | **DENIED** |
| `router refresh` | Store Mutation | Reconciles live rules and mutates disk store | Blocked: policy store mutation prohibited in lab | **DENIED** |
| `scan` | Active Probe | Sends broadcast/unicast ARP probes to subnet | Blocked: active network scanning disabled | **DENIED** |
| `ports` | Active Probe | Sends TCP SYN / connect probes across ports | Blocked: port scanning disabled | **DENIED** |
| `audit` | Active Probe | Connects to SMB/TLS ports for vulnerability checks | Blocked: active security audit disabled | **DENIED** |
| `add` | Local Mutation | Manually adds host to table; triggers ARP | Blocked: manual host addition disabled | **DENIED** |
| `scope` | Local Mutation | Modifies authorized CIDRs / exclusions on disk | Blocked: scope mutations disabled | **DENIED** |
| `free` | Local Mutation | Removes targets; transmits restorative ARP frames | Blocked: target removal & restorative ARP disabled | **DENIED** |
| `block` | Local Enforcement | Activates ARP poisoning & WinDivert drop rules | Blocked: local network enforcement disabled | **DENIED** |
| `limit` | Local Enforcement | Activates WinDivert token bucket shaping | Blocked: local network enforcement disabled | **DENIED** |
| `simulate` | Local Enforcement | Activates WinDivert packet loss/delay injection | Blocked: network simulation disabled | **DENIED** |
| `export` (top-level) | File Write | Writes assessment markdown/JSON/SARIF | Blocked: use `router export-evidence` instead | **DENIED** |

---

## 3. Subsystem Modifications

### 3.1 `src/cli/prompt.rs`
- Implemented `pub fn is_command_allowed_in_router_lab(&self, args: &[&str]) -> Result<(), String>` enforcing default-deny allowlist.
- Implemented `pub fn dispatch_command(&mut self, input: &str) -> bool` handling interactive REPL execution with router-lab enforcement.
- Fixed EOF handling in `run_interactive()`: detects `read_line` returning 0 bytes, invokes `self.shutdown()`, and breaks immediately.
- Added router-lab safety checks at the handler boundaries:
  - `handle_scan`, `handle_ports`, `handle_audit`, `handle_add`, `handle_scope`, `handle_free`, `handle_block`, `handle_limit`, `handle_simulate`, `handle_export`.
  - In `handle_router`: `pause`, `resume`, `adjust`, `refresh`, and `connect mock` fail closed.
  - `--yes` flag cannot bypass router-lab rejection.
- Tailored `print_help()` and `handle_router` help screens to display only permitted read-only commands and highlight prohibited verbs.
- Exposed `scope(&self)` and `spoofer(&self)` getters.

### 3.2 `src/main.rs`
- Decoupled privilege checks: `if !is_router_lab && !env_status.is_admin` allows standard users to run `--router-lab`.
- Bypassed Npcap and WinDivert availability warnings when in `--router-lab` mode.
- Omitted `platform::cleanup_forwarding()` at normal shutdown when running in `--router-lab` mode (zero forwarding mutations).

### 3.3 Source-Level Instrumentation Counters
- `src/spoofer/raw_l2.rs`: `RAW_FRAME_SEND_COUNT` atomic counter increments in `send_frame()`.
- `src/spoofer/engine.rs`: `SPOOFER_TARGET_ADD_COUNT` atomic counter increments in `ArpSpoofer::add()`. Added `target_count(&self)`.
- `src/limiter/divert.rs`: `LIMITER_ACTIVATION_COUNT` atomic counter increments in `limit()`, `block()`, and `set_fault()`.
- `src/platform/windows.rs`: `FORWARDING_MUTATION_COUNT` atomic counter increments in `set_interface_forwarding_with()`.

### 3.4 Re-exports & Test Harness
- `src/spoofer/mod.rs`: Re-exported `reset_target_add_count`, `target_add_count`.
- `src/limiter/mod.rs`: Re-exported `limiter_activation_count`, `reset_limiter_activation_count`.
- `tests/test_router_lab_isolation.rs`: 16 comprehensive integration tests covering all isolation and safety requirements.

---

## 4. Verification Results Summary

- **Local Rust Stable (1.97.1)**: `cargo test --all-targets` $\rightarrow$ **331 tests passed** (0 failed, 0 ignored) across 29 test binaries.
- **Local Rust MSRV (1.88.0)**: `cargo +1.88.0 test --all-targets` $\rightarrow$ **331 tests passed** (0 failed, 0 ignored) across 29 test binaries.
- **Static Analysis & Linting**: `cargo clippy --all-targets -- -D warnings` $\rightarrow$ Clean (0 warnings).
- **Code Formatting**: `cargo fmt --check` $\rightarrow$ Clean (0 diffs).
- **Native Release Build**: `cargo +1.88.0 build --release` $\rightarrow$ Succeeded in 51.78s, binary generated at `target\release\rustrict.exe` (3,015,168 bytes).
- **Native Windows NIC Smoke Test**:
  - `rustrict.exe nic list` $\rightarrow$ Exit 0, 4 adapters detected.
  - `rustrict.exe nic health Wi-Fi` $\rightarrow$ Exit 0, valid throughput (380.35 Kbps Rx / 1.38 Mbps Tx), complete error/discard counters (0), [HEALTH: NORMAL].
  - Pre/Post OS Forwarding & Adapter comparison: `Compare-Object` returned **zero differences**.
