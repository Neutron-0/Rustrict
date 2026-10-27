# Rustrict Phase 19.1–19.3 — Test Evidence & Native Windows Verification

**Date:** 2026-10-27  
**Platform:** Native Windows 11 Home 64-bit (Build 26100), MSVC Rust toolchain  
**Tested Revision:** `326516b4894e091635aac6600daa99180c5e67c2`  

---

## 1. Native Windows MSVC Smoke Test Execution

### 1.1 Before-State Capture: IPv4 Forwarding and Adapters
```powershell
$beforeForwarding = Get-NetIPInterface -AddressFamily IPv4 | Sort-Object InterfaceAlias | Select-Object InterfaceAlias, Forwarding
$beforeAdapters = Get-NetAdapter | Sort-Object Name | Select-Object Name, Status, InterfaceDescription
$beforeForwarding | Format-Table -AutoSize
$beforeAdapters | Format-Table -AutoSize
```

**Before-State Output:**
```text
InterfaceAlias               Forwarding
--------------               ----------
Bluetooth Network Connection    Enabled
Ethernet                       Disabled
Local Area Connection          Disabled
Local Area Connection* 1       Disabled
Local Area Connection* 2       Disabled
Loopback Pseudo-Interface 1    Disabled
Wi-Fi                          Disabled

Name                         Status       InterfaceDescription                                
----                         ------       --------------------                                
Bluetooth Network Connection Disconnected Bluetooth Device (Personal Area Network)            
Ethernet                     Disconnected Realtek Gaming GbE Family Controller                
Local Area Connection        Disconnected TAP-ProtonVPN Windows Adapter V9                    
Wi-Fi                        Up           MediaTek Wi-Fi 6E MT7922 (RZ616) 160MHz PCIe Adapter
```

---

### 1.2 Standalone Read-Only NIC Adapter Listing
```powershell
.\target\release\rustrict.exe nic list
```

**Output:**
```text
Detected Network Adapters:
  [19] Bluetooth Network Connection Status: Disconnected Link: 3 Mbps     (Bluetooth Device (Personal Area Network))
  [17] Wi-Fi                    Status: Up           Link: 286.8 Mbps (MediaTek Wi-Fi 6E MT7922 (RZ616) 160MHz PCIe Adapter)
  [16] Local Area Connection    Status: Disconnected Link: 1 Gbps     (TAP-ProtonVPN Windows Adapter V9)
  [10] Ethernet                 Status: Disconnected Link: 0 bps      (Realtek Gaming GbE Family Controller)
```
- Exit Code: `0`

---

### 1.3 Standalone Read-Only NIC Health Diagnostic
```powershell
.\target\release\rustrict.exe nic health Wi-Fi
```

**Output:**
```text
Sampling network adapter telemetry for 'Wi-Fi' (2-second interval)...

=== Physical Network Adapter Health Diagnostic ===
Adapter:      Wi-Fi (Index: 17)
Description:  MediaTek Wi-Fi 6E MT7922 (RZ616) 160MHz PCIe Adapter
Status:       Up | Declared Link Speed: 286.8 Mbps
Sample Window: 2.00s requested interval, 5.006s measured snapshot interval

[Measured Telemetry]
  Rx Rate:     380.35 Kbps (    238009 bytes)  |  Rx Utilization:   0.1%
  Tx Rate:       1.38 Mbps (    864960 bytes)  |  Tx Utilization:   0.5%
  Rx Discard:            0  |  Rx Packet Errors:      0
  Tx Discard:            0  |  Tx Packet Errors:      0

[Heuristic Health Classification]
  Classification: [HEALTH: NORMAL]
  Diagnosis:      Nominal telemetry: thresholds not crossed (0.5% peak utilization, 0 packet errors/discards). Note: Heuristic check does not guarantee hardware health.
```
- Exit Code: `0`
- Selected Adapter: `Wi-Fi` (Interface Index 17)
- Link Speed: `286.8 Mbps`
- Measured Sample Duration: `5.006s`
- Telemetry Integrity:
  - Throughput Valid: `Yes` (Rx: 380.35 Kbps, Tx: 1.38 Mbps)
  - Error/Discard Counters: `Complete` (Rx Discard: 0, Rx Error: 0, Tx Discard: 0, Tx Error: 0)
  - Counter Decrease/Reset: None detected
- Health Verdict: `[HEALTH: NORMAL]` (Nominal telemetry; no false-normal condition)

---

### 1.4 After-State Capture & Differential Analysis
```powershell
$afterForwarding = Get-NetIPInterface -AddressFamily IPv4 | Sort-Object InterfaceAlias | Select-Object InterfaceAlias, Forwarding
$afterAdapters = Get-NetAdapter | Sort-Object Name | Select-Object Name, Status, InterfaceDescription
$diffFwd = Compare-Object $beforeForwarding $afterForwarding -Property InterfaceAlias, Forwarding
$diffAdapters = Compare-Object $beforeAdapters $afterAdapters -Property Name, Status, InterfaceDescription
```

**Comparison Output:**
```text
ZERO_DIFFERENCE: Forwarding and adapter state are completely unchanged.
```
- Forwarding Discrepancy: `None` ($null)
- Adapter Status Discrepancy: `None` ($null)
- Verification Verdict: **PASS**. The smoke test was strictly non-mutating.

---

## 2. Automated Test Suite Breakdown (331 Tests Across 29 Binaries)

```text
running 46 tests (src/lib.rs unit tests) ........................ ok (46 passed)
running  0 tests (src/main.rs unit tests) ....................... ok (0 passed)
running  5 tests (tests/test_assessment.rs) ..................... ok (5 passed)
running 20 tests (tests/test_avm_admin.rs) ...................... ok (20 passed)
running  6 tests (tests/test_batched_readiness.rs) .............. ok (6 passed)
running 10 tests (tests/test_cli_confirmation.rs) .............. ok (10 passed)
running  1 tests (tests/test_dhcp.rs) ........................... ok (1 passed)
running 15 tests (tests/test_diagnostics.rs) .................... ok (15 passed)
running  8 tests (tests/test_fixes.rs) .......................... ok (8 passed)
running  4 tests (tests/test_gateway.rs) ........................ ok (4 passed)
running 20 tests (tests/test_mikrotik_admin.rs) ................. ok (20 passed)
running 21 tests (tests/test_openwrt_admin.rs) .................. ok (21 passed)
running  9 tests (tests/test_persistence.rs) .................... ok (9 passed)
running 13 tests (tests/test_policy_engine.rs) .................. ok (13 passed)
running  7 tests (tests/test_policy_views.rs) ................... ok (7 passed)
running 17 tests (tests/test_protocol_integration.rs) ........... ok (17 passed)
running  6 tests (tests/test_provider_contracts.rs) ............. ok (6 passed)
running  9 tests (tests/test_reliability.rs) .................... ok (9 passed)
running 12 tests (tests/test_router_admin.rs) ................... ok (12 passed)
running 16 tests (tests/test_router_lab_isolation.rs) ........... ok (16 passed)
running 12 tests (tests/test_safe_networking.rs) ................ ok (12 passed)
running  2 tests (tests/test_smb.rs) ............................ ok (2 passed)
running 17 tests (tests/test_ssh_admin.rs) ...................... ok (17 passed)
running 12 tests (tests/test_target_resolution.rs) .............. ok (12 passed)
running  2 tests (tests/test_tls.rs) ............................ ok (2 passed)
running 19 tests (tests/test_unifi_admin.rs) .................... ok (19 passed)
running 10 tests (tests/test_unified_admin.rs) .................. ok (10 passed)
running  5 tests (tests/test_verification.rs) ................... ok (5 passed)
running  7 tests (tests/unit_tests.rs) .......................... ok (7 passed)
--------------------------------------------------------------------------------
Total: 331 tests passed, 0 failed, 0 ignored, 0 measured, 0 filtered out
```

---

## 3. Router-Lab Isolation Adversarial Test Suite Details

The newly authored `tests/test_router_lab_isolation.rs` exercises all 16 safety requirements:

| Test ID | Test Name | Invariant Asserted | Status |
| :--- | :--- | :--- | :---: |
| Test 01 | `test_01_router_lab_rejects_scan_ports_audit_add` | Rejects `scan`, `ports`, `audit`, `add` at dispatcher and handler boundaries | **PASS** |
| Test 02 | `test_02_router_lab_rejects_scope_mutations_and_free` | Scope cannot be mutated; `free` rejected without restorative ARP | **PASS** |
| Test 03 | `test_03_router_lab_rejects_block_limit_simulate` | Rejects local enforcement and fault simulation | **PASS** |
| Test 04 | `test_04_router_lab_rejects_router_pause_adjust_resume` | Rejects `router pause`, `router adjust`, `router resume`, `router refresh` | **PASS** |
| Test 05 | `test_05_adding_yes_flag_cannot_bypass_router_lab_policy` | `--yes` or `-y` flag cannot bypass default-deny router-lab admission | **PASS** |
| Test 06 | `test_06_rejected_commands_perform_zero_side_effects` | Batch of 23 disallowed commands executes with zero side effects | **PASS** |
| Test 07 | `test_07_valid_read_only_commands_remain_available` | Read-only commands (`providers`, `status`, `capabilities`, `devices`, etc.) remain fully functional | **PASS** |
| Test 08 | `test_08_connecting_to_real_provider_establishes_session_safely` | Authenticates with OpenWrt SSH provider; runs discovery queries | **PASS** |
| Test 09 | `test_09_mock_mode_cannot_be_misrepresented_as_physical_validation` | `router connect mock` rejected in lab mode; visibly marked simulated outside lab | **PASS** |
| Test 10 | `test_10_router_disconnect_does_not_fall_back_to_arp_or_local_enforcement` | Disconnecting provider cleanly terminates without ARP fallback | **PASS** |
| Test 11 | `test_11_evidence_export_and_offline_validation_do_not_mutate_router` | Exports and validates JSON evidence bundle offline without router mutation | **PASS** |
| Test 12 | `test_12_provider_transport_failures_fail_safely` | Transport auth failure fails closed without ARP or fallback | **PASS** |
| Test 13 | `test_13_normal_cli_retains_intended_behavior` | Ordinary development mode retains all feature capabilities | **PASS** |
| Test 14 | `test_14_exit_command_causes_clean_shutdown` | `exit`/`quit` causes clean session termination | **PASS** |
| Test 15 | `test_15_router_lab_startup_in_unprivileged_process_never_initializes_drivers` | Drivers (raw sender, spoofer worker, limiter) remain inactive | **PASS** |
| Test 16 | `test_16_strict_counter_verification_proves_zero_side_effects` | Atomic side-effect counters verify exactly 0 frame sends, 0 target adds, 0 limiter activations, 0 forwarding mutations | **PASS** |

---

## 4. Quality & Linting Gates

- `cargo fmt --check`: Clean (exit code 0).
- `cargo clippy --all-targets -- -D warnings`: Clean (exit code 0, 0 warnings).
- `cargo +1.88.0 test --all-targets`: Clean (exit code 0, 331 tests passed).
