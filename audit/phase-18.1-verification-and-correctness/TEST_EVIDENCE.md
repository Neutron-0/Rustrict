# Phase 18.1 Test Evidence & Verification Records

## 1. Automated Test Suite Results

### Full Suite Summary
- **Stable Toolchain:** `rustc 1.97.1 (8bab26f4f 2026-07-14)`
- **MSRV Toolchain:** `rustc 1.88.0 (6b00bc388 2025-06-23)`
- **Target Architecture:** `x86_64-pc-windows-msvc`
- **Total Test Binaries:** 27
- **Total Passed Tests:** **276 passed; 0 failed; 0 ignored**

### Complete Target-by-Target Breakdown (Derived from Raw Test Output)

| Test Target Binary | Type | Passed | Failed | Status |
| :--- | :--- | :---: | :---: | :---: |
| `unittests src\lib.rs` | Unit | 17 | 0 | PASS |
| `unittests src\main.rs` | Unit | 0 | 0 | PASS |
| `tests\test_assessment.rs` | Integration | 5 | 0 | PASS |
| `tests\test_avm_admin.rs` | Integration | 20 | 0 | PASS |
| `tests\test_cli_confirmation.rs` | Integration | 10 | 0 | PASS |
| `tests\test_dhcp.rs` | Integration | 1 | 0 | PASS |
| `tests\test_diagnostics.rs` | Integration | 15 | 0 | PASS |
| `tests\test_fixes.rs` | Integration | 8 | 0 | PASS |
| `tests\test_gateway.rs` | Integration | 4 | 0 | PASS |
| `tests\test_mikrotik_admin.rs` | Integration | 20 | 0 | PASS |
| `tests\test_openwrt_admin.rs` | Integration | 21 | 0 | PASS |
| `tests\test_persistence.rs` | Integration | 9 | 0 | PASS |
| `tests\test_policy_engine.rs` | Integration | 13 | 0 | PASS |
| `tests\test_policy_views.rs` | Integration | 7 | 0 | PASS |
| `tests\test_protocol_integration.rs` | Integration | 17 | 0 | PASS |
| `tests\test_provider_contracts.rs` | Integration | 6 | 0 | PASS |
| `tests\test_reliability.rs` | Integration | 9 | 0 | PASS |
| `tests\test_router_admin.rs` | Integration | 12 | 0 | PASS |
| `tests\test_safe_networking.rs` | Integration | 8 | 0 | PASS |
| `tests\test_smb.rs` | Integration | 2 | 0 | PASS |
| `tests\test_ssh_admin.rs` | Integration | 17 | 0 | PASS |
| `tests\test_target_resolution.rs` | Integration | 12 | 0 | PASS |
| `tests\test_tls.rs` | Integration | 2 | 0 | PASS |
| `tests\test_unifi_admin.rs` | Integration | 19 | 0 | PASS |
| `tests\test_unified_admin.rs` | Integration | 10 | 0 | PASS |
| `tests\test_verification.rs` | Integration | 5 | 0 | PASS |
| `tests\unit_tests.rs` | Unit | 7 | 0 | PASS |
| **Total** | | **276** | **0** | **100% PASS** |

---

## 2. Repeated Protocol Integration Stability Tests

The local loopback protocol integration harness was executed consecutively:
- **Stable Toolchain:** 10 consecutive executions of `cargo test --test test_protocol_integration` (170/170 passed, 0 failures).
- **MSRV (Rust 1.88.0):** 5 consecutive executions of `cargo +1.88.0 test --test test_protocol_integration` (85/85 passed, 0 failures).
- **Result:** 100% deterministic success; no port exhaustion, race conditions, or transport deadlocks observed.

---

## 3. Native Windows Smoke Test Evidence

Executed on native Windows 11 host:

```powershell
# 1. Verify baseline forwarding prior to test
PS D:\Vault\Rustrict> Get-NetIPInterface -AddressFamily IPv4 | Select-Object InterfaceAlias, Forwarding

InterfaceAlias              Forwarding
--------------              ----------
Local Area Connection* 2      Disabled
Local Area Connection* 1      Disabled
Local Area Connection         Disabled
Ethernet                      Disabled
Wi-Fi                         Disabled
Loopback Pseudo-Interface 1   Disabled

# 2. Standalone NIC List (bypassing SendARP and admin checks)
PS D:\Vault\Rustrict> .\target\debug\rustrict.exe nic list

Detected Network Adapters:
  [17] Wi-Fi                    Status: Up           Link: 286.8 Mbps (MediaTek Wi-Fi 6E MT7922 (RZ616) 160MHz PCIe Adapter)
  [16] Local Area Connection    Status: Disconnected Link: 1 Gbps     (TAP-ProtonVPN Windows Adapter V9)
  [10] Ethernet                 Status: Disconnected Link: 0 bps      (Realtek Gaming GbE Family Controller)

# 3. Standalone NIC Telemetry Sampling (Wi-Fi)
PS D:\Vault\Rustrict> .\target\debug\rustrict.exe nic health "Wi-Fi"
Sampling network adapter telemetry for 'Wi-Fi' (2-second interval)...

=== Physical Network Adapter Health Diagnostic ===
Adapter:      Wi-Fi (Index: 17)
Description:  MediaTek Wi-Fi 6E MT7922 (RZ616) 160MHz PCIe Adapter
Status:       Up | Declared Link Speed: 286.8 Mbps
Sample Window: 2.00s requested, 5.192s actual wall-clock

[Measured Telemetry]
  Rx Rate:       4.32 Kbps (      2805 bytes)  |  Rx Utilization:   0.0%
  Tx Rate:       2.76 Kbps (      1791 bytes)  |  Tx Utilization:   0.0%
  Rx Discard:            0  |  Rx Packet Errors:      0
  Tx Discard:            0  |  Tx Packet Errors:      0

[Heuristic Health Classification]
  Classification: [HEALTH: NORMAL]
  Diagnosis:      Nominal telemetry: thresholds not crossed (0.0% peak utilization, 0 packet errors/discards). Note: Heuristic check does not guarantee hardware health.

# 4. Verify post-test forwarding remains unchanged
PS D:\Vault\Rustrict> Get-NetIPInterface -AddressFamily IPv4 | Select-Object InterfaceAlias, Forwarding

InterfaceAlias              Forwarding
--------------              ----------
Local Area Connection* 2      Disabled
Local Area Connection* 1      Disabled
Local Area Connection         Disabled
Ethernet                      Disabled
Wi-Fi                         Disabled
Loopback Pseudo-Interface 1   Disabled
```

---

## 4. Lint and Static Analysis Verification
- `cargo fmt --check`: 0 formatting diffs.
- `cargo check --all-targets`: Passed with 0 errors.
- `cargo clippy --all-targets -- -D warnings`: Passed with 0 warnings.
- `cargo +1.88.0 check --all-targets`: Passed with 0 errors.
