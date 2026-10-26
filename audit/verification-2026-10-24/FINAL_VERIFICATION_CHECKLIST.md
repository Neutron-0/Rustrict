# Rustrict — Final Verification & Lab Testing Checklist

**Audit Date:** 2026-10-24  
**Purpose:** Executable checklist for post-remediation regression verification and future authorized lab-router testing.

---

## Part 1: Automated Regression Verification Checklist

Execute these checks after applying code fixes, before any network testing:

- [ ] **1. Compilation & Formatting:**
  ```powershell
  cargo fmt --check
  cargo check --all-targets
  ```
  *Expected:* Exit code 0, zero warnings.

- [ ] **2. Static Analysis Lint Gate:**
  ```powershell
  cargo clippy --all-targets -- -D warnings
  ```
  *Expected:* Exit code 0, zero warnings/errors.

- [ ] **3. Full Test Suite Execution:**
  ```powershell
  cargo test --all-targets
  ```
  *Expected:* All integration test binaries pass cleanly (at least 182 passed, 0 failed, 0 ignored).

- [ ] **4. Startup Disconnected State Check:**
  - Launch application: `cargo run`.
  - Execute: `router status`.
  - *Expected:* Status reports `DISCONNECTED`. Must **not** connect to `Mock Router Provider` by default.

- [ ] **5. Fail-Closed Disconnected Mutation Check:**
  - In disconnected state, execute: `router pause all --duration 60`.
  - *Expected:* Command rejected with error: `No router provider is currently connected. Establish a connection first with 'router connect <provider>'.`

- [ ] **6. Multi-Target Batch Enforcement Check:**
  - Submit policy with 2 targets: `vec![192.168.1.100, 192.168.1.101]`.
  - *Expected:* Provider creates firewall rules for **both** IP addresses, not only `targets[0]`.

- [ ] **7. Curl Stdin Pipeline Check (AVM & UniFi):**
  - Verify that `ProcessAvmTransport` and `ProcessUnifiTransport` do not multiplex `--config -` and `--data-binary @-` over stdin.
  - *Expected:* Subprocess completes without curl option syntax errors.

---

## Part 2: Authorized Lab-Router Physical Testing Plan

> [!CAUTION]
> **DO NOT EXECUTE AGAINST PRODUCTION NETWORKS OR REAL OPERATIONAL ROUTERS.**  
> Testing must occur strictly inside an isolated hardware laboratory on a dedicated test network.

### Pre-Requisite Lab Setup
1. **Isolated Lab Router:** Disposable test router running verified firmware (e.g., OpenWrt 23.05 or MikroTik RouterOS v7.14) configured on isolated subnet (e.g. `192.168.99.0/24`).
2. **Controller Workstation:** Windows 11 PC connected via Ethernet to lab router (`192.168.99.10`).
3. **Victim Test Devices:**
   - Test Client A: Ethernet connected (`192.168.99.100`).
   - Test Client B: Wi-Fi connected (`192.168.99.101`).
4. **Out-of-Band Console Access:** Serial console or secondary management port on lab router to ensure immediate physical recovery if communication drops.

### Step-by-Step Test Procedure

| Step | Action / Command | Verification Procedure | Expected Outcome |
| :---: | :--- | :--- | :--- |
| **LAB-01** | Connect to Lab Router via CLI:  <br>`router connect openwrt-http 192.168.99.1 --user root` | Check console output | Authenticates cleanly; displays verified router model and firmware; status shows `CONNECTED`. |
| **LAB-02** | Query Router Diagnostics & Devices: <br>`router diag` <br>`router devices` | Inspect output tables | Correctly returns router system resources; device table shows live connected test clients. |
| **LAB-03** | Attempt Gateway Lockout: <br>`router pause 192.168.99.1` | Check command response | **REJECTED** with `LockoutPrevented`; router administrative access remains unaffected. |
| **LAB-04** | Attempt Controller Lockout: <br>`router pause 192.168.99.10` | Check command response | **REJECTED** with `LockoutPrevented`; controller IP remains unaffected. |
| **LAB-05** | Apply Single-Device Timed Pause: <br>`router pause 192.168.99.100 --duration 120` | Ping WAN (`8.8.8.8`) from Client A; ping gateway (`192.168.99.1`) from Client A | Client A loses internet transit; Client A retains access to router gateway and intra-LAN. |
| **LAB-06** | Verify Client B Unaffected: <br>Ping WAN from Client B (`192.168.99.101`) | Continuous ping on Client B | Client B experiences zero packet loss and normal throughput. |
| **LAB-07** | Verify Autonomous Watchdog Recovery: <br>Disconnect controller workstation; wait 130s | Continuous ping from Client A | At t=120s, router autonomous watchdog runs, deletes firewall rule, and Client A internet automatically restores. |
| **LAB-08** | Verify Manual Revocation: <br>`router pause 192.168.99.100 --duration 600` <br>`router resume 192.168.99.100` | Ping WAN from Client A immediately after `resume` | Internet access immediately restored upon resume execution. |
| **LAB-09** | Disconnect Subsystem: <br>`router disconnect` | Inspect CLI status | Disconnects cleanly; no fallback to ARP spoofing; router rules remain intact or clean up as configured. |
