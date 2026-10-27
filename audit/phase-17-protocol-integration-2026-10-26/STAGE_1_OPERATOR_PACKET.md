# Rustrict Phase 17 — Stage 1 Operator Runbook & Lab Safety Packet

**Document Version:** 1.2.0
**Date:** 2026-10-27 (Phase 17.1 Restored & Reconciled Baseline)
**Audience:** Physical Router Test Operators, Network Test Engineers, Safety Verifiers
**Target Codebase Revision:** Phase 17.1 (`ac1c4e9`)

---

## 1. Safety Mandate & Stage 1 Objectives

Stage 1 is the **first physical connection test** between the Rustrict management engine and physical router hardware in an electrically and logically isolated test network.

> [!IMPORTANT]
> **Zero Unplanned Mutations**: Stage 1 verifies discovery, authentication, read-only status inspection, and diagnostic evidence export. **No policy enforcement (`pause`, `adjust`) may be committed during read-only Stage 1.**
>
> This document authorizes **READ-ONLY LAB DIAGNOSTICS ONLY**. It does NOT authorize Stage 2 active policy enforcement or live production deployment.

### Hard Constraints:
1. **Zero Unplanned Mutations**: All active policy enforcement commands (`router pause`, `router adjust`, `router resume`) are strictly excluded from Stage 1 execution.
2. **Strict Loopback & Isolated Subnet**: The physical lab test must execute on a dedicated, non-routable physical switch or isolated VLAN with zero access to corporate, production, or internet transit networks.
3. **Fail-Closed Verification**: The operator must verify that Rustrict never falls back to ARP poisoning, Layer 2 redirection, or mock provider mode when a router connection is closed or errors.
4. **Operation-Aware Transport Retry Policy (Phase 17.1)**:
   - **Mutations & Unknown Operations**: Strictly zero automatic retries (`max_attempts == 1`). If a connection is terminated or times out after mutation dispatch, Rustrict does NOT blindly repeat the request, preventing duplicate rules or repeated state toggles.
   - **Read-Only Inquiries**: At most 2 attempts (`max_attempts == 2`) isolated across independent process executions to prevent stale buffered standard I/O corruption.
5. **Uncertain Outcome Handling (`PolicyLifecycleState::Unknown`)**:
   - If a mutation request is transmitted to the router and the connection is subsequently dropped, truncated, or times out, Rustrict classifies the policy lifecycle as `PolicyLifecycleState::Unknown` rather than assuming failure or success.
   - An active unconfirmed record is persisted locally to prevent duplicate conflicting actions.
   - Follow-up mutations overlapping with any active unconfirmed (`Unknown`) or `PartialFailure` scope are **strictly blocked** by the execution engine until manually verified or reconciled out-of-band by the operator.
6. **No Mock Mode Equivalence**: Mock mode (`router connect mock`) is strictly an in-memory development harness and must never be recorded as live router hardware validation.

---

## 2. Lab Hardware Setup & Network Baseline

### Test Bench Topology
```
[ Rustrict Controller ] (Native Windows 11 MSVC)
       │ IP: 192.168.1.100 / 24, MAC: 00:11:22:33:44:01
       │
[ Isolated L2 Switch ] (VLAN 99 - No WAN / No Uplink)
       │
       ├── [ Physical Test Router ] (OpenWrt / MikroTik / FRITZ!Box / UniFi)
       │      LAN IP: 192.168.1.1 / 24, MAC: 00:11:22:33:44:GW
       │
       └── [ Test Client Device ] (Linux / Android / Laptop)
              IP: 192.168.1.50 / 24, MAC: 00:11:22:33:44:50
```

### Windows Single-Instance Verification
Before launching Rustrict, ensure that no prior instances or competing network tools are holding handles:
```powershell
Get-Process rustrict -ErrorAction SilentlyContinue | Format-Table Id, ProcessName, Path
```
If any existing `rustrict` processes are running, terminate them cleanly before starting. Rustrict acquires a cross-process lock (`rustrict-policy-store.json.lock`) to serialize persistent state operations, but running a single interactive shell is required for deterministic diagnostics.

### Pre-Connection Router Snapshots (Required Baseline)
Before connecting Rustrict, capture raw router state via native out-of-band management tools:

* **OpenWrt (SSH terminal)**:
  ```sh
  uci export firewall > /tmp/firewall_baseline.uci
  nft list ruleset > /tmp/nftables_baseline.txt
  uci changes > /tmp/uci_changes_baseline.txt
  crontab -l > /tmp/crontab_baseline.txt
  ```
* **MikroTik RouterOS (WinBox or Terminal)**:
  ```routeros
  /ip/firewall/filter/export file=filter_baseline.rsc
  /system/script/job/print
  /system/scheduler/print
  ```
* **AVM FRITZ!Box (Web GUI)**:
  - Export system configuration (`System > Backup > Save`).
  - Verify parental control filter profiles under `Internet > Filters`.
  - Take screenshot or record active device list under `Home Network > Mesh / Devices`.
* **Ubiquiti UniFi (Network Web GUI)**:
  - Settings > Firewall & Security > Traffic Rules / Firewall Rules (snapshot baseline table).
  - Export backup archive (`.unf`).

---

## 3. Wireshark Packet Capture Protocol

1. Start Wireshark on controller interface before launching Rustrict:
   - Capture Filter: `host 192.168.1.1 and (tcp port 80 or tcp port 443 or tcp port 22 or tcp port 8443 or tcp port 49000 or tcp port 49443 or udp port 53)`
2. Permitted Stage 1 Network Operations:
   - **OpenWrt HTTP**:
     - `POST /ubus` with `{"method": "call", "params": ["00...00", "session", "login", ...]}` (read-only auth).
     - `POST /ubus` with `{"method": "call", "params": [sid, "system", "info", {}]}` (read-only system info).
     - `POST /ubus` with `{"method": "call", "params": [sid, "hostapd.*", "get_clients", {}]}` (read-only client inventory).
   - **OpenWrt SSH**:
     - Remote SSH session with read-only commands: `id -u`, `cat /proc/sys/kernel/hostname`, `uci show firewall`.
   - **MikroTik**:
     - `GET /rest/system/resource` (read-only system identity).
     - `GET /rest/ip/firewall/filter` (read-only rule inspection).
   - **AVM FRITZ!Box**:
     - `POST /upnp/control/hosts` SOAP `GetHostNumberOfEntries` / `GetGenericHostEntry` (read-only client discovery).
     - `POST /upnp/control/x_contact` SOAP auth challenges / session setup.
   - **Ubiquiti UniFi**:
     - `POST /api/auth/login` (read-only session creation).
     - `GET /api/s/{site}/stat/sta` (read-only active client stations).
     - `GET /api/s/{site}/rest/trafficrule` (read-only rule listing).
3. **Strictly Prohibited Stage 1 Operations**:
   - Any mutating call: `uci add firewall rule`, `uci commit firewall`, `POST /rest/ip/firewall/filter`, `DELETE /rest/ip/firewall/filter`, `DisallowWANAccessByIP`, `AllowWANAccessByIP`, or UniFi `POST /rest/trafficrule`.
   - Any ARP spoofing, frame redirection, or Layer-2 manipulation.

---

## 4. Source-Traced CLI Execution Runbook

Launch the Rustrict executable natively from Windows PowerShell:
```powershell
.\target\release\rustrict.exe
```

### Step 1: Query Available Providers and Check Safety Status
```text
rustrict> router providers
```
*Expected Output*:
- Displays registered providers: `openwrt-http`, `openwrt-ssh`, `mikrotik-rest`, `avm-tr064`, `unifi-rest`, `mock`.
- Safety status displays: Disconnected, zero mutations active.

```text
rustrict> router inventory
```
*Expected Output*:
- Displays normalized inventory table. Marks live router identity as Unavailable / Disconnected until authenticated.

### Step 2: Establish Authenticated Read-Only Connection
Select the test router provider:

* **For OpenWrt HTTP JSON-RPC**:
  ```text
  rustrict> router connect http https://192.168.1.1/ubus --user root
  Password: [Entered securely without console echo]
  ```
* **For OpenWrt SSH**:
  ```text
  rustrict> router connect ssh 192.168.1.1 --user root --port 22
  ```
* **For MikroTik REST**:
  ```text
  rustrict> router connect mikrotik https://192.168.1.1/rest --user admin
  Password: [Entered securely without console echo]
  ```
* **For AVM FRITZ!Box**:
  ```text
  rustrict> router connect avm https://192.168.1.1:49443 --user dsl_user
  Password: [Entered securely without console echo]
  ```
* **For Ubiquiti UniFi**:
  ```text
  rustrict> router connect unifi https://192.168.1.1:8443 --user admin --site default
  Password: [Entered securely without console echo]
  ```

*Verification*:
- CLI reports `[SUCCESS] Connected to <Provider Name> (Identity: <Vendor> <Model> <Version>)`.
- Verify Wireshark capture reflects only permitted authentication and discovery endpoints.

### Step 3: Inspect Live Discovered Inventory and Capabilities (Read-Only)
```text
rustrict> router status
rustrict> router capabilities
rustrict> router devices
rustrict> router diagnostics
```

*Actual Effects & Verification*:
- `router status`: Displays router management IP, hardware vendor/model string, firmware version, and connection uptime. Performs zero configuration changes.
- `router capabilities`: Displays supported features (IPv4, IPv6, autonomous expiry mechanisms like UCI cron or MikroTik script). Note: Providers like AVM TR-064 or UniFi REST will report `AutonomousExpiry: false`, which causes temporary policies to fail closed.
- `router devices`: Queries live ARP/DHCP/station tables from the router. Note provider limitations:
  - UniFi queries `/api/s/{site}/stat/sta`
  - AVM queries `Hosts:1` service (`GetGenericHostEntry`)
  - OpenWrt queries `hostapd.*.get_clients`
  - If the router firmware does not expose client tables, the CLI reports discovery limitations cleanly without failing.
- `router diagnostics`: Executes comprehensive read-only checks, verifying credential security, socket reachability, and zero configuration mutations.

```text
rustrict> router refresh
```
*Actual Effects & Verification*:
- Queries live router firewall rules to verify active policies against local store.
- **Provider Limitation**: Providers that do not expose a queryable full-ruleset API cannot return third-party rules. Rustrict reconciles known tracked rules and marks untracked states accordingly.

### Step 4: Validate Mutation Preflight & Confirmation Gates
Verify that preflight inspection can be run dry without transmitting packets to the router:
```text
rustrict> router preview pause 192.168.1.50
```
*Verification*:
- Preflight report details provider, target scope, duration, persistence, recovery mechanism, and risk assessment.
- Wireshark trace confirms **zero** network packets transmitted to the router during preview.

Test interactive cancellation safety:
```text
rustrict> router pause 192.168.1.50
[PREFLIGHT] Preflight Inspection for Router Firewall Mutation:
  • Provider:       OpenWrt HTTP (ubus JSON-RPC)
  • Scope:          192.168.1.50 (Target Count: 1)
  ...
[CONFIRMATION REQUIRED] Confirm policy enforcement on physical router? [yes/N]: N
[INFO] Policy enforcement cancelled by administrator. Zero router mutations performed.
```
*Verification*:
- Prompt rejected by operator (`N` or Enter).
- CLI reports cancellation and zero router mutations performed.
- Wireshark confirms **zero** mutating packets on the wire.

### Step 5: Export and Offline Validate Diagnostic Evidence Bundle
Export the read-only operational bundle:
```text
rustrict> router export-evidence C:\RustrictLab\stage1_evidence.json
[SUCCESS] Diagnostic evidence bundle successfully exported to: C:\RustrictLab\stage1_evidence.json
```

Validate the exported bundle offline (zero router contact):
```text
rustrict> router validate-evidence C:\RustrictLab\stage1_evidence.json
[VALID] Evidence Bundle is VALID: C:\RustrictLab\stage1_evidence.json
  • Schema Version:      rustrict-evidence-v1.0
  • Generated (UTC):     2026-10-27T...Z
  • Provider ID:         ...
  • Active Policies:     0
  • Device Inventory:    ...
```
*Verification*:
- Offline validator verifies JSON schema `rustrict-evidence-v1.0`, timestamp sanity, file size bounds (<10 MiB), and scans text for credential leakage.
- Verify that `stage1_evidence.json` contains no unredacted passwords, authorization tokens, or private keys.

### Step 6: Clean Disconnection
```text
rustrict> router disconnect
[INFO] Disconnected router provider '<provider_id>'. Subsystem cleanly disconnected without fallback to ARP poisoning.
```
*Verification*:
- CLI returns to disconnected state.
- Controller does NOT initiate ARP spoofing or fallback to mock mode.

---

## 5. Post-Test Verification & Differential Analysis

Compare post-test router state against baseline snapshots:

* **OpenWrt**:
  ```sh
  uci changes
  diff -u /tmp/firewall_baseline.uci <(uci export firewall)
  diff -u /tmp/crontab_baseline.txt <(crontab -l)
  ```
  *Pass Criteria*: `uci changes` must return completely empty. Firewall configuration diff must be zero. Crontab diff must be zero.
* **MikroTik**:
  ```routeros
  /ip/firewall/filter/export file=filter_post.rsc
  ```
  *Pass Criteria*: `filter_post.rsc` matches `filter_baseline.rsc` identically. Zero extra scripts or schedulers.
* **AVM FRITZ!Box**:
  - Refresh `Internet > Filters`. Confirm parental profiles and device access states remain identical to baseline.
* **Ubiquiti UniFi**:
  - Refresh Traffic Rules / Firewall Rules table. Confirm rule count and definitions remain identical to baseline.

---

## 6. Disconnection Rules & Emergency Abort Matrix

| Category | Event Trigger | Required Operator Action | Permitted Next Step | Stop Condition | Router Recovery Method |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Planned Controlled Disconnect** | Operator issues `router disconnect` | Verify clean CLI output and socket closure | Complete post-test diff | Provider reports disconnected | N/A (zero mutations performed) |
| **Unexpected Network Drop / Ambiguous Outcome** | Cable disconnect, switch failure, or router crash during operation | **IMMEDIATE ABORT**. Halt all Rustrict processes. Do NOT attempt blind CLI retries. Inspect policy state (`router status`). If state is `Unknown`, check router rules out-of-band via serial/console before clearing. | Capture Wireshark PCAP and router physical logs | Loss of router ping / HTTP RST / Socket Drop | Connect via out-of-band management console (serial/WinBox/web GUI); inspect active ruleset; remove dangling rules manually if present |
| **Router Auth Failure** | Invalid credentials or account lockout | Do not retry in a loop (prevents router brute-force lockouts) | Verify credentials on router local console | HTTP 401 / 403 response | Reset test password via local serial/console |
| **State Discrepancy** | Unexplained diff in router firewall rules | **HARD FAIL**. Abort test run. Export diagnostic bundle. | Run `router validate-evidence` on evidence bundle | Any unauthorized rule detected | Revert router from baseline backup: `uci import firewall < /tmp/firewall_baseline.uci && /etc/init.d/firewall restart` |

---

## 7. Stage 1 Operator Result Template

Operators must complete and sign this report upon completing the Stage 1 physical lab protocol:

```text
================================================================================
RUSTRICT STAGE 1 PHYSICAL LAB OPERATOR REPORT
================================================================================
Date / Time (UTC):        ____________________________________
Test Operator Name:       ____________________________________
Target Router Vendor:     ____________________________________
Hardware Model:           ____________________________________
Firmware / OS Version:    ____________________________________
Provider ID Selected:     [ ] openwrt-http  [ ] openwrt-ssh  [ ] mikrotik-rest
                          [ ] avm-tr064     [ ] unifi-rest

1. Network Isolation Verification:
   [ ] Controller and router connected via isolated VLAN / unmanaged switch
   [ ] Confirmed zero uplink / WAN internet connectivity on test bench
   [ ] Confirmed single Rustrict process running on Windows controller

2. Pre-Test Baseline Snapshots Captured:
   [ ] Router configuration backup exported and saved offline
   [ ] Firewall ruleset baseline exported (UCI / RSC / Backup)
   [ ] Out-of-band management console open and verified functional

3. Read-Only Execution Checklist:
   [ ] Wireshark PCAP capture initiated (Capture filename: __________________)
   [ ] 'router providers' output confirmed
   [ ] 'router connect' authenticated successfully
   [ ] 'router status' displayed correct identity and uptime
   [ ] 'router capabilities' displayed valid classification
   [ ] 'router devices' queried connected clients without error
   [ ] 'router diagnostics' executed with zero mutations
   [ ] 'router preview pause <ip>' executed dry without packets transmitted
   [ ] 'router pause <ip>' cancellation tested (prompt answered 'N')
   [ ] Wireshark verified zero mutating requests transmitted on wire

4. Diagnostic Evidence Export & Validation:
   [ ] 'router export-evidence' generated valid JSON bundle
   [ ] 'router validate-evidence' confirmed valid schema and zero leaked secrets
   [ ] 'router disconnect' cleanly detached provider without ARP fallback

5. Post-Test Differential Verification:
   [ ] Post-test firewall ruleset compared to baseline
   [ ] Configuration difference is EXACTLY ZERO
   [ ] Router operational state verified stable

OPERATOR VERDICT:
[ ] PASS — Read-only diagnostics verified. Zero router mutations occurred.
[ ] FAIL — Discrepancy or unexpected behavior detected (Describe below).

Operator Signature: ____________________________________
================================================================================
```
