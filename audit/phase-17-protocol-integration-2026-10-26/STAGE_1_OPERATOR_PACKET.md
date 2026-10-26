# Rustrict Phase 17 — Stage 1 Operator Runbook & Lab Safety Packet

**Document Version:** 1.0.0  
**Date:** 2026-10-26  
**Audience:** Physical Router Test Operators, Network Test Engineers, Safety Verifiers  
**Target Codebase Revision:** Phase 17 (`bbbda5a`)  

---

## 1. Safety Mandate & Stage 1 Objectives

Stage 1 is the **first physical connection test** between the Rustrict management engine and physical router hardware in an electrically and logically isolated test network.

### Hard Constraints:
1. **Zero Unplanned Mutations**: Stage 1 verifies discovery, authentication, read-only status inspection, and diagnostic evidence export. **No policy enforcement (`pause`, `adjust`) may be committed during read-only Stage 1.**
2. **Strict Loopback & Isolated Subnet**: The physical lab test must execute on a dedicated, non-routable physical switch or VLAN with zero access to corporate, production, or internet transit networks.
3. **Fail-Closed Verification**: The operator must verify that Rustrict never falls back to ARP poisoning, Layer 2 redirection, or mock provider mode when a router connection is closed or errors.

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

### Pre-Connection Router Snapshots (Required Baseline)
Before connecting Rustrict, capture raw router state via native management tools:

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
  ```
* **AVM FRITZ!Box (Web GUI)**:
  - Export system configuration (`System > Backup > Save`).
  - Verify parental control filter profiles under `Internet > Filters`.
* **Ubiquiti UniFi (Network Web GUI)**:
  - Settings > Firewall & Security > Firewall Rules (snapshot baseline table).
  - Export backup (.unf).

---

## 3. Wireshark Packet Capture Protocol

1. Start Wireshark on controller interface before launching Rustrict:
   - Capture Filter: `host 192.168.1.1 and (tcp port 80 or tcp port 443 or tcp port 22 or tcp port 8443 or tcp port 49000 or udp port 53)`
2. Permitted Stage 1 Network Operations:
   - **OpenWrt**:
     - `POST /ubus` with `{"method": "call", "params": ["00...00", "session", "login", ...]}` (read-only auth).
     - `POST /ubus` with `{"method": "call", "params": [sid, "system", "info", {}]}` (read-only system info).
     - `POST /ubus` with `{"method": "call", "params": [sid, "hostapd.*", "get_clients", {}]}` (read-only client inventory).
   - **MikroTik**:
     - `GET /rest/system/resource` (read-only system identity).
     - `GET /rest/ip/firewall/filter` (read-only rule inspection).
   - **AVM FRITZ!Box**:
     - `POST /upnp/control/hosts` SOAP `GetHostNumberOfEntries` / `GetGenericHostEntry` (read-only client discovery).
     - `POST /upnp/control/x_contact` SOAP auth challenges.
   - **Ubiquiti UniFi**:
     - `POST /api/auth/login` (read-only session creation).
     - `GET /api/s/{site}/stat/sta` (read-only active client stations).
3. **Prohibited Stage 1 Operations**:
   - Any `uci add firewall rule`, `uci commit firewall`, `POST /rest/ip/firewall/filter`, `DELETE /rest/ip/firewall/filter`, `DisallowWANAccessByIP`, or UniFi rule creation.

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
- Lists supported providers: `openwrt-http`, `openwrt-ssh`, `mikrotik-rest`, `avm-tr064`, `unifi-rest`, `mock`.
- Safety status displays: Disconnected, zero mutations active.

### Step 2: Establish Authenticated Read-Only Connection
Select the test router provider:

* **For OpenWrt HTTP JSON-RPC**:
  ```text
  rustrict> router connect http https://192.168.1.1/ubus --user root
  Password: [Entered securely without console echo]
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

### Step 3: Inspect Live Discovered Inventory and Capabilities
```text
rustrict> router status
rustrict> router capabilities
rustrict> router devices
```
*Verification*:
- `router status` displays correct gateway IP, router identity, and connection uptime.
- `router capabilities` displays IPv4/IPv6 support, autonomous expiry mechanisms (UCI cron, MikroTik script, etc.).
- `router devices` displays active LAN clients discovered via the router's internal tables.

### Step 4: Validate Mutation Preflight & Confirmation Gates
Test the interactive preflight without applying changes:
```text
rustrict> router preview pause 192.168.1.50
```
*Verification*:
- Preflight report details provider, scope, duration, persistence, recovery mechanism, and risk assessment.
- Zero network packets transmitted to the router.

Test interactive cancellation:
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
- Zero router firewall mutations executed.
- Wireshark trace shows zero mutating packets.

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
  • Generated (UTC):     2026-10-26T23:30:00Z
  • Provider ID:         openwrt-http
  • Active Policies:     0
  • Device Inventory:    1
```
*Verification*:
- Bundle validates cleanly.
- Verify that `stage1_evidence.json` contains no unredacted passwords, basic auth tokens, or private keys.

### Step 6: Clean Disconnection
```text
rustrict> router disconnect
[INFO] Disconnected router provider 'openwrt-http'. Subsystem cleanly disconnected without fallback to ARP poisoning.
```
*Verification*:
- Status returns to disconnected.
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
  *Pass Criteria*: `uci changes` must return completely empty. Firewall configuration diff must be zero.
* **MikroTik**:
  ```routeros
  /ip/firewall/filter/export file=filter_post.rsc
  ```
  *Pass Criteria*: `filter_post.rsc` matches `filter_baseline.rsc` identically.

---

## 6. Disconnection Rules & Emergency Abort Matrix

| Category | Event Trigger | Required Operator Action | Permitted Next Step | Stop Condition | Router Recovery Method |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Planned Controlled Disconnect** | Operator issues `router disconnect` | Verify clean CLI output and socket closure | Proceed to next lab stage | Provider reports disconnected | N/A (zero mutations) |
| **Unexpected Network Drop** | Cable disconnect, switch failure, or router crash | **IMMEDIATE ABORT**. Halt all Rustrict processes. Do NOT reconnect automatically. | Capture Wireshark PCAP and router physical logs | Loss of router ping / HTTP RST | Reconnect out-of-band management console; inspect state |
| **Router Auth Failure** | Invalid credentials or account lockout | Do not retry in a loop (prevents router brute-force lockouts) | Verify credentials on router local console | HTTP 401 / 403 response | Reset test password via local serial/console |
| **State Discrepancy** | Unexplained diff in router firewall rules | **HARD FAIL**. Abort test run. Export diagnostic bundle. | Run `router validate-evidence` on evidence bundle | Any unauthorized rule detected | Revert router from baseline backup: `uci import firewall < /tmp/firewall_baseline.uci && /etc/init.d/firewall restart` |
