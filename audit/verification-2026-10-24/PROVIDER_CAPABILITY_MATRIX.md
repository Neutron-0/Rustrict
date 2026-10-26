# Rustrict — Provider Capability Matrix & Operational Evaluation

**Audit Date:** 2026-10-24  
**Scope:** Rigorous evaluation of all 6 router administration providers in Rustrict v2.0.0 (`D:\Vault\Rustrict`)

---

## 1. Provider Comparative Matrix

| Feature / Attribute | `openwrt-http` | `openwrt-ssh` | `mikrotik-rest` | `avm-tr064` | `unifi-rest` | `mock` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Vendor / System** | OpenWrt | OpenWrt | MikroTik RouterOS | AVM FRITZ!Box | Ubiquiti UniFi | Rustrict In-Memory |
| **Transport** | Raw TCP HTTP 1.1 (`std::net::TcpStream`) | Native Windows `ssh.exe` subprocess | Native Windows `curl.exe` HTTPS | Native Windows `curl.exe` HTTPS / SOAP | Native Windows `curl.exe` HTTPS REST | In-Memory Struct |
| **Default Port** | TCP 80 | TCP 22 | TCP 443 | TCP 49000 / 49443 | TCP 8443 / 443 | N/A |
| **Authentication** | `ubus` JSON-RPC session token | SSH key / password via batch mode | HTTP Basic Auth (base64) | TR-064 HTTP Digest Auth (MD5) | Session cookie / API Key | Simulated token |
| **Credential Shielding** | In-memory session token | Private key / BatchMode; no password on CLI | `--config -` via stdin; no password on CLI | `--config -` via stdin; **broken stdin pipe** | `--config -` via stdin; **broken stdin pipe** | `ProtectedString` |
| **Read-Only Discovery** | Implemented (`system:board`) | Implemented (`cat /etc/openwrt_release`) | Implemented (`/rest/system/resource`) | Implemented (`tr64desc.xml`) | Implemented (`/api/v2/meta`) | Implemented |
| **Device Inventory** | Unsupported | Unsupported | Unsupported | Implemented (`GetGenericHostEntry`) | Implemented (`/api/s/{site}/stat/sta`) | Implemented |
| **Per-Device Pause** | Implemented (UCI firewall rule) | Implemented (UCI firewall rule) | Implemented (`/ip/firewall/filter`) | Implemented (`X_AVM-DE_HostFilter`) | Implemented (Traffic Rule) | Implemented |
| **Multi-Target Support** | **BROKEN** (takes only `targets[0]`) | **BROKEN** (takes only `targets[0]`) | **BROKEN** (takes only `targets[0]`) | Implemented (loops all targets) | Implemented (loops all targets) | Implemented |
| **Network-Wide Pause** | Implemented (lan -> wan reject) | Implemented (lan -> wan reject) | Implemented (forward chain reject) | Implemented (disallow all LAN hosts) | Implemented (`ALL_DEVICES` rule) | Implemented |
| **IPv6 Enforcement** | Implemented (MAC match) | Implemented (MAC match) | **BROKEN** (posts only to `/ip`, not `/ipv6`) | NotImplemented (IPv4 only) | Implemented (Traffic Rule matches MAC) | Implemented |
| **Autonomous Recovery** | Implemented (`/etc/rustrict/watchdog.sh` + cron) | Implemented (`/etc/rustrict/watchdog.sh` + cron) | Implemented (`/system/script` + scheduler) | **NotImplemented** (Fails closed on temporary) | **NotImplemented** (Fails closed on temporary) | Implemented (Timer simulation) |
| **Read-Back Confirmation**| Reconcile via UCI show | Reconcile via UCI show | Reconcile via `/rest/ip/firewall/filter` | Implemented (`GetWANAccessByIP`) | Reconcile via Traffic Rules API | In-memory check |
| **Timeout Handling** | Socket timeout (`TcpStream`) | Polling loop + `child.kill()` / `wait()` | `--connect-timeout`, `--max-time` | `--max-time` | `--max-time` | Atomic flag |
| **Test Coverage** | 100% Mock (`MockOpenWrtTransport`) | 100% Mock (`MockSshExecutor`) | 100% Mock (`MockMikroTikTransport`) | 100% Mock (`MockAvmTransport`) | 100% Mock (`MockUnifiTransport`) | 100% Mock |
| **Real Hardware Tested** | **NO** | **NO** | **NO** | **NO** | **NO** | N/A |

---

## 2. Detailed Provider-by-Provider Operational Evaluation

### 1. `openwrt-http` (OpenWrt JSON-RPC via ubus)
- **Implemented Operations:** `detect_identity`, `plan_operation`, `apply_policy`, `resume_policy`, `adjust_policy_duration`, `query_active_policies`, `reconcile_policies`.
- **Read-Only Capabilities:** Identity detection via `system board`, session acquisition via `session login`, active rule query via `uci get`. Device inventory is unsupported.
- **Mutation Capabilities:** Injects UCI firewall reject rules from `lan` to `wan`. Installs `/etc/rustrict/watchdog.sh` and crontab entry for autonomous recovery.
- **Defects Identified:**
  1. Multi-target truncation: When `PolicyScope::SpecificTargets` has multiple targets, only `targets[0]` is added to the UCI rule.
  2. Plaintext HTTP transport only: Does not support HTTPS or TLS if uhttpd has TLS enabled on port 443.
- **Required Firmware Assumptions:** OpenWrt 19.07+, `uhttpd`, `rpcd`, `rpcd-mod-file`, `rpcd-mod-uci`.

### 2. `openwrt-ssh` (OpenWrt CLI via Native OpenSSH)
- **Implemented Operations:** Same policy operations as `openwrt-http`, dispatched via SSH commands (`cat /etc/crontabs/root`, `uci add firewall rule`, etc.).
- **Security & Safety:** Bounded execution loop with `child.try_wait()` and child process killing; strict host-key checking enabled (`StrictHostKeyChecking=yes`); command argument injection protection.
- **Defects Identified:**
  1. Multi-target truncation: Inherits the `targets[0]` truncation bug from `OpenWrtAdminProvider`.
  2. Stdout/stderr pipe buffer deadlock risk: Looping `child.try_wait()` without reading pipes can block if output exceeds the OS pipe buffer (Finding SEC-07).
- **Required Firmware Assumptions:** OpenWrt with `dropbear` or `openssh-server`, root access, `uci` utility.

### 3. `mikrotik-rest` (MikroTik RouterOS v7 HTTPS REST)
- **Implemented Operations:** `detect_identity`, `plan_operation`, `apply_policy`, `resume_policy`, `adjust_policy_duration`, `query_active_policies`, `reconcile_policies`.
- **Security & Safety:** Strict TLS certificate verification (refuses self-signed / expired certs); credentials passed via stdin config (`--config -`); lockout protection.
- **Autonomous Recovery:** Installs RouterOS script `/system/script/rustrict_watchdog` and scheduler `/system/scheduler/rustrict_watchdog_sched` running every minute.
- **Defects Identified:**
  1. Multi-target truncation: Takes only `targets[0]` when creating `/rest/ip/firewall/filter` rules.
  2. False IPv6 capability claim: Declares IPv6 implemented, but only creates rules in `/rest/ip/firewall/filter`, completely omitting `/rest/ipv6/firewall/filter`. The watchdog script also only inspects IPv4.
- **Required Firmware Assumptions:** MikroTik RouterOS v7.1+ (v6 lacks the `/rest` API), `www-ssl` service enabled, user in `admin` group.

### 4. `avm-tr064` (AVM FRITZ!Box TR-064 SOAP)
- **Implemented Operations:** `detect_identity`, `plan_operation`, `apply_policy`, `resume_policy`, `query_active_policies`, `list_devices`.
- **Autonomous Recovery:** Correctly identifies that FRITZ!Box lacks an autonomous router scheduler. Fails closed when temporary policies are requested.
- **Defects Identified:**
  1. **FATAL:** Stdin multiplexing bug in `ProcessAvmTransport` crashes `curl.exe` on any SOAP request containing a body (Finding SEC-01). The provider is completely non-functional in production.
  2. Unqualified `curl.exe` invocation without explicit System32 verification (Finding SEC-09).
- **Required Firmware Assumptions:** FRITZ!OS 7.0+, TR-064 enabled in Network Settings, FRITZ!Box user with "FRITZ!Box settings" permission.

### 5. `unifi-rest` (Ubiquiti UniFi Network REST API)
- **Implemented Operations:** `detect_identity`, `plan_operation`, `apply_policy`, `resume_policy`, `query_active_policies`, `reconcile_policies`, `list_devices`.
- **Autonomous Recovery:** Correctly identifies that UniFi API lacks a controller-resident autonomous scheduler. Fails closed on temporary policies.
- **Defects Identified:**
  1. **FATAL:** Stdin multiplexing bug in `ProcessUnifiTransport` crashes `curl.exe` on any POST/PUT request containing JSON data (Finding SEC-01). The provider cannot apply policies in production.
  2. Policy ID naming inconsistency: Assigns policy ID using only `targets[0]` even though `dev_list` contains all targets.
- **Required Firmware Assumptions:** UniFi Network Application v7.0+ (UniFi OS console or standalone controller), Site with Traffic Rules support.

### 6. `mock` (In-Memory Simulator)
- **Implemented Operations:** All operations fully implemented in memory.
- **Role:** Deterministic, offline unit test provider.
- **Defect:** Silently connected by default at application startup in `Prompt::new` (Finding SEC-02).
