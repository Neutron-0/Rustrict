# Rustrict User Guide & Comprehensive Command Reference

Welcome to the definitive user guide for **Rustrict v2.0.1** — the native Windows network bandwidth limiter, traffic shaper, and multi-vendor router manager.

---

## Table of Contents
1. [Modes of Operation](#1-modes-of-operation)
2. [Target Addressing Syntax](#2-target-addressing-syntax)
3. [Network Discovery (`scan`, `devices`)](#3-network-discovery-scan-devices)
4. [Scope & Operational Boundaries (`scope`)](#4-scope--operational-boundaries-scope)
5. [Active Traffic Enforcement (`block`, `unblock`, `limit`)](#5-active-traffic-enforcement-block-unblock-limit)
6. [Resilience Simulation & Fault Injection (`simulate`)](#6-resilience-simulation--fault-injection-simulate)
7. [Security Auditing & Port Enumeration (`ports`, `audit`, `export`)](#7-security-auditing--port-enumeration-ports-audit-export)
8. [Router-Lab & Physical Router Management (`router`)](#8-router-lab--physical-router-management-router)
9. [Physical Adapter Telemetry & Health (`nic`, `status`)](#9-physical-adapter-telemetry--health-nic-status)
10. [Persistence & State Management (`state`)](#10-persistence--state-management-state)
11. [Troubleshooting & Safety Guardrails](#11-troubleshooting--safety-guardrails)

---

## 1. Modes of Operation

Rustrict operates in two distinct, mutually isolated modes:

| Mode | Launch Command | Required Privileges | Network Mutation | Unsolicited Probes |
| :--- | :--- | :--- | :--- | :--- |
| **Active Mode (Default)** | `rustrict` | Administrator PowerShell | Supported (ARP spoofing, WinDivert shaping) | Active ARP sweep & gateway resolution |
| **Router-Lab Mode** | `rustrict --router-lab` | Standard User | Strictly Prohibited (Default-Deny) | Zero probes (No SendARP, no ICMP pings) |

---

## 2. Target Addressing Syntax

Every enforcement and probing command accepts flexible, mixed-format target selectors:

```text
rustrict > block 1                          # Target by single inventory ID
rustrict > block 192.168.1.50               # Target by direct IPv4 address
rustrict > block 1,2,3                      # Comma-separated IDs
rustrict > block 40 61 84 93                # Space-separated IDs (multi-target)
rustrict > block 1,192.168.1.50,3           # Mixed IDs and IP addresses
rustrict > block all                        # All discovered in-scope hosts
rustrict > unblock 40 61 84 93              # Space-separated unblock
rustrict > limit all 1mbit                  # Throttle all hosts on network
```

> **Safety Invariant:** Rustrict automatically filters out your own machine's IP/MAC (**Self-Preservation**) and your default gateway's IP/MAC (**Gateway-Preservation**) so that running `block all` or `limit all` will never sever your own connection or crash the local router.

---

## 3. Network Discovery (`scan`, `devices`)

### `scan`
Discovers active online hosts on your local subnet via parallel ARP requests.

```text
rustrict > scan                             # Fast parallel ARP sweep of active subnet
rustrict > scan --fresh                     # Purges stale offline devices, keeps active rules
rustrict > scan --range 192.168.1.50-192.168.1.100  # Scan specific IP window
rustrict > scan --ports                     # Combines ARP sweep with top-25 TCP service audit
```

### `hosts` (Aliases: `devices`, `targets`, `list`, `ls`)
Displays the formatted host table including IP, MAC address, vendor OUI, hostname, online status, and active enforcement state:

```text
rustrict > devices
```

---

## 4. Scope & Operational Boundaries (`scope`)

Rustrict protects operators against accidental broadcast storms or leaking ARP spoofing onto unauthorized subnets through the **Scope Manager**.

### The Problem Rustrict Solves:
In enterprise Wi-Fi, mesh networks, or subnets larger than `/24` (e.g. `/22` spanning `192.168.36.0` to `192.168.39.255`), single-subnet tools fail. Rustrict provides instant boundary management:

### Core Scope Commands:

| Command | Action |
| :--- | :--- |
| `scope add all` (or `scope all`) | **Recommended:** Instantly authorizes all standard private LAN subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10`, `169.254.0.0/16`) and your local adapter's subnet. You will never see an "out-of-scope" error for any LAN device. |
| `scope add <cidr>` | Adds a specific subnet boundary (e.g., `scope add 192.168.36.0/22`). Smart parsing automatically infers `/24` if given a `.0` subnet or `/32` for a single host. |
| `scope remove <cidr>` | Removes an authorized CIDR boundary. |
| `scope strict on` (or `scope on`) | Enables strict mode: targets outside explicitly configured CIDRs are blocked. |
| `scope strict off` (or `scope off`) | Enables permissive mode: all RFC 1918 private LAN addresses are admitted automatically. Public Internet routable IPs (e.g. `8.8.8.8`) remain blocked from accidental Layer 2 poisoning. |
| `scope reset` | Clears custom CIDRs and resets scope strictly to the active network interface. |
| `scope clear` | Clears all operational scope definitions and exclusions. |
| `scope exclude-ip <ip>` | Explicitly blacklists an IP from any active operation. |
| `scope exclude-mac <mac>` | Explicitly blacklists a MAC address from any active operation. |
| `scope status` | Displays active operational CIDRs, exclusions, and strict mode state. |

---

## 5. Active Traffic Enforcement (`block`, `unblock`, `limit`)

### Absolute Network Severing (`block`)
Completely cuts off a target's internet access by poisoning ARP tables and blackholing traffic.

```text
rustrict > block 1                          # Block device ID 1 (bidirectional)
rustrict > block 40 61 84 93                # Block multiple devices simultaneously
rustrict > block 192.168.1.45 --download    # Block incoming download only
rustrict > block 192.168.1.45 --upload      # Block outgoing upload only
rustrict > block all                        # Cut off all devices except controller & gateway
```
* **Persistent Recovery:** Blocked devices are automatically saved to disk and re-armed upon restart.
* **Kernel Blackhole:** Uses dedicated `BLACKHOLE_MAC` poisoning so blocked packets never enter your PC's Wi-Fi adapter or saturate your bandwidth.

### Unblocking Targets (`unblock` / `free`)
Aliases: `unblock`, `free`, `unlimit`, `release`.

```text
rustrict > unblock 1                        # Restore authentic ARP and unblock device 1
rustrict > unblock 40 61 84 93              # Unblock multiple devices at once
rustrict > unblock all                      # Restore all devices on the network
```

### Rate Limiting & Traffic Shaping (`limit`)
Caps target bandwidth using a high-precision token-bucket rate limiter via WinDivert kernel filtering.

```text
rustrict > limit 2 500kbit                  # Throttle device 2 to 500 kbps (bidirectional)
rustrict > limit 2 2mbit --download         # Throttle download to 2 Mbps
rustrict > limit 2 100kbit --upload         # Throttle upload to 100 kbps
rustrict > limit all 1.5mbit                # Throttle entire network to 1.5 Mbps
```
* Supported bitrate units: `bit`, `kbit`, `mbit`, `gbit`.

---

## 6. Resilience Simulation & Fault Injection (`simulate`)

Simulate real-world degraded network conditions for testing apps, video streaming, or VoIP resilience:

```text
rustrict > simulate 1 drop 25               # Inject 25% random packet loss
rustrict > simulate 1 delay 150             # Inject 150 ms latency
rustrict > simulate 1 jitter 100 30         # 100 ms baseline delay ± 30 ms jitter
rustrict > simulate 1 clear                 # Restore normal forwarding
```

---

## 7. Security Auditing & Port Enumeration (`ports`, `audit`, `export`)

### Port Scanning & Banner Grabbing (`ports`)
Fast multi-threaded TCP connect scanner:
```text
rustrict > ports 1                          # Scans Top 25 management ports
rustrict > ports 1 80,443,8080,9000-9050    # Custom port list and range
```

### Security Posture Checks (`audit`)
Audits TLS and SMB security configurations:
```text
rustrict > audit 1
```
* **TLS Posture:** Probes SSLv3, TLS 1.0, TLS 1.1 (flags insecure deprecated protocols) and extracts X.509 Common Names.
* **SMB Security:** Flags obsolete SMBv1 support and reports whether SMB message signing is mandatory or optional.

### Report Generation (`export`)
Exports structured evidence for compliance and reporting:
```text
rustrict > export markdown audit_report.md  # Executive summary report
rustrict > export json inventory.json       # Machine-readable asset dump
rustrict > export sarif findings.sarif      # SARIF v2.1.0 for GitHub Security tab
```

---

## 8. Router-Lab & Physical Router Management (`router`)

Manage physical gateway routers via authenticated vendor APIs without local ARP manipulation:

### Supported Providers:
* **OpenWrt** (HTTPS REST UCI & SSH)
* **MikroTik RouterOS** (REST API)
* **Ubiquiti UniFi** (UniFi Network Controller REST API)
* **AVM FRITZ!Box** (TR-064 SOAP SSL)

### Router Commands:
```text
rustrict > router providers                 # List all supported router hardware
rustrict > router connect openwrt --host 192.168.1.1 --user root --password secret
rustrict > router status                    # Uptime, CPU load, memory, firmware
rustrict > router capabilities              # Inspect supported router features
rustrict > router devices                   # Query connected clients from router DHCP
rustrict > router preview block 192.168.1.45 # Dry-run preflight check (zero mutation)
rustrict > router export-evidence bundle.json # Export offline verifiable evidence
rustrict > router disconnect                # Cleanly close session
```

---

## 9. Physical Adapter Telemetry & Health (`nic`, `status`)

### System & Network Dashboard (`status`)
Displays live adapter status, controller and gateway IPs, strict mode, active blocks, and driver readiness:
```text
rustrict > status
```

### Standalone NIC Telemetry (No Admin Required)
You can run adapter diagnostics directly from PowerShell without entering the REPL:
```powershell
rustrict nic list                           # List all physical adapters and link speeds
rustrict nic stats "Wi-Fi"                  # Query RX/TX bytes, discards, and errors
rustrict nic health "Wi-Fi"                 # Comprehensive health rating
```

---

## 10. Persistence & State Management (`state`)

Rustrict preserves blocked devices across reboots in `%ProgramData%\Rustrict\rustrict_state.json`.

```text
rustrict > state status                     # Inspect saved persistent blocks and scope
rustrict > state clear                      # Wipe all saved persistent blocks from disk
```

---

## 11. Troubleshooting & Safety Guardrails

| Symptom | Cause | Solution |
| :--- | :--- | :--- |
| **"Please run as Administrator"** | Elevated token missing | Right-click PowerShell $\rightarrow$ **Run as Administrator** (or use `rustrict --router-lab` for unprivileged mode). |
| **"Npcap unavailable"** | Missing Npcap packet driver | Install Npcap from [npcap.com](https://npcap.com/) with **"Install Npcap in WinPcap API-compatible Mode"** checked. |
| **"Target IP is out of authorized scope"** | Subnet boundary mismatch | Run `scope add all` to authorize all private subnets. |
| **"WinDivertOpen failed (Error Code: 5)"** | Driver permission denied | Ensure PowerShell is running as Administrator. |
| **"WinDivert.dll not found"** | Missing driver DLL/SYS | Run the 1-line PowerShell installer (`install.ps1`) or ensure `WinDivert.dll` and `WinDivert64.sys` are alongside `rustrict.exe`. |
| **"Gateway IP cannot be an enforcement target"** | Gateway preservation active | Rustrict deliberately prevents blocking your default router to prevent whole-LAN outages. |
