```text
██████╗ ██╗   ██╗███████╗████████╗██████╗ ██╗ ██████╗████████╗
██╔══██╗██║   ██║██╔════╝╚══██╔══╝██╔══██╗██║██╔════╝╚══██╔══╝
██████╔╝██║   ██║███████╗   ██║   ██████╔╝██║██║        ██║   
██╔══██╗██║   ██║╚════██║   ██║   ██╔══██╗██║██║        ██║   
██║  ██║╚██████╔╝███████║   ██║   ██║  ██║██║╚██████╗   ██║   
╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝ ╚═════╝   ╚═╝   
             Windows Network Bandwidth Limiter & Controller
                                     v2.0.0 [Rust Core]
```

# Rustrict

> **High-performance Windows network bandwidth limiter, traffic shaper, and device manager — written in native Rust.**

Rustrict employs asynchronous Layer 2 ARP operations, multi-protocol identity resolution, kernel-level packet filtering (WinDivert + Npcap), and router UPnP/TR-064 gateway interrogation to discover, fingerprint, monitor, and regulate every device on a local network — all from a single Windows CLI.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [System Architecture Diagram](#system-architecture-diagram)
- [Module Dependency Graph](#module-dependency-graph)
- [Core Subsystems](#core-subsystems)
  - [1. Platform & Kernel Interface Layer](#1-platform--kernel-interface-layer)
  - [2. Scanner Subsystem](#2-scanner-subsystem)
  - [3. Identity & Resolution Subsystem](#3-identity--resolution-subsystem)
  - [4. Router Gateway Discovery (UPnP / TR-064)](#4-router-gateway-discovery-upnp--tr-064)
  - [5. MITM & Traffic Shaping Engine](#5-mitm--traffic-shaping-engine)
  - [6. State & Persistence Subsystem](#6-state--persistence-subsystem)
  - [7. Wireless Subsystem (802.11)](#7-wireless-subsystem-80211)
- [End-to-End Data Flow](#end-to-end-data-flow)
  - [Device Discovery Pipeline](#device-discovery-pipeline)
  - [Traffic Throttling & MITM Pipeline](#traffic-throttling--mitm-pipeline)
  - [Persistent Block Lifecycle](#persistent-block-lifecycle)
- [CLI Command Reference](#cli-command-reference)
- [Requirements](#requirements)
- [Building from Source](#building-from-source)
- [Project Structure](#project-structure)
- [Test Suite](#test-suite)
- [External Dependencies](#external-dependencies)

---

## Architecture Overview

Rustrict is organized into seven architectural layers, each responsible for a distinct concern in the network management pipeline:

| Layer | Modules | Responsibility |
| :--- | :--- | :--- |
| **CLI & Presentation** | `src/cli/`, `src/main.rs` | Interactive REPL shell, ANSI-colored device tables, target resolution, argument parsing |
| **Platform & Kernel Interface** | `src/platform/`, `build.rs` | Windows API bindings (`SendARP`, `IsUserAnAdmin`), PowerShell automation, WinDivert/Npcap dynamic linking |
| **Scanner** | `src/scanner/` | Parallel ARP subnet sweeping via Rayon, rate-limited in batches of 48 to prevent router queue exhaustion |
| **Identity & Resolution** | `src/resolver/`, `src/gateway/` | 10-protocol hostname fingerprinting chain, OUI vendor lookup, router UPnP/TR-064 SOAP interrogation |
| **MITM & Traffic Shaping** | `src/spoofer/`, `src/limiter/`, `src/monitor/` | Bidirectional ARP cache poisoning, WinDivert kernel packet interception, token-bucket rate limiting |
| **State & Persistence** | `src/state.rs` | JSON-backed durable block rules surviving restarts and rescans |
| **Wireless (802.11)** | `src/wireless/` | Deauth frame crafting, Radiotap parsing, 4-way WPA handshake / PMKID inspection |

---

## System Architecture Diagram

```mermaid
graph TB
    subgraph USER["User Terminal (Administrator PowerShell)"]
        CLI["rustrict.exe"]
    end

    subgraph PRESENTATION["CLI & Presentation Layer"]
        Banner["Banner (ASCII Art)"]
        REPL["Interactive REPL Loop"]
        Table["Host Inventory Table (comfy-table)"]
        TargetRes["Target Resolver (ID / IP / all)"]
    end

    subgraph PLATFORM["Platform & Kernel Interface"]
        WinAPI["Windows APIs (SendARP, IsUserAnAdmin)"]
        PSCmd["PowerShell Commands (Get-NetRoute, Set-NetIPInterface)"]
        NpcapDLL["wpcap.dll (Npcap)"]
        WinDivertDLL["WinDivert.dll + WinDivert64.sys"]
    end

    subgraph DISCOVERY["Discovery & Identity Pipeline"]
        Scanner["SubnetScanner (Rayon Parallel ARP)"]
        Resolver["Multi-Protocol Identity Resolver"]
        Sniffer["Passive DHCP Sniffer (Background)"]
        Gateway["GatewayClient (UPnP / TR-064)"]
        OUI["OUI Vendor Database (25+ vendors)"]
    end

    subgraph MITM["Traffic Control & MITM Engine"]
        Spoofer["ArpSpoofer (Bidirectional Poisoning)"]
        L2Sender["RawL2Sender (pcap_sendpacket)"]
        Limiter["TrafficLimiter (WinDivert NETWORK_FORWARD)"]
        TokenBucket["TokenBucket Rate Shaper"]
        Meter["BandwidthMeter (Atomic Counters)"]
    end

    subgraph PERSIST["Persistence"]
        State["PersistentState (rustrict_state.json)"]
    end

    subgraph WIRELESS["802.11 Wireless Subsystem"]
        Deauth["Deauth Frame Crafter"]
        FrameParser["802.11 Frame Parser"]
        Handshake["WPA Handshake / PMKID Inspector"]
        Radiotap["Radiotap Header Parser"]
    end

    CLI --> Banner
    CLI --> REPL
    REPL --> Table
    REPL --> TargetRes
    REPL -->|scan| Scanner
    REPL -->|limit / block| Spoofer
    REPL -->|limit / block| Limiter
    REPL -->|block| State
    REPL -->|free| State

    Scanner -->|Parallel Probes| WinAPI
    Scanner -->|Background Query| Gateway
    Scanner -->|Discovered Hosts| Resolver
    Resolver --> OUI
    Sniffer -->|Passive Captures| REPL

    Spoofer -->|Crafted ARP Frames| L2Sender
    L2Sender --> NpcapDLL
    Limiter --> WinDivertDLL
    Limiter -->|Rate Check| TokenBucket
    Limiter -->|Traffic Stats| Meter

    Gateway -->|SSDP M-SEARCH| PSCmd
    WinAPI --> PSCmd

    State -->|Load on Startup| REPL
    State -->|Restore Blocks| Spoofer
    State -->|Restore Blocks| Limiter

    Deauth --> L2Sender
    FrameParser --> Handshake
    Radiotap --> FrameParser
```

---

## Module Dependency Graph

```mermaid
graph LR
    subgraph main_bin["Binary (src/main.rs)"]
        main["main()"]
    end

    subgraph lib_crate["Library Crate (src/lib.rs)"]
        cli_mod["cli"]
        gateway_mod["gateway"]
        limiter_mod["limiter"]
        monitor_mod["monitor"]
        platform_mod["platform"]
        resolver_mod["resolver"]
        scanner_mod["scanner"]
        spoofer_mod["spoofer"]
        state_mod["state"]
        types_mod["types"]
        wireless_mod["wireless"]
    end

    main -->|"use rustrict::cli"| cli_mod
    main -->|"use rustrict::platform"| platform_mod

    cli_mod --> scanner_mod
    cli_mod --> spoofer_mod
    cli_mod --> limiter_mod
    cli_mod --> resolver_mod
    cli_mod --> state_mod
    cli_mod --> types_mod
    cli_mod --> monitor_mod

    scanner_mod --> platform_mod
    scanner_mod --> resolver_mod
    scanner_mod --> gateway_mod
    scanner_mod --> types_mod

    resolver_mod --> gateway_mod
    resolver_mod --> types_mod

    spoofer_mod --> types_mod

    limiter_mod --> types_mod

    gateway_mod --> types_mod

    state_mod --> types_mod
```

---

## Core Subsystems

### 1. Platform & Kernel Interface Layer

The platform layer (`src/platform/`) provides the bridge between Rustrict and the Windows kernel. A compile-time guard rejects non-Windows targets:

```rust
#[cfg(not(windows))]
compile_error!("Rustrict is built specifically for Windows (Windows 10/11 x64).");
```

**Key operations performed through this layer:**

| Function | Mechanism | Purpose |
| :--- | :--- | :--- |
| `is_privileged()` | Win32 `IsUserAnAdmin()` | Verify Administrator elevation |
| `send_arp(ip)` | Win32 `SendARP` (iphlpapi.dll) | Synchronous kernel-level ARP resolution |
| `get_arp_cache()` | Parses `arp -a` output | Seed scanner with known devices |
| `get_default_interface()` | PowerShell `Get-NetRoute`, `Get-NetIPAddress`, `Get-NetAdapter` | Auto-detect active NIC, gateway IP/MAC, local IP/MAC, Npcap device path |
| `enable_ip_forwarding()` | PowerShell `Set-NetIPInterface -Forwarding Enabled` | Required for MITM packet forwarding |
| `disable_ip_forwarding()` | PowerShell `Set-NetIPInterface -Forwarding Disabled` | Clean shutdown restoration |

**The build system** (`build.rs`) automatically locates and bundles WinDivert binaries (`WinDivert.dll`, `WinDivert64.sys`) from Anaconda/pip `pydivert` site-packages or local directories into the target output folder.

---

### 2. Scanner Subsystem

The scanner (`src/scanner/arp.rs`) performs high-speed parallel ARP sweeps across IPv4 subnets:

```mermaid
sequenceDiagram
    participant User as User (scan command)
    participant CLI as RustrictCli
    participant Scanner as SubnetScanner
    participant GW as GatewayClient (Background)
    participant Rayon as Rayon Thread Pool
    participant Kernel as Windows SendARP API
    participant Resolver as Identity Resolver

    User->>CLI: scan [--fresh] [--range]
    CLI->>Scanner: scan_subnet() / scan_range()

    par Background Router Query
        Scanner->>GW: refresh_hosts() [async thread]
        GW-->>Scanner: DHCP lease table cached
    and Parallel ARP Sweep
        Scanner->>Scanner: Compute subnet bounds (network..broadcast)
        Scanner->>Scanner: Seed from ARP cache (non-fresh mode)
        loop Batches of 48 IPs
            Scanner->>Rayon: par_iter() over IP batch
            Rayon->>Kernel: send_arp(ip) per IP
            Kernel-->>Rayon: MAC address or timeout
            Note over Rayon: 10ms throttle between batches
        end
    end

    Scanner->>Resolver: resolve_identity_with_gateway(ip, mac, gateway_client)
    Resolver-->>Scanner: HostIdentity (hostname, source, vendor)
    Scanner-->>CLI: Vec of Host
    CLI->>CLI: reconcile_hosts(new_hosts, is_fresh)
    CLI->>CLI: render_hosts_table()
```

**Key design decisions:**
- **Batch size of 48** with **10ms inter-batch delays** prevents consumer routers from dropping ARP frames due to queue exhaustion.
- **Non-fresh scans** pre-seed from the Windows kernel ARP cache (`arp -a`), reducing network traffic for already-known devices.
- **Fresh scans** (`--fresh`) purge all offline, unmanaged entries from the table while strictly preserving any host with active limits, blocks, or persistent rules.

---

### 3. Identity & Resolution Subsystem

Rustrict resolves device hostnames through a **10-protocol priority chain**, stopping at the first successful identification:

```mermaid
flowchart TD
    Start["Discovered IP + MAC"] --> GatewayCheck{"Is this the Gateway IP?"}
    GatewayCheck -->|Yes| GWLabel["'Gateway' (NameSource::Gateway)"]
    GatewayCheck -->|No| LocalCheck{"Is this the local machine?"}
    LocalCheck -->|Yes| LocalLabel["COMPUTERNAME (NameSource::Local)"]
    LocalCheck -->|No| UPnP["1. Router UPnP / TR-064 Lookup"]

    UPnP -->|Found| UPnPResult["DHCP Hostname (NameSource::RouterUpnp)"]
    UPnP -->|Not Found| SMB["2. SMB2 NTLMSSP Type 2 Challenge (TCP 445)"]

    SMB -->|Found| SMBResult["NetBIOS Name (NameSource::Smb)"]
    SMB -->|Not Found| TLS["3. TLS X.509 Certificate CN (TCP 3389, 443)"]

    TLS -->|Found| TLSResult["Certificate CN (NameSource::Tls)"]
    TLS -->|Not Found| NetBIOS["4. NetBIOS NBNS Query (UDP 137)"]

    NetBIOS -->|Found| NBResult["Workstation Name (NameSource::NetBios)"]
    NetBIOS -->|Not Found| mDNS["5. mDNS Reverse PTR (UDP 5353)"]

    mDNS -->|Found| mDNSResult["'.local' Hostname (NameSource::Mdns)"]
    mDNS -->|Not Found| LLMNR["6. LLMNR PTR Query (UDP 5355)"]

    LLMNR -->|Found| LLMNRResult["Link-Local Name (NameSource::Local)"]
    LLMNR -->|Not Found| HTTP["7. HTTP Banner/Title (TCP 80, 8080)"]

    HTTP -->|Found| HTTPResult["Page Title (NameSource::Local)"]
    HTTP -->|Not Found| RDNS["8. Reverse DNS (nslookup)"]

    RDNS -->|Found| RDNSResult["PTR Record (NameSource::Local)"]
    RDNS -->|Not Found| OUI["9. OUI Vendor-Only Identification"]

    OUI --> Unresolved["NameSource::Unresolved (vendor still resolved)"]

    style UPnP fill:#2d5016,color:#fff
    style SMB fill:#2d5016,color:#fff
    style TLS fill:#2d5016,color:#fff
    style NetBIOS fill:#2d5016,color:#fff
    style mDNS fill:#2d5016,color:#fff
    style LLMNR fill:#2d5016,color:#fff
    style HTTP fill:#2d5016,color:#fff
    style RDNS fill:#2d5016,color:#fff
```

**Additionally**, a **passive background sniffer** (`PassiveIdentitySniffer`) runs continuously in a separate thread, capturing broadcast DHCP packets via Npcap promiscuous mode and extracting **DHCP Option 12 (Host Name)** from BOOTP/DHCP exchanges. These passively discovered identities are merged into the host table on every `hosts` command.

**OUI Vendor Database** covers 25+ manufacturers including Apple, Samsung, Xiaomi, Google, Amazon, Intel, Realtek, TP-Link, Cisco, Dell, HP, Lenovo, and more. Randomized MACs (locally administered bit set) are detected and flagged.

---

### 4. Router Gateway Discovery (UPnP / TR-064)

The gateway module (`src/gateway/`) queries the local router's UPnP `LANHostConfigManagement:1` service to extract the authoritative DHCP lease table — providing device names that are impossible to obtain by probing endpoints directly (e.g., firewalled smartphones, IoT devices, smart TVs).

```mermaid
sequenceDiagram
    participant Scanner as SubnetScanner
    participant GW as GatewayClient
    participant SSDP as SsdpScanner
    participant Router as Router (192.168.x.1)
    participant SOAP as SoapClient

    Scanner->>GW: refresh_hosts() [background thread]

    Note over GW,SSDP: Phase 1: Service Discovery
    GW->>SSDP: discover(gateway_ip)

    alt Multicast Discovery
        SSDP->>Router: M-SEARCH to 239.255.255.250:1900
        Note right of SSDP: Target: InternetGatewayDevice:1
        Router-->>SSDP: HTTP 200 (LOCATION header)
    else Unicast Fallback (Wi-Fi isolation)
        loop Ports: 1900, 49152, 49153, 5000, 80, 8080
            SSDP->>Router: HTTP GET /rootDesc.xml
            SSDP->>Router: HTTP GET /desc.xml
            SSDP->>Router: HTTP GET /igd.xml
            SSDP->>Router: HTTP GET /upnp/IGD.xml
            SSDP->>Router: HTTP GET /gatedesc.xml
        end
        Router-->>SSDP: XML Description Document
    end

    SSDP->>SSDP: Parse XML for controlURL and serviceType
    SSDP-->>GW: GatewayServiceInfo (addr, control_url, service_urn)

    Note over GW,SOAP: Phase 2: DHCP Lease Enumeration
    loop Index 0..N (until Error 714)
        GW->>SOAP: get_generic_host_entry(index)
        SOAP->>Router: SOAP POST (GetGenericHostEntry)
        alt Valid Entry
            Router-->>SOAP: XML Response (IP, MAC, HostName, InterfaceType, Active)
            SOAP-->>GW: GatewayHostEntry
        else Error 714 (NoSuchEntryInArray)
            Router-->>SOAP: SOAP Fault 714
            Note over SOAP: Enumeration complete
        end
    end

    GW->>GW: Cache entries by IP in Arc of RwLock of HashMap
    GW-->>Scanner: Cached, ready for instant lookups
```

---

### 5. MITM & Traffic Shaping Engine

The traffic control system operates through three tightly coordinated subsystems:

```mermaid
flowchart TB
    subgraph ARP_POISONING["ARP Cache Poisoning (src/spoofer/)"]
        direction TB
        SpooferEngine["ArpSpoofer Engine"]
        WorkerThread["Background Worker Thread (2s interval)"]
        L2Sender["RawL2Sender (wpcap.dll)"]

        SpooferEngine -->|"add(host)"| WorkerThread
        WorkerThread -->|"Every 2 seconds"| PoisonTarget["Poison Target: 'Gateway IP is at MY MAC'"]
        WorkerThread -->|"Every 2 seconds"| PoisonGW["Poison Gateway: 'Target IP is at MY MAC'"]
        PoisonTarget --> L2Sender
        PoisonGW --> L2Sender
    end

    subgraph PACKET_FILTER["Kernel Packet Interception (src/limiter/)"]
        direction TB
        WinDivert["WinDivert Layer 1 (NETWORK_FORWARD)"]
        IPParse["IPv4 Header Parser (src/dst IP extraction)"]
        RuleCheck{"Rule Lookup"}
        ULBucket["Upload TokenBucket"]
        DLBucket["Download TokenBucket"]
        Drop["DROP Packet"]
        Forward["FORWARD Packet (WinDivertSend)"]

        WinDivert -->|"Intercepted Packet"| IPParse
        IPParse --> RuleCheck
        RuleCheck -->|"Blocked"| Drop
        RuleCheck -->|"Limited (outbound)"| ULBucket
        RuleCheck -->|"Limited (inbound)"| DLBucket
        ULBucket -->|"Tokens available"| Forward
        ULBucket -->|"Tokens exhausted"| Drop
        DLBucket -->|"Tokens available"| Forward
        DLBucket -->|"Tokens exhausted"| Drop
        RuleCheck -->|"No rule"| Forward
    end

    subgraph MONITORING["Traffic Monitoring (src/monitor/)"]
        Meter["BandwidthMeter"]
        AtomicCounters["Per-Host Atomic Counters (bytes_sent, bytes_recv)"]
        Meter --> AtomicCounters
    end

    L2Sender -->|"Poisoned ARP traffic redirected"| WinDivert
    Forward --> Meter
```

#### Token Bucket Rate Limiter

The `TokenBucket` implements a classic token-bucket algorithm with high-resolution timing:

```
Capacity (burst) = rate_bps * 2 (default)
Refill rate      = rate_bps bits/second
Consumption      = packet_size_bytes * 8 bits per packet

For each intercepted packet:
  1. elapsed = now - last_refill
  2. tokens += elapsed * rate_bps (capped at capacity)
  3. if tokens >= packet_bits: consume → FORWARD
  4. else: DROP (throttle)
```

#### ARP Restoration on Cleanup

When a device is freed (`free` command) or Rustrict exits (`quit`/`exit`), the spoofer sends **3 bursts** of legitimate ARP replies to both the target and gateway, restoring the authentic MAC-to-IP bindings and undoing the cache poisoning.

---

### 6. State & Persistence Subsystem

```mermaid
flowchart TD
    subgraph STARTUP["Application Launch & Re-Arming"]
        Start(["rustrict.exe Launched"]) --> CheckState{"rustrict_state.json exists?"}
        CheckState -->|"Yes"| LoadState["PersistentState::load()"]
        CheckState -->|"No"| Ready["Interactive REPL Shell Ready"]

        LoadState --> ParseBlocked["Parse Persisted Block Rules"]
        ParseBlocked --> RestoreSpoof["ArpSpoofer::add() — Resume ARP Poisoning"]
        ParseBlocked --> RestoreDrop["TrafficLimiter::block() — Re-install Drop Filter"]
        RestoreSpoof --> Ready
        RestoreDrop --> Ready
    end

    subgraph RUNTIME["Interactive Runtime State"]
        Ready --> WaitCmd["rustrict > (Prompt Waiting for Command)"]

        WaitCmd -->|"block target"| ExecBlock["Add Host to PersistentState"]
        ExecBlock --> WriteSave1["Write to rustrict_state.json"]
        WriteSave1 --> EngageBlock["Engage Poisoning & WinDivert Drop"]
        EngageBlock --> WaitCmd

        WaitCmd -->|"free target"| ExecFree["Remove Host from PersistentState"]
        ExecFree --> WriteSave2["Update rustrict_state.json"]
        WriteSave2 --> RestoreTarget["Send Authentic ARP Burst & Remove Drop"]
        RestoreTarget --> WaitCmd

        WaitCmd -->|"scan --fresh"| Sweep["Subnet Sweep"]
        Sweep --> Reconcile["reconcile_hosts()"]
        Reconcile --> PreserveRule["Purge stale entries but PRESERVE all blocked hosts"]
        PreserveRule --> WaitCmd
    end

    subgraph SHUTDOWN["Clean Termination"]
        WaitCmd -->|"quit / exit"| StopEngine["Stop Spoofer & Limiter"]
        StopEngine --> Unpoison["Send 3-Burst Authentic ARP Replies"]
        Unpoison --> DisableFwd["Disable Windows IP Forwarding"]
        DisableFwd --> Exit(["Process Exited (Rules Preserved on Disk)"])
    end
```

**Persistence format** (`rustrict_state.json`):
```json
{
  "blocked_hosts": [
    {
      "ip": "192.168.18.50",
      "mac": "a4:83:e7:21:00:19",
      "name": "Lakshyas-iPhone",
      "direction": "Both"
    }
  ]
}
```

**Critical invariant:** During `scan --fresh`, the reconciliation algorithm **never** prunes hosts that have `persistent_block = true` or an active `HostStatus::Blocked` / `HostStatus::Limited` status — even if they are offline and absent from the fresh scan results.

---

### 7. Wireless Subsystem (802.11)

The wireless module provides low-level 802.11 frame analysis capabilities:

```mermaid
flowchart LR
    subgraph CAPTURE["Raw Wireless Capture"]
        RawFrame["Raw 802.11 Frame (bytes)"]
    end

    subgraph PARSING["Frame Parsing Pipeline"]
        Radiotap["RadiotapHeader::parse()"]
        Dot11["Dot11Frame::parse()"]
        TypeCheck{"Frame Type?"}
    end

    subgraph MANAGEMENT["Management Frame Analysis"]
        Beacon["Beacon → extract_ssid()"]
        Probe["Probe → extract_ssid()"]
        DeauthRx["Deauth Detection"]
    end

    subgraph DATA_FRAME["Data Frame Analysis"]
        EAPOLCheck{"is_eapol_frame()?"}
        HandshakeInspect["inspect_eapol_key()"]
        MsgIdentify{"Message #?"}
        Msg1["Message 1: ANonce + PMKID extraction"]
        Msg2["Message 2: SNonce"]
        Msg3["Message 3: GTK Install"]
        Msg4["Message 4: Confirmation"]
    end

    subgraph INJECTION["Frame Injection"]
        CraftDeauth["craft_deauth_frame()"]
        BiDeauth["craft_bidirectional_deauth()"]
        Inject["RawL2Sender::send_frame()"]
    end

    RawFrame --> Radiotap
    Radiotap -->|"Payload after header"| Dot11
    Dot11 --> TypeCheck

    TypeCheck -->|Management| Beacon
    TypeCheck -->|Management| Probe
    TypeCheck -->|Management| DeauthRx
    TypeCheck -->|Data| EAPOLCheck

    EAPOLCheck -->|Yes| HandshakeInspect
    HandshakeInspect --> MsgIdentify
    MsgIdentify --> Msg1
    MsgIdentify --> Msg2
    MsgIdentify --> Msg3
    MsgIdentify --> Msg4

    CraftDeauth --> Inject
    BiDeauth --> CraftDeauth
```

**Capabilities:**
- **Deauthentication frame crafting:** Generates valid IEEE 802.11 management frames (Frame Control `0x00c0`) with configurable reason codes. Bidirectional mode sends both AP→Client (Reason 7: Class 3 frame from nonassociated STA) and Client→AP (Reason 3: STA leaving) frames.
- **Radiotap header parsing:** Zero-copy extraction of channel frequency (MHz) and signal strength (dBm) from monitor-mode captures.
- **802.11 frame parsing:** Decodes Frame Control, addresses (Receiver, Transmitter, BSSID), To/From DS bits, and management subtypes (Beacon, Probe, Auth, Deauth, Disassociation).
- **WPA/WPA2 handshake inspection:** Identifies all four EAPOL-Key messages in the 4-way handshake by analyzing key info flags (`Pairwise`, `Install`, `ACK`, `MIC`). Extracts **PMKID** from RSN KDE tag (`00-0F-AC-04`) in Message 1.

---

## End-to-End Data Flow

### Device Discovery Pipeline

```mermaid
flowchart TD
    A["User: 'scan --fresh'"] --> B["RustrictCli::handle_scan()"]
    B --> C["Parse --fresh and --range flags"]
    C --> D["SubnetScanner::scan_subnet()"]

    D --> E["Compute network/broadcast bounds from netmask"]
    E --> F{"Fresh mode?"}

    F -->|No| G["Seed discovered set from Windows ARP cache"]
    F -->|Yes| H["Start with empty set"]

    G --> I["Spawn background thread: GatewayClient::refresh_hosts()"]
    H --> I

    I --> J["SSDP M-SEARCH + Unicast Probe → SOAP GetGenericHostEntry"]
    J --> K["Cache router DHCP lease table"]

    I --> L["Rayon parallel ARP sweep (batches of 48, 10ms throttle)"]
    L --> M["platform::send_arp(ip) for each IP in subnet"]
    M --> N{"MAC returned?"}
    N -->|Yes| O["Add to discovered set"]
    N -->|No| P["Skip IP"]

    O --> Q["Parallel identity resolution (Rayon par_iter)"]
    Q --> R["resolve_identity_with_gateway()"]
    R --> S["10-protocol priority chain"]
    S --> T["Return Vec of Host with hostname, vendor, source"]

    T --> U["RustrictCli::reconcile_hosts()"]
    U --> V{"Fresh mode?"}
    V -->|Yes| W["Prune offline unmanaged hosts, preserve blocked/limited"]
    V -->|No| X["Merge: update existing, append new, preserve all"]

    W --> Y["Re-index IDs, sort by IP"]
    X --> Y
    Y --> Z["render_hosts_table() → Terminal output"]
```

### Traffic Throttling & MITM Pipeline

```mermaid
sequenceDiagram
    participant User as User
    participant CLI as RustrictCli
    participant Resolve as Target Resolver
    participant Spoofer as ArpSpoofer
    participant L2 as RawL2Sender (Npcap)
    participant Target as Target Device
    participant Gateway as Network Gateway
    participant Limiter as TrafficLimiter
    participant WD as WinDivert Kernel Driver
    participant TB as TokenBucket

    User->>CLI: limit 1 500kbit --download
    CLI->>Resolve: resolve_targets("1")
    Resolve-->>CLI: Host at 192.168.18.50

    Note over CLI: Phase 1: Establish MITM Position
    CLI->>Spoofer: add(host)
    loop Every 2 seconds
        Spoofer->>L2: craft_arp_reply(target, "gateway is MY MAC")
        L2->>Target: Poisoned ARP Reply
        Spoofer->>L2: craft_arp_reply(gateway, "target is MY MAC")
        L2->>Gateway: Poisoned ARP Reply
    end
    Note over Target,Gateway: All traffic now routes through local machine

    Note over CLI: Phase 2: Install Rate Limiter
    CLI->>Limiter: limit(ip, Incoming, 500kbit)
    Limiter->>Limiter: Create HostLimitRule with DL TokenBucket(500kbps)
    Limiter->>WD: WinDivertOpen("ip", NETWORK_FORWARD)

    Note over WD: Phase 3: Runtime Packet Processing
    loop Every forwarded packet
        WD->>Limiter: Intercepted IPv4 packet
        Limiter->>Limiter: Extract src/dst IP from IPv4 header
        alt Packet destined for 192.168.18.50 (download)
            Limiter->>TB: try_consume(packet_bits)
            alt Tokens available
                TB-->>Limiter: true
                Limiter->>WD: WinDivertSend (forward packet)
            else Tokens exhausted
                TB-->>Limiter: false
                Note over Limiter: Packet DROPPED (throttled)
            end
        else Unrelated packet
            Limiter->>WD: WinDivertSend (forward immediately)
        end
    end
```

### Persistent Block Lifecycle

```mermaid
flowchart TD
    A["User: 'block 1'"] --> B["resolve_targets('1') → Host at 192.168.18.50"]
    B --> C["host.status = Blocked(Both)"]
    C --> D["host.persistent_block = true"]

    D --> E["PersistentState::add_blocked(host, Both)"]
    E --> F["Write rustrict_state.json to disk"]

    D --> G["ArpSpoofer::add(host) — Start ARP poisoning"]
    D --> H["TrafficLimiter::block(ip, Both) — DROP all packets"]

    F --> I["User closes Rustrict (quit)"]
    I --> J["ArpSpoofer::stop() — Restore ARP tables (3-burst)"]
    I --> K["TrafficLimiter::stop() — Close WinDivert handle"]
    I --> L["platform::disable_ip_forwarding()"]

    L --> M["User relaunches rustrict.exe"]
    M --> N["PersistentState::load() reads rustrict_state.json"]
    N --> O["For each blocked_host in state:"]
    O --> P["platform::send_arp(ip) → Resolve current MAC"]
    O --> Q["ArpSpoofer::add(host) — Resume poisoning"]
    O --> R["TrafficLimiter::block(ip, dir) — Resume dropping"]

    Q --> S["Device is blocked again without user intervention"]
    R --> S

    S --> T["User: 'free 1'"]
    T --> U["ArpSpoofer::remove(ip) — Restore ARP + stop poisoning"]
    T --> V["TrafficLimiter::unlimit(ip) — Remove WinDivert rule"]
    T --> W["PersistentState::remove_blocked(ip)"]
    W --> X["Write updated rustrict_state.json"]
    X --> Y["Block permanently removed"]
```

---

## CLI Command Reference

### Interactive Shell Commands

| Command | Syntax | Description |
| :--- | :--- | :--- |
| **`scan`** | `scan [--range <start-end>] [--fresh]` | Discovers online hosts via parallel ARP sweep. `--fresh` purges stale offline entries while preserving active rules. `--range 100-200` limits scan to a specific host range within the subnet. |
| **`hosts`** | `hosts` | Displays the current device inventory table with IP, MAC, verified hostname, vendor, online/offline state, and management status (Free / Limited / Blocked). Merges any passively discovered DHCP identities. |
| **`limit`** | `limit <targets> <rate> [--upload] [--download]` | Throttles device bandwidth. Targets can be device IDs (`1`), IP addresses (`192.168.18.50`), comma-separated lists (`1,192.168.18.50`), or `all`. Rate supports `bit`, `kbit`, `mbit`, `gbit` units. Direction defaults to `Both`. |
| **`block`** | `block <targets> [--upload] [--download]` | Completely cuts off device internet access by dropping all forwarded packets. **Persists across restarts** — blocked devices are saved to `rustrict_state.json` and automatically re-armed on next launch. |
| **`free`** | `free <targets>` | Removes all limits and blocks for specified devices. Restores authentic ARP cache entries. Removes persistent block rules from disk. |
| **`add`** | `add <ip> [--mac <mac>]` | Manually inserts a device into the management table. If `--mac` is omitted, the MAC is resolved via the Windows kernel ARP API. |
| **`clear`** | `clear` / `cls` | Clears the terminal screen. |
| **`help`** | `help` / `?` | Displays command reference. |
| **`exit`** | `quit` / `exit` | Stops all spoofing, restores ARP tables, disables IP forwarding, and exits cleanly. |

### Target Resolution Syntax

Targets support flexible mixed-format addressing:

```
rustrict > block 1                    # By device ID
rustrict > block 192.168.18.50        # By IPv4 address
rustrict > block 1,2,3                # Multiple IDs
rustrict > block 1,192.168.18.50,3    # Mixed IDs and IPs
rustrict > block all                  # All discovered devices
rustrict > limit all 200kbit          # Throttle entire network
```

---

## Requirements

| Requirement | Details |
| :--- | :--- |
| **Operating System** | Windows 10 / 11 (x86_64) |
| **Privileges** | Administrator terminal (PowerShell or Command Prompt) |
| **Npcap** | [npcap.com](https://npcap.com/) — installed in **WinPcap API-compatible mode** |
| **WinDivert** | `WinDivert.dll` + `WinDivert64.sys` — auto-bundled by `build.rs` or manually placed alongside `rustrict.exe` |
| **Rust Toolchain** | `rustc` / `cargo` 1.75+ (for building from source) |

---

## Building from Source

```powershell
# Clone the repository
git clone https://github.com/Neutron-0/rustrict.git
cd rustrict

# Build optimized release binary
cargo build --release

# Run the test suite (26 tests)
cargo test

# Launch (Administrator terminal required)
.\target\release\rustrict.exe
```

The compiled binary is located at `target\release\rustrict.exe`. WinDivert drivers are automatically copied to the release directory by the build script.

---

## Project Structure

```
rustrict/
├── Cargo.toml                    # Package manifest (rustrict v2.0.0)
├── Cargo.lock                    # Dependency lockfile
├── build.rs                      # Build script: auto-bundles WinDivert binaries
├── .gitignore                    # Excludes target/, state file, IDE configs
├── README.md                     # This document
│
├── src/
│   ├── main.rs                   # Binary entry point: banner, elevation check, REPL launch
│   ├── lib.rs                    # Library root: exports all 11 modules
│   ├── types.rs                  # Core types: MacAddress, Host, BitRate, Direction, HostStatus, NameSource
│   │
│   ├── cli/
│   │   ├── mod.rs                # CLI module exports
│   │   ├── banner.rs             # ASCII art banner renderer
│   │   ├── prompt.rs             # RustrictCli: REPL loop, command handlers, reconciliation logic
│   │   └── table.rs              # Host inventory table renderer (comfy-table)
│   │
│   ├── platform/
│   │   ├── mod.rs                # Platform gate: compile_error for non-Windows
│   │   └── windows.rs            # Windows API bindings: SendARP, IsUserAnAdmin, PowerShell commands
│   │
│   ├── scanner/
│   │   ├── mod.rs                # Scanner module exports
│   │   └── arp.rs                # SubnetScanner: parallel ARP sweep, batch throttling, gateway integration
│   │
│   ├── resolver/
│   │   ├── mod.rs                # Identity resolver: 10-protocol priority chain, HTTP title probe
│   │   ├── passive.rs            # PassiveIdentitySniffer: background DHCP Option 12 capture
│   │   ├── oui.rs                # OUI vendor database (25+ manufacturers)
│   │   ├── smb.rs                # SMB2 NTLMSSP Type 2 challenge hostname extraction
│   │   ├── tls.rs                # TLS X.509 certificate Common Name parser
│   │   ├── netbios.rs            # NetBIOS NBNS Node Status Query (UDP 137)
│   │   ├── mdns.rs               # mDNS reverse PTR lookup (UDP 5353)
│   │   ├── llmnr.rs              # LLMNR PTR query (UDP 5355)
│   │   └── dns.rs                # Reverse DNS via nslookup
│   │
│   ├── gateway/
│   │   ├── mod.rs                # GatewayClient: caching coordinator
│   │   ├── ssdp.rs               # SSDP M-SEARCH + unicast HTTP probe for UPnP service discovery
│   │   ├── soap.rs               # SOAP request executor + XML tag extractor
│   │   └── hosts.rs              # GatewayHostEntry struct
│   │
│   ├── spoofer/
│   │   ├── mod.rs                # Spoofer module exports
│   │   ├── engine.rs             # ArpSpoofer: background poisoning worker, ARP restoration
│   │   └── raw_l2.rs             # RawL2Sender: Npcap pcap_sendpacket, ARP frame crafting
│   │
│   ├── limiter/
│   │   ├── mod.rs                # Limiter module exports
│   │   ├── divert.rs             # TrafficLimiter: WinDivert NETWORK_FORWARD packet filter
│   │   └── token_bucket.rs       # TokenBucket + SharedTokenBucket rate limiter
│   │
│   ├── monitor/
│   │   ├── mod.rs                # Monitor module exports
│   │   └── counter.rs            # BandwidthMeter: per-host atomic traffic counters
│   │
│   ├── wireless/
│   │   ├── mod.rs                # Wireless module exports
│   │   ├── deauth.rs             # 802.11 Deauthentication frame crafter
│   │   ├── frame.rs              # Dot11Frame parser, FrameType/ManagementSubtype enums
│   │   ├── handshake.rs          # WPA 4-way handshake inspector, PMKID extractor
│   │   └── radiotap.rs           # Radiotap header parser (channel freq, signal dBm)
│   │
│   └── state.rs                  # PersistentState: JSON serialization for durable block rules
│
└── tests/
    ├── unit_tests.rs             # MAC formatting, OUI lookup, BitRate parsing, TokenBucket, ARP crafting, Deauth, EAPOL
    ├── test_dhcp.rs              # DHCP Option 12 packet parsing
    ├── test_smb.rs               # SMB2 NTLMSSP Type 2 challenge parsing
    ├── test_tls.rs               # X.509 certificate CN extraction
    ├── test_gateway.rs           # SOAP XML parsing, SSDP header parsing, GatewayHostEntry construction
    └── test_target_resolution.rs # Target resolver: ID/IP/mixed/all, dedup, fresh rescan, persistence roundtrip
```

---

## Test Suite

Rustrict includes **26 automated tests** covering all critical subsystems:

| Test File | Tests | Coverage |
| :--- | :---: | :--- |
| `unit_tests.rs` | 7 | MAC formatting/parsing, OUI vendor lookup, BitRate unit parsing, TokenBucket rate-limiting, Layer 2 ARP reply frame crafting, 802.11 Deauth frame generation, EAPOL frame detection |
| `test_target_resolution.rs` | 12 | Target resolution by ID, by IP, mixed lists, `all` keyword, deduplication, unknown ID/IP errors, ambiguous records, non-destructive upsert, fresh rescan pruning with blocked device preservation, PersistentState roundtrip |
| `test_gateway.rs` | 4 | SOAP XML tag extraction, missing tag handling, SSDP response header parsing, GatewayHostEntry construction |
| `test_dhcp.rs` | 1 | DHCP Option 12 (Host Name) extraction from raw BOOTP packet bytes |
| `test_smb.rs` | 1 | SMB2 NTLMSSP Type 2 challenge AV_PAIR parsing (MsvAvDnsComputerName / MsvAvNbComputerName) |
| `test_tls.rs` | 1 | X.509 certificate Common Name extraction via ASN.1 OID `2.5.4.3` |

Run the full suite:
```powershell
cargo test
```

---

## External Dependencies

| Dependency | Type | Purpose |
| :--- | :--- | :--- |
| **WinDivert** (`WinDivert.dll`, `WinDivert64.sys`) | Kernel driver + DLL | Intercepts IPv4 packets at the `NETWORK_FORWARD` layer for bandwidth throttling and packet dropping. Dynamically loaded at runtime. |
| **Npcap** (`wpcap.dll`) | User-mode DLL | Raw Layer 2 Ethernet frame transmission (`pcap_sendpacket`) for ARP spoofing, promiscuous packet capture (`pcap_open_live` / `pcap_next_ex`) for passive DHCP snooping. |
| **Windows iphlpapi.dll** | System DLL | Native `SendARP` API for synchronous kernel-level ARP resolution during subnet scanning. |
| **PowerShell** | System utility | Network interface discovery (`Get-NetRoute`, `Get-NetIPAddress`, `Get-NetAdapter`) and IP forwarding management (`Set-NetIPInterface`). |