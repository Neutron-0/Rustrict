# Rustrict Phase 18 — Implementation Report
**Sprint Date:** October 27, 2026  
**Target Environment:** Native Windows 11 MSVC (`x86_64-pc-windows-msvc`), stable `rustc 1.97.1`, MSRV `rustc 1.88.0`  
**Git Base Commit:** `73644aedf2fe36adf97611482a9d51d683ff6c22`  

---

## 1. Executive Summary

Phase 18 successfully eliminates non-hermetic network side effects from automated testing and normal tool invocation, protects host IP forwarding configurations from unwarranted global mutations, and introduces a read-only physical network-adapter health diagnostic command (`nic`).

All 275 automated tests across 27 test binaries compile and pass cleanly on native Windows 11 under both stable Rust (`rustc 1.97.1`) and the declared MSRV (`rustc 1.88.0`). Zero clippy warnings exist under `-D warnings`.

---

## 2. Key Remediations & Technical Architecture

### 2.1 Blocker 1 Resolved: Hermetic Scanner Test Seam
- **Issue:** Previously, `SubnetScanner::scan_subnet` and `scan_range` initiated background threads that contacted the local default gateway via UPnP/SSDP multicast (`239.255.255.250:1900`) and issued kernel ARP queries (`SendARP`) across live subnets during test runs.
- **Architectural Seam:**
  - Introduced the `NetworkProbe` trait in `src/scanner/arp.rs` with methods:
    - `send_arp(&self, ip: Ipv4Addr) -> Option<MacAddress>`
    - `get_arp_cache(&self) -> Vec<(Ipv4Addr, MacAddress)>`
    - `resolve_identity(&self, ip: Ipv4Addr, mac: &MacAddress, local_ip: Ipv4Addr, gateway_ip: Ipv4Addr, gc: Option<&GatewayClient>) -> HostIdentity`
  - Implemented `RealNetworkProbe` for production live scanning (delegating to Windows `SendARP` and active resolution).
  - Implemented `NoopNetworkProbe` and `MockNetworkProbe` for tests.
  - Added constructors `SubnetScanner::new_with_probe(...)` and `SubnetScanner::new_safe_test(...)`.
  - Extracted pure mathematical range calculations:
    - `calculate_subnet_ip_range(&self) -> Vec<Ipv4Addr>`
    - `calculate_bounded_range(&self, start: Ipv4Addr, end: Ipv4Addr) -> Vec<Ipv4Addr>`
  - Verified in `tests/test_safe_networking.rs` that range planning and boundary checks issue strictly **0 ARP probes** and **0 network queries**.

### 2.2 Blocker 2 Resolved: Safe Scoped IP Forwarding
- **Issue:** Previously, `platform::enable_ip_forwarding()` was unconditionally executed at program startup, and `platform::disable_ip_forwarding()` was unconditionally executed at exit across all system network interfaces (`Set-NetIPInterface -Forwarding Disabled`), disrupting pre-existing user configurations (WSL2, Hyper-V, VPN adapters).
- **Implementation:**
  - Eliminated global forwarding mutations from `main.rs` startup.
  - Scoped forwarding mutations strictly to the active interface alias (e.g., `'Wi-Fi'`) and address family (`IPv4`).
  - Added `CommandRunner` abstraction with `SystemCommandRunner` and `MockCommandRunner` for test verification.
  - Pre-flight State Capture: Before mutating forwarding state, `ensure_scoped_forwarding_enabled` queries `Get-NetIPInterface -InterfaceAlias <alias> -AddressFamily IPv4`.
    - If already `Enabled`, Rustrict marks `currently_mutated = false` and performs **zero changes**.
    - If `Disabled`, Rustrict enables it on that interface and marks `currently_mutated = true`.
  - Scoped Restoration: `cleanup_forwarding()` inspects tracked state and restores **only interfaces mutated by Rustrict** back to `Disabled`. If no interfaces were mutated during the session, zero PowerShell commands are executed.
  - Both normal exit and `SetConsoleCtrlHandler` invoke `cleanup_forwarding()`.
  - Forwarding is deferred until explicitly required by active subsystems (`limit`, `block`, `isolate`, `simulate`).

### 2.3 Read-Only Physical NIC Health Diagnostic (`nic`)
- **Subsystem:** Added `src/monitor/nic.rs` and integrated into interactive CLI prompt via `nic` and `adapter` commands.
- **Data Model:**
  - `NicAdapterInfo`: Name, InterfaceIndex, Description, Status, LinkSpeed (parsed to bps).
  - `NicRawStats`: Received/Sent bytes, Discarded packets, Packet errors (Rx/Tx).
  - `NicHealthReport`: Measured raw telemetry deltas and throughput (bps) alongside heuristic health classification.
- **Sampling Window:** Bounded 2-second default interval (configurable) measuring exact rate deltas.
- **LinkSpeed Parser:** Parses units `Gbps`, `Mbps`, `Kbps`, `bps` with case insensitivity and floating point multipliers.
- **Calculations & Resilience:**
  - Bitrate: `((delta_bytes * 8.0) / elapsed_secs) as u64`
  - Independent Tx/Rx utilization: `(rate_bps / link_speed_bps) * 100.0`
  - Counter reset & wraparound protection: uses `saturating_sub` to safely handle driver resets without panics or spurious spikes.
- **Classification Engine:**
  - `Normal`: Error rate == 0, discards == 0, peak utilization < 70%.
  - `Elevated`: Peak utilization between 70% and 90%.
  - `Saturated`: Peak utilization >= 90%.
  - `Degraded`: Active error or discard increments during the sampling window.
  - `Unavailable`: Adapter disconnected (`Status != "Up"`) or zero link speed.

---

## 3. Comprehensive Feature-to-Test Matrix

| Subsystem | Scope / Functionality | Implementation Files | Automated Verification Suites |
| :--- | :--- | :--- | :--- |
| **1. Windows Environment & Discovery** | Admin detection, Npcap / WinDivert DLL checks, default route (`Get-NetRoute`), adapter discovery | `src/platform/windows.rs` | `test_fixes::test_check_environment_diagnostics`, `test_safe_networking` |
| **2. ARP Scanning & Subnet Range** | RFC 3021 /31 and /32 subnets, range clamping (max 65,534 hosts), inversion guard, SendARP kernel calls | `src/scanner/arp.rs` | `test_verification::test_subnet_scanner_rfc3021_and_range_clamping`, `test_safe_networking::test_subnet_scanner_boundary_calculations_send_zero_probes` |
| **3. Device Identity Resolution** | Passive DHCP Option 12, mDNS question echo, LLMNR PTR parsing, NetBIOS, HTTP title extraction | `src/resolver/` | `test_dhcp`, `test_fixes::test_mdns_parsing_with_question_echo`, `test_fixes::test_llmnr_ptr_response_parsing`, `test_fixes::test_extract_html_title_with_unicode_and_case` |
| **4. Target Resolution & Management** | Parsing IDs, IPs, mixed lists, `all`, deduplication, non-destructive upsert, state persistence | `src/cli/prompt.rs`, `src/types.rs` | `test_target_resolution::*` (12 tests) |
| **5. Scoped Operational Boundaries** | Strict mode target authorization, CIDR containment, target exclusion by IP/MAC | `src/core/scope.rs` | `test_assessment::test_scope_manager_boundaries_and_exclusions`, `test_verification::test_scope_manager_persistence_and_enforcement` |
| **6. Bandwidth Throttling & Limiting** | Token bucket algorithm, byte consumption, refill intervals, burst rate enforcement | `src/limiter/token_bucket.rs` | `test_verification::test_token_bucket_shaping_and_refill`, `unit_tests::test_token_bucket` |
| **7. L2 ARP Spoofing & MITM** | Raw Ethernet frames, unicast blackhole MAC (`02:bf:00:00:00:01`), spoofed vs authentic gateway reply crafting | `src/spoofer/` | `test_verification::test_blackhole_mac_spec_and_properties`, `test_verification::test_blocked_vs_limited_arp_frame_crafting`, `unit_tests::test_craft_arp_reply` |
| **8. Fault Injection & Resilience** | Packet drop simulation, latency delay injection, millisecond jitter distribution | `src/limiter/divert.rs` | `test_assessment::test_fault_profile_simulation_metrics` |
| **9. Security Posture Checks** | TLS handshake negotiation, obsolete protocol detection (SSLv3-TLS1.1), SMBv1 & SMB signing checks | `src/resolver/tls.rs`, `src/resolver/smb.rs` | `test_tls::*` (2 tests), `test_smb::*` (2 tests) |
| **10. Assessment Evidence Export** | SARIF v2.1.0 schema compliance, structured JSON findings, executive Markdown generation | `src/core/reporting.rs` | `test_assessment::test_report_export_markdown_json_sarif` |
| **11. State & Credential Persistence** | DPAPI credential protection, memory zeroization, atomic file replacement, cross-process advisory lock | `src/state.rs`, `src/gateway/admin/persistence.rs` | `test_persistence::*` (9 tests), `test_reliability::*` (9 tests) |
| **12. Router Administration Adapters** | OpenWrt (ubus + SSH), MikroTik (REST), UniFi (REST), AVM (TR-064 SOAP), Mock provider | `src/gateway/admin/` | `test_openwrt_admin` (21), `test_ssh_admin` (17), `test_mikrotik_admin` (20), `test_unifi_admin` (19), `test_avm_admin` (20), `test_router_admin` (12) |
| **13. Policy Engine & Safety Guarantees** | Preflight checks, controller/gateway lockout protection, atomic rollback, autonomous recovery watchdog, loopback protocol emulation | `src/gateway/admin/policy_engine.rs`, `tests/support/router_emulator/` | `test_policy_engine` (13), `test_policy_views` (7), `test_provider_contracts` (8), `test_protocol_integration` (17), `test_cli_confirmation` (10), `test_diagnostics` (15) |
| **14. NIC Health Diagnostic Telemetry** | Physical adapter telemetry, LinkSpeed parsing, Rx/Tx throughput rates, error/discard tracking, heuristic classification | `src/monitor/nic.rs`, `src/platform/windows.rs` | `src/monitor/nic.rs::tests` (7 tests), `test_safe_networking::*` (6 tests) |
