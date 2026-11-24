# Rustrict Platform Expansion & Anti-Eviction Resilience Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Evolve Rustrict from a standalone Windows CLI network shaper into a comprehensive, enterprise-grade network security and infrastructure management platform featuring multi-layer anti-eviction connectivity, advanced router configuration, kernel-level traffic observability, blue-team intrusion detection, red-team lab simulations, enrolled remote administration agents, and an authenticated Next.js operational dashboard.

**Architecture:** A modular client-server model centered around an asynchronous core engine (`rustrict-core` + `tokio` + `axum`), streaming telemetry and events over an authenticated WebSocket/IPC bus to `rustrict-web` and `rustrict-cli`. Infrastructure is governed through existing and extended router providers, Layer 2-4 traffic observability is powered by WinDivert kernel stream dissection, network connection persistence is guaranteed via L2 neighbor pinning and an encrypted roaming overlay tunnel, and remote endpoints are managed via an enrolled `rustrict-agent`.

**Tech Stack:** 
- **Core Engine & Backend:** Rust (edition 2021, rustc 1.88+), `tokio`, `axum`, `tower-http`, `parking_lot`, `serde`, `serde_json`, `windows-sys`, `socket2`, `rayon`.
- **Packet & Kernel Layer:** WinDivert 2.2 (`WinDivert.dll`), Npcap (`wpcap.dll`), Windows IP Helper API (`iphlpapi.dll`).
- **Resilience & Overlay:** WireGuard / Noise protocol (or authenticated mTLS UDP tunnel), static ARP table pinning via Win32 NetNeighbor.
- **Frontend / Dashboard:** Next.js 16 (App Router, Turbopack), React 19, Tailwind CSS v4, Lucide Icons, Canvas API / HTML5 Graph visualization.

**Spec:** [docs/superpowers/specs/2026-11-24-rustrict-platform-expansion-design.md](file:///d:/Vault/Rustrict/docs/superpowers/specs/2026-11-24-rustrict-platform-expansion-design.md)

---

## Global Constraints

- Must compile on Windows (x86_64-pc-windows-msvc) with zero regressions to existing `cargo test` suite (33 test modules).
- Administrative mutations must be strictly permission-gated by the `ScopeManager` (CIDR boundaries, IP/MAC exclusions, strict mode).
- All offensive privilege-escalation simulations must be locked to subnets explicitly tagged `lab_isolated: true`.
- Packet interception must preserve fail-safe recovery: if the process terminates, all network routes and ARP tables must auto-heal cleanly.
- No covert persistence, backdoor access, or hidden remote control: `rustrict-agent` must be explicitly enrolled, visible, and uninstallable.
- Sensitive credentials (router passwords, tunnel private keys) must be protected using Windows DPAPI (`src/gateway/admin/credentials.rs`) and zeroed in memory on drop (`zeroize`).

---

## Review Focus

1. **WinDivert Packet Throughput & Latency:** In-flight DNS/SNI dissection and flow tracking must not introduce noticeable latency or packet drops on high-throughput connections (>500 Mbps).
2. **ARP Healer Race Conditions:** The anti-eviction ARP guard must not create an infinite broadcast loop when competing with another active ARP spoofer on the LAN.
3. **Router Disconnect Cleanliness:** Temporary router policies and firewall pinholes must automatically expire via the duration lease or clean up on engine shutdown.
4. **WebSocket Backpressure:** Slow dashboard web clients must not cause unbound memory growth in the core broadcast event bus.
5. **Agent Authentication & Revocation:** Severed or revoked agent certificates must immediately fail connection attempts and trigger alerts.

---

## System Architecture

```mermaid
flowchart TD
    subgraph PRESENTATION["Presentation & Operator Tier"]
        WebUI["rustrict-web (Next.js 16 / React 19)"]
        CLI["rustrict CLI (Interactive REPL)"]
    end

    subgraph API_GATEWAY["API & Control Gateway (axum / tokio)"]
        APIServer["Authenticated REST & WS Server"]
        EventBus["Broadcast Event Bus (tokio::sync::broadcast)"]
        RBAC["RBAC & Scope Gatekeeper"]
    end

    subgraph CORE_SERVICES["Core Subsystems"]
        Resilience["Anti-Eviction & Resilience Subsystem\n- Static ARP Guard\n- DHCP Fallback Profile\n- Roaming Overlay Tunnel\n- Router Admin Exemption"]
        RouterEngine["Advanced Router Control\n- DHCP/DNS Management\n- NAT & Port Forwards\n- Config Diff & Backup\n- OpenWrt / MikroTik / UniFi / AVM"]
        TrafficEngine["Traffic Observability\n- WinDivert 5-Tuple Flow Tracker\n- In-Flight DNS Dissector\n- Passive TLS SNI Dissector\n- IPFIX / NetFlow Exporter"]
        DefenseEngine["Blue-Team IDS & Telemetry\n- Rogue ARP / DHCP Detection\n- DNS Entropy & DGA Alerts\n- Incident Correlation Engine"]
        RedTeamEngine["Red-Team & Privilege Research\n- Attack-Path Topology Graph\n- Config Baseline Auditing\n- Isolated Lab Simulator"]
        AgentManager["Endpoint Agent Controller\n- mTLS Secure Channel\n- Host Telemetry Ingestion\n- Signed Remote Runner"]
    end

    subgraph ENDPOINTS["Network Nodes & Target Equipment"]
        RouterDevice["Physical Gateway / Switch"]
        ManagedAgent["rustrict-agent (Windows / Linux)"]
        NetworkTraffic["In-Flight Subnet Packets (WinDivert)"]
    end

    WebUI <-->|WebSocket & REST (JWT/Token)| APIServer
    CLI <-->|Local IPC / REST| APIServer
    APIServer --> RBAC
    RBAC --> CORE_SERVICES
    CORE_SERVICES --> EventBus
    EventBus -->|Live Telemetry Stream| APIServer

    Resilience --> RouterDevice
    RouterEngine --> RouterDevice
    TrafficEngine <--> NetworkTraffic
    DefenseEngine <--> TrafficEngine
    AgentManager <--> ManagedAgent
```

---

## Component Breakdown & Task Structure

### Phase 1: Core Async Engine, Event Bus & WebSocket Bridge

#### Task 1: Async Runtime Scaffolding & Broadcast Event Bus
**Files:**
- Create: `src/server/event_bus.rs`
- Create: `src/server/mod.rs`
- Modify: `Cargo.toml`
- Test: `tests/test_event_bus.rs`

**Interfaces:**
- Consumes: `crate::core::assessment::AuditFinding`, `crate::types::Host`
- Produces: `EngineEvent`, `EventBus::publish(event: EngineEvent)`, `EventBus::subscribe() -> Receiver<EngineEvent>`

- [ ] **Step 1: Write the failing test**
```rust
#[tokio::test]
async fn test_event_bus_broadcast() {
    let bus = EventBus::new(100);
    let mut rx = bus.subscribe();
    bus.publish(EngineEvent::HostDiscovered(sample_host())).unwrap();
    let received = rx.recv().await.unwrap();
    assert!(matches!(received, EngineEvent::HostDiscovered(_)));
}
```
- [ ] **Step 2: Run test to verify it fails**
Run: `cargo test --test test_event_bus` -> FAIL
- [ ] **Step 3: Implement `EventBus` and `EngineEvent`**
Add `tokio` (features `rt-multi-thread`, `sync`, `macros`) and `axum` to `Cargo.toml`. Implement bounded `broadcast::channel` with capacity eviction handling.
- [ ] **Step 4: Run test to verify it passes**
Run: `cargo test --test test_event_bus` -> PASS
- [ ] **Step 5: Commit**
`git commit -m "feat(server): implement core async event bus"`

---

#### Task 2: Authenticated REST & WebSocket API Server
**Files:**
- Create: `src/server/routes.rs`
- Create: `src/server/ws.rs`
- Create: `src/server/auth.rs`
- Modify: `src/server/mod.rs`
- Test: `tests/test_api_server.rs`

**Interfaces:**
- Consumes: `EventBus`, `ScopeManager`, `PolicyExecutionEngine`
- Produces: `start_api_server(bind_addr: SocketAddr, state: Arc<ServerState>) -> JoinHandle<()>`

- [ ] **Step 1: Write the failing test**
```rust
#[tokio::test]
async fn test_rest_hosts_endpoint_requires_auth() {
    let (addr, _handle) = spawn_test_server().await;
    let client = reqwest::Client::new();
    let resp = client.get(format!("http://{}/api/hosts", addr)).send().await.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}
```
- [ ] **Step 2: Run test to verify it fails**
Run: `cargo test --test test_api_server` -> FAIL
- [ ] **Step 3: Implement Axum routes with bearer token auth and WebSocket upgrade**
Implement `/api/hosts`, `/api/router/*`, `/api/traffic/flows`, `/api/ws` with token header validation and real-time event streaming.
- [ ] **Step 4: Run test to verify it passes**
Run: `cargo test --test test_api_server` -> PASS
- [ ] **Step 5: Commit**
`git commit -m "feat(server): add axum REST and WebSocket API endpoints"`

---

### Phase 2: Anti-Eviction & Connection Resilience Subsystem

#### Task 3: Layer 2 Static ARP Guard & Active Healer
**Files:**
- Create: `src/resilience/arp_guard.rs`
- Create: `src/resilience/mod.rs`
- Modify: `src/platform/windows.rs`
- Test: `tests/test_arp_guard.rs`

**Interfaces:**
- Consumes: `NetworkInterface`, `MacAddress`, `Ipv4Addr`
- Produces: `ArpGuard::lock_gateway(iface: &NetworkInterface) -> io::Result<()>`, `ArpGuard::verify_or_heal() -> bool`

- [ ] **Step 1: Write the failing test**
```rust
#[test]
fn test_arp_guard_neighbor_entry_creation() {
    let guard = ArpGuard::new(Ipv4Addr::new(192, 168, 1, 1), MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]));
    let cmd = guard.format_netsh_lock_command("Ethernet");
    assert!(cmd.contains("add neighbors"));
    assert!(cmd.contains("192.168.1.1"));
}
```
- [ ] **Step 2: Run test to verify it fails**
Run: `cargo test --test test_arp_guard` -> FAIL
- [ ] **Step 3: Implement ARP Guard with Windows IP Helper pinning & WinDivert ARP spoof drop**
Pin static ARP entry in Windows IP table and filter any inbound ARP reply claiming to be the gateway from a conflicting MAC address.
- [ ] **Step 4: Run test to verify it passes**
Run: `cargo test --test test_arp_guard` -> PASS
- [ ] **Step 5: Commit**
`git commit -m "feat(resilience): implement Layer 2 static ARP guard and anti-poisoning healer"`

---

#### Task 4: Router Infrastructure Admin Exemption
**Files:**
- Create: `src/resilience/router_exemption.rs`
- Modify: `src/gateway/admin/provider.rs`
- Modify: `src/gateway/admin/engine.rs`
- Test: `tests/test_router_exemption.rs`

**Interfaces:**
- Consumes: `RouterAdminProvider`, `PolicyExecutionEngine`, `MacAddress`, `Ipv4Addr`
- Produces: `PolicyExecutionEngine::enforce_admin_exemption(mac: MacAddress, ip: Ipv4Addr) -> Result<String, AdminError>`

- [ ] **Step 1: Write the failing test**
```rust
#[test]
fn test_router_admin_exemption_mock() {
    let mock = Arc::new(MockRouterAdminProvider::new());
    let engine = PolicyExecutionEngine::new(mock.clone(), default_store());
    let res = engine.enforce_admin_exemption(sample_mac(), sample_ip());
    assert!(res.is_ok());
    assert!(mock.has_exemption(sample_mac()));
}
```
- [ ] **Step 2: Run test to verify it fails**
Run: `cargo test --test test_router_exemption` -> FAIL
- [ ] **Step 3: Implement exemption across OpenWrt (nftables/firewall rule), MikroTik (/ip firewall filter rule), UniFi (traffic rule)**
Add `apply_admin_exemption` to `RouterAdminProvider` to inject persistent, top-priority bypass rules ensuring the station is never dropped or filtered by the router.
- [ ] **Step 4: Run test to verify it passes**
Run: `cargo test --test test_router_exemption` -> PASS
- [ ] **Step 5: Commit**
`git commit -m "feat(resilience): implement router-level administrative exemption rules"`

---

#### Task 5: Roaming Overlay Tunnel Daemon (WireGuard / TLS Stream Persistence)
**Files:**
- Create: `src/resilience/tunnel.rs`
- Modify: `src/resilience/mod.rs`
- Test: `tests/test_tunnel.rs`

**Interfaces:**
- Consumes: `TunnelConfig { endpoint: SocketAddr, psk: ProtectedString, keepalive_secs: u16 }`
- Produces: `ResilientTunnel::start() -> Result<TunnelHandle, io::Error>`, `TunnelHandle::is_connected() -> bool`

- [ ] **Step 1: Write the failing test**
```rust
#[test]
fn test_tunnel_keepalive_packet_crafting() {
    let tunnel = ResilientTunnel::new(sample_config());
    let pkt = tunnel.craft_heartbeat_payload();
    assert!(!pkt.is_empty());
}
```
- [ ] **Step 2: Run test to verify it fails**
Run: `cargo test --test test_tunnel` -> FAIL
- [ ] **Step 3: Implement tunnel connection manager with roaming failover and heartbeats**
Maintain an active outbound encrypted tunnel session. If the physical IP rebinds or gateway blips, trigger automatic endpoint roaming without terminating active control sessions.
- [ ] **Step 4: Run test to verify it passes**
Run: `cargo test --test test_tunnel` -> PASS
- [ ] **Step 5: Commit**
`git commit -m "feat(resilience): add roaming overlay tunnel for unkickable connection persistence"`

---

### Phase 3: Advanced Router & Infrastructure Management

#### Task 6: Router DHCP & DNS Configuration Management
**Files:**
- Create: `src/gateway/admin/dhcp_dns.rs`
- Modify: `src/gateway/admin/provider.rs`
- Modify: `src/gateway/admin/openwrt.rs`
- Modify: `src/gateway/admin/mikrotik.rs`
- Test: `tests/test_router_dhcp_dns.rs`

**Interfaces:**
- Produces: `RouterDhcpConfig`, `RouterDnsConfig`, `RouterAdminProvider::get_dhcp_leases()`, `RouterAdminProvider::set_static_lease()`

- [ ] **Step 1: Write failing tests for lease parsing and reservation injection**
- [ ] **Step 2: Run test to verify failure**
- [ ] **Step 3: Implement UCI / RouterOS REST calls for DHCP static bindings and DNS forwarders**
- [ ] **Step 4: Run test to verify pass**
- [ ] **Step 5: Commit**
`git commit -m "feat(router): add DHCP lease management and DNS forwarder configuration"`

---

#### Task 7: Router NAT, Port Forwarding & Routing Table Inspection
**Files:**
- Create: `src/gateway/admin/nat_routes.rs`
- Modify: `src/gateway/admin/provider.rs`
- Test: `tests/test_router_nat_routes.rs`

**Interfaces:**
- Produces: `PortForwardRule`, `RoutingTableEntry`, `RouterAdminProvider::list_port_forwards()`, `RouterAdminProvider::list_routes()`

- [ ] **Step 1: Write failing tests for port forward structure and routing table parsing**
- [ ] **Step 2: Run test to verify failure**
- [ ] **Step 3: Implement port forward and route extraction across OpenWrt and MikroTik providers**
- [ ] **Step 4: Run test to verify pass**
- [ ] **Step 5: Commit**
`git commit -m "feat(router): implement NAT port-forwarding and routing table inspection"`

---

#### Task 8: Router Configuration Backup, Diff & Rollback Engine
**Files:**
- Create: `src/gateway/admin/config_backup.rs`
- Modify: `src/gateway/admin/engine.rs`
- Test: `tests/test_router_config_backup.rs`

**Interfaces:**
- Produces: `ConfigSnapshot`, `ConfigDiff`, `backup_configuration()`, `diff_configurations()`, `restore_configuration()`

- [ ] **Step 1: Write failing tests for config snapshot diffing**
- [ ] **Step 2: Run test to verify failure**
- [ ] **Step 3: Implement text-based diffing with line additions/removals and safe transactional rollback**
- [ ] **Step 4: Run test to verify pass**
- [ ] **Step 5: Commit**
`git commit -m "feat(router): add config backup, side-by-side diffing, and rollback"`

---

### Phase 4: Network Traffic Observability & Packet Dissection

#### Task 9: In-Flight 5-Tuple Stateful Connection Tracker
**Files:**
- Create: `src/monitor/flow_tracker.rs`
- Modify: `src/limiter/divert.rs`
- Test: `tests/test_flow_tracker.rs`

**Interfaces:**
- Consumes: Raw IPv4 + TCP/UDP packets from WinDivert loop
- Produces: `ConnectionFlow`, `FlowKey { src: SocketAddrV4, dst: SocketAddrV4, proto: u8 }`, `FlowTracker::update_packet()`

- [ ] **Step 1: Write failing test verifying byte counter increments and TCP FIN session retirement**
- [ ] **Step 2: Run test to verify failure**
- [ ] **Step 3: Implement lock-free / read-optimized concurrent flow table with `dashmap` or partitioned `parking_lot::RwLock`**
- [ ] **Step 4: Run test to verify pass**
- [ ] **Step 5: Commit**
`git commit -m "feat(monitor): add 5-tuple stateful connection flow tracker"`

---

#### Task 10: In-Flight DNS & Passive TLS SNI Dissectors
**Files:**
- Create: `src/monitor/dns_dissector.rs`
- Create: `src/monitor/tls_sni.rs`
- Modify: `src/limiter/divert.rs`
- Test: `tests/test_dissectors.rs`

**Interfaces:**
- Produces: `DnsEvent { client: Ipv4Addr, domain: String, answers: Vec<Ipv4Addr> }`, `SniEvent { client: Ipv4Addr, server_name: String }`

- [ ] **Step 1: Write failing tests for parsing zero-copy DNS A-record responses and TLS ClientHello SNI extension**
- [ ] **Step 2: Run test to verify failure**
- [ ] **Step 3: Implement RFC 1035 wire parser and TLS ClientHello extension scanner without allocating on non-matching packets**
- [ ] **Step 4: Run test to verify pass**
- [ ] **Step 5: Commit**
`git commit -m "feat(monitor): implement in-flight DNS and TLS SNI dissectors"`

---

### Phase 5: Blue-Team Monitoring & Intrusion Detection

#### Task 11: Rogue ARP & DHCP Anomaly Detectors
**Files:**
- Create: `src/defense/arp_detector.rs`
- Create: `src/defense/dhcp_detector.rs`
- Create: `src/defense/mod.rs`
- Test: `tests/test_defense_detectors.rs`

**Interfaces:**
- Produces: `SecurityAlert { alert_type: AlertType, severity: AuditSeverity, source_mac: MacAddress, details: String }`

- [ ] **Step 1: Write failing test verifying alert generation when an unauthorized MAC replies for gateway IP**
- [ ] **Step 2: Run test to verify failure**
- [ ] **Step 3: Implement detection logic with gateway MAC fingerprint cache and valid DHCP server address validation**
- [ ] **Step 4: Run test to verify pass**
- [ ] **Step 5: Commit**
`git commit -m "feat(defense): implement rogue ARP and rogue DHCP intrusion detection"`

---

#### Task 12: DNS Anomaly & Tunneling Heuristics Engine
**Files:**
- Create: `src/defense/dns_heuristics.rs`
- Modify: `src/defense/mod.rs`
- Test: `tests/test_dns_heuristics.rs`

**Interfaces:**
- Produces: `calculate_shannon_entropy(s: &str) -> f64`, `DnsAnomalyDetector::inspect_query(domain: &str) -> Option<SecurityAlert>`

- [ ] **Step 1: Write failing test verifying Shannon entropy calculation (>4.2 flags DNS tunnel payload)**
- [ ] **Step 2: Run test to verify failure**
- [ ] **Step 3: Implement fast entropy calculator and NXDOMAIN rate tracker**
- [ ] **Step 4: Run test to verify pass**
- [ ] **Step 5: Commit**
`git commit -m "feat(defense): add DNS Shannon entropy calculation and tunneling heuristics"`

---

### Phase 6: Red-Team Testing & Controlled Privilege Research

#### Task 13: Attack-Path Topology & Exposure Graph
**Files:**
- Create: `src/probes/attack_graph.rs`
- Modify: `src/probes/mod.rs`
- Test: `tests/test_attack_graph.rs`

**Interfaces:**
- Consumes: Discovered hosts, open ports, banners, and routing tables
- Produces: `AttackGraphNode`, `AttackPath`, `AttackGraph::compute_attack_paths() -> Vec<AttackPath>`

- [ ] **Step 1: Write failing test computing multi-hop pivot routes based on dual-homed hosts and weak protocols**
- [ ] **Step 2: Run test to verify failure**
- [ ] **Step 3: Implement directed graph structure using `petgraph` or adjacency matrix with risk weighting**
- [ ] **Step 4: Run test to verify pass**
- [ ] **Step 5: Commit**
`git commit -m "feat(probes): add attack-path mapping and subnet exposure graph"`

---

#### Task 14: Isolated Lab Privilege-Escalation Simulation Harness
**Files:**
- Create: `src/core/lab_simulation.rs`
- Modify: `src/core/scope.rs`
- Test: `tests/test_lab_simulation.rs`

**Interfaces:**
- Consumes: `ScopeManager` (verifies `target.is_lab_isolated == true`)
- Produces: `SimulationRun`, `SimulationResult`, `run_privilege_simulation(target: Ipv4Addr, test_id: &str) -> Result<SimulationResult, ScopeError>`

- [ ] **Step 1: Write failing test proving simulation aborts with `ScopeViolation` if target is outside lab CIDR**
- [ ] **Step 2: Run test to verify failure**
- [ ] **Step 3: Implement hard-gated simulation executor with cryptographic confirmation and audit trails**
- [ ] **Step 4: Run test to verify pass**
- [ ] **Step 5: Commit**
`git commit -m "feat(core): add scope-gated lab privilege-escalation simulation harness"`

---

### Phase 7: Enrolled Remote Administration Agent (`rustrict-agent`)

#### Task 15: Lightweight Host Agent Binary & mTLS Client
**Files:**
- Create: `crates/rustrict-agent/Cargo.toml`
- Create: `crates/rustrict-agent/src/main.rs`
- Create: `crates/rustrict-agent/src/telemetry.rs`
- Create: `crates/rustrict-agent/src/runner.rs`
- Modify: Root `Cargo.toml` (convert to workspace or add member)
- Test: `tests/test_agent_protocol.rs`

**Interfaces:**
- Produces: `HostTelemetry { cpu_usage: f32, ram_used_mb: u64, disk_pct: f32, active_services: Vec<String> }`
- Enforces: Visible tray / console status, revocable certs, non-root user execution constraints.

- [ ] **Step 1: Write failing test for telemetry serialization and mTLS handshake simulation**
- [ ] **Step 2: Run test to verify failure**
- [ ] **Step 3: Implement agent daemon with `sysinfo` metric collection and authenticated command dispatcher**
- [ ] **Step 4: Run test to verify pass**
- [ ] **Step 5: Commit**
`git commit -m "feat(agent): scaffold rustrict-agent lightweight host administration daemon"`

---

### Phase 8: Unified Web Operations Dashboard Integration (`rustrict-web`)

#### Task 16: Next.js WebSocket Client & Live Topology Visualizer
**Files:**
- Create: `d:\Vault\rustrict-web\src\lib\api-client.ts`
- Create: `d:\Vault\rustrict-web\src\components\TopologyCanvas.tsx`
- Create: `d:\Vault\rustrict-web\src\components\FlowStreamTable.tsx`
- Modify: `d:\Vault\rustrict-web\src\app\page.tsx`

**Interfaces:**
- Consumes: `ws://localhost:9090/api/ws` (EngineEvent stream)
- Renders: Real-time network nodes, live bandwidth gauges, connection flows, and active alerts.

- [ ] **Step 1: Build typed WebSocket client with auto-reconnect and state store (Zustand or React context)**
- [ ] **Step 2: Implement dynamic force-directed topology graph rendering hosts, routers, and traffic links**
- [ ] **Step 3: Wire up real-time 5-tuple flow streaming table with search and filtering**
- [ ] **Step 4: Verify UI locally with `npm run build` and `npm run dev`**
- [ ] **Step 5: Commit**
`git commit -m "feat(web): add live WebSocket topology canvas and flow stream table"`

---

#### Task 17: Web Router Management & Security Operations Console
**Files:**
- Create: `d:\Vault\rustrict-web\src\components\RouterAdminPanel.tsx`
- Create: `d:\Vault\rustrict-web\src\components\IncidentTimeline.tsx`
- Create: `d:\Vault\rustrict-web\src\components\ResilienceStatus.tsx`
- Modify: `d:\Vault\rustrict-web\src\app\page.tsx`

**Interfaces:**
- Consumes: `/api/router/*`, `/api/defense/alerts`, `/api/resilience/status`
- Renders: One-click admin exemption toggle, DHCP lease management, security alert timeline, and config diff viewer.

- [ ] **Step 1: Implement RouterAdminPanel with DHCP reservations and port-forwarding forms**
- [ ] **Step 2: Implement IncidentTimeline displaying real-time blue-team alerts and SARIF audit results**
- [ ] **Step 3: Implement ResilienceStatus showing ARP lock state, gateway health, and tunnel status**
- [ ] **Step 4: Verify complete build with `npm run build`**
- [ ] **Step 5: Commit**
`git commit -m "feat(web): add router management console, incident timeline, and resilience dashboard"`

---

## Verification & Validation Plan

### Automated Test Suite
Run the full test suite at each phase:
```powershell
# Core unit and integration tests
cargo test --all

# Run specific new subsystems
cargo test --test test_event_bus
cargo test --test test_arp_guard
cargo test --test test_router_exemption
cargo test --test test_flow_tracker
cargo test --test test_defense_detectors
cargo test --test test_lab_simulation

# Verify web client compiles without type or lint errors
cd d:\Vault\rustrict-web
npm run lint
npm run build
```

### Manual & Lab Verification Scenarios
1. **Anti-Eviction Verification**:
   - Run Rustrict on a test Windows host with ARP Guard enabled.
   - Fire an intentional ARP poisoner (`arpspoof` or test script) from a second machine targeting the gateway IP.
   - Verify Rustrict drops the poisoned ARP frame in WinDivert and transmits a corrective Gratuitous ARP to the gateway within 50ms.
2. **Router Admin Exemption**:
   - Connect to an OpenWrt / MikroTik test router.
   - Apply admin exemption via CLI / Web dashboard.
   - Confirm persistent firewall rule appears at line 1 of the forward chain and station MAC is assigned a static lease.
3. **Observability & DNS Dissection**:
   - Browse various websites from a client machine whose traffic passes through the WinDivert limiter.
   - Verify destination domains appear in real time on the `rustrict-web` Flow Table without decrypting TLS payloads.
4. **Clean Shutdown & Emergency Teardown**:
   - Trigger Ctrl+C or kill `rustrict.exe`.
   - Verify Windows static ARP neighbor entries are cleared, WinDivert driver unloads cleanly, and the network adapter continues normal operation.
