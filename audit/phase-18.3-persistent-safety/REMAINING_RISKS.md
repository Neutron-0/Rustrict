# Rustrict Phase 18.3 — Remaining Operational Risks & Lab Hardware Requirements

**Document Version:** 1.0.0  
**Date:** 2026-10-27  
**Platform:** Native Windows 11 MSVC  

---

## 1. What Hermetic Testing & Emulation Proves vs Physical Lab Testing

### Proved Hermetically & Synthetically:
1. **Persistent Block Restoration Fail-Closed Safety**: Persisted blocked targets cannot be added to `ArpSpoofer` or `TrafficLimiter` if scoped forwarding or packet injection capabilities fail. State files are strictly preserved without deletion or overwrite.
2. **Observable Forwarding Teardown**: Windows forwarding cleanup executes state query verification on restore, captures partial or complete failures in a structured `ForwardingCleanupReport`, preserves `currently_mutated = true` on failure for retryability, and exits with code 1.
3. **Loopback Protocol Safety**: All router provider transports (OpenWrt HTTP/SSH, MikroTik REST, AVM TR-064, UniFi REST) enforce bounded timeouts, payload size limits (<2 MiB), zero-retry mutation policy, and uncertain outcome transitions (`PolicyLifecycleState::Unknown`).
4. **NIC Health Telemetry Accuracy**: Monotonically decreasing counters, missing RX/TX errors, and missing RX/TX discards are rejected from claiming `Normal` health. PowerShell queries terminate and reap hung processes reliably.

### Requires Physical Router Validation (Stage 1 Lab Testing):
1. **Physical Link State & Hardware Driver Interop**: Real Npcap raw packet injection against physical network switch hardware (802.3 PHY link negotiation, jumbo frame behavior, switch port security / MAC flooding limits).
2. **Real Router Firewall Behavior**: Specific firmware implementations of `nftables`, `iptables`, RouterOS filter rules, TR-064 parental filters, and UniFi traffic rules under real network traffic loads.
3. **Out-of-Band Disconnect Recovery**: Physical cable unplugging or power disruption during active sessions to verify physical out-of-band recovery protocols.

---

## 2. Active Risk Register Post-Phase 18.3

| Risk ID | Description | Severity | Mitigation in Phase 18.3 | Lab Requirement |
| :--- | :--- | :---: | :--- | :--- |
| **R-18.3-01** | External Operating System or Group Policy Forwarding Override | Low | Scoped forwarding state is verified immediately after setting. Any failure is recorded in `failed_interfaces` and reported on exit. | Operator monitors `Get-NetIPInterface -Forwarding` during testing. |
| **R-18.3-02** | Flash Storage Wear-Leveling Secret Retention | Low | In-memory secrets use zeroizing wrappers (`ProtectedCredentials`). Temporary files use RAII `AutoCleanFile`. | Controller uses BitLocker or dedicated test machine wiped after hardware testing. |
| **R-18.3-03** | Router Expiration Clock Drift Without NTP | Medium | Providers without autonomous recovery reject temporary policies fail-closed. | Lab router NTP synchronized before Stage 1 execution. |
| **R-18.3-04** | Target Device Static IP Change | Medium | Rescan preserves blocked records while flagging missing hosts as `Persisted [Inactive]` if network parameters shift. | Controlled static DHCP reservations on lab test network. |
