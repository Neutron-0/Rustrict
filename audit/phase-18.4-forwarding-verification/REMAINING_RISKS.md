# Rustrict Phase 18.4 — Remaining Operational Risks & Lab Hardware Requirements

**Document Version:** 1.0.0  
**Date:** 2026-10-27  
**Platform:** Native Windows 11 MSVC  

---

## 1. What Hermetic Testing & Emulation Proves vs Physical Lab Testing

### Proved Hermetically & Synthetically:
1. **OS Forwarding Precondition Verification**: Scoped forwarding is verified against actual OS state before reporting readiness. If the OS remains `Disabled` after setter execution, or if verification fails, operation fails closed.
2. **Teardown Baseline Restoration**: Captured original baseline (`Enabled` or `Disabled`) is preserved and verified upon cleanup, with bounded retries (3 attempts) and structured error reporting.
3. **Subnet Network & Broadcast Target Rejection**: Rejection of subnet network addresses and directed-broadcast addresses across single and overlapping CIDRs, while preserving RFC 3021 `/31` point-to-point and `/32` host routes.
4. **Fail-Closed Persistence**: Unchecked or invalid records are rejected from enforcement without altering or deleting the saved persistent store on disk.
5. **Runtime Reconciliation**: Loss of forwarding during rescan deactivates enforcement to prevent blackholing; reactivation occurs only after forwarding is re-enabled and verified in the OS.

### Requires Physical Router Validation (Stage 1 Lab Testing):
1. **Physical Link State & Hardware Driver Interop**: Real Npcap raw packet injection against physical network switch hardware (802.3 PHY link negotiation, jumbo frame behavior, switch port security / MAC flooding limits).
2. **Real Router Firewall Behavior**: Specific firmware implementations of `nftables`, `iptables`, RouterOS filter rules, TR-064 parental filters, and UniFi traffic rules under real network traffic loads.
3. **Out-of-Band Disconnect Recovery**: Physical cable unplugging or power disruption during active sessions to verify physical out-of-band recovery protocols.

---

## 2. Active Risk Register Post-Phase 18.4

| Risk ID | Description | Severity | Mitigation in Phase 18.4 | Lab Requirement |
| :--- | :--- | :---: | :--- | :--- |
| **R-18.4-01** | External Operating System or Group Policy Forwarding Override | Low | Scoped forwarding state is verified before readiness and after setter execution. Bounded retries and structured reporting alert operator on exit. | Operator monitors `Get-NetIPInterface -Forwarding` during testing. |
| **R-18.4-02** | Flash Storage Wear-Leveling Secret Retention | Low | In-memory secrets use zeroizing wrappers (`ProtectedCredentials`). Temporary files use RAII `AutoCleanFile`. | Controller uses BitLocker or dedicated test machine wiped after hardware testing. |
| **R-18.4-03** | Router Expiration Clock Drift Without NTP | Medium | Providers without autonomous recovery reject temporary policies fail-closed. | Lab router NTP synchronized before Stage 1 execution. |
| **R-18.4-04** | Target Device Static IP Change | Medium | Rescan preserves blocked records while flagging missing hosts as `Persisted [Inactive]` if network parameters shift. | Controlled static DHCP reservations on lab test network. |
