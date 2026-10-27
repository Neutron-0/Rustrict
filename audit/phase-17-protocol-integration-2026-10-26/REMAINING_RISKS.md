# Rustrict Phase 17 — Remaining Operational Risks & Lab Hardware Requirements

**Document Version:** 1.2.0
**Date:** 2026-10-27 (Phase 17.1 Restored & Reconciled Baseline)
**Status:** Post-Phase 17.1 Mutation Retry Safety & Protocol Baseline

---

## 1. What Loopback Simulation Proves vs What Requires Physical Lab Testing

The Phase 17 and Phase 17.1 loopback integration harness (`tests/support/router_emulator/`) proves that:
1. Rustrict correctly constructs real wire-level HTTP request headers, JSON-RPC envelopes, SOAP XML bodies, and REST JSON schemas.
2. Production adapters correctly invoke and supervise Windows native `curl.exe` processes without leaking file handles, hanging on Expect-100 headers, or deadlocking on pipe buffers.
3. Transports enforce bounded memory consumption (<2 MiB response ceilings) and timeout bounds.
4. Error handling correctly maps HTTP 401, HTTP 500, SOAP Faults, redirects, and network drops to typed `AdminError` variants.
5. Multi-target partial application triggers atomic rollback and proper error propagation.
6. Interactive CLI confirmation gates prevent unauthorized or accidental router mutations.
7. **Mutation Retry Safety**: Blanket `--retry` arguments are completely eliminated from mutation-capable curl transports. Mutation calls are executed strictly once (`max_attempts == 1`). If the transport drops or times out after mutation dispatch, no automatic retry is attempted.
8. **Ambiguous Outcome Isolation**: Lost mutation responses transition policies to `PolicyLifecycleState::Unknown`, preventing conflicting follow-up mutations from being applied until reconciled out-of-band.

---

## 2. Active Operational Risks Register

The following risks remain active and cannot be resolved solely through synthetic testing or unit tests:

### 2.1 Lack of Physical Router Testing
- Synthetic loopback testing over `127.0.0.1:0` simulates socket disconnects and payload framing, but cannot replicate the real physical Ethernet/Wi-Fi PHY states, link renegotiation, or electrical packet drops that occur during live router testing.

### 2.2 Provider and Firmware Variations
- **OpenWrt**: Different releases (e.g. 21.02 vs 23.05+) transitioned from iptables (`fw3`) to nftables (`fw4`). While UCI abstraction buffers some differences, custom firewall zones or third-party packages can alter firewall behavior.
- **MikroTik RouterOS**: RouterOS v7 introduced REST API changes compared to earlier v6 (which required WinBox or SSH/API ports). Specific firmware builds may exhibit slight JSON schema nuances or require REST to be manually enabled (`/ip/service/enable rest`).
- **AVM FRITZ!Box**: Different FRITZ!OS releases (e.g. 7.29 vs 7.50+) altered TR-064 authentication flows and multi-user privilege structures. ISP-branded FRITZ!Boxes often lock down TR-064 access entirely.
- **Ubiquiti UniFi**: The UniFi Network Application API is officially private and evolves between major versions (v7 vs v8+ changed cookie handling, CSRF tokens, and application routing prefixes).

### 2.3 Ambiguous Mutation Outcomes After Dropped Responses
- If a router receives a firewall mutation packet and applies it, but the TCP connection drops, resets (RST), or times out before the client receives the HTTP 200 OK response:
  - The client cannot know whether the mutation was applied or rejected.
  - Rustrict correctly sets `PolicyLifecycleState::Unknown` and prevents conflicting mutations.
  - However, the router may remain in a modified state until an operator performs an out-of-band inspection or manual recovery.

### 2.4 Incomplete Rollback or Inaccessible Router During Recovery
- If an atomic rollback is triggered (e.g., during multi-target enforcement) and the router becomes unreachable mid-rollback:
  - Rustrict marks the policy as `PartialFailure` and records `unrecovered_applied_targets`.
  - The router will continue to drop transit for the unrecovered targets until the operator intervenes via out-of-band management console (serial/SSH/WinBox).

### 2.5 Router-Side Expiry and Clock Synchronization Dependencies
- Autonomous recovery mechanisms (e.g., OpenWrt watchdog cron script, MikroTik scheduler script) rely on the router's internal clock or uptime counter.
- If the router lacks an RTC (common in consumer routers) and NTP synchronization fails or drifts, router-resident expiration timers may fire prematurely or fail to trigger.

### 2.6 Persistence and Local State Verification Limitations
- Rustrict maintains cross-process file-locked persistence (`rustrict-policy-store.json.lock`).
- If an operator manually edits or deletes the state file, or if another tool alters router firewall rules independently, local state and router state will diverge until a manual `router refresh` is performed.
- Where router APIs do not provide a full ruleset dump, third-party rules cannot be authoritatively verified.

### 2.7 Evidence-Export Provenance Limitations
- Exported diagnostic evidence bundles (`router export-evidence`) contain cryptographic metadata, system timestamps, and sanitized configurations.
- However, because evidence bundles are stored as local JSON files, their provenance is bound to the security of the host controller filesystem.

### 2.8 Secret Zeroization and Temporary-File Erasure Limitations
- Credentials in memory use zeroizing memory wrappers (`ProtectedCredentials`), and temporary curl argument files use RAII auto-deletion (`AutoCleanFile`).
- However, on modern flash storage (SSDs) and Windows virtual memory paging files, physical sector overwrites cannot be guaranteed at the hardware level due to wear-leveling algorithms.

---

## 3. Mandatory Pre-Conditions for Physical Router Testing (Stage 1)

Before connecting Rustrict to any physical router:
1. Execute the Stage 1 Runbook in `audit/phase-17-protocol-integration-2026-10-26/STAGE_1_OPERATOR_PACKET.md`.
2. Ensure the test router is in an isolated, private test VLAN with zero connection to the internet or production networks.
3. Verify baseline router configuration snapshots are exported and archived offline prior to test launch.
4. Keep native management tools (OpenWrt serial/SSH, MikroTik WinBox, FRITZ!Box web interface) open and ready for immediate manual override if required.
5. In the event of an ambiguous outcome (`PolicyLifecycleState::Unknown`), follow Section 6 of the Operator Packet: halt Rustrict, query the router via native console, and restore the baseline configuration before resuming testing.
