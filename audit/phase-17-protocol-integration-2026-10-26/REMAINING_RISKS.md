# Rustrict Phase 17 — Remaining Operational Risks & Lab Hardware Requirements

**Document Version:** 1.0.0  
**Date:** 2026-10-26  
**Status:** Post-Phase 17 Protocol Simulation Baseline  

---

## 1. What Loopback Simulation Proves vs What Requires Physical Lab Testing

The Phase 17 loopback integration harness (`tests/support/router_emulator/`) proves that:
1. Rustrict correctly forms real HTTP request headers, JSON-RPC envelopes, SOAP XML bodies, and REST JSON schemas.
2. Production adapters correctly invoke and supervise Windows native `curl.exe` processes without leaking file handles, hanging on Expect-100 headers, or deadlocking on pipe buffers.
3. Transports enforce bounded memory consumption (<2 MiB response ceilings) and timeout bounds.
4. Error handling correctly maps HTTP 401, HTTP 500, SOAP Faults, redirects, and network drops to typed `AdminError` variants.
5. Multi-target partial application triggers atomic rollback and proper error propagation.
6. Interactive CLI confirmation gates prevent unauthorized or accidental router mutations.

However, **loopback simulation cannot prove physical router behaviors**:
1. **Physical Interface Drops & Half-Open TCP Sockets**: A router power drop, cable disconnection, or switch reset creates half-open TCP states that local loopback does not experience.
2. **Firmware-Specific SOAP/REST Quirks**:
   - Specific FRITZ!OS versions (e.g. 7.29 vs 7.50+) handle `X_AVM-DE_HostFilter` session tokens with subtle XML namespace differences.
   - MikroTik RouterOS v7.1 vs v7.14 have minor schema variations in REST output.
   - Ubiquiti UniFi Network Application v7 vs v8 altered CSRF cookie headers and API paths.
3. **High-Load Latency Spikes**: Routers undergoing heavy traffic or CPU exhaustion may exceed normal HTTP timeout thresholds (e.g., OpenWrt ubus blocking on slow flash commits).
4. **Autonomous Hardware Expiry Validation**: While cron jobs (`openwrt-ssh`), scheduler scripts (`mikrotik-rest`), and host filter expirations (`avm-tr064`) are syntax-verified, autonomous hardware recovery across router reboots can only be proven on physical hardware.

---

## 2. Mandatory Pre-Conditions for Physical Router Testing (Stage 1)

Before connecting Rustrict to any physical router:
1. Execute the Stage 1 Runbook in `audit/phase-17-protocol-integration-2026-10-26/STAGE_1_OPERATOR_PACKET.md`.
2. Ensure the test router is in an isolated, private test VLAN with zero connection to the internet or production networks.
3. Verify baseline router configuration snapshots are exported and archived offline prior to test launch.
4. Keep native management tools (OpenWrt serial/SSH, MikroTik WinBox, FRITZ!Box web interface) open and ready for immediate manual override if required.
