# Rustrict Phase 18 — Remaining Risks & Pre-Lab Registry
**Sprint Date:** October 27, 2026  
**Status:** Software Ready for Physical Stage 1 Lab Authorization  

---

## 1. Active Risk Register

| Risk ID | Severity | Subsystem | Description | Mitigating Control Implemented | Remaining Residual Exposure |
| :---: | :---: | :--- | :--- | :--- | :--- |
| **RSK-18-01** | Medium | Router Hardware | Physical firmware deviations from simulated REST/SOAP schemas (OpenWrt fw4, MikroTik RouterOS v7.14+, UniFi Network 8.x, AVM FRITZ!OS 7.5x). | Full loopback emulation suite (`test_protocol_integration.rs`) with fault injection, timeout handling, and ambiguous outcome guards. | Physical execution gated behind Stage 1 Isolated-Lab Authorization Packet. Zero hardware tests run yet. |
| **RSK-18-02** | Low | NIC Telemetry | Third-party or virtual network drivers (TAP, VPN, Hyper-V, WireGuard) reporting non-standard `LinkSpeed` strings or omitting statistical counters in `Get-NetAdapterStatistics`. | Regex/split unit-aware link speed parser (`parse_link_speed_to_bps`), default fallbacks, safe error formatting, and `Unavailable` classification on missing data. | Telemetry on unusual virtual interfaces may report `Unavailable` or 0 bps without failing application runtime. |
| **RSK-18-03** | Low | IP Forwarding | Interface alias renaming during an active session while scoped forwarding is enabled. | Interfaces are tracked by initial alias and verified against PowerShell `Get-NetIPInterface`. `cleanup_forwarding()` safely handles command errors if an interface disappears. | If an interface is disabled in Device Manager while mutated, restoration command will gracefully report error. |
| **RSK-18-04** | Medium | WinDivert Driver | Driver signature requirements and antivirus heuristic flags for `WinDivert64.sys` on corporate Windows workstations. | `platform::check_environment()` diagnostic inspects driver file presence and reports clear diagnostic warnings rather than crashing. | Production packet diversion requires local administrative privileges and driver signing trust. |

---

## 2. Stage 1 Operator Authorization Decision

- **Recommendation:** **READY FOR PHYSICAL STAGE 1 TESTING** (in isolated laboratory environment).
- **Justification:**
  - Ordinary automated tests are completely safe and hermetic, issuing 0 live ARP or SSDP probes.
  - Startup IP forwarding mutations are eliminated, preventing interference with host network stacks.
  - The deterministic router protocol emulator confirms correct operation classification, retry safety, and uncertain mutation tracking across OpenWrt, MikroTik, UniFi, and AVM providers.
  - All 275 tests compile and pass under both stable Rust and the declared 1.88.0 MSRV.
