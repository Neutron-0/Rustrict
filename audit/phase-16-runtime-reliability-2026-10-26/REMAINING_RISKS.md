# Rustrict Phase 16 — Remaining Operational Risks & Hardware Constraints

**Date:** 2026-10-26
**Status:** Post-Phase 16 Hardening

---

## 1. Physical Hardware & Network Lab Constraints

1. **Synthetic vs Physical Hardware Verification**:
   - All tests in the current suite run against local mock transports, loopback interfaces, or simulated process pipelines.
   - While transports implement bounded pipe draining, timeout handling, and contract conformance, physical router interaction involves vendor-specific quirks that synthetic tests cannot fully simulate:
     - OpenWrt `ubus` session timeouts under high CPU load.
     - MikroTik RouterOS REST API rate-limiting or concurrent connection limits.
     - FRITZ!OS TR-064 SOAP authentication challenge variations across regional firmware builds.
     - Ubiquiti UniFi Controller version differences (Network Application 7.x vs 8.x).
   - **Mitigation**: Staged physical lab testing (Stage 1 through Stage 3) according to `audit/pre-lab-safety-gate-2026-10-24/LAB_TEST_CHECKLIST.md` remains mandatory prior to operational deployment.

2. **AVM FRITZ!Box TR-064 Service Availability**:
   - FRITZ!Box parental control transit blocking relies on the `X_AVM-DE_HostFilter` TR-064 service.
   - Certain stripped ISP-customized FRITZ!Box firmwares disable or omit this service.
   - **Mitigation**: Preflight identity and service description parsing checks for the presence of `X_AVM-DE_HostFilter` and fails closed with a clear diagnostic message if absent.

3. **Ubiquiti UniFi Self-Signed TLS Certificates**:
   - Many on-premise UniFi Cloud Key or self-hosted controllers run with self-signed TLS certificates.
   - In strict TLS mode, curl rejects self-signed certificates (`AdminError::SecurityViolation`).
   - **Mitigation**: Operators must supply `--ca-cert <path>` to establish an explicit trust anchor for the controller's TLS certificate.

4. **SSH Client Availability on Non-Standard Windows Builds**:
   - `openwrt-ssh` relies on native `ssh.exe` discovery (standard in Windows 10/11 OpenSSH Optional Feature).
   - If `ssh.exe` is missing or disabled by Windows group policy, SSH connections fail closed.
   - **Mitigation**: Clear error reporting directs operators to enable the OpenSSH Client feature or connect via `openwrt-http`.

5. **Firewall Chain Conflicts with Third-Party Router Packages**:
   - OpenWrt `firewall4` (nftables) rules injected by Rustrict use dedicated named chains and priority offsets.
   - Routers running conflicting packages (e.g. `mwan3`, `sqm-scripts`, or custom raw iptables scripts) might intercept or override chain evaluation order.
   - **Mitigation**: Preflight diagnostic checks and `router reconcile` verify chain integrity.
