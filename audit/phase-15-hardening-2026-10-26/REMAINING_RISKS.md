# Rustrict Phase 15 Hardening — Remaining Risks and Pre-Lab Safety Boundaries

**Date:** 2026-10-26  
**Auditor / Verification Lead:** Antigravity Autonomous Systems Review  

---

## 1. Physical Hardware Divergence vs Mock Transport Testing

### Risk Description
All automated tests in the repository run against deterministic in-memory mock transports simulating OpenWrt ubus, MikroTik REST, AVM TR-064 SOAP, and UniFi Network REST. While these mock transports rigorously simulate HTTP error codes, authentication failures, lock contention, timeout semantics, and payload structures, **they do not run physical router firmware**.

### Specific Areas of Potential Divergence:
- **AVM FRITZ!OS Versions:** AVM's `X_AVM-DE_HostFilter` SOAP action can exhibit firmware-specific behavior across FRITZ!OS 7.x vs 8.x, particularly concerning whether WAN access rules take effect immediately or require DHCP lease renegotiation for certain wireless clients.
- **MikroTik RouterOS v7 REST API Behavior:** Certain RouterOS minor versions (e.g. 7.1 vs 7.15) have undocumented changes in JSON error response schemas and handling of concurrent REST sessions.
- **OpenWrt Firewall Variants:** OpenWrt 21.02 used `iptables` / `fw3`, while OpenWrt 22.03+ uses `nftables` / `fw4`. While the ubus `uci` configuration layer remains identical across versions, `nft` reload times and rule counter increments can differ under heavy traffic.

### Required Mitigation:
- Strict compliance with `audit/pre-lab-safety-gate-2026-10-24/LAB_TEST_CHECKLIST.md` and `audit/pre-lab-safety-gate-2026-10-24/STAGE_1_READ_ONLY_PROTOCOL.md`.
- No Stage 2 (mutating) physical tests may be executed without first completing Stage 1 (read-only diagnostics and inventory) with complete Wireshark PCAP and router baseline snapshots.

---

## 2. Process Crash During Child Process Execution

### Risk Description
If the host operating system experiences an abrupt power loss or the Rustrict process is forcibly killed (e.g. `taskkill /F`) while a `curl.exe` or `ssh.exe` child process is actively applying a policy:
1. `AutoCleanFile` RAII drop handlers will not run if the host process is killed with `SIGKILL` / `TerminateProcess`.
2. A temporary payload file in `%TEMP%` might remain on disk (although its contents are ephemeral JSON/XML payloads and curl configs are passed via stdin, not command line arguments).
3. The router might be left in a partially applied state if the child process was interrupted during a multi-command sequence.

### Required Mitigation:
- The persistent store's autonomous watchdog record (`watchdog_job`) ensures that on OpenWrt and MikroTik, the on-router cron/scheduler will clean up rules regardless of controller host termination.
- For AVM and UniFi, temporary policies without on-router autonomous recovery are explicitly prohibited and rejected by preflight capability classification.

---

## 3. Windows DPAPI Storage Scope and User Context

### Risk Description
The `save_protected_credentials` and `load_protected_credentials` functions utilize Windows Data Protection API (`CryptProtectData` with `CRYPTPROTECT_UI_FORBIDDEN`).
- Credentials encrypted by User A cannot be decrypted by User B on the same Windows machine.
- If Rustrict is run as an unprivileged user to configure credentials and later run as a Windows Service under `NT AUTHORITY\SYSTEM` or a different service account, credential decryption will fail with `AuthenticationFailed`.

### Required Mitigation:
- Document clearly that CLI credential management commands (`rustrict router login`) must be run under the exact same Windows user account that executes scheduled or daemon tasks.

---

## 4. SSH Known Hosts and Man-in-the-Middle (MitM) Protections

### Risk Description
OpenWrt administration over SSH relies on `ssh.exe`. While `SshConfig` supports `known_hosts_path` and `pinned_host_key`, if an operator connects to a newly flashed router without providing a pinned host key or pre-populating `known_hosts`, OpenSSH prompt behavior could block execution if `StrictHostKeyChecking` is misconfigured.

### Required Mitigation:
- The implementation strictly validates host keys and fails closed if host key checking fails or if an untrusted host key is encountered. Operators must always provide known host entries or pinned host keys.
