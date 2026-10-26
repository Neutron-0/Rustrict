# Rustrict — Unresolved Defects and Technical Debt Register

**Audit Cycle:** Post-Remediation Verification  
**Date:** 2026-10-24  
**Scope:** Inventory of confirmed unaddressed vulnerabilities, technical debt, architectural limitations, and operational risks remaining in the Rustrict codebase following the Phase 1 remediation pass.  
**Classification System:**  
- **Severity:** High / Medium / Low / Informational  
- **Status:** Unresolved / Partially Addressed / Accepted Architectural Limitation  

---

## 1. Executive Summary

While Phase 1 remediation successfully eliminated the critical and high-severity security vulnerabilities (SEC-01 through SEC-04, SEC-06, SEC-07, CODE-01), several low-to-medium severity findings, defense-in-depth gaps, and operational limitations remain in the codebase. These issues do not cause immediate runtime crashes or silent security bypasses under standard operations, but they represent technical debt and potential failure points under adversarial conditions or multi-instance concurrency.

This document catalogs every remaining issue, provides technical details, reproduction paths, and recommended remediation steps for future development phases.

---

## 2. Unresolved Defects and Technical Debt Register

### DEF-01: Lack of Cross-Process OS Kernel File Locking for Persistence Store
- **Severity:** Medium
- **Status:** Partially Addressed (In-Memory Merge Implemented; OS File Lock Absent)
- **Component:** `src/core/policy/engine.rs` (`PolicyEngine::persist_internal`, `sync_from_disk_if_present`)
- **Description:**  
  Although Phase 1 remediation added in-memory timestamp comparison and bidirectional merging during disk syncs, Rustrict still does not acquire a Windows OS kernel file lock (`LockFileEx` or `fs2::FileExt::lock_exclusive`) when reading or writing `rustrict_policies.json`.
- **Failure Mode & Risk:**  
  If two independent Rustrict GUI/CLI processes simultaneously call `persist_internal`, both processes will read the file, merge changes in memory, and attempt atomic rename (`std::fs::rename`). While atomic rename prevents file corruption or half-written files, the last writer will overwrite the previous writer's atomic rename, potentially losing policies committed within the millisecond window between read and rename.
- **Reproduction:**  
  Spawn two distinct OS processes that continuously modify and save policy states simultaneously at > 50 writes/second. Observe periodic `PermissionDenied` errors or dropped intermediate policy updates due to Windows file-sharing violations on rename.
- **Recommended Remediation:**  
  Integrate `fs2` or call Win32 `LockFileEx` on a dedicated companion lockfile (`rustrict_policies.json.lock`) before executing `sync_from_disk_if_present` and hold it until `std::fs::rename` completes.

---

### DEF-02: Intermediate Secret String Zeroization Omission (SEC-08)
- **Severity:** Low (Defense-in-Depth)
- **Status:** Unresolved
- **Component:** `src/gateway/admin/mod.rs`, `src/gateway/admin/credentials.rs`, `src/gateway/admin/curl_util.rs`
- **Description:**  
  Passwords and API tokens stored in `AdminCredentials::Password(String)` and `AdminCredentials::Token(String)` are stored in standard heap-allocated Rust `String` instances. When credentials are decrypted via DPAPI (`ProtectedBuffer`), they are cloned into standard strings and eventually dropped without zeroizing memory.
- **Failure Mode & Risk:**  
  Sensitive authentication credentials persist in uninitialized heap memory until overwritten by subsequent allocations. In the event of a user-mode memory dump, hibernation file inspection, or process scraping attack, plaintext passwords may be recoverable from process RAM.
- **Reproduction:**  
  Authenticate to a router using `router connect unifi`. Force a mini-dump of the Rustrict process via Windows Task Manager. Search the `.dmp` file for the entered plaintext password string. The password will be present in the heap dump.
- **Recommended Remediation:**  
  Adopt `secrecy::SecretString` or `zeroize::Zeroize` / `zeroize::Zeroizing<String>` across all `AdminCredentials` structs and transport configuration builders, ensuring buffers are scrubbed (`SecureZeroMemory`) when dropped.

---

### DEF-03: CRLF Line Endings in OpenWrt SSH Script Execution (NET-01)
- **Severity:** Low
- **Status:** Unresolved
- **Component:** `src/gateway/admin/openwrt.rs` (`OpenWrtProvider::build_enforcement_script`)
- **Description:**  
  When compiling multi-line shell command batches for remote execution on OpenWrt via SSH, commands are joined using `\n`. However, if scripts or strings are generated using Windows format macros (`format!("\r\n...")`) or if crontab lines are appended, Windows CRLF line endings may be transmitted over the SSH stream.
- **Failure Mode & Risk:**  
  The OpenWrt POSIX shell (`/bin/ash` or `busybox sh`) treats `\r` as part of the command identifier or argument rather than whitespace. Commands may fail with `ash: uci\r: not found` or create malformed firewall section names.
- **Reproduction:**  
  Generate an OpenWrt batch script containing `\r\n` and execute it through `ash` in OpenWrt. Observe syntax errors due to trailing carriage return bytes.
- **Recommended Remediation:**  
  Add an explicit sanitization filter (`script.replace("\r\n", "\n").replace('\r', "\n")`) immediately before sending any shell command payload across the `SshClient` channel.

---

### DEF-04: Lack of Windows Security Descriptor (DACL) on Temp Files
- **Severity:** Low
- **Status:** Unresolved
- **Component:** `src/gateway/admin/curl_util.rs` (`AutoCleanFile::create_restricted`)
- **Description:**  
  `AutoCleanFile::create_restricted` generates temporary payload files in `%TEMP%` using standard file creation attributes. On Windows, files created in `%TEMP%` inherit the discretionary access control list (DACL) of the temp folder.
- **Failure Mode & Risk:**  
  While standard Windows configurations grant temp folder access only to the current user and Administrators, custom enterprise environments or misconfigured multi-user workstations may have broader read permissions on the shared `%SYSTEMROOT%\Temp` directory if Rustrict runs as a system service.
- **Reproduction:**  
  Inspect the ACL of the created temporary file in PowerShell via `Get-Acl $tempPath`. Verify that permissions are inherited from parent container rather than explicitly restricted with an explicit DACL containing only `OWNER_RIGHTS: FullControl`.
- **Recommended Remediation:**  
  Utilize `windows-sys` or `windows::Win32::Security` to set an explicit `SECURITY_ATTRIBUTES` structure with `DACL_PROTECTED` during file creation.

---

### DEF-05: Absence of Automated Hardware-in-the-Loop (HIL) Integration Tests
- **Severity:** Medium (Operational Risk)
- **Status:** Unresolved (Acceptable for Isolated Software Phase; Mandatory for General Release)
- **Component:** Entire `src/gateway/admin/` router provider subsystem
- **Description:**  
  All 187 test cases pass cleanly using synthetic mock processes, in-memory HTTP response parsers, and command capture harnesses. No integration tests execute against real physical appliances (UniFi Dream Machine, AVM FRITZ!Box 7590, MikroTik hEX / CHR, or OpenWrt 23.05).
- **Failure Mode & Risk:**  
  Subtle firmware variations, authentication challenge handshakes (e.g. Fritz!Box PBKDF2 hashing vs MD5 challenge-response), RouterOS rate-limiting, or UniFi UniFiOS v3 CSRF token lifetime changes could cause failures in the field despite 100% test pass rates in mock environments.
- **Reproduction:**  
  Run `cargo test --all-targets`. All tests pass. Connect to a physical Fritz!Box running FRITZ!OS 8.00 with multi-factor authentication enabled; authentication may fail due to unhandled 2FA prompt requirements.
- **Recommended Remediation:**  
  Establish an isolated test lab with virtualized firmware instances (OpenWrt x86 in QEMU, MikroTik RouterOS CHR in Hyper-V/VirtualBox) integrated into a night-build CI pipeline.

---

## 3. Prioritized Remediation Roadmap

| Priority | Issue ID | Area | Effort | Target Milestone |
| :---: | :---: | :---: | :---: | :---: |
| **P1** | **DEF-01** | Cross-Process File Locking (`LockFileEx`) | Low (1 day) | Phase 15.1 |
| **P2** | **DEF-03** | OpenWrt SSH CRLF Stripping Sanitizer | Minimal (2 hours) | Phase 15.1 |
| **P3** | **DEF-02** | Secret Zeroization (`secrecy` / `zeroize`) | Medium (2 days) | Phase 15.2 |
| **P4** | **DEF-04** | Windows Temp File Explicit DACL | Medium (1 day) | Phase 15.2 |
| **P5** | **DEF-05** | Virtualized Router Lab (HIL) Testing | High (1-2 weeks) | Phase 16 |

---

## 4. Conclusion

The unresolved defects identified above are technical debt and defense-in-depth enhancements; **none of them invalidate the critical security fixes implemented in Phase 1**. The codebase remains robust, memory-safe, and free of blocking compiler warnings. The verdict of **`CONDITIONALLY READY FOR ISOLATED LAB TESTING`** stands firm, and the above register provides a clear roadmap for subsequent hardening cycles.
