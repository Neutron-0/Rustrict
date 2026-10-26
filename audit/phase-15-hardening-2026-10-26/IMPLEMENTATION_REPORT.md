# Rustrict Phase 15 Hardening — Implementation Report

**Date:** 2026-10-26  
**Target Environment:** Native Windows 10/11 (MSVC, PowerShell, native Win32 APIs)  
**Baseline Hash:** `15e68b194f06d797a6f21fd00355cd912a0944a7`  

---

## Executive Summary

Phase 15 transitioned Rustrict from extensive multi-stage auditing and safety reviews into active engineering implementation, reliability hardening, secret lifetime minimization, regression testing, and CI automation.

All implementations strictly respect the core architectural and safety mandates:
1. Native Windows compatibility (no WSL, Docker, or Unix shell dependencies).
2. Zero physical router mutation during development and automated testing (relying on deterministic in-memory mock transports).
3. Cross-process safety for concurrently running Rustrict instances.
4. Fail-closed contract enforcement ensuring partial failures are never silently reported as successes.
5. Cryptographic and memory hygiene ensuring secret material is redacted and zeroed.

---

## Key Hardening Implementations

### 1. Cross-Process Policy Persistence Locking (`fs2`)
- **Problem:** When multiple Rustrict processes run concurrently (e.g., CLI queries, background daemons, or separate operator consoles), uncoordinated read-modify-write cycles on `policy_store.json` could cause lost updates or file corruption.
- **Solution:** Integrated `fs2 = "0.4.3"` into `src/gateway/admin/persistence.rs`.
- **Mechanism:**
  - Implemented `PolicyStoreLockGuard` which acquires an exclusive file lock on a dedicated sibling lockfile (`<path>.lock`) via `fs2::FileExt::try_lock_exclusive`.
  - Windows-specific contention handling: on Windows, file locking contention returns raw OS error 33 (`ERROR_LOCK_VIOLATION`) rather than `ErrorKind::WouldBlock`. The lock retry loop explicitly catches both conditions with a bounded timeout (`POLICY_STORE_LOCK_TIMEOUT = Duration::from_secs(5)`), polling every 10ms.
  - The exclusive lock is held across the entire transaction: disk read $\to$ memory merge $\to$ atomic temporary file creation $\to$ atomic file replacement (`atomic_write_file`).
- **Tests Added:**
  - `test_cross_process_locking_contention_and_timeout`
  - `test_cross_process_concurrent_disjoint_writers`

### 2. Multi-Target Partial Enforcement & Rollback Failure Reporting
- **Problem:** If a multi-target policy application failed halfway through a batch of targets, providers previously attempted rollback, but if rollback of already-applied targets failed on the router, the system returned a generic error and recorded the policy as `Failed`, hiding the critical fact that some targets remained restricted on the router.
- **Solution:**
  - Added `AdminError::RollbackFailed { applied_targets, failed_target, original_error, rollback_errors }`.
  - Added `PolicyLifecycleState::PartialFailure`.
  - Updated MikroTik, AVM, and OpenWrt providers to track each rollback invocation independently.
  - Updated `PolicyExecutionEngine` and CLI rendering tables (`src/cli/table.rs`) to display `PARTIAL FAILURE (Rollback Failed - Router State Dirty)` with distinct warning highlights.
- **Tests Added:**
  - `test_mikrotik_rollback_failure_reporting`
  - `test_avm_rollback_failure_reporting`

### 3. Secret Lifetime Minimization & Credential Hygiene
- **Problem:** Intermediate strings and byte buffers used to construct HTTP Basic Auth headers, TR-064 SOAP authentication, curl stdin configs, and DPAPI decrypted payloads lingered in process heap memory indefinitely after allocation.
- **Solution:**
  - Created `zero_slice(slice: &mut [u8])` using volatile memory writes (`std::ptr::write_volatile`) to defeat compiler dead-store elimination.
  - Introduced `ProtectedBuffer` struct with RAII `Drop` implementation that volatile-zeroes memory upon scope exit.
  - Enhanced Windows DPAPI decryption (`dpapi_decrypt`): volatile-zeroes the unmanaged memory returned in `CRYPT_INTEGER_BLOB.pbData` prior to freeing it via `LocalFree`.
  - Enhanced `save_protected_credentials` and `load_protected_credentials` to parse credentials without allocating unzeroed intermediate password strings.
  - Enhanced `AutoCleanFile` in `curl_util.rs`: securely zeroes file contents on disk before unlinking.
  - Enhanced curl transports (`avm.rs`, `mikrotik.rs`, `unifi.rs`): volatile-zeroes stdin configuration and auth buffers immediately after piping to `curl.exe`.
- **Tests Added:**
  - `test_credential_hygiene_and_protected_buffer_zeroing`
  - `test_protected_credentials_file_roundtrip_with_zeroization`

### 4. Fail-Closed Provider Contract & Diagnostics Isolation
- **Problem:** Need absolute assurance that:
  - Connection failure to a real router never silently switches to `mock` mode or ARP spoofing.
  - Router capability preflight checks reject unsupported operations before executing any router mutations.
  - Diagnostic and inventory calls are strictly read-only and never mutate firewall rules.
- **Solution & Tests:**
  - `test_real_provider_failure_never_triggers_mock_or_arp_fallback`: verifies registry stays strictly disconnected with no fallback.
  - `test_capability_preflight_fails_closed_before_mutation`: verifies AVM temporary policy without autonomous recovery fails closed before any router mutation.
  - `test_read_only_diagnostics_and_inventory_perform_zero_mutations`: asserts zero state changes across repeated diagnostic and inventory executions.

### 5. Native Windows GitHub Actions CI
- **File:** `.github/workflows/windows.yml`
- **Configuration:**
  - Runs on `windows-latest`.
  - Installs stable Rust with `rustfmt` and `clippy`.
  - Executes:
    - `cargo fmt --check`
    - `cargo check --all-targets`
    - `cargo clippy --all-targets -- -D warnings`
    - `cargo test --all-targets`
