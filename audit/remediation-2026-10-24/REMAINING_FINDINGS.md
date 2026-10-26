# Rustrict — Remaining Findings & Technical Debt Assessment
**Date:** 2026-10-24  
**Audit Reference:** `audit/verification-2026-10-24/`  
**Phase:** Phase 1 Remediation Complete  
**Status:** All Critical and High-Severity Findings Closed; Minor Technical Debt Cataloged for Phase 2

---

## 1. Status Overview

| Finding ID | Title | Original Severity | Remediated in Phase 1? | Current Status |
| :--- | :--- | :--- | :--- | :--- |
| **SEC-01** | AVM & UniFi curl stdin multiplexing defect | **Critical** | **YES** | **CLOSED (VERIFIED)** |
| **SEC-02** | Misleading startup mock provider connection | **Critical** | **YES** | **CLOSED (VERIFIED)** |
| **SEC-03** | Multi-target policy scope truncation | **High** | **YES** | **CLOSED (VERIFIED)** |
| **SEC-04** | MikroTik false IPv6 capability advertisement | **High** | **YES** | **CLOSED (VERIFIED)** |
| **SEC-05** | Multi-instance persistence synchronization race | **High** | **YES** | **CLOSED (VERIFIED)** |
| **SEC-06** | Plaintext password console echoing | **Medium / High** | **YES** | **CLOSED (VERIFIED)** |
| **SEC-07** | SSH pipe buffer deadlock risk on large outputs | **Medium / High** | **YES** | **CLOSED (VERIFIED)** |
| **CODE-01** | 23 Compiler and Clippy lint warnings | **Low / Quality** | **YES** | **CLOSED (VERIFIED)** |
| **SEC-08** | In-memory zeroization of decrypted credentials | Low | Partially (Zeroize on ProtectedString) | Open (Phase 2 enhancement) |
| **NET-01** | OpenWrt SSH watchdog crontab newline normalization | Low | No | Open (Phase 2 hardening) |
| **DOC-01** | Historical Phase Reports discrepancy documentation | Informational | No | Open (Documentation only) |

---

## 2. Detailed Assessment of Remaining Items

### 1. SEC-08: In-Memory Zeroization of Decrypted Credentials
- **Severity:** Low
- **Description:**
  `ProtectedString` uses a `zeroize_on_drop` pattern for wrapped credential buffers. However, during HTTP digest response calculation (`calculate_digest_response`) and basic authentication string encoding (`format!("{}:{}", user, pass)`), temporary `String` instances are created on the heap that are not explicitly zeroized upon allocation drop.
- **Risk Assessment:**
  Low. These buffers reside in the private address space of `rustrict.exe` with standard Windows process isolation (DEP/ASLR). No unauthorized process can read this memory without administrator / `SeDebugPrivilege` rights.
- **Recommended Phase 2 Action:**
  Introduce a zeroizing secret allocator or scoped `secrecy::SecretString` wrappers for intermediate string formatting in HTTP Digest and Basic auth encoders.

---

### 2. NET-01: OpenWrt SSH Watchdog Crontab Newline Normalization
- **Severity:** Low
- **Description:**
  `SshOpenWrtTransport` installs an autonomous watchdog by appending a line to `/etc/crontabs/root`. While it checks for trailing newlines before appending, certain OpenWrt busybox `crond` builds are sensitive to CR-LF (`\r\n`) vs LF (`\n`) line endings if the controller host environment injects Windows carriage returns.
- **Risk Assessment:**
  Low. `SshOpenWrtTransport` writes commands via remote shell strings containing explicit `\n`, but explicit sanitization of all line endings to strictly LF (`\n`) will ensure compatibility with non-standard OpenWrt builds.
- **Recommended Phase 2 Action:**
  Ensure crontab payload string sanitization explicitly converts `\r\n` to `\n` prior to SSH invocation.

---

### 3. DOC-01: Historical Documentation Alignment
- **Severity:** Informational
- **Description:**
  The project history previously contained references claiming 177 passing tests culminating at Phase 14, while the initial audit substantiated 182 tests across 23 binaries. Following Phase 1 remediation, the test suite now contains 187 passing tests with 0 failures and 0 warnings.
- **Recommended Phase 2 Action:**
  Update `README.md` and user manual to reflect the verified 187 test baseline and document the explicit `router connect mock` requirement for offline testing.
