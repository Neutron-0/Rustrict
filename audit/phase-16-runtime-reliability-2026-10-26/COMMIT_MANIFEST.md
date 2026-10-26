# Rustrict Phase 16 — Commit Manifest & Traceability

**Date:** 2026-10-26
**Base Commit:** `efa43ca` (`docs(audit): reconcile Phase 15 verification evidence`)
**Branch:** `main` (tracking `origin/main`)

---

## Commit Sequence

### Commit 1: `d74dc82`
- **Subject:** `fix(security): make diagnostic redaction unicode-safe`
- **Scope:** Credential sanitization, Unicode byte offset preservation, error redaction.
- **Affected Files:**
  - `src/gateway/admin/engine.rs`
  - `tests/test_policy_engine.rs`
- **Summary:**
  - Replaced `to_lowercase()` with `to_ascii_lowercase()` on byte slices to guarantee 1:1 byte offset preservation.
  - Eliminated byte offset skewing when text contains characters such as Turkish `\u{0130}`, German `\u{1E9E}`, Greek `\u{03A3}`, and emoji.
  - Added support for Authorization Bearer/Basic headers, URL query parameters, and userinfo authority redaction.
  - Covered all `AdminError` variants in `sanitize_error` without panicking.
  - Added regression tests in `test_policy_engine.rs`.

### Commit 2: `3ff0bf0`
- **Subject:** `fix(transport): bound router requests and subprocess output`
- **Scope:** Transport resource bounds, subprocess output draining, pipe deadlock prevention, redirect rejection.
- **Affected Files:**
  - `src/gateway/admin/curl_util.rs`
  - `src/gateway/admin/avm.rs`
  - `src/gateway/admin/mikrotik.rs`
  - `src/gateway/admin/unifi.rs`
  - `src/gateway/admin/ssh.rs`
  - `src/gateway/admin/openwrt.rs`
  - `tests/test_openwrt_admin.rs`
  - `tests/test_ssh_admin.rs`
- **Summary:**
  - Implemented `read_bounded_pipe`, `BoundedChildOutput`, and `wait_child_bounded` (`MAX_SUBPROCESS_OUTPUT_BYTES = 2 MiB`).
  - Drains subprocess stdout/stderr to EOF to prevent OS pipe buffer saturation and hangs.
  - Integrated bounded subprocess handling in AVM, MikroTik, UniFi, and SSH transports.
  - Enforced `MAX_HTTP_RESPONSE_BYTES = 2 MiB` and rejected 3xx redirects with `SecurityViolation` in OpenWrt HTTP transport.
  - Added unit and regression tests in `curl_util.rs`, `test_openwrt_admin.rs`, and `test_ssh_admin.rs`.

### Commit 3: `ac78e42`
- **Subject:** `fix(router): require accurate preflight for policy mutations`
- **Scope:** Preflight mutation checks, prior partial/unknown state surfacing, CLI confirmation safety.
- **Affected Files:**
  - `src/gateway/admin/engine.rs`
  - `src/gateway/admin/mod.rs`
  - `src/cli/prompt.rs`
  - `tests/test_policy_engine.rs`
- **Summary:**
  - Added `MutationPreflightReport`, `preflight_mutation`, and `check_unreconciled_failures`.
  - Surfaced prior partial failures (`PolicyLifecycleState::PartialFailure`) and ambiguous states (`Unknown`) in dry-run plans.
  - Detected and warned on target IP overlap with existing active policies.
  - Required explicit `[yes/N]` operator confirmation for pause, resume, and adjust against real routers, with non-interactive `--yes` bypass.
  - Cleanly cancelled with zero mutations and zero transport calls on operator decline or EOF.
  - Added regression tests for zero-mutation dry run, partial failure surfacing, and target overlap detection.

### Commit 4: `b3367d6`
- **Subject:** `feat(diagnostics): export sanitized router evidence bundles`
- **Scope:** Read-only evidence bundle export, credential redaction across all bundle sections, atomic file write.
- **Affected Files:**
  - `src/gateway/admin/diagnostics.rs`
  - `src/gateway/admin/engine.rs`
  - `src/gateway/admin/mod.rs`
  - `src/cli/prompt.rs`
  - `tests/test_diagnostics.rs`
- **Summary:**
  - Introduced `RouterEvidenceBundle` (schema `rustrict-evidence-v1.0`).
  - Added `build_evidence_bundle` and atomic `export_evidence_bundle`.
  - Added CLI command `router export-evidence [path] [--overwrite]`.
  - Strictly redacted all credentials, passwords, tokens, and authorization headers from all sections before serialization.
  - Enforced overwrite protection unless explicitly permitted.
  - Verified zero router configuration mutations during evidence generation.
  - Added regression tests in `test_diagnostics.rs`.

### Commit 5: `ecd8f1f`
- **Subject:** `test(router): add cross-provider contract and failure-injection coverage`
- **Scope:** Cross-provider contract verification, failure injection, capability enforcement.
- **Affected Files:**
  - `src/gateway/admin/engine.rs`
  - `tests/test_provider_contracts.rs`
- **Summary:**
  - Added `b"pass"` pattern to secret key-value sanitizer.
  - Created reusable cross-provider test suite covering all 6 providers (`openwrt-http`, `openwrt-ssh`, `mikrotik-rest`, `avm-tr064`, `unifi-rest`, `mock`).
  - Verified read-only diagnostics make zero mutations across all providers.
  - Verified unsupported capabilities fail closed before mutation.
  - Verified unauthenticated operations are rejected before dispatch.
  - Verified credential redaction on all error variants.
  - Verified multi-target partial failure reporting preserves targets without panicking.

### Commit 6: (Pending)
- **Subject:** `docs(audit): record Phase 16 runtime reliability results`
- **Scope:** Audit documentation package.
- **Affected Files:**
  - `audit/phase-16-runtime-reliability-2026-10-26/IMPLEMENTATION_REPORT.md`
  - `audit/phase-16-runtime-reliability-2026-10-26/TEST_EVIDENCE.md`
  - `audit/phase-16-runtime-reliability-2026-10-26/REMAINING_RISKS.md`
  - `audit/phase-16-runtime-reliability-2026-10-26/COMMIT_MANIFEST.md`
