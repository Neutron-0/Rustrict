# Rustrict Phase 17 & Phase 17.1 — Git Commit Manifest

**Date:** 2026-10-27
**Target Branch:** `main`
**Starting Commit:** `7bd9428 docs(audit): record Phase 16 runtime reliability results`

---

## Commit Sequence

### 1. `cf559b9` — `test(router): add loopback protocol simulation harness`
- **Scope**: `tests/support/mod.rs`, `tests/support/router_emulator/mod.rs`
- **Description**: Introduces deterministic, in-process TCP server on `127.0.0.1:0` emulating OpenWrt ubus JSON-RPC, AVM TR-064 SOAP, UniFi REST, and MikroTik REST API. Handles Winsock TCP reset avoidance (`Expect: 100-continue`, orderly TCP shutdown, and receive buffer draining).

### 2. `32cc64a` — `test(router): exercise provider request and rollback flows`
- **Scope**: `tests/test_protocol_integration.rs`
- **Description**: Implements 11 protocol integration tests exercising production adapters over live TCP loopback sockets. Tests authentication, request formatting, failure injection (timeouts, malformed JSON/XML, redirects), multi-target partial enforcement rollbacks, and SSH executor pipelines.

### 3. `8222e1b` — `test(cli): cover mutation confirmation end to end`
- **Scope**: `src/cli/prompt.rs`, `src/resolver/passive.rs`, `src/spoofer/engine.rs`, `tests/test_cli_confirmation.rs`, `tests/support/router_emulator/mod.rs`, `tests/test_protocol_integration.rs`
- **Description**: Connects interactive CLI mutation confirmation prompts (`[yes/N]`) for `pause`, `resume`, and `adjust` to a testable `read_confirmation_input()` harness. Adds inactive test constructors for `ArpSpoofer` and `PassiveIdentitySniffer` to prevent driver locks during CI testing. Tests confirmed, cancelled, empty, and `--yes` flag execution paths.

### 4. `bbbda5a` — `feat(diagnostics): validate exported evidence bundles offline`
- **Scope**: `src/gateway/admin/diagnostics.rs`, `src/gateway/admin/engine.rs`, `src/gateway/admin/mod.rs`, `src/cli/prompt.rs`, `tests/test_diagnostics.rs`, `tests/test_cli_confirmation.rs`
- **Description**: Implements `PolicyExecutionEngine::validate_evidence_file` and CLI `router validate-evidence <path>` to validate exported evidence bundles offline without router contact. Enforces JSON schema versioning, timestamp sanity, size limits, and secret leakage detection. Adds 5 diagnostics unit tests and CLI integration test.

### 5. `e091ea7` — `docs(audit): record Phase 17 protocol integration and Stage 1 packet`
- **Scope**: `audit/phase-16-runtime-reliability-2026-10-26/REMAINING_RISKS.md`, `audit/phase-16-runtime-reliability-2026-10-26/IMPLEMENTATION_REPORT.md`, `audit/phase-17-protocol-integration-2026-10-26/`
- **Description**: Documents the Stage 1 physical lab operator packet, protocol coverage matrix, failure simulation report, remaining hardware risks, and reconstructed fresh test evidence (257 passing tests).

### 6. `7af23a0` — `fix(test): eliminate duplicate socket handle and drain sleep in emulator`
- **Scope**: `tests/support/router_emulator/mod.rs`
- **Description**: Resolves socket handle duplication and removes blocking receive drain in the test emulator. Ensures seamless Windows Winsock TCP teardown across both native Windows MSVC and GitHub Actions runner environments for MSRV 1.88.0 and stable Rust.

### 7. `3b1cfb8` — `docs(manifest): record final Phase 17 commit manifest`
- **Scope**: `audit/phase-17-protocol-integration-2026-10-26/COMMIT_MANIFEST.md`
- **Description**: Records completed Phase 17 commits up through the emulator socket handle and drain sleep remediation.

### 8. `957f086` — `fix(transport): add transient retry and socket lingering to curl router adapters`
- **Scope**: `src/gateway/admin/avm.rs`, `src/gateway/admin/mikrotik.rs`, `src/gateway/admin/unifi.rs`, `tests/support/router_emulator/mod.rs`
- **Description**: Configured initial retry and socket lingering on simulated router streams to address transient Winsock 10053/10054 connection aborts.

### 9. `68a6ef2` — `docs(manifest): record transport retry commit in Phase 17 manifest`
- **Scope**: `audit/phase-17-protocol-integration-2026-10-26/COMMIT_MANIFEST.md`
- **Description**: Documented the transient retry and socket lingering commit in the Phase 17 manifest.

### 10. `88932ab` — `fix(transport): prevent unsafe retries of router mutations`
- **Scope**: `src/gateway/admin/curl_util.rs`, `src/gateway/admin/avm.rs`, `src/gateway/admin/unifi.rs`, `src/gateway/admin/mikrotik.rs`, `src/gateway/admin/plan.rs`, `src/gateway/admin/mod.rs`
- **Description**: Eliminates unsafe blanket retries (`--retry 2`, `--retry-all-errors`) from mutation-capable router transports. Introduces `OperationSemantics` (`ReadOnly`, `StateChanging`, `Unknown`) with strict `max_attempts() == 1` for state-changing mutations and at most 2 attempts for read-only queries using isolated process executions.

### 11. `8ea89db` — `fix(router): preserve uncertain outcomes after response loss`
- **Scope**: `src/gateway/admin/engine.rs`
- **Description**: Maps dropped mutation responses, timeouts, and connection aborts to `PolicyLifecycleState::Unknown` and persists unconfirmed active policy state. Blocks follow-up mutation attempts on scopes conflicting with any active `Unknown` or `PartialFailure` policy.

### 12. `47a8050` — `test(router): cover ambiguous transport outcomes and retry policy`
- **Scope**: `tests/support/mod.rs`, `tests/support/router_emulator/mod.rs`, `tests/test_protocol_integration.rs`
- **Description**: Adds failure injection modes (`MutateThenDrop`, `ReadOnlyDrop`, `MultiTargetPartialWithRollbackFail`) and regression tests asserting that client adapters execute mutations strictly once without repeating, report `Unknown` outcome on response drops, and enforce conflict blocking. Expands protocol test suite to 17 tests.

### 13. `6badb8e` — `docs(safety): align Stage 1 packet with final transport semantics` *(ACCIDENTAL TRUNCATION)*
- **Scope**: `audit/phase-17-protocol-integration-2026-10-26/STAGE_1_OPERATOR_PACKET.md`, `PROTOCOL_COVERAGE_MATRIX.md`, `REMAINING_RISKS.md`
- **Description**: Intended to update Stage 1 packet, coverage matrix, and remaining risks, but inadvertently committed truncated blank files.

### 14. `ac1c4e9` — `docs(audit): record mutation retry safety closure` *(ACCIDENTAL TRUNCATION)*
- **Scope**: `audit/phase-17-protocol-integration-2026-10-26/COMMIT_MANIFEST.md`, `IMPLEMENTATION_REPORT.md`, `TEST_EVIDENCE.md`
- **Description**: Intended to update manifest, report, and evidence, but inadvertently committed truncated blank files.

### 15. *(Pending Recovery Commit)* — `docs(lab): restore Stage 1 readiness and provider risk documents`
- **Scope**: `audit/phase-17-protocol-integration-2026-10-26/STAGE_1_OPERATOR_PACKET.md`, `PROTOCOL_COVERAGE_MATRIX.md`, `REMAINING_RISKS.md`, `COMMIT_MANIFEST.md`, `IMPLEMENTATION_REPORT.md`, `TEST_EVIDENCE.md`
- **Description**: Restores all six Phase 17 documentation files with full substantive content, source-traced CLI commands, active risk registers, test-layer classifications, and accurate chronological record of the Phase 17.1 remediation.
