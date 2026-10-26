# Rustrict Phase 17 — Git Commit Manifest

**Date:** 2026-10-26  
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

### 8. (Pending) — `fix(transport): add transient retry and socket lingering to curl router adapters`
- **Scope**: `src/gateway/admin/avm.rs`, `src/gateway/admin/mikrotik.rs`, `src/gateway/admin/unifi.rs`, `tests/support/router_emulator/mod.rs`
- **Description**: Configures `--retry 2 --retry-delay 0 --retry-connrefused --retry-all-errors` across AVM TR-064, UniFi Network, and MikroTik REST curl adapters to ensure resilience against transient Windows loopback connection aborts (Winsock 10053/10054 / exit code 56). Sets `SO_LINGER` on simulated router streams to guarantee graceful TCP teardown without abrupt connection resets.
