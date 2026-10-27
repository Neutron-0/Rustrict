# Rustrict Phase 18.3 — Commit Manifest & Staging Plan

**Date:** 2026-10-27  
**Baseline Git Revision:** `bd06f1c7fb90ac9716e514145d02df8aebd2520a`  

---

## 1. Commit Sequence

To maintain clean separation between source/test implementations and documentation/audit artifacts, Phase 18.3 changes are staged into two focused commits:

### Commit 1: Implementation & Automated Regression Tests
**Message:** `fix(core): enforce fail-closed persistent block restoration and observable forwarding cleanup`  
**Files:**
- `src/core/restoration.rs` (new restoration engine with strict target validation and precondition traits)
- `src/core/mod.rs` (re-export of restoration module)
- `src/types.rs` (`HostStatus::PersistedInactive(Direction)`, `MacAddress::is_broadcast`, `Host: PartialEq, Eq`)
- `src/cli/table.rs` (render `Persisted [Inactive]` in yellow)
- `src/cli/prompt.rs` (integrate `restore_persistent_blocks_with`, fail-closed rescan handling, spoofer result handling)
- `src/spoofer/engine.rs` (`has_sender`, validation in `add()`, non-enforcement for `PersistedInactive`)
- `src/platform/windows.rs` (`ForwardingCleanupReport`, state query verification on restore, mutation state preservation on failure)
- `src/main.rs` (forwarding report evaluation and exit code 1 on cleanup failure)
- `tests/test_safe_networking.rs` (integration tests for fail-closed restoration and structured cleanup reporting)

### Commit 2: Documentation, Audit Records & Stage 1 Reconciliation
**Message:** `docs(audit): record Phase 18.3 persistent safety, startup side effects, and Stage 1 packet reconciliation`  
**Files:**
- `README.md` (updated test suite count: 295 tests across 27 binaries)
- `audit/phase-17-protocol-integration-2026-10-26/STAGE_1_OPERATOR_PACKET.md` (reconciled baseline to Phase 18.3, prerequisite state checks, clarified dry-run cancellation gate)
- `audit/phase-17-protocol-integration-2026-10-26/REMAINING_RISKS.md` (updated risk register with persistent safety and forwarding verification)
- `audit/phase-18.3-persistent-safety/IMPLEMENTATION_REPORT.md` (complete implementation report including startup/shutdown side effect audit)
- `audit/phase-18.3-persistent-safety/TEST_EVIDENCE.md` (breakdown of 295 passing tests on stable and MSRV)
- `audit/phase-18.3-persistent-safety/REMAINING_RISKS.md` (post-Phase 18.3 operational risk register)
- `audit/phase-18.3-persistent-safety/COMMIT_MANIFEST.md` (this staging manifest)
