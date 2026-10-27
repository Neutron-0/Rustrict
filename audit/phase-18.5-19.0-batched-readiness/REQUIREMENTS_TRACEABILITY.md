# Rustrict Phases 18.5–19.0 — Requirements Traceability Matrix

**Document Version:** 1.0.0  
**Date:** 2026-10-27  
**Commit:** `10dd09706d2796ebc62b34354719485a4edb92eb`  

---

| Phase / Batch | Requirement Summary | Implementation Artifacts | Verification Tests | Gate Status |
| :--- | :--- | :--- | :--- | :---: |
| **Phase 18.5 (Batch 1)** | Mandatory immutable Controller & Gateway exclusions (IP & MAC) | `src/core/admission.rs` (`TargetAdmissionValidator`) | `test_admission_mandatory_controller_and_gateway_exclusions`, `test_admission_layer_contract` | **PASSED** |
| **Phase 18.5 (Batch 1)** | Concrete boundary requirement for active local enforcement (no permissive mode bypass) | `src/core/admission.rs` (`AdmissionOperation::LocalEnforcement`) | `test_admission_concrete_boundary_required_even_in_permissive_mode`, `test_admission_layer_contract` | **PASSED** |
| **Phase 18.5 (Batch 1)** | Untrusted saved scope sanitization on load with automatic local interface fallback | `src/core/scope.rs` (`ScopeManager::sanitize()`), `src/cli/prompt.rs` | `test_scope_sanitize_filters_invalid_untrusted_entries`, `test_saved_scope_sanitization_and_fallback` | **PASSED** |
| **Phase 18.5 (Batch 1)** | Subnet network ID & directed broadcast rejection while preserving RFC 3021 /31 and /32 endpoints | `src/core/scope.rs` (`Ipv4Cidr::is_valid_host_ip`) | `test_cidr_network_and_broadcast_addresses`, `test_scope_rejects_subnet_network_and_broadcast` | **PASSED** |
| **Phase 18.6 (Batch 2)** | Precondition verification prior to target mutation (Npcap injection ready, OS forwarding enabled) | `src/cli/prompt.rs` (`handle_block`, `handle_limit`, `handle_simulate`) | `test_atomic_enforcement_fail_closed_without_injection_driver` | **PASSED** |
| **Phase 18.6 (Batch 2)** | Multi-target atomic activation with rollback on failure (zero partial success states) | `src/cli/prompt.rs` (transactional activation loop with rollback) | `test_transactional_multi_target_activation_and_rollback` | **PASSED** |
| **Phase 18.6 (Batch 2)** | Idempotent free and teardown operations | `src/cli/prompt.rs` (`handle_free`), `src/limiter/divert.rs`, `src/spoofer/engine.rs` | `test_idempotent_free_operations` | **PASSED** |
| **Phase 18.7 (Batch 3)** | Read-only Router-Lab mode with zero Layer 2 injection sender initialization | `src/cli/prompt.rs` (`RustrictCli::new_router_lab`), `src/main.rs` (`--router-lab`) | `test_read_only_router_lab_mode_semantics` | **PASSED** |
| **Phase 18.7 (Batch 3)** | Persisted blocks loaded as inactive inventory without activation in Router-Lab mode | `src/cli/prompt.rs` (`new_router_lab`) | `test_read_only_router_lab_mode_semantics` | **PASSED** |
| **Phase 18.7 (Batch 3)** | Bounded forwarding restoration retries and OS postcondition verification | `src/platform/windows.rs` (`cleanup_forwarding_with_retries(3)`) | `test_cleanup_forwarding_with_retries_transient_failure_succeeds` | **PASSED** |
| **Phase 18.8 (Batch 4)** | Operation-aware retry safety: zero retries on mutating requests (`max_attempts == 1`) | `src/gateway/admin/curl_util.rs`, `avm.rs`, `mikrotik.rs`, `unifi.rs`, `openwrt.rs`, `ssh.rs` | `test_transport_operation_classification_and_retry_matrix`, `test_execute_with_operation_retry_isolation` | **PASSED** |
| **Phase 18.8 (Batch 4)** | Credential redaction in diagnostic evidence bundles and display | `src/gateway/admin/diagnostics.rs` (`sanitize_endpoint`, `RouterEvidenceBundle`) | `test_read_only_diagnostics_and_inventory_perform_zero_mutations` | **PASSED** |
| **Phase 18.9 (Batch 5)** | Bounded subprocess execution, timeout reaping, and kill enforcement | `src/monitor/nic.rs` (`run_powershell_bounded`) | `test_powershell_bounded_timeout_terminates_and_reaps_process` | **PASSED** |
| **Phase 18.9 (Batch 5)** | Zero false-normals on missing counters or counter resets in NIC telemetry | `src/monitor/nic.rs` (`sample_nic_health`, `NicRawStats::is_complete`) | `test_missing_statistics_reported_unavailable_not_zero_normal`, `test_nic_counter_reset_treated_as_invalidation_and_degraded` | **PASSED** |
| **Phase 19.0 (Batch 6)** | Cross-platform MSRV compatibility & release packaging | `Cargo.toml`, GitHub Actions workflows | `cargo +1.88.0 test --all-targets` (315/315 passed) | **PASSED** |
