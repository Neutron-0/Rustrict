# Rustrict Phase 19.4 — Requirements Traceability Matrix

**Date:** 2026-10-27  
**Baseline Implementation Commit:** `326516b4894e091635aac6600daa99180c5e67c2`  

---

| Req # | Requirement Description | Implementation Location | Test Verification | Status |
| :---: | :--- | :--- | :--- | :---: |
| **REQ-19.4-01** | Router-lab startup queries local OS route, address, prefix, and adapter info via read-only APIs without active probes | `src/platform/windows.rs`: `get_default_interface_read_only_with` | `tests/test_router_lab_zero_probe.rs`: `test_01_read_only_resolver_retrieves_metadata_without_probes` | **VERIFIED** |
| **REQ-19.4-02** | Gateway MAC resolved strictly passively; preserved as unresolved (`MacAddress::ZERO`) when absent from local cache | `src/platform/windows.rs`: `ArpCacheLookup`, `SystemArpCache` | `tests/test_router_lab_zero_probe.rs`: `test_02_gateway_mac_unresolved_when_absent_from_cache` | **VERIFIED** |
| **REQ-19.4-03** | Fails closed with actionable error on discovery failure; does not silently fall back to ordinary `get_default_interface()` | `src/main.rs`: `bootstrap_router_lab` match arm; `src/platform/windows.rs` | `tests/test_router_lab_zero_probe.rs`: `test_03_read_only_discovery_failure_fails_closed_without_active_fallback` | **VERIFIED** |
| **REQ-19.4-04** | Router-lab mode bypasses Npcap (`wpcap.dll`) and WinDivert driver initialization and checks | `src/platform/windows.rs`: `check_router_lab_environment`; `src/main.rs` | `tests/test_router_lab_zero_probe.rs`: `test_04_router_lab_environment_check_skips_enforcement_drivers` | **VERIFIED** |
| **REQ-19.4-05** | Normal application mode retains intended active default interface resolution and driver diagnostics | `src/platform/windows.rs`: `get_default_interface`, `ActiveInterfaceResolver` | `tests/test_router_lab_zero_probe.rs`: `test_05_normal_application_mode_maintains_intended_active_behavior` | **VERIFIED** |
| **REQ-19.4-06** | Router provider requests do not occur before explicit user selection (`router connect`) | `src/cli/prompt.rs`: `new_router_lab`, `bootstrap_router_lab` | `tests/test_router_lab_zero_probe.rs`: `test_06_router_lab_provider_requests_do_not_occur_before_explicit_selection` | **VERIFIED** |
| **REQ-19.4-07** | Missing routes, multiple interfaces, missing MAC, malformed prefix, and adapter-query failure fail safely | `src/platform/windows.rs`: `get_default_interface_read_only_with` | `tests/test_router_lab_zero_probe.rs`: `test_07_malformed_routes_ips_prefixes_and_adapters_fail_safely` | **VERIFIED** |
| **REQ-19.4-08** | Current default gateway never receives unsolicited startup probes in router-lab mode | `src/main.rs`, `src/platform/windows.rs` | `tests/test_router_lab_zero_probe.rs`: `test_08_current_default_gateway_never_receives_unsolicited_startup_probe` | **VERIFIED** |
| **REQ-19.4-09** | Existing router-lab command allowlist and all prior tests remain valid | `src/cli/prompt.rs`: `is_command_allowed_in_router_lab` | `tests/test_router_lab_zero_probe.rs`: `test_09_existing_router_lab_allowlist_enforced_during_zero_probe_session`; full suite (341 tests) | **VERIFIED** |
| **REQ-19.4-10** | EOF and clean exit perform zero forwarding mutations and emit zero network frames | `src/main.rs`: `if !is_router_lab { cleanup_forwarding(); }` | `tests/test_router_lab_zero_probe.rs`: `test_10_clean_shutdown_and_eof_zero_forwarding_cleanup_and_zero_frames` | **VERIFIED** |
