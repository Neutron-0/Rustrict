# Rustrict Phase 17 — Router Protocol & Transport Coverage Matrix

**Date:** 2026-10-27 (Phase 17.1 Restored & Reconciled Baseline)
**Status:** Validated under Native Windows MSVC (MSRV 1.88.0 and Stable 1.97.1)
**Scope:** Protocol Simulation Harness, Retry Safety & Failure Matrix Conformance

---

## 1. Provider Protocol Coverage & Actual Test Layers

The following table distinguishes between what has been tested via **in-process loopback protocol integration (`127.0.0.1:0`)**, what has been verified via **mock / synthetic subprocess execution**, and what remains **untested / physical hardware dependent**:

| Provider ID | Protocol / Wire Framing | Transport Mechanism | Test Layer | Production Paths Exercised | Untested / Simulated Aspects | Firmware-Specific Uncertainties |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `openwrt-http` | JSON-RPC 2.0 over HTTP POST | Child `curl.exe` with bounded pipe draining | Loopback Protocol Integration (`127.0.0.1:0`) & Contract Tests | `session.login`, `system.info`, `hostapd.*.get_clients`, `uci.add`, `uci.commit`, atomic rollback | Physical flash wear, slow flash write timeouts | OpenWrt 21.02 vs 23.05+ nftables vs iptables syntax differences |
| `openwrt-ssh` | SSH-2.0 native CLI commands | Child `ssh.exe` with strict host key checking | Mock Subprocess Executor Pipeline | Host key mismatch rejection, non-root user rejection, remote timeout handling, command generation | Real SSH network handshake, live dropbear/OpenSSH daemon | Shell escaping variations across busybox vs ash/bash; non-standard sudo setups |
| `mikrotik-rest` | HTTPS REST (JSON & Basic Auth) | Child `curl.exe` with TLS cert validation & `execute_with_operation_retry` | Loopback Protocol Integration (`127.0.0.1:0`) & Contract Tests | HTTP Basic Auth, `/rest/system/resource`, `/rest/ip/firewall/filter` (POST/DELETE), 204 No Content | Real RouterOS REST daemon latency under load | RouterOS v7.1 vs v7.14 REST API schema drift; disabled REST service on router |
| `avm-tr064` | SOAP 1.1 XML over HTTP POST | Child `curl.exe` with MD5 Digest & `execute_with_operation_retry` | Loopback Protocol Integration (`127.0.0.1:0`) & Contract Tests | HTTP Digest challenge parsing, `Hosts:1` discovery, `X_AVM-DE_HostFilter:1` WAN access control, SOAP Fault 500 handling | Real FRITZ!Box multi-user session management | FRITZ!OS 7.29 vs 7.50+ XML namespace variations; ISP-locked TR-064 interfaces |
| `unifi-rest` | HTTPS REST with Session Cookies | Child `curl.exe` with cookie jar & `execute_with_operation_retry` | Loopback Protocol Integration (`127.0.0.1:0`) & Contract Tests | `POST /api/auth/login`, cookie storage/reuse, `/stat/sta` station query, `/rest/trafficrule` (POST/DELETE) | Real UniFi OS Controller background task queuing | UniFi Network Application v7 vs v8+ CSRF headers and API path changes |
| `mock` | In-Memory Data Structures | Direct Rust Trait invocation | In-Memory Unit / Contract Tests | Full policy lifecycle, state transitions, expiration, recovery | Zero hardware interaction (all state synthetic) | N/A (Does not interact with network hardware) |

> [!NOTE]
> **OpenWrt SSH Testing Classification**: As recorded above, `openwrt-ssh` is tested via mock executor pipelines (using simulated subprocess outputs and error injections) and unit tests. It is **NOT** tested against a live loopback OpenSSH daemon.
>
> **Cross-Provider Contract Tests**: Shared contract tests (`tests/test_provider_contracts.rs`) verify uniform trait conformance, lockout prevention, and error sanitization, but do not replace vendor-specific protocol wire validation.

---

## 2. Operation Retry Policy Matrix (Phase 17.1)

| Operation Category | Operation Semantics | Max Attempts | Retries Allowed | Process Isolation | Behavior on Response Drop / Timeout |
| :--- | :--- | :---: | :---: | :---: | :--- |
| **Status / Info Queries** (`GET`, `system.info`, `Hosts:1`, `stat/sta`) | `ReadOnly` | 2 | 1 retry (max 2 attempts) | Fresh child process per attempt; isolated stdout pipe | Returns last error; does not mutate router state |
| **Policy Mutations** (`POST`, `PUT`, `DELETE`, `DisallowWANAccessByIP`, `uci.add`, `uci.commit`) | `StateChanging` | 1 | 0 (Zero retries) | Single child process invocation | Maps to `AdminError::is_ambiguous_outcome()`; sets policy state to `PolicyLifecycleState::Unknown`; persists unconfirmed state; blocks conflicting operations |
| **Unclassified / Ambiguous Operations** | `Unknown` | 1 | 0 (Zero retries) | Single child process invocation | Fails closed immediately |

---

## 3. Failure Simulation & Protocol Resilience Matrix

| Failure Mode | Emulated In Harness | Production Adapter Behavior | Tested In | Pass Criteria |
| :--- | :---: | :--- | :--- | :--- |
| **Connection Timeout** | Yes | Transport terminates child process after deadline; returns `AdminError::Timeout` | `test_openwrt_http_failure_modes`, `test_unifi_api_timeout_handling` | Zero hang; clean process termination |
| **Malformed JSON** | Yes | Catches serde deserialization error; returns `AdminError::CommunicationError` | `test_openwrt_http_failure_modes` | No panic; descriptive error message |
| **Malformed XML / SOAP Fault** | Yes | Parses SOAP `<faultcode>` or detects invalid XML; returns `AdminError::TransactionFailed` | `test_avm_tr064_soap_fault_and_malformed` | Safe fallback; transaction cancelled |
| **Oversized Response (>2 MiB)** | Yes | Bounded pipe reader aborts at limit, draining excess data; returns `AdminError::CommunicationError` | `test_openwrt_oversized_http_response_rejection`, `test_ssh_oversized_output_with_continued_pipe_draining` | Zero OOM; bounded memory consumption |
| **HTTP 301/302 Redirects** | Yes | Detects redirect location header; refuses silent redirect; returns `AdminError::SecurityViolation` | `test_openwrt_http_failure_modes` | Disallows credential relay to third-party |
| **Multi-Target Partial Failure** | Yes | Reverts previously applied targets in reverse order; sets lifecycle state to Failed | `test_openwrt_multi_target_partial_failure_rollback`, `test_unifi_partial_transaction_failure_and_rollback` | No orphan rules remain on router |
| **Authentication Rejection** | Yes | Detects HTTP 401 / 403; returns `AdminError::AuthenticationFailed`; halts retry loop | `test_unifi_invalid_credentials_rejected`, `test_mikrotik_loopback_rest_flow` | Prevents router brute-force lockouts |
| **Mutate Then Socket Drop (Ambiguous Outcome)** | Yes | Mutation is dispatched, but socket is severed before response. Client executes exactly 1 attempt (0 retries); engine records `PolicyLifecycleState::Unknown` and blocks conflicting mutations | `test_avm_mutation_response_dropped_uncertainty_and_no_retry`, `test_unifi_mutation_response_dropped_uncertainty_and_no_retry`, `test_mikrotik_mutation_response_dropped_uncertainty_and_no_retry` | Exactly 1 mutation request on wire; engine blocks subsequent mutations with ambiguous policy conflict error |
| **Multi-Target Partial with Rollback Failure** | Yes | First target succeeds; second target fails; rollback of first target also fails. Engine detects unrecovered router mutation; records `PartialFailure` with explicit unrecovered targets; blocks conflicting mutations | `test_multi_target_partial_with_rollback_failure_reporting` | Engine returns `PartialEnforcementFailure`; records `unrecovered_applied_targets`; blocks subsequent operations on that scope |
