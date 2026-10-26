# Rustrict Phase 17 — Router Protocol & Transport Coverage Matrix

**Date:** 2026-10-26  
**Status:** Validated under Native Windows MSVC  
**Scope:** Protocol Simulation Harness & Failure Matrix Conformance  

---

## 1. Provider Protocol Coverage Summary

| Provider ID | Protocol / Wire Framing | Transport Mechanism | Loopback Harness Test (`127.0.0.1:0`) | Unit / Contract Test | Authentication Tested | Discovery Tested | Mutation / Rollback Tested | Fail-Closed Verified |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `openwrt-http` | JSON-RPC 2.0 over HTTP POST | Child `curl.exe` with bounded pipe draining | Yes | Yes | `session.login` | `system.info`, `hostapd` | `uci.add`, `uci.commit`, atomic rollback | Yes (timeouts, redirects, malformed JSON) |
| `openwrt-ssh` | SSH-2.0 native CLI commands | Child `ssh.exe` with strict host checking | Mock Executor Pipeline | Yes | Public key / Password | `id -u`, `uci show`, `cat /proc` | `uci add`, `crontab` cron watchdog | Yes (non-root UID, host key mismatch) |
| `mikrotik-rest` | HTTPS REST (JSON & Basic Auth) | Child `curl.exe` with TLS certificate validation | Yes | Yes | HTTP Basic Auth | `/system/resource`, `/system/routerboard` | `/ip/firewall/filter` POST/DELETE | Yes (HTTP 401, HTTP 500, unencrypted reject) |
| `avm-tr064` | SOAP 1.1 XML over HTTP POST | Child `curl.exe` with MD5 Digest challenge | Yes | Yes | HTTP Digest / Session ID | `Hosts:1` `GetGenericHostEntry` | `X_AVM-DE_HostFilter:1` `DisallowWANAccessByIP` | Yes (SOAP Fault 500, XML parse error) |
| `unifi-rest` | HTTPS REST with Session Cookies | Child `curl.exe` with cookie jar management | Yes | Yes | `POST /api/auth/login` | `/stat/sta` station discovery | `/rest/firewallrule` POST/DELETE | Yes (HTTP 401 Unauthorized, bad JSON) |
| `mock` | In-Memory Data Structures | Direct Rust Trait invocation | N/A (Internal) | Yes | Instant / In-memory | Synthetic device inventory | In-memory atomic policy map | Yes (No hardware access) |

---

## 2. Failure Simulation & Protocol Resilience Matrix

| Failure Mode | Emulated In Harness | Production Adapter Behavior | Tested In | Pass Criteria |
| :--- | :---: | :--- | :--- | :--- |
| **Connection Timeout** | Yes | Transport terminates child process after deadline; returns `AdminError::Timeout` | `test_openwrt_http_failure_modes`, `test_unifi_api_timeout_handling` | Zero hang; clean process termination |
| **Malformed JSON** | Yes | Catches serde deserialization error; returns `AdminError::CommunicationError` | `test_openwrt_http_failure_modes` | No panic; descriptive error message |
| **Malformed XML / SOAP Fault** | Yes | Parses SOAP `<faultcode>` or detects invalid XML; returns `AdminError::TransactionFailed` | `test_avm_tr064_soap_fault_and_malformed` | Safe fallback; transaction cancelled |
| **Oversized Response (>2 MiB)** | Yes | Bounded pipe reader aborts at limit, draining excess data; returns `AdminError::CommunicationError` | `test_openwrt_oversized_http_response_rejection`, `test_ssh_oversized_output_with_continued_pipe_draining` | Zero OOM; bounded memory consumption |
| **HTTP 301/302 Redirects** | Yes | Detects redirect location header; refuses silent redirect; returns `AdminError::SecurityViolation` | `test_openwrt_http_failure_modes` | Disallows credential relay to third-party |
| **Multi-Target Partial Failure** | Yes | Reverts previously applied targets in reverse order; sets lifecycle state to Failed | `test_openwrt_multi_target_partial_failure_rollback`, `test_unifi_partial_transaction_failure_and_rollback` | No orphan rules remain on router |
| **Authentication Rejection** | Yes | Detects HTTP 401 / 403; returns `AdminError::AuthenticationFailed`; halts retry loop | `test_unifi_invalid_credentials_rejected`, `test_mikrotik_loopback_rest_flow` | Prevents router brute-force lockouts |
