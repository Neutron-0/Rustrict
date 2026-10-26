# Rustrict — Actionable Audit Findings & Defect Register

**Audit Date:** 2026-10-24  
**Audit Target:** Rustrict v2.0.0 (`D:\Vault\Rustrict`)  
**Ranking Criterion:** Exploitability, policy integrity impact, and operational failure likelihood.

---

## Part 1: Confirmed Implementation Defects

---

### Finding SEC-01: Fatal Stdin Multiplexing Collision in Production AVM and UniFi Transports
- **Finding ID:** SEC-01
- **Severity:** **CRITICAL**
- **Confidence:** **HIGH**
- **File & Function:** [`src/gateway/admin/avm.rs:229-250`](file:///D:/Vault/Rustrict/src/gateway/admin/avm.rs#L229-L250), [`src/gateway/admin/unifi.rs:131-153`](file:///D:/Vault/Rustrict/src/gateway/admin/unifi.rs#L131-L153)
- **Violated Requirement:** REQ-PROC-01 (Production HTTPS/SOAP transport execution via Windows `curl.exe`)
- **Impact:** Complete failure of production router mutation. The application is completely unable to apply, adjust, or resume policies on real AVM FRITZ!Box or Ubiquiti UniFi gateways.
- **Why it matters:** Both providers attempt to pass curl configuration options and the request body (SOAP XML or JSON payload) simultaneously through the same `stdin` pipe by specifying `.arg("--config").arg("-").arg("--data-binary").arg("@-")`. In reality, curl's `--config -` reads stdin until EOF. When curl encounters the body data, it attempts to parse it as configuration options (`key = value`), immediately terminating with a syntax error (`curl: option --config: found an unknown config option`).
- **Reproduction Steps:**
  Execute the following command in Windows Command Prompt:
  ```cmd
  powershell -Command "$soap = @\"`nurl = 'https://example.com'`nsilent`nshow-error`n<?xml version='1.0'?>`n<s:Envelope>`n\"@; Set-Content -Path $env:TEMP\curl_soap_test.txt -Value $soap; curl.exe --config $env:TEMP\curl_soap_test.txt"
  ```
- **Actual Result:**
  ```
  curl: C:\Users\...\Temp\curl_soap_test.txt:4 config file
  curl: option '<?xml' is unknown
  curl: option --config: found an unknown config option
  curl: try 'curl --help' for more information
  ```
- **Remediation Recommendation:**
  Do not multiplex `--config -` and `--data-binary @-` onto stdin. Either:
  1. Write the payload into the curl config file using `data = "..."` (escaping quotes), as correctly done in [`mikrotik.rs:186`](file:///D:/Vault/Rustrict/src/gateway/admin/mikrotik.rs#L186); or
  2. Write the SOAP XML / JSON payload to a temporary file guarded by `TempFileGuard` and pass `--data-binary @<path>`.

---

### Finding SEC-02: Silent Fallback to Mock Provider at Application Startup
- **Finding ID:** SEC-02
- **Severity:** **CRITICAL**
- **Confidence:** **HIGH**
- **File & Function:** [`src/cli/prompt.rs:119-122`](file:///D:/Vault/Rustrict/src/cli/prompt.rs#L119-L122)
- **Violated Requirement:** REQ-PROV-03 (No automatic fallback or startup fallback to mock)
- **Impact:** Misleading operational confirmation. An operator running `router pause` without having executed `router connect` will see success messages and valid policy IDs, while the tool actually mutates an in-memory mock simulator and leaves the physical network completely unrestricted.
- **Why it matters:** The constructor `Prompt::new` explicitly connects `mock_provider` to the registry:
  ```rust
  let mock_provider = Arc::new(MockRouterAdminProvider::new(iface.gateway));
  let _ = router_registry.connect("mock", mock_provider, "internal://mock");
  let policy_engine = Arc::new(PolicyExecutionEngine::new(router_registry.clone()));
  let admin_provider = policy_engine.clone() as Arc<dyn RouterAdminProvider>;
  ```
  Because `MockRouterAdminProvider` has `authenticated: true` by default, any subsequent router command operates on the mock.
- **Reproduction Steps:**
  1. Launch Rustrict: `cargo run`.
  2. Immediately type `router status`. Notice it reports connected to `Mock Router Provider`.
  3. Type `router pause all --duration 300` and confirm `yes`.
  4. Notice the CLI prints `[SUCCESS] Policy applied successfully!` with a policy ID like `mock_pol_...`.
- **Actual Result:** Router commands succeed against in-memory mock without warning that no physical router connection was established.
- **Expected Result:** Application startup should initialize the router registry in a `DISCONNECTED` state. Router commands should fail closed with: `"No router provider is currently connected. Establish a connection first with 'router connect <provider>'."`
- **Remediation Recommendation:**
  Remove lines 119–120 in `src/cli/prompt.rs`. Initialize `router_registry` with no active connection. Only connect to `mock` if the user explicitly enters `router connect mock`.

---

### Finding SEC-03: Multi-Target Scope Truncation in OpenWrt, MikroTik, and AVM Providers
- **Finding ID:** SEC-03
- **Severity:** **HIGH**
- **Confidence:** **HIGH**
- **File & Function:** [`src/gateway/admin/openwrt.rs:805-810`](file:///D:/Vault/Rustrict/src/gateway/admin/openwrt.rs#L805-L810), [`src/gateway/admin/mikrotik.rs:1091-1096`](file:///D:/Vault/Rustrict/src/gateway/admin/mikrotik.rs#L1091-L1096), [`src/gateway/admin/avm.rs:1304-1315`](file:///D:/Vault/Rustrict/src/gateway/admin/avm.rs#L1304-L1315)
- **Violated Requirement:** REQ-SAFE-03 (Multi-target policy enforcement across all specified targets)
- **Impact:** Partial policy failure and false sense of security. When multiple IP targets are specified in a policy request, only the first target is restricted on the router. The remaining targets remain unrestricted, despite the local audit record logging that all targets were blocked.
- **Why it matters:** In all three providers, the code indexes only `targets[0]`:
  ```rust
  // OpenWrt
  values["src_ip"] = json!(targets[0].to_string());
  // MikroTik
  rule_payload["src-address"] = Value::String(targets[0].to_string());
  ```
- **Reproduction Steps:**
  Call `engine.apply_policy` with `PolicyScope::SpecificTargets(vec![ip1, ip2])`. Inspect the resulting firewall rules generated on the provider.
- **Actual Result:** Only `ip1` is added to the firewall rejection rule. `ip2` is completely ignored.
- **Expected Result:** The provider must either create a rule containing an IP address list/set matching all targets, create individual rules for each target in the scope, or explicitly reject multi-target requests if batch creation is unsupported.
- **Remediation Recommendation:**
  Refactor `apply_policy` in each provider to iterate over `targets` and apply firewall rules for each target in the list, or create a consolidated address list.

---

### Finding SEC-04: False Capability Declaration and IPv6 Bypass in MikroTik Provider
- **Finding ID:** SEC-04
- **Severity:** **HIGH**
- **Confidence:** **HIGH**
- **File & Function:** [`src/gateway/admin/mikrotik.rs:886`](file:///D:/Vault/Rustrict/src/gateway/admin/mikrotik.rs#L886), [`src/gateway/admin/mikrotik.rs:1101`](file:///D:/Vault/Rustrict/src/gateway/admin/mikrotik.rs#L1101), [`src/gateway/admin/mikrotik.rs:624`](file:///D:/Vault/Rustrict/src/gateway/admin/mikrotik.rs#L624)
- **Violated Requirement:** REQ-PROV-05 (Accurate declaration of IPv6 capability on MikroTik)
- **Impact:** Complete policy bypass on dual-stack IPv4/IPv6 networks. Target devices continue accessing the internet via IPv6.
- **Why it matters:** `MikroTikAdminProvider` explicitly advertises `ipv6_policy_enforcement: CapabilityClassification::Implemented`. However, in `apply_policy`, it POSTs only to `/rest/ip/firewall/filter`. In MikroTik RouterOS v7, IPv6 forwarding rules reside exclusively in `/rest/ipv6/firewall/filter`. Furthermore, the autonomous recovery watchdog script installed in RouterOS only iterates over `/ip firewall filter`:
  ```routeros
  :foreach r in=[/ip firewall filter find where comment~"rustrict_pause"] do={ ... }
  ```
  Even if IPv6 rules were added manually, the watchdog would never clean them up.
- **Reproduction Steps:**
  Inspect `mikrotik.rs:1098-1104` and `mikrotik.rs:624`.
- **Actual Result:** No `/rest/ipv6/firewall/filter` requests are sent; watchdog ignores IPv6.
- **Expected Result:** When IPv6 capability is declared as `Implemented`, the provider must create corresponding forward drop rules in `/rest/ipv6/firewall/filter`, and the watchdog must iterate over both IPv4 and IPv6 filter tables.
- **Remediation Recommendation:**
  Either downgrade `ipv6_policy_enforcement` to `CapabilityClassification::NotImplemented`, or implement dual-stack rule injection and update the watchdog script.

---

### Finding SEC-05: Multi-Instance Persistence Synchronization Race and Data Loss
- **Finding ID:** SEC-05
- **Severity:** **HIGH**
- **Confidence:** **HIGH**
- **File & Function:** [`src/gateway/admin/persistence.rs:373-410`](file:///D:/Vault/Rustrict/src/gateway/admin/persistence.rs#L373-L410)
- **Violated Requirement:** REQ-PERS-02 (Multi-instance disk synchronization without update loss)
- **Impact:** Stale-state overwrite and loss of active policy modifications across concurrent CLI instances.
- **Why it matters:** When `sync_from_disk_if_present` loads updates from disk:
  ```rust
  if p.lifecycle_state == PolicyLifecycleState::Recovered
      && lock.historical_policies[pos].lifecycle_state != PolicyLifecycleState::Recovered
  {
      lock.historical_policies[pos] = p;
  }
  ```
  It ONLY updates in-memory policies if the disk policy is in the `Recovered` state. If another instance updated the policy's duration (`adjust`), error status, or expiration timestamp, those updates are completely ignored. When the current instance subsequently calls `persist_internal`, it writes its stale in-memory state back to disk, overwriting the other instance's updates.
- **Reproduction Steps:**
  1. Instance A applies a policy.
  2. Instance B adjusts the policy duration.
  3. Instance A appends an unrelated record and saves.
- **Actual Result:** Instance B's duration adjustment is wiped out on disk.
- **Remediation Recommendation:**
  Merge disk policy entries based on `last_updated_unix` timestamps or revision counters rather than filtering strictly for `Recovered`.

---

### Finding SEC-06: Plaintext Administrative Password Console Echo
- **Finding ID:** SEC-06
- **Severity:** **MEDIUM**
- **Confidence:** **HIGH**
- **File & Function:** [`src/cli/prompt.rs:2043`](file:///D:/Vault/Rustrict/src/cli/prompt.rs#L2043), [`2172`](file:///D:/Vault/Rustrict/src/cli/prompt.rs#L2172), [`2314`](file:///D:/Vault/Rustrict/src/cli/prompt.rs#L2314), [`2428`](file:///D:/Vault/Rustrict/src/cli/prompt.rs#L2428)
- **Violated Requirement:** REQ-CLI-05 (Password input must not echo plaintext credentials)
- **Impact:** Credential disclosure to shoulder-surfers, screen recordings, terminal scrollback buffers, or console history.
- **Why it matters:** Every provider connection command prompts for the password using:
  ```rust
  io::stdin().read_line(&mut password_input)
  ```
  The characters are echoed in plain text on the screen as the operator types them.
- **Reproduction Steps:**
  Run `router connect mikrotik 192.168.1.1 --user admin`. When prompted for the password, type a string; observe each character displayed in cleartext.
- **Remediation Recommendation:**
  Use the Windows Console API (`SetConsoleMode` clearing `ENABLE_ECHO_INPUT`) or a secure input crate (e.g. `rpassword`) to read passwords without console echo.

---

### Finding SEC-07: Unbounded Process Output Pipe Deadlock Risk in `ssh.rs`
- **Finding ID:** SEC-07
- **Severity:** **MEDIUM**
- **Confidence:** **HIGH**
- **File & Function:** [`src/gateway/admin/ssh.rs:226-264`](file:///D:/Vault/Rustrict/src/gateway/admin/ssh.rs#L226-L264)
- **Violated Requirement:** REQ-PROC-02 (Bounded command execution without process hangs)
- **Impact:** Subprocess deadlock and timeout abort when querying large router configurations.
- **Why it matters:** `ProcessSshExecutor` configures stdout and stderr as `Stdio::piped()` and enters a loop calling `child.try_wait()` with `thread::sleep(50ms)`. It does not read from the pipes until after `try_wait()` returns `Some`. If an SSH command (e.g. `uci export firewall` or a full device inventory) produces output that fills the OS pipe buffer (typically 4KB to 64KB on Windows), `ssh.exe` will block on `write()` while the parent blocks in `try_wait()`, deadlocking until the 15-second timeout fires and kills the child.
- **Remediation Recommendation:**
  Spawn threads to asynchronously drain stdout and stderr concurrently with `try_wait()`, or use `child.wait_with_output()` directly if wrapped in an external timeout thread.

---

### Finding SEC-08: Dead / Unused DPAPI Credential Storage
- **Finding ID:** SEC-08
- **Severity:** **MEDIUM**
- **Confidence:** **HIGH**
- **File & Function:** [`src/gateway/admin/credentials.rs:193-237`](file:///D:/Vault/Rustrict/src/gateway/admin/credentials.rs#L193-L237)
- **Violated Requirement:** REQ-PERS-05 (Windows DPAPI encryption for stored credentials)
- **Impact:** Dead code in security subsystem; credentials are never actually persisted securely across sessions.
- **Why it matters:** Phase 11 implemented `save_protected_credentials` and `load_protected_credentials` using Win32 `CryptProtectData` and `CryptUnprotectData`. However, a comprehensive repository grep confirms that neither function is ever called in `src/` or in `tests/`. The entire DPAPI persistence layer is completely dormant.
- **Remediation Recommendation:**
  Either integrate `save_protected_credentials` into `router connect` (e.g. `--save-credentials`), or remove the dead code if storing credentials on disk is not intended.

---

### Finding SEC-09: Unqualified Subprocess Execution in AVM and UniFi Transports
- **Finding ID:** SEC-09
- **Severity:** **MEDIUM**
- **Confidence:** **HIGH**
- **File & Function:** [`src/gateway/admin/avm.rs:229`](file:///D:/Vault/Rustrict/src/gateway/admin/avm.rs#L229), [`src/gateway/admin/unifi.rs:131`](file:///D:/Vault/Rustrict/src/gateway/admin/unifi.rs#L131)
- **Violated Requirement:** REQ-PLAT-01 (Robust Windows execution)
- **Impact:** Potential binary hijacking or execution failure if PATH is misconfigured.
- **Why it matters:** Unlike `mikrotik.rs` and `ssh.rs` which explicitly verify `C:\Windows\System32\curl.exe` and `ssh.exe` before searching PATH, `avm.rs` and `unifi.rs` directly invoke `Command::new("curl.exe")`. On Windows, this relies entirely on the ambient PATH and could attempt to load a `curl.exe` from the current working directory.
- **Remediation Recommendation:**
  Use the centralized `find_curl()` resolver from `mikrotik.rs` across all providers.

---

### Finding CODE-01: 23 Clippy Warnings Break Clean CI Compilation
- **Finding ID:** CODE-01
- **Severity:** **LOW**
- **Confidence:** **HIGH**
- **File & Function:** Multiple files across `src/gateway/admin/` and `src/limiter/divert.rs`
- **Violated Requirement:** Code quality and CI lint gates (`cargo clippy --all-targets -- -D warnings`)
- **Impact:** `cargo clippy -- -D warnings` fails with 23 errors.
- **Details:**
  - `avm.rs:109`: `calculate_digest_response` has 9 arguments (max 7).
  - `engine.rs:932`: `called unwrap on active_provider after checking its variant with is_some`.
  - `views.rs:121`: `this if has identical blocks`.
  - `unifi.rs:415, 437`: `called Iterator::last on a DoubleEndedIterator`.
  - `limiter/divert.rs:289`: `single match destructuring should be if let`.
- **Remediation Recommendation:**
  Apply standard Clippy refactorings and adjust function signatures.

---

### Finding DOC-01: Test Count Discrepancy in Phase 14 Report (177 Reported vs 182 Actual)
- **Finding ID:** DOC-01
- **Severity:** **LOW**
- **Confidence:** **HIGH**
- **File & Function:** `phase14_windows_runtime_reliability.md:104`
- **Violated Requirement:** Accurate documentation traceability
- **Impact:** Audit confusion and lack of confidence in reported metrics.
- **Why it matters:** The Phase 14 completion report documented a total of 177 tests passing. In reality, `cargo test --all-targets` runs 182 tests across 21 test binaries. The discrepancy was caused by incorrect manual entries in the Phase 14 markdown table (`test_persistence.rs: 8` vs 7 actual; `test_policy_engine.rs: 13` vs 8 actual; `test_openwrt_admin.rs: 17` vs 18 actual).
- **Remediation Recommendation:**
  Update the documentation to reflect the verified automated test counts.

---

## Part 2: Potential Operational Risks & Architectural Limitations

---

### Risk RISK-01: Head-of-Line Blocking in WinDivert Delay Queue
- **Category:** Architecture / Traffic Shaper Performance
- **Severity:** **INFORMATIONAL**
- **File:** [`src/limiter/divert.rs:286-309`](file:///D:/Vault/Rustrict/src/limiter/divert.rs#L286-L309)
- **Description:** When traffic delay simulation is active, packets are placed into a single FIFO `mpsc::channel`. The worker thread executes `thread::sleep(pkt.send_at - now)` sequentially. If packet A has a 500ms delay and packet B has a 10ms delay, packet B is delayed by 500ms instead of 10ms.
- **Recommendation:** Use a priority queue (`BinaryHeap`) ordered by `send_at` timestamp.

### Risk RISK-02: OpenWrt HTTP Naive Chunked Transfer Parsing
- **Category:** Transport / Protocol Conformance
- **Severity:** **INFORMATIONAL**
- **File:** [`src/gateway/admin/openwrt.rs:122-132`](file:///D:/Vault/Rustrict/src/gateway/admin/openwrt.rs#L122-L132)
- **Description:** `HttpOpenWrtTransport` slices the raw TCP response after `\r\n\r\n` and passes it directly to `serde_json::from_str`. If an HTTP proxy or custom web server on the router uses `Transfer-Encoding: chunked`, the hex chunk markers will cause JSON parsing to fail.
- **Recommendation:** Add basic chunked transfer de-chunking logic before JSON decoding.
