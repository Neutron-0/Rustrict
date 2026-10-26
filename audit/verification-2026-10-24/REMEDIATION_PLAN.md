# Rustrict — Actionable Remediation & Hardening Plan

**Audit Date:** 2026-10-24  
**Target:** Rustrict v2.0.0 (`D:\Vault\Rustrict`)  
**Status:** **PROPOSED — DO NOT IMPLEMENT PRIOR TO STAKEHOLDER APPROVAL**

---

## 1. Remediation Priority Worklist

```
  +-------------------------------------------------------------------------+
  | PRIORITY | FINDING ID | DESCRIPTION                          | EFFORT   |
  +----------+------------+--------------------------------------+----------+
  | P0       | SEC-01     | Fix stdin multiplexing in AVM/UniFi  | 2 hours  |
  | P0       | SEC-02     | Remove startup mock auto-connect     | 30 mins  |
  +----------+------------+--------------------------------------+----------+
  | P1       | SEC-03     | Fix multi-target scope truncation    | 2 hours  |
  | P1       | SEC-04     | Fix MikroTik IPv6 capability & rules | 2 hours  |
  | P1       | SEC-05     | Fix multi-instance sync race         | 1 hour   |
  +----------+------------+--------------------------------------+----------+
  | P2       | SEC-06     | Mask password console input echo     | 1 hour   |
  | P2       | SEC-07     | Fix SSH subprocess pipe deadlock     | 1 hour   |
  | P2       | SEC-09     | Centralize curl.exe path validation  | 30 mins  |
  | P2       | SEC-08     | Integrate or clean up DPAPI storage  | 1 hour   |
  +----------+------------+--------------------------------------+----------+
  | P3       | CODE-01    | Fix 23 Clippy warnings               | 1 hour   |
  | P3       | DOC-01     | Correct test count documentation     | 15 mins  |
  +-------------------------------------------------------------------------+
```

---

## 2. Priority P0: Critical Release Blockers

### Item 1: Fix Stdin Multiplexing in `ProcessAvmTransport` & `ProcessUnifiTransport` (SEC-01)
- **Problem:** Attempting to pass `--config -` and `--data-binary @-` over the same stdin stream causes curl to crash on syntax error when encountering the request body.
- **Minimal Fix in `src/gateway/admin/avm.rs` and `src/gateway/admin/unifi.rs`:**
  Rather than multiplexing on stdin, write the XML/JSON request payload to a temporary file via `TempFileGuard`, and pass `--data-binary @<temp_path>` while passing only headers and options via `--config -`:
  ```rust
  let mut temp_body = None;
  if !body_str.is_empty() {
      let path = std::env::temp_dir().join(format!("rustrict_body_{}_{}.tmp", pid, now));
      fs::write(&path, body_str)?;
      cmd.arg("--data-binary").arg(format!("@{}", path.display()));
      temp_body = Some(TempFileGuard::new(&path));
  }
  ```
- **Required Regression Test:**
  Add an integration test in `tests/test_reliability.rs` that spawns the real Windows `curl.exe` with a local HTTP test server or verified command generator to assert that curl completes without syntax errors.

---

### Item 2: Remove Silent Startup Connection to Mock Provider (SEC-02)
- **Problem:** `Prompt::new` in `src/cli/prompt.rs` connects to `MockRouterAdminProvider` with `authenticated: true` on launch, causing router commands to run against the mock simulator without user awareness.
- **Minimal Fix in `src/cli/prompt.rs`:**
  Remove lines 119–120 in `src/cli/prompt.rs`:
  ```rust
  // REMOVE:
  // let mock_provider = Arc::new(MockRouterAdminProvider::new(iface.gateway));
  // let _ = router_registry.connect("mock", mock_provider, "internal://mock");
  ```
  Ensure `router_registry` initializes with `active_connection: None`. The CLI will correctly display `DISCONNECTED` on startup until the user runs `router connect <provider>`.
- **Required Regression Test:**
  Add a test asserting that `Prompt::new` has `router_registry.is_connected() == false` and that attempting `apply_policy` fails closed with `UnsupportedOperation("No router provider is currently connected")`.

---

## 3. Priority P1: High-Severity Policy & Safety Defects

### Item 3: Fix Multi-Target Scope Truncation in OpenWrt, MikroTik, and AVM (SEC-03)
- **Problem:** Code indexes `targets[0]` only, ignoring `targets[1..]` when `PolicyScope::SpecificTargets` contains multiple targets.
- **Minimal Fix in `openwrt.rs`, `mikrotik.rs`, and `avm.rs`:**
  Loop over `targets` and generate firewall rules / API calls for every target in the vector:
  ```rust
  PolicyScope::SpecificTargets(targets) => {
      for (idx, target) in targets.iter().enumerate() {
          let mac = req.target_macs.get(idx);
          // dispatch rule for each target
      }
  }
  ```
- **Required Regression Test:**
  Add tests in `test_openwrt_admin.rs`, `test_mikrotik_admin.rs`, and `test_avm_admin.rs` submitting a policy with 3 distinct target IPs and asserting that 3 rules are created in provider state.

---

### Item 4: Fix MikroTik False IPv6 Capability & Rule Dispatch (SEC-04)
- **Problem:** Declares `ipv6_policy_enforcement: Implemented` but only mutates `/rest/ip/firewall/filter`, completely ignoring IPv6.
- **Minimal Fix:**
  In `src/gateway/admin/mikrotik.rs`:
  - When target MAC or IPv6 addresses are present, also POST to `/rest/ipv6/firewall/filter`.
  - Update `ensure_router_watchdog` script to iterate over both `/ip firewall filter` and `/ipv6 firewall filter`.
- **Required Regression Test:**
  Add a test in `test_mikrotik_admin.rs` verifying that an IPv6 policy request adds rules to both IPv4 and IPv6 filter tables.

---

### Item 5: Fix Multi-Instance Persistence Synchronization Race (SEC-05)
- **Problem:** `sync_from_disk_if_present` only merges policies if `p.lifecycle_state == Recovered`, overwriting duration adjustments and active policy updates from other instances.
- **Minimal Fix in `src/gateway/admin/persistence.rs`:**
  Update policy merging logic to compare timestamps or merge active policy modifications:
  ```rust
  if let Some(pos) = lock.historical_policies.iter().position(|hp| hp.policy_id == p.policy_id) {
      if p.applied_at_unix >= lock.historical_policies[pos].applied_at_unix {
          lock.historical_policies[pos] = p;
      }
  }
  ```
- **Required Regression Test:**
  Add a test where Instance A updates duration, Instance B appends a record, and Instance A's duration survives on disk.

---

## 4. Priority P2: Correctness & Maintainability

### Item 6: Mask Plaintext Password Console Echo (SEC-06)
- **Fix in `src/cli/prompt.rs`:**
  Replace `io::stdin().read_line()` with a helper function that calls Win32 `SetConsoleMode` clearing `ENABLE_ECHO_INPUT` before reading, or integrate `rpassword`.

### Item 7: Prevent Subprocess Output Pipe Deadlock in `ssh.rs` (SEC-07)
- **Fix in `src/gateway/admin/ssh.rs`:**
  Spawn background threads to read `child.stdout` and `child.stderr` into memory buffers concurrently with the `try_wait()` polling loop.

### Item 8: Centralize `curl.exe` Path Verification (SEC-09)
- **Fix in `avm.rs` and `unifi.rs`:**
  Replace `Command::new("curl.exe")` with `let curl = HttpsMikroTikTransport::find_curl()?; Command::new(curl)`.

### Item 9: Integrate or Remove Dead DPAPI Credential Storage (SEC-08)
- **Fix:** Either expose `--save-credentials` / `--load-credentials` in `router connect`, or remove the dormant functions to maintain a lean codebase.

---

## 5. Priority P3: Code Quality & Clean CI Gates

### Item 10: Resolve 23 Clippy Warnings (CODE-01)
- Refactor `calculate_digest_response` to accept a config struct.
- Replace `unwrap` on `active_provider` with `if let Some(p) = active_provider.as_ref()`.
- Fix identical `if` blocks in `views.rs:121`.
- Clean up redundant iterator traversals (`.last()` on double-ended iterators).
