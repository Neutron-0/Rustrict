# Rustrict — Phase 1 Remediation Diff & Architectural Summary
**Date:** 2026-10-24  
**Workspace:** `D:\Vault\Rustrict`  
**Base Commit:** HEAD (`15e68b1`)  

---

## 1. File Modification Matrix

| File Path | Nature of Change | Findings Addressed |
| :--- | :--- | :--- |
| `Cargo.toml` | Added `Win32_System_Console` to `windows-sys` features | SEC-06 |
| `src/gateway/admin/curl_util.rs` (New) | Implemented `find_curl()` and `AutoCleanFile` RAII guard | SEC-01 |
| `src/gateway/admin/mod.rs` | Registered and exported `curl_util` (`find_curl`, `AutoCleanFile`) | SEC-01 |
| `src/gateway/admin/avm.rs` | Separated curl stdin config from payload; multi-target rollback; Clippy fixes | SEC-01, SEC-03, CODE-01 |
| `src/gateway/admin/unifi.rs` | Separated curl stdin config from payload; Clippy fixes (`.next_back()`) | SEC-01, CODE-01 |
| `src/gateway/admin/mikrotik.rs` | Reused `find_curl()`; multi-target loops & rollback; IPv6 `NotImplemented`; Clippy fixes | SEC-01, SEC-03, SEC-04, CODE-01 |
| `src/gateway/admin/openwrt.rs` | Multi-target UCI rules iteration; atomic commit & rollback | SEC-03 |
| `src/gateway/admin/registry.rs` | Corrected `mikrotik-rest` IPv6 capability declaration; Clippy fixes | SEC-04, CODE-01 |
| `src/gateway/admin/persistence.rs` | Fixed multi-instance synchronization race; implemented `Default`; Clippy fixes | SEC-05, CODE-01 |
| `src/gateway/admin/ssh.rs` | Threaded asynchronous stdout/stderr pipe draining to prevent deadlocks | SEC-07 |
| `src/gateway/admin/engine.rs` | Pattern simplification; collapsible if; unnecessary unwrap; `is_some_and` | CODE-01 |
| `src/gateway/admin/mock.rs` | Struct initializer cleanup | CODE-01 |
| `src/gateway/admin/plan.rs` | Derived `Default` on `PolicyLifecycleState` with `#[default]` | CODE-01 |
| `src/gateway/admin/views.rs` | Corrected OpenWrt recovery mechanism mapping | CODE-01 |
| `src/limiter/divert.rs` | Simplified single match to `if let` | CODE-01 |
| `src/cli/prompt.rs` | Removed startup mock auto-connect; added `read_masked_password()`; simulated banners | SEC-02, SEC-06 |
| `tests/test_avm_admin.rs` | Added curl transport payload cleanup & multi-target regression tests | SEC-01, SEC-03 |
| `tests/test_mikrotik_admin.rs` | Added multi-target regression test & IPv6 honesty test | SEC-03, SEC-04 |
| `tests/test_openwrt_admin.rs` | Added multi-target regression test | SEC-03 |
| `tests/test_router_admin.rs` | Added disconnected startup & explicit mock connection test | SEC-02 |
| `tests/test_unifi_admin.rs` | Added curl transport payload cleanup regression test | SEC-01 |
| `tests/test_unified_admin.rs` | Updated assertion to expect `NotImplemented` for MikroTik IPv6 | SEC-04 |
| `tests/test_verification.rs` | Struct initializer cleanup | CODE-01 |

---

## 2. Key Code Changes

### SEC-01: Curl Stdin / Payload Separation (`src/gateway/admin/curl_util.rs`)
```rust
pub struct AutoCleanFile {
    path: PathBuf,
}

impl AutoCleanFile {
    pub fn create(prefix: &str, suffix: &str, content: &[u8]) -> Result<Self, AdminError> {
        let temp_dir = std::env::temp_dir();
        let pid = std::process::id();
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let count = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = temp_dir.join(format!("{}_{}_{}_{}{}", prefix, pid, timestamp, count, suffix));
        let mut file = File::create(&path)?;
        file.write_all(content)?;
        file.flush()?;
        Ok(Self { path })
    }
}

impl Drop for AutoCleanFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
```

### SEC-02: Disconnected Startup in `src/cli/prompt.rs`
```rust
// Removed:
// let mock_provider = Arc::new(MockRouterAdminProvider::new(iface.gateway));
// let _ = router_registry.connect("mock", mock_provider, "internal://mock");

// Retained:
let router_registry = Arc::new(RouterRegistry::new(iface.gateway));
router_registry.set_controller_ip(iface.ip);
let policy_engine = Arc::new(PolicyExecutionEngine::new(router_registry.clone()));
let admin_provider = policy_engine.clone() as Arc<dyn RouterAdminProvider>;
```

### SEC-03: Multi-Target Loop & Rollback (`src/gateway/admin/mikrotik.rs`)
```rust
PolicyScope::SpecificTargets(targets) => {
    let mut created_ids = Vec::new();
    for (idx, target_ip) in targets.iter().enumerate() {
        let mut rule_payload = json!({
            "chain": "forward",
            "action": "reject",
            "reject-with": "icmp-network-unreachable",
            "comment": comment,
            "src-address": target_ip.to_string()
        });
        if let Some(mac) = req.target_macs.get(idx) {
            rule_payload["src-mac-address"] = Value::String(mac.to_string());
        }

        let post_res = self.transport.request(&self.endpoint, "POST", "/rest/ip/firewall/filter", Some(rule_payload), Some(creds));
        match post_res {
            Ok(val) => created_ids.push(val.get(".id").unwrap().as_str().unwrap().to_string()),
            Err(e) => {
                for id in &created_ids {
                    let _ = self.transport.request(&self.endpoint, "DELETE", &format!("/rest/ip/firewall/filter/{}", id), None, Some(creds));
                }
                return Err(AdminError::TransactionFailed(format!("Failed to commit rule for target {} (rolled back): {}", target_ip, e)));
            }
        }
    }
}
```

### SEC-06: Windows Console Masked Password Reading (`src/cli/prompt.rs`)
```rust
fn read_masked_password() -> io::Result<String> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Console::{
            GetConsoleMode, GetStdHandle, SetConsoleMode, ENABLE_ECHO_INPUT, STD_INPUT_HANDLE,
        };
        unsafe {
            let handle = GetStdHandle(STD_INPUT_HANDLE);
            let mut mode = 0;
            if !handle.is_null()
                && handle != windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE
                && GetConsoleMode(handle, &mut mode) != 0
            {
                let prev_mode = mode;
                SetConsoleMode(handle, mode & !ENABLE_ECHO_INPUT);
                let mut input = String::new();
                let res = io::stdin().read_line(&mut input);
                SetConsoleMode(handle, prev_mode);
                println!();
                return res.map(|_| input.trim().to_string());
            }
        }
    }
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}
```

### SEC-07: Background Pipe Draining in `src/gateway/admin/ssh.rs`
```rust
let stdout_pipe = child.stdout.take();
let stderr_pipe = child.stderr.take();

let stdout_handle = std::thread::spawn(move || {
    let mut buf = Vec::new();
    if let Some(mut s) = stdout_pipe {
        let _ = s.read_to_end(&mut buf);
    }
    buf
});

let stderr_handle = std::thread::spawn(move || {
    let mut buf = Vec::new();
    if let Some(mut s) = stderr_pipe {
        let _ = s.read_to_end(&mut buf);
    }
    buf
});
```

---

## 3. Preserved Architecture & Safety Invariants

1. **Lockout Protection:** Administrator management IP (`self.target_ip`) and controller host IP (`router_registry.set_controller_ip`) remain strictly protected in `validate_scope_safety` across all providers.
2. **ARP Poisoning Fallback Prohibition:** No fallback to L2 spoofing occurs when router providers return errors or fail closed.
3. **Autonomous Watchdog Preservation:** Unrelated cron jobs on OpenWrt and scheduler tasks on MikroTik remain preserved during watchdog install, update, or uninstall cycles.
4. **WinDivert & Packet Engine Integrity:** Native packet diversion, token-bucket shaping, fault profiling, and active ARP spoofing subsystems remain 100% untouched and functional.
