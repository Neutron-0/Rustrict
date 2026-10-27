use crate::types::{MacAddress, NetworkInterface};
use std::net::Ipv4Addr;
use std::process::Command;

pub fn enable_ansi_support() {
    let _ = colored::control::set_virtual_terminal(true);

    extern "system" {
        fn GetStdHandle(nStdHandle: u32) -> *mut std::ffi::c_void;
        fn GetConsoleMode(hConsoleHandle: *mut std::ffi::c_void, lpMode: *mut u32) -> i32;
        fn SetConsoleMode(hConsoleHandle: *mut std::ffi::c_void, dwMode: u32) -> i32;
    }

    const STD_OUTPUT_HANDLE: u32 = -11i32 as u32;
    const STD_ERROR_HANDLE: u32 = -12i32 as u32;
    const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;

    for handle_id in [STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        unsafe {
            let handle = GetStdHandle(handle_id);
            if !handle.is_null() && handle != -1isize as *mut std::ffi::c_void {
                let mut mode = 0u32;
                if GetConsoleMode(handle, &mut mode) != 0 {
                    let _ = SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
                }
            }
        }
    }
}

pub fn is_privileged() -> bool {
    unsafe { windows_sys::Win32::UI::Shell::IsUserAnAdmin() != 0 }
}

#[derive(Debug, Clone)]
pub struct EnvironmentStatus {
    pub is_admin: bool,
    pub npcap_available: bool,
    pub windivert_available: bool,
    pub npcap_details: String,
    pub windivert_details: String,
}

pub fn check_environment() -> EnvironmentStatus {
    let is_admin = is_privileged();

    // Check Npcap (wpcap.dll)
    let npcap_name = std::ffi::CString::new("wpcap.dll").unwrap();
    let h_wpcap = unsafe {
        windows_sys::Win32::System::LibraryLoader::LoadLibraryA(npcap_name.as_ptr() as *const u8)
    };
    let (npcap_available, npcap_details) = if !h_wpcap.is_null() {
        unsafe {
            free_library(h_wpcap);
        }
        (true, "Npcap packet capture library detected".to_string())
    } else {
        (
            false,
            "wpcap.dll missing. Install Npcap in WinPcap-compatible mode (https://npcap.com)"
                .to_string(),
        )
    };

    // Check WinDivert (.dll and .sys)
    let mut divert_dll_found = false;
    let mut candidate_paths = vec!["WinDivert.dll".to_string(), "WinDivert64.dll".to_string()];
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(parent) = exe_path.parent() {
            candidate_paths.push(parent.join("WinDivert.dll").to_string_lossy().to_string());
            candidate_paths.push(parent.join("WinDivert64.dll").to_string_lossy().to_string());
        }
    }
    for path in &candidate_paths {
        let dll_name = std::ffi::CString::new(path.as_str()).unwrap();
        let handle = unsafe {
            windows_sys::Win32::System::LibraryLoader::LoadLibraryA(dll_name.as_ptr() as *const u8)
        };
        if !handle.is_null() {
            divert_dll_found = true;
            unsafe {
                free_library(handle);
            }
            break;
        }
    }

    // Check for WinDivert64.sys alongside exe or current dir
    let mut sys_found = std::path::Path::new("WinDivert64.sys").exists()
        || std::path::Path::new("WinDivert32.sys").exists();
    if !sys_found {
        if let Ok(exe_path) = std::env::current_exe() {
            if let Some(parent) = exe_path.parent() {
                sys_found = parent.join("WinDivert64.sys").exists()
                    || parent.join("WinDivert32.sys").exists();
            }
        }
    }

    let (windivert_available, windivert_details) = if divert_dll_found && sys_found {
        (true, "WinDivert driver and library detected".to_string())
    } else if divert_dll_found && !sys_found {
        (
            false,
            "WinDivert.dll found, but WinDivert64.sys is missing alongside rustrict.exe"
                .to_string(),
        )
    } else {
        (
            false,
            "WinDivert.dll and WinDivert64.sys missing from application directory".to_string(),
        )
    };

    EnvironmentStatus {
        is_admin,
        npcap_available,
        windivert_available,
        npcap_details,
        windivert_details,
    }
}

static SHUTDOWN_CALLBACKS: parking_lot::Mutex<Vec<Box<dyn FnOnce() + Send + 'static>>> =
    parking_lot::Mutex::new(Vec::new());
static HANDLER_REGISTERED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

unsafe extern "system" fn console_ctrl_handler(ctrl_type: u32) -> i32 {
    if ctrl_type == 0 || ctrl_type == 1 || ctrl_type == 2 || ctrl_type == 5 || ctrl_type == 6 {
        eprintln!("\n[!] Shutdown signal received. Restoring network state...");
        let mut callbacks = SHUTDOWN_CALLBACKS.lock();
        for cb in callbacks.drain(..) {
            cb();
        }
        let report = cleanup_forwarding();
        if !report.is_success() {
            for (iface, err) in &report.failed_interfaces {
                eprintln!("[ERR] Failed to restore forwarding on {}: {}", iface, err);
            }
            eprintln!("[WARN] Operator intervention required: manual interface state verification via 'Get-NetIPInterface' recommended.");
            std::process::exit(1);
        } else {
            eprintln!("[OK] Clean shutdown complete. Exiting.");
            std::process::exit(0);
        }
    }
    0
}

pub fn register_shutdown_handler<F: FnOnce() + Send + 'static>(handler: F) {
    SHUTDOWN_CALLBACKS.lock().push(Box::new(handler));
    if !HANDLER_REGISTERED.swap(true, std::sync::atomic::Ordering::SeqCst) {
        extern "system" {
            fn SetConsoleCtrlHandler(
                HandlerRoutine: Option<unsafe extern "system" fn(u32) -> i32>,
                Add: i32,
            ) -> i32;
        }
        unsafe {
            SetConsoleCtrlHandler(Some(console_ctrl_handler), 1);
        }
    }
}

/// # Safety
///
/// Caller must ensure `h_module` is a valid handle to a loaded library module
/// and no threads are currently executing code inside the target module.
pub unsafe fn free_library(h_module: *mut std::ffi::c_void) -> bool {
    extern "system" {
        fn FreeLibrary(hModule: *mut std::ffi::c_void) -> i32;
    }
    FreeLibrary(h_module) != 0
}

/// Abstract command execution to allow hermetic testing without spawning external shells or mutating host interfaces.
pub trait CommandRunner: Send + Sync {
    fn run_powershell(&self, command: &str) -> Result<String, String>;
}

pub struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run_powershell(&self, command: &str) -> Result<String, String> {
        // Enforce terminating error handling so cmdlet failures cause non-zero exit codes
        // and emit stderr instead of silently continuing with exit code 0.
        let ps_script = format!("$ErrorActionPreference = 'Stop'; {}", command);
        let output = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &ps_script])
            .output()
            .map_err(|e| format!("Failed to execute PowerShell: {}", e))?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let err_msg = if !stderr.is_empty() {
                stderr
            } else if !stdout.is_empty() {
                stdout
            } else {
                format!(
                    "PowerShell command failed with status {:?}",
                    output.status.code()
                )
            };
            Err(err_msg)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceForwardingRecord {
    pub interface_name: String,
    pub original_enabled: bool,
    pub currently_mutated: bool,
}

pub static FORWARDING_MUTATION_COUNT: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

pub fn forwarding_mutation_count() -> u64 {
    FORWARDING_MUTATION_COUNT.load(std::sync::atomic::Ordering::SeqCst)
}

pub fn reset_forwarding_mutation_count() {
    FORWARDING_MUTATION_COUNT.store(0, std::sync::atomic::Ordering::SeqCst);
}

pub struct ForwardingManager {
    tracked: parking_lot::Mutex<Vec<InterfaceForwardingRecord>>,
}

impl Default for ForwardingManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ForwardingManager {
    pub const fn new() -> Self {
        Self {
            tracked: parking_lot::Mutex::new(Vec::new()),
        }
    }

    pub fn query_interface_forwarding_with<R: CommandRunner>(
        &self,
        runner: &R,
        iface_name: &str,
    ) -> Result<bool, String> {
        let safe_name = iface_name.replace('\'', "''");
        let cmd = format!(
            "Get-NetIPInterface -InterfaceAlias '{}' -AddressFamily IPv4 | Select-Object -First 1 -ExpandProperty Forwarding",
            safe_name
        );
        let output = runner.run_powershell(&cmd)?;
        let val = output.trim();
        if val.eq_ignore_ascii_case("Enabled") {
            Ok(true)
        } else if val.eq_ignore_ascii_case("Disabled") {
            Ok(false)
        } else {
            Err(format!(
                "Unexpected forwarding state '{}' for interface '{}'",
                val, iface_name
            ))
        }
    }

    pub fn set_interface_forwarding_with<R: CommandRunner>(
        &self,
        runner: &R,
        iface_name: &str,
        enabled: bool,
    ) -> Result<(), String> {
        FORWARDING_MUTATION_COUNT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let safe_name = iface_name.replace('\'', "''");
        let state_str = if enabled { "Enabled" } else { "Disabled" };
        let cmd = format!(
            "Set-NetIPInterface -InterfaceAlias '{}' -AddressFamily IPv4 -Forwarding {}",
            safe_name, state_str
        );
        let _ = runner.run_powershell(&cmd)?;
        Ok(())
    }

    pub fn ensure_scoped_forwarding_enabled_with<R: CommandRunner>(
        &self,
        runner: &R,
        iface_name: &str,
    ) -> Result<bool, String> {
        let mut tracked = self.tracked.lock();

        // Invariant 1: Never treat internal tracking flags as proof of OS state.
        // Query the actual interface state before reporting that scoped forwarding is ready.
        let current_state = self.query_interface_forwarding_with(runner, iface_name)?;

        // Invariant 4: Preserve the original interface state captured at the first observation.
        // Never overwrite that baseline merely because a later observation differs.
        if !tracked.iter().any(|e| e.interface_name == iface_name) {
            tracked.push(InterfaceForwardingRecord {
                interface_name: iface_name.to_string(),
                original_enabled: current_state,
                currently_mutated: false,
            });
        }

        let entry = tracked
            .iter_mut()
            .find(|e| e.interface_name == iface_name)
            .expect("interface forwarding record must exist in tracked list");

        if current_state {
            // Forwarding is currently verified as Enabled in the OS.
            if entry.original_enabled {
                // Was originally Enabled when first observed; untouched by us.
                entry.currently_mutated = false;
                Ok(false)
            } else {
                // Was originally Disabled; our mutation is active and verified in OS.
                entry.currently_mutated = true;
                Ok(true)
            }
        } else {
            // Forwarding is currently Disabled in OS; it must be enabled.
            // Invariant 5: Record pending mutation intent. If the setter fails ambiguously
            // or state verification fails, the record preserves currently_mutated = true so cleanup
            // can restore the original baseline.
            entry.currently_mutated = true;

            // Invariant 2: Set forwarding to Enabled.
            if let Err(e) = self.set_interface_forwarding_with(runner, iface_name, true) {
                return Err(format!(
                    "Failed to set IPv4 forwarding to Enabled on interface '{}': {}",
                    iface_name, e
                ));
            }

            // Invariant 2: Query actual state and verify postcondition is Enabled.
            match self.query_interface_forwarding_with(runner, iface_name) {
                Ok(true) => {
                    entry.currently_mutated = true;
                    Ok(true)
                }
                Ok(false) => {
                    Err(format!(
                        "Forwarding verification failed: interface '{}' remained Disabled after Set-NetIPInterface",
                        iface_name
                    ))
                }
                Err(e) => {
                    Err(format!(
                        "Forwarding verification failed on interface '{}': unable to verify state: {}",
                        iface_name, e
                    ))
                }
            }
        }
    }

    pub fn cleanup_forwarding_with<R: CommandRunner>(&self, runner: &R) -> ForwardingCleanupReport {
        let mut tracked = self.tracked.lock();
        let mut report = ForwardingCleanupReport::default();

        for entry in tracked.iter_mut() {
            if entry.currently_mutated {
                let target_state = entry.original_enabled;
                let target_str = if target_state { "Enabled" } else { "Disabled" };

                // Attempt to restore interface to its captured original state
                match self.set_interface_forwarding_with(
                    runner,
                    &entry.interface_name,
                    target_state,
                ) {
                    Ok(()) => {
                        // Query and verify actual OS state
                        match self.query_interface_forwarding_with(runner, &entry.interface_name) {
                            Ok(actual_state) => {
                                if actual_state == target_state {
                                    // Successfully restored and verified
                                    entry.currently_mutated = false;
                                    report
                                        .restored_interfaces
                                        .push(entry.interface_name.clone());
                                } else {
                                    let actual_str =
                                        if actual_state { "enabled" } else { "disabled" };
                                    report.failed_interfaces.push((
                                        entry.interface_name.clone(),
                                        format!(
                                            "Verification failed: interface forwarding remains {} after restore command (expected original state: {}). Manual verification required.",
                                            actual_str, target_str
                                        ),
                                    ));
                                    // Preserve currently_mutated = true so subsequent cleanup can retry
                                    entry.currently_mutated = true;
                                }
                            }
                            Err(e) => {
                                report.failed_interfaces.push((
                                    entry.interface_name.clone(),
                                    format!(
                                        "Verification query failed after restore command: {}. Expected original state: {}. Manual verification required.",
                                        e, target_str
                                    ),
                                ));
                                // Preserve currently_mutated = true so subsequent cleanup can retry
                                entry.currently_mutated = true;
                            }
                        }
                    }
                    Err(e) => {
                        let last_known = self
                            .query_interface_forwarding_with(runner, &entry.interface_name)
                            .ok();
                        let last_str = last_known.map(|s| if s { "Enabled" } else { "Disabled" });
                        report.failed_interfaces.push((
                            entry.interface_name.clone(),
                            format!(
                                "Set-NetIPInterface restoration to {} failed: {}. Expected original state: {}. Last known state: {:?}. Manual verification required.",
                                target_str, e, target_str, last_str
                            ),
                        ));
                        // Preserve currently_mutated = true so subsequent cleanup can retry
                        entry.currently_mutated = true;
                    }
                }
            } else {
                report
                    .untouched_interfaces
                    .push(entry.interface_name.clone());
            }
        }

        report
    }

    pub fn cleanup_forwarding_with_retries<R: CommandRunner>(
        &self,
        runner: &R,
        max_attempts: usize,
    ) -> ForwardingCleanupReport {
        let attempts = max_attempts.max(1);
        let mut last_report = ForwardingCleanupReport::default();
        for attempt in 1..=attempts {
            last_report = self.cleanup_forwarding_with(runner);
            if last_report.is_success() {
                return last_report;
            }
            if attempt < attempts {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
        last_report
    }

    pub fn tracked_records(&self) -> Vec<InterfaceForwardingRecord> {
        self.tracked.lock().clone()
    }

    pub fn clear(&self) {
        self.tracked.lock().clear();
    }
}

/// Structured summary of interface IPv4 forwarding restoration.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ForwardingCleanupReport {
    /// Interfaces that were successfully restored to their original Disabled state and verified.
    pub restored_interfaces: Vec<String>,
    /// Interfaces that were originally untouched / already enabled.
    pub untouched_interfaces: Vec<String>,
    /// Interfaces that failed restoration or verification, along with the error reason.
    pub failed_interfaces: Vec<(String, String)>,
}

impl ForwardingCleanupReport {
    pub fn is_success(&self) -> bool {
        self.failed_interfaces.is_empty()
    }
}

static GLOBAL_FORWARDING_MANAGER: ForwardingManager = ForwardingManager::new();

/// Queries the IPv4 forwarding state of a specific network interface alias.
pub fn query_interface_forwarding_with<R: CommandRunner>(
    runner: &R,
    iface_name: &str,
) -> Result<bool, String> {
    GLOBAL_FORWARDING_MANAGER.query_interface_forwarding_with(runner, iface_name)
}

pub fn query_interface_forwarding(iface_name: &str) -> Result<bool, String> {
    query_interface_forwarding_with(&SystemCommandRunner, iface_name)
}

/// Sets the IPv4 forwarding state of a specific network interface alias.
pub fn set_interface_forwarding_with<R: CommandRunner>(
    runner: &R,
    iface_name: &str,
    enabled: bool,
) -> Result<(), String> {
    GLOBAL_FORWARDING_MANAGER.set_interface_forwarding_with(runner, iface_name, enabled)
}

pub fn set_interface_forwarding(iface_name: &str, enabled: bool) -> Result<(), String> {
    set_interface_forwarding_with(&SystemCommandRunner, iface_name, enabled)
}

/// Ensures IPv4 forwarding is enabled strictly on the specified interface, capturing
/// the original state beforehand. Returns Ok(true) if mutated, Ok(false) if it was already enabled.
pub fn ensure_scoped_forwarding_enabled_with<R: CommandRunner>(
    runner: &R,
    iface_name: &str,
) -> Result<bool, String> {
    GLOBAL_FORWARDING_MANAGER.ensure_scoped_forwarding_enabled_with(runner, iface_name)
}

pub fn ensure_scoped_forwarding_enabled(iface_name: &str) -> Result<bool, String> {
    ensure_scoped_forwarding_enabled_with(&SystemCommandRunner, iface_name)
}

/// Restores only interfaces that were mutated by Rustrict to their original forwarding state.
/// If no interfaces were mutated, zero system commands are executed.
/// Returns a structured report detailing restored, untouched, and failed interfaces.
pub fn cleanup_forwarding_with<R: CommandRunner>(runner: &R) -> ForwardingCleanupReport {
    GLOBAL_FORWARDING_MANAGER.cleanup_forwarding_with(runner)
}

pub fn cleanup_forwarding_with_retries<R: CommandRunner>(
    runner: &R,
    max_attempts: usize,
) -> ForwardingCleanupReport {
    GLOBAL_FORWARDING_MANAGER.cleanup_forwarding_with_retries(runner, max_attempts)
}

pub fn cleanup_forwarding() -> ForwardingCleanupReport {
    cleanup_forwarding_with_retries(&SystemCommandRunner, 3)
}

/// Deprecated: Unscoped global IP forwarding is unsafe and disallowed.
/// Scoped forwarding per interface must be used instead.
#[deprecated(
    note = "Unscoped global IP forwarding is disallowed for safety. Use ensure_scoped_forwarding_enabled(iface_name) instead."
)]
pub fn enable_ip_forwarding() -> Result<(), String> {
    Err("Unscoped global IP forwarding is disallowed for safety. Use ensure_scoped_forwarding_enabled(&interface_name) to scope forwarding changes strictly to the active interface.".into())
}

/// Backward compatibility shim for tests and external callers.
pub fn disable_ip_forwarding() -> Result<ForwardingCleanupReport, String> {
    let report = cleanup_forwarding();
    if report.is_success() {
        Ok(report)
    } else {
        let errs: Vec<String> = report
            .failed_interfaces
            .iter()
            .map(|(iface, e)| format!("{}: {}", iface, e))
            .collect();
        Err(format!(
            "Forwarding cleanup failed on interfaces: {}",
            errs.join("; ")
        ))
    }
}

/// SendARP sends an ARP request directly through the Windows kernel network stack
pub fn send_arp(ip: Ipv4Addr) -> Option<MacAddress> {
    let ip_octets = ip.octets();
    let dest_ip = u32::from_ne_bytes(ip_octets);
    let mut mac_bytes = [0u8; 6];
    let mut mac_len: u32 = 6;

    let res = unsafe {
        windows_sys::Win32::NetworkManagement::IpHelper::SendARP(
            dest_ip,
            0,
            mac_bytes.as_mut_ptr() as *mut _,
            &mut mac_len as *mut _,
        )
    };

    if res == 0 && mac_len == 6 {
        let mac = MacAddress(mac_bytes);
        if mac != MacAddress::ZERO && mac != MacAddress::BROADCAST {
            return Some(mac);
        }
    }
    None
}

/// Reads existing active dynamic entries from Windows kernel ARP table
pub fn get_arp_cache() -> Vec<(Ipv4Addr, MacAddress)> {
    let mut entries = Vec::new();
    if let Ok(output) = Command::new("arp").arg("-a").output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 && parts[2].eq_ignore_ascii_case("dynamic") {
                if let (Ok(ip), Ok(mac)) =
                    (parts[0].parse::<Ipv4Addr>(), parts[1].parse::<MacAddress>())
                {
                    if mac != MacAddress::ZERO && mac != MacAddress::BROADCAST {
                        entries.push((ip, mac));
                    }
                }
            }
        }
    }
    entries
}

/// Resolves standard durable state file path in %ProgramData%\Rustrict or %APPDATA%\Rustrict
pub fn get_state_file_path() -> std::path::PathBuf {
    if let Ok(progdata) = std::env::var("ProgramData") {
        let dir = std::path::PathBuf::from(progdata).join("Rustrict");
        let _ = std::fs::create_dir_all(&dir);
        return dir.join("rustrict_state.json");
    }
    if let Ok(appdata) = std::env::var("APPDATA") {
        let dir = std::path::PathBuf::from(appdata).join("Rustrict");
        let _ = std::fs::create_dir_all(&dir);
        return dir.join("rustrict_state.json");
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            return dir.join("rustrict_state.json");
        }
    }
    std::path::PathBuf::from("rustrict_state.json")
}

/// Discovers the active default IPv4 interface using Windows routing and netsh
pub fn get_default_interface() -> Result<NetworkInterface, String> {
    // Query route sorted by RouteMetric and InterfaceMetric to pick the lowest metric active route
    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            r#"Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object -Property RouteMetric, InterfaceMetric | Select-Object -First 1 -Property InterfaceAlias, NextHop, InterfaceMetric | ForEach-Object { "$($_.InterfaceAlias)|$($_.NextHop)" }"#,
        ])
        .output()
        .map_err(|e| format!("Failed to query route: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout.trim();
    if line.is_empty() || !line.contains('|') {
        return Err("No default route (gateway) found on this machine.".into());
    }

    let parts: Vec<&str> = line.split('|').collect();
    let iface_name = parts[0].trim().to_string();
    let gateway_ip: Ipv4Addr = parts[1]
        .trim()
        .parse()
        .map_err(|_| format!("Invalid gateway IP: {}", parts[1]))?;

    let safe_iface_name = iface_name.replace('\'', "''");

    // Now query IP address and netmask for this interface
    let ip_cmd = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                r#"Get-NetIPAddress -InterfaceAlias '{}' -AddressFamily IPv4 | Select-Object -First 1 | ForEach-Object {{"$($_.IPAddress)|$($_.PrefixLength)"}}"#,
                safe_iface_name
            ),
        ])
        .output()
        .map_err(|e| format!("Failed to query IP address: {}", e))?;

    let ip_stdout = String::from_utf8_lossy(&ip_cmd.stdout);
    let ip_line = ip_stdout.trim();
    let ip_parts: Vec<&str> = ip_line.split('|').collect();
    if ip_parts.len() < 2 {
        return Err(format!(
            "Could not query IP address for interface {}",
            iface_name
        ));
    }

    let local_ip: Ipv4Addr = ip_parts[0]
        .trim()
        .parse()
        .map_err(|_| format!("Invalid local IP: {}", ip_parts[0]))?;
    let prefix_len: u8 = ip_parts[1].trim().parse().unwrap_or(24);
    let prefix_len = prefix_len.min(32);
    let mask_u32 = if prefix_len == 0 {
        0
    } else {
        !((1u32 << (32 - prefix_len)) - 1)
    };
    let netmask = Ipv4Addr::from(mask_u32);

    // Resolve gateway MAC with retries and ARP cache fallback
    let mut gateway_mac = MacAddress::ZERO;
    for _ in 0..3 {
        if let Some(mac) = send_arp(gateway_ip) {
            gateway_mac = mac;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    if gateway_mac == MacAddress::ZERO {
        for (cached_ip, cached_mac) in get_arp_cache() {
            if cached_ip == gateway_ip && cached_mac != MacAddress::ZERO {
                gateway_mac = cached_mac;
                break;
            }
        }
    }
    if gateway_mac == MacAddress::ZERO {
        // Attempt an active ICMP echo to force Windows ARP resolution
        let _ = Command::new("ping")
            .args(["-n", "1", "-w", "500", &gateway_ip.to_string()])
            .output();
        if let Some(mac) = send_arp(gateway_ip) {
            gateway_mac = mac;
        }
    }

    if gateway_mac == MacAddress::ZERO {
        return Err(format!(
            "Failed to resolve MAC address for default gateway ({}) on interface '{}'. Ensure your network connection is active.",
            gateway_ip, iface_name
        ));
    }

    // Query MAC address and GUID of local adapter
    let adapter_cmd = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                r#"Get-NetAdapter -Name '{}' | Select-Object -First 1 | ForEach-Object {{ "$($_.MacAddress)|$($_.InterfaceGuid)" }}"#,
                safe_iface_name
            ),
        ])
        .output()
        .map_err(|e| format!("Failed to query adapter info: {}", e))?;

    let adapter_str = String::from_utf8_lossy(&adapter_cmd.stdout);
    let parts: Vec<&str> = adapter_str.trim().split('|').collect();
    let mac_str = parts.first().unwrap_or(&"").replace('-', ":");
    let local_mac = mac_str.parse::<MacAddress>().unwrap_or(MacAddress::ZERO);

    if local_mac == MacAddress::ZERO {
        return Err(format!(
            "Failed to query local MAC address for interface '{}'.",
            iface_name
        ));
    }

    let guid_str = parts.get(1).unwrap_or(&"").trim();
    let device_path = if !guid_str.is_empty() {
        format!(r"\Device\NPF_{}", guid_str)
    } else {
        iface_name.clone()
    };

    Ok(NetworkInterface {
        name: iface_name.clone(),
        description: iface_name,
        ip: local_ip,
        netmask,
        gateway: gateway_ip,
        gateway_mac,
        mac: local_mac,
        device_path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    struct MockCommandRunner {
        current_state: parking_lot::Mutex<String>,
        executed_commands: parking_lot::Mutex<Vec<String>>,
        call_count: Arc<AtomicUsize>,
    }

    impl MockCommandRunner {
        fn new(initial_state: &str) -> Self {
            Self {
                current_state: parking_lot::Mutex::new(initial_state.to_string()),
                executed_commands: parking_lot::Mutex::new(Vec::new()),
                call_count: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    impl CommandRunner for MockCommandRunner {
        fn run_powershell(&self, command: &str) -> Result<String, String> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            self.executed_commands.lock().push(command.to_string());
            if command.contains("Get-NetIPInterface") {
                Ok(self.current_state.lock().clone())
            } else if command.contains("Set-NetIPInterface") {
                if command.contains("-Forwarding Enabled") {
                    *self.current_state.lock() = "Enabled".to_string();
                } else if command.contains("-Forwarding Disabled") {
                    *self.current_state.lock() = "Disabled".to_string();
                }
                Ok(String::new())
            } else {
                Ok(String::new())
            }
        }
    }

    #[test]
    fn test_forwarding_mutation_and_restoration_when_initially_disabled() {
        let manager = ForwardingManager::new();
        let runner = MockCommandRunner::new("Disabled");
        let iface = "TestEthernet0";

        // Query
        let original = manager
            .query_interface_forwarding_with(&runner, iface)
            .expect("query should succeed");
        assert!(!original);

        // Ensure enabled
        let mutated = manager
            .ensure_scoped_forwarding_enabled_with(&runner, iface)
            .expect("enabling scoped forwarding should succeed");
        assert!(mutated);
        assert_eq!(*runner.current_state.lock(), "Enabled");

        // Cleanup
        let report = manager.cleanup_forwarding_with(&runner);
        assert!(report.is_success());
        assert_eq!(*runner.current_state.lock(), "Disabled");

        // Verify commands recorded
        let cmds = runner.executed_commands.lock();
        assert!(cmds.iter().any(|c| c.contains("Get-NetIPInterface")));
        assert!(cmds.iter().any(|c| c.contains("-Forwarding Enabled")));
        assert!(cmds.iter().any(|c| c.contains("-Forwarding Disabled")));
    }

    #[test]
    fn test_forwarding_not_touched_when_initially_enabled() {
        let manager = ForwardingManager::new();
        let runner = MockCommandRunner::new("Enabled");
        let iface = "PreConfiguredVNic";

        // Ensure enabled
        let mutated = manager
            .ensure_scoped_forwarding_enabled_with(&runner, iface)
            .expect("scoped forwarding should query and succeed");
        assert!(!mutated, "Should not report mutation when already enabled");
        assert_eq!(*runner.current_state.lock(), "Enabled");

        let cmds_before_cleanup = runner.executed_commands.lock().len();

        // Cleanup should not issue any disable command
        let report = manager.cleanup_forwarding_with(&runner);
        assert!(report.is_success());
        assert_eq!(report.restored_interfaces.len(), 0);
        assert_eq!(*runner.current_state.lock(), "Enabled");
        let cmds_after_cleanup = runner.executed_commands.lock().len();
        assert_eq!(
            cmds_before_cleanup, cmds_after_cleanup,
            "Cleanup must not execute commands if forwarding was already enabled originally"
        );
    }

    #[derive(Default)]
    struct AdvancedMockRunner {
        states: parking_lot::Mutex<std::collections::HashMap<String, String>>,
        fail_set: parking_lot::Mutex<bool>,
        fail_get: parking_lot::Mutex<bool>,
        disappeared_interface: parking_lot::Mutex<Option<String>>,
        disable_leaves_enabled: parking_lot::Mutex<bool>,
        enable_leaves_disabled: parking_lot::Mutex<bool>,
        fail_get_after_set: parking_lot::Mutex<bool>,
        executed_commands: parking_lot::Mutex<Vec<String>>,
    }

    impl AdvancedMockRunner {
        fn with_interface(iface: &str, state: &str) -> Self {
            let mut states = std::collections::HashMap::new();
            states.insert(iface.to_string(), state.to_string());
            Self {
                states: parking_lot::Mutex::new(states),
                ..Default::default()
            }
        }
    }

    impl CommandRunner for AdvancedMockRunner {
        fn run_powershell(&self, command: &str) -> Result<String, String> {
            self.executed_commands.lock().push(command.to_string());

            // Extract alias from command if present
            let alias = if let Some(start) = command.find("-InterfaceAlias '") {
                let rest = &command[start + 17..];
                if let Some(end) = rest.find('\'') {
                    rest[..end].to_string()
                } else {
                    "unknown".to_string()
                }
            } else {
                "unknown".to_string()
            };

            if let Some(ref diss) = *self.disappeared_interface.lock() {
                if diss == &alias {
                    return Err(format!("Interface '{}' not found in system table", alias));
                }
            }

            if command.contains("Get-NetIPInterface") {
                if *self.fail_get.lock() {
                    return Err("WMI RPC communication error during forwarding query".into());
                }
                if *self.fail_get_after_set.lock()
                    && self
                        .executed_commands
                        .lock()
                        .iter()
                        .any(|c| c.contains("Set-NetIPInterface"))
                {
                    return Err("RPC communication error querying interface postcondition".into());
                }
                let states = self.states.lock();
                let state = states
                    .get(&alias)
                    .cloned()
                    .unwrap_or_else(|| "Disabled".into());
                Ok(state)
            } else if command.contains("Set-NetIPInterface") {
                if *self.fail_set.lock() {
                    return Err("Access denied executing Set-NetIPInterface".into());
                }
                if command.contains("-Forwarding Enabled") {
                    if *self.enable_leaves_disabled.lock() {
                        self.states.lock().insert(alias, "Disabled".into());
                    } else {
                        self.states.lock().insert(alias, "Enabled".into());
                    }
                } else if command.contains("-Forwarding Disabled") {
                    if *self.disable_leaves_enabled.lock() {
                        self.states.lock().insert(alias, "Enabled".into());
                    } else {
                        self.states.lock().insert(alias, "Disabled".into());
                    }
                }
                Ok(String::new())
            } else {
                Ok(String::new())
            }
        }
    }

    #[test]
    fn test_cleanup_forwarding_setter_failure_preserves_mutation_state_for_retry() {
        let manager = ForwardingManager::new();
        let runner = AdvancedMockRunner::with_interface("FailSetterNic", "Disabled");

        // Enable forwarding (mutates)
        let mutated = manager
            .ensure_scoped_forwarding_enabled_with(&runner, "FailSetterNic")
            .unwrap();
        assert!(mutated);

        // Configure setter to fail on cleanup
        *runner.fail_set.lock() = true;

        let report = manager.cleanup_forwarding_with(&runner);
        assert!(
            !report.is_success(),
            "Cleanup must report failure when setter fails"
        );
        assert_eq!(report.failed_interfaces.len(), 1);
        assert_eq!(report.failed_interfaces[0].0, "FailSetterNic");
        assert!(report.failed_interfaces[0].1.contains("Access denied"));

        // Crucial guarantee: currently_mutated remains true in tracked records
        let tracked = manager.tracked_records();
        assert_eq!(tracked.len(), 1);
        assert!(
            tracked[0].currently_mutated,
            "Interface must remain marked as currently_mutated after failure"
        );

        // Now simulate retry where setter succeeds
        *runner.fail_set.lock() = false;
        let retry_report = manager.cleanup_forwarding_with(&runner);
        assert!(retry_report.is_success(), "Retry cleanup must succeed");
        assert_eq!(
            retry_report.restored_interfaces,
            vec!["FailSetterNic".to_string()]
        );

        let tracked_after = manager.tracked_records();
        assert!(
            !tracked_after[0].currently_mutated,
            "Interface must be marked as not mutated after successful retry"
        );
    }

    #[test]
    fn test_cleanup_forwarding_query_verification_failure_preserves_mutation_state() {
        let manager = ForwardingManager::new();
        let runner = AdvancedMockRunner::with_interface("VerifyFailNic", "Disabled");

        manager
            .ensure_scoped_forwarding_enabled_with(&runner, "VerifyFailNic")
            .unwrap();

        // Setter returns Ok, but interface remains Enabled (verification detects discrepancy)
        *runner.disable_leaves_enabled.lock() = true;

        let report = manager.cleanup_forwarding_with(&runner);
        assert!(!report.is_success());
        assert_eq!(report.failed_interfaces.len(), 1);
        assert!(report.failed_interfaces[0]
            .1
            .contains("remains enabled after restore command"));

        let tracked = manager.tracked_records();
        assert!(
            tracked[0].currently_mutated,
            "State must remain mutated if verification reveals enabled state"
        );
    }

    #[test]
    fn test_cleanup_forwarding_interface_disappeared_reports_failure() {
        let manager = ForwardingManager::new();
        let runner = AdvancedMockRunner::with_interface("DisappearingNic", "Disabled");

        manager
            .ensure_scoped_forwarding_enabled_with(&runner, "DisappearingNic")
            .unwrap();

        // Interface disappears from Windows before cleanup
        *runner.disappeared_interface.lock() = Some("DisappearingNic".into());

        let report = manager.cleanup_forwarding_with(&runner);
        assert!(!report.is_success());
        assert_eq!(report.failed_interfaces.len(), 1);
        assert!(report.failed_interfaces[0]
            .1
            .contains("not found in system table"));

        let tracked = manager.tracked_records();
        assert!(
            tracked[0].currently_mutated,
            "Disappeared interface must remain pending in manager"
        );
    }

    #[test]
    fn test_cleanup_forwarding_repeated_cleanup_is_idempotent() {
        let manager = ForwardingManager::new();
        let runner = AdvancedMockRunner::with_interface("IdempotentNic", "Disabled");

        manager
            .ensure_scoped_forwarding_enabled_with(&runner, "IdempotentNic")
            .unwrap();

        let report1 = manager.cleanup_forwarding_with(&runner);
        assert!(report1.is_success());
        assert_eq!(
            report1.restored_interfaces,
            vec!["IdempotentNic".to_string()]
        );

        let commands_count_after_first = runner.executed_commands.lock().len();

        // Repeated cleanup must issue zero additional commands and report clean status
        let report2 = manager.cleanup_forwarding_with(&runner);
        assert!(report2.is_success());
        assert_eq!(report2.restored_interfaces.len(), 0);
        assert_eq!(
            report2.untouched_interfaces,
            vec!["IdempotentNic".to_string()]
        );

        let commands_count_after_second = runner.executed_commands.lock().len();
        assert_eq!(
            commands_count_after_first, commands_count_after_second,
            "Repeated cleanup must not execute commands"
        );
    }

    #[test]
    fn test_cleanup_forwarding_multiple_interfaces_mixed_initial_states() {
        let manager = ForwardingManager::new();
        let runner = AdvancedMockRunner::default();
        runner
            .states
            .lock()
            .insert("NicA".into(), "Disabled".into());
        runner.states.lock().insert("NicB".into(), "Enabled".into());
        runner
            .states
            .lock()
            .insert("NicC".into(), "Disabled".into());

        // Ensure scoped forwarding on NicA (mutated: Disabled -> Enabled)
        assert!(manager
            .ensure_scoped_forwarding_enabled_with(&runner, "NicA")
            .unwrap());
        // Ensure scoped forwarding on NicB (untouched: originally Enabled)
        assert!(!manager
            .ensure_scoped_forwarding_enabled_with(&runner, "NicB")
            .unwrap());
        // Ensure scoped forwarding on NicC (mutated: Disabled -> Enabled)
        assert!(manager
            .ensure_scoped_forwarding_enabled_with(&runner, "NicC")
            .unwrap());

        let cmd_count_before_cleanup = runner.executed_commands.lock().len();

        let report = manager.cleanup_forwarding_with(&runner);
        assert!(
            report.is_success(),
            "Cleanup of multiple interfaces must succeed"
        );
        assert_eq!(report.restored_interfaces.len(), 2);
        assert!(report.restored_interfaces.contains(&"NicA".to_string()));
        assert!(report.restored_interfaces.contains(&"NicC".to_string()));
        assert_eq!(report.untouched_interfaces, vec!["NicB".to_string()]);

        // Verify that NicB was never sent a disable command
        let cmds_during_cleanup = &runner.executed_commands.lock()[cmd_count_before_cleanup..];
        for cmd in cmds_during_cleanup {
            assert!(
                !cmd.contains("NicB"),
                "Must not issue disable commands to originally enabled interface NicB"
            );
        }
    }

    #[test]
    fn test_ensure_forwarding_setter_success_but_remains_disabled_fails() {
        let manager = ForwardingManager::new();
        let runner = AdvancedMockRunner::with_interface("StubbornNic", "Disabled");
        *runner.enable_leaves_disabled.lock() = true;

        let res = manager.ensure_scoped_forwarding_enabled_with(&runner, "StubbornNic");
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("remained Disabled"));

        // Crucial invariant: entry is tracked as currently_mutated = true so cleanup can restore
        let tracked = manager.tracked_records();
        assert_eq!(tracked.len(), 1);
        assert!(tracked[0].currently_mutated);
    }

    #[test]
    fn test_ensure_forwarding_query_fails_after_setter() {
        let manager = ForwardingManager::new();
        let runner = AdvancedMockRunner::with_interface("FailQueryNic", "Disabled");
        *runner.fail_get_after_set.lock() = true;

        let res = manager.ensure_scoped_forwarding_enabled_with(&runner, "FailQueryNic");
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("unable to verify state"));

        let tracked = manager.tracked_records();
        assert_eq!(tracked.len(), 1);
        assert!(tracked[0].currently_mutated);
    }

    #[test]
    fn test_ensure_forwarding_previously_mutated_then_externally_disabled_queries_and_reenables() {
        let manager = ForwardingManager::new();
        let runner = AdvancedMockRunner::with_interface("FlappingNic", "Disabled");

        // 1. Initial enable: Disabled -> Enabled
        let mut1 = manager
            .ensure_scoped_forwarding_enabled_with(&runner, "FlappingNic")
            .unwrap();
        assert!(mut1);

        // 2. Externally changed to Disabled
        runner
            .states
            .lock()
            .insert("FlappingNic".into(), "Disabled".into());

        // Configure setter failure: ensure it does NOT claim success from internal flag
        *runner.fail_set.lock() = true;
        let fail_res = manager.ensure_scoped_forwarding_enabled_with(&runner, "FlappingNic");
        assert!(fail_res.is_err());
        assert!(fail_res
            .unwrap_err()
            .contains("Failed to set IPv4 forwarding"));

        // 3. Clear setter failure: re-enable succeeds and is verified in OS
        *runner.fail_set.lock() = false;
        let mut2 = manager
            .ensure_scoped_forwarding_enabled_with(&runner, "FlappingNic")
            .unwrap();
        assert!(mut2);

        // Crucial invariant: original baseline is still Disabled
        let tracked = manager.tracked_records();
        assert!(!tracked[0].original_enabled);
        assert!(tracked[0].currently_mutated);

        // Cleanup restores Disabled
        let report = manager.cleanup_forwarding_with(&runner);
        assert!(report.is_success());
        assert_eq!(runner.states.lock().get("FlappingNic").unwrap(), "Disabled");
    }

    #[test]
    fn test_original_state_enabled_later_changed_cleanup_restores_enabled() {
        let manager = ForwardingManager::new();
        let runner = AdvancedMockRunner::with_interface("InitiallyEnabledNic", "Enabled");

        // 1. Initial observation: Enabled -> original_enabled: true
        let mut1 = manager
            .ensure_scoped_forwarding_enabled_with(&runner, "InitiallyEnabledNic")
            .unwrap();
        assert!(!mut1, "Should report false when initially enabled");

        // 2. Later, interface is externally or accidentally disabled
        runner
            .states
            .lock()
            .insert("InitiallyEnabledNic".into(), "Disabled".into());

        // 3. ensure_scoped_forwarding_enabled detects Disabled, enables it, and verifies
        let mut2 = manager
            .ensure_scoped_forwarding_enabled_with(&runner, "InitiallyEnabledNic")
            .unwrap();
        assert!(mut2);

        // Invariant: original_enabled must STILL be true!
        let tracked = manager.tracked_records();
        assert_eq!(tracked.len(), 1);
        assert!(
            tracked[0].original_enabled,
            "Original enabled baseline must be preserved"
        );
        assert!(tracked[0].currently_mutated);

        // 4. Cleanup MUST restore Enabled (not Disabled!)
        let report = manager.cleanup_forwarding_with(&runner);
        assert!(report.is_success());
        assert_eq!(
            report.restored_interfaces,
            vec!["InitiallyEnabledNic".to_string()]
        );
        assert_eq!(
            runner.states.lock().get("InitiallyEnabledNic").unwrap(),
            "Enabled",
            "Cleanup must restore original Enabled state"
        );
    }

    #[test]
    fn test_cleanup_forwarding_with_retries_transient_failure_succeeds() {
        let manager = ForwardingManager::new();
        let runner = AdvancedMockRunner::with_interface("RetryNic", "Disabled");

        manager
            .ensure_scoped_forwarding_enabled_with(&runner, "RetryNic")
            .unwrap();

        // Fail first cleanup attempt
        *runner.fail_set.lock() = true;
        let fail_report = manager.cleanup_forwarding_with(&runner);
        assert!(!fail_report.is_success());
        assert_eq!(fail_report.failed_interfaces.len(), 1);

        // Recover on second attempt
        *runner.fail_set.lock() = false;
        let retry_report = manager.cleanup_forwarding_with_retries(&runner, 2);
        assert!(retry_report.is_success());
        assert_eq!(
            retry_report.restored_interfaces,
            vec!["RetryNic".to_string()]
        );
    }
}
