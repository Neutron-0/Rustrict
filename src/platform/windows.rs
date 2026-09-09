use std::net::Ipv4Addr;
use std::process::Command;
use crate::types::{MacAddress, NetworkInterface};

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
    unsafe {
        windows_sys::Win32::UI::Shell::IsUserAnAdmin() != 0
    }
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
        unsafe { free_library(h_wpcap); }
        (true, "Npcap packet capture library detected".to_string())
    } else {
        (false, "wpcap.dll missing. Install Npcap in WinPcap-compatible mode (https://npcap.com)".to_string())
    };

    // Check WinDivert (.dll and .sys)
    let mut divert_dll_found = false;
    let mut candidate_paths = vec![
        "WinDivert.dll".to_string(),
        "WinDivert64.dll".to_string(),
    ];
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(parent) = exe_path.parent() {
            candidate_paths.push(parent.join("WinDivert.dll").to_string_lossy().to_string());
            candidate_paths.push(parent.join("WinDivert64.dll").to_string_lossy().to_string());
        }
    }
    for path in &candidate_paths {
        let dll_name = std::ffi::CString::new(path.as_str()).unwrap();
        let handle = unsafe { windows_sys::Win32::System::LibraryLoader::LoadLibraryA(dll_name.as_ptr() as *const u8) };
        if !handle.is_null() {
            divert_dll_found = true;
            unsafe { free_library(handle); }
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
        (false, "WinDivert.dll found, but WinDivert64.sys is missing alongside rustrict.exe".to_string())
    } else {
        (false, "WinDivert.dll and WinDivert64.sys missing from application directory".to_string())
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
static HANDLER_REGISTERED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

unsafe extern "system" fn console_ctrl_handler(ctrl_type: u32) -> i32 {
    if ctrl_type == 0 || ctrl_type == 1 || ctrl_type == 2 || ctrl_type == 5 || ctrl_type == 6 {
        eprintln!("\n[!] Shutdown signal received. Restoring network state...");
        let mut callbacks = SHUTDOWN_CALLBACKS.lock();
        for cb in callbacks.drain(..) {
            cb();
        }
        let _ = disable_ip_forwarding();
        eprintln!("[OK] Clean shutdown complete. Exiting.");
        std::process::exit(0);
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

pub fn enable_ip_forwarding() -> Result<(), String> {
    let status = Command::new("powershell")
        .args(["-NoProfile", "-Command", "Set-NetIPInterface -Forwarding Enabled"])
        .status()
        .map_err(|e| format!("Failed to execute PowerShell: {}", e))?;

    if status.success() {
        Ok(())
    } else {
        Err("Failed to enable IP forwarding via Set-NetIPInterface".into())
    }
}

pub fn disable_ip_forwarding() -> Result<(), String> {
    let status = Command::new("powershell")
        .args(["-NoProfile", "-Command", "Set-NetIPInterface -Forwarding Disabled"])
        .status()
        .map_err(|e| format!("Failed to execute PowerShell: {}", e))?;

    if status.success() {
        Ok(())
    } else {
        Err("Failed to disable IP forwarding via Set-NetIPInterface".into())
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
                if let (Ok(ip), Ok(mac)) = (parts[0].parse::<Ipv4Addr>(), parts[1].parse::<MacAddress>()) {
                    if mac != MacAddress::ZERO && mac != MacAddress::BROADCAST {
                        entries.push((ip, mac));
                    }
                }
            }
        }
    }
    entries
}

/// Discovers the active default IPv4 interface using Windows routing and netsh
pub fn get_default_interface() -> Result<NetworkInterface, String> {
    // Query route print to find active default gateway and interface IP
    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            r#"Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -First 1 -Property InterfaceAlias, NextHop, InterfaceMetric | ForEach-Object { "$($_.InterfaceAlias)|$($_.NextHop)" }"#,
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
    let gateway_ip: Ipv4Addr = parts[1].trim().parse()
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
        return Err(format!("Could not query IP address for interface {}", iface_name));
    }

    let local_ip: Ipv4Addr = ip_parts[0].trim().parse()
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
