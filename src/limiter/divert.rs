use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use parking_lot::RwLock;

use crate::limiter::fault::FaultProfile;
use crate::limiter::token_bucket::SharedTokenBucket;
use crate::types::{BitRate, Direction};

#[derive(Clone)]
pub struct HostLimitRule {
    pub direction: Direction,
    pub rate: Option<BitRate>,
    pub blocked: bool,
    pub ul_bucket: Option<Arc<SharedTokenBucket>>,
    pub dl_bucket: Option<Arc<SharedTokenBucket>>,
}

pub type WinDivertCloseFn = unsafe extern "system" fn(handle: *mut std::ffi::c_void) -> i32;

#[derive(Clone, Copy)]
pub struct WinDivertHandle(pub *mut std::ffi::c_void);
unsafe impl Send for WinDivertHandle {}
unsafe impl Sync for WinDivertHandle {}

#[derive(Clone)]
pub struct TrafficLimiter {
    rules: Arc<RwLock<HashMap<Ipv4Addr, HostLimitRule>>>,
    fault_profiles: Arc<RwLock<HashMap<Ipv4Addr, FaultProfile>>>,
    running: Arc<AtomicBool>,
    active_handle: Arc<parking_lot::Mutex<Option<(WinDivertHandle, WinDivertCloseFn)>>>,
}

impl Default for TrafficLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl TrafficLimiter {
    pub fn new() -> Self {
        Self {
            rules: Arc::new(RwLock::new(HashMap::new())),
            fault_profiles: Arc::new(RwLock::new(HashMap::new())),
            running: Arc::new(AtomicBool::new(false)),
            active_handle: Arc::new(parking_lot::Mutex::new(None)),
        }
    }


    pub fn limit(&self, ip: Ipv4Addr, direction: Direction, rate: BitRate) {
        let ul_bucket = if direction.includes_outgoing() {
            Some(Arc::new(SharedTokenBucket::new(rate.0, None)))
        } else {
            None
        };

        let dl_bucket = if direction.includes_incoming() {
            Some(Arc::new(SharedTokenBucket::new(rate.0, None)))
        } else {
            None
        };

        let rule = HostLimitRule {
            direction,
            rate: Some(rate),
            blocked: false,
            ul_bucket,
            dl_bucket,
        };

        self.rules.write().insert(ip, rule);
        self.start_worker();
    }

    pub fn block(&self, ip: Ipv4Addr, direction: Direction) {
        let rule = HostLimitRule {
            direction,
            rate: None,
            blocked: true,
            ul_bucket: None,
            dl_bucket: None,
        };

        self.rules.write().insert(ip, rule);
        self.start_worker();
    }

    pub fn unlimit(&self, ip: &Ipv4Addr) {
        self.rules.write().remove(ip);
        self.fault_profiles.write().remove(ip);
    }

    pub fn set_fault(&self, ip: Ipv4Addr, profile: FaultProfile) {
        self.fault_profiles.write().insert(ip, profile);
        self.start_worker();
    }

    pub fn clear_fault(&self, ip: &Ipv4Addr) {
        self.fault_profiles.write().remove(ip);
    }

    pub fn get_fault(&self, ip: &Ipv4Addr) -> Option<FaultProfile> {
        self.fault_profiles.read().get(ip).cloned()
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some((h, close_fn)) = self.active_handle.lock().take() {
            unsafe { close_fn(h.0); }
        }
    }

    fn start_worker(&self) {
        if self.running.swap(true, Ordering::SeqCst) {
            return; // Already running
        }

        let rules = Arc::clone(&self.rules);
        let fault_profiles = Arc::clone(&self.fault_profiles);
        let running = Arc::clone(&self.running);
        let active_handle = Arc::clone(&self.active_handle);

        thread::spawn(move || {
            run_windivert_loop(rules, fault_profiles, running, active_handle);
        });
    }
}

impl Drop for TrafficLimiter {
    fn drop(&mut self) {
        self.stop();
    }
}

fn run_windivert_loop(
    rules: Arc<RwLock<HashMap<Ipv4Addr, HostLimitRule>>>,
    fault_profiles: Arc<RwLock<HashMap<Ipv4Addr, FaultProfile>>>,
    running: Arc<AtomicBool>,
    active_handle: Arc<parking_lot::Mutex<Option<(WinDivertHandle, WinDivertCloseFn)>>>,
) {
    use std::ffi::CString;

    type WinDivertOpenFn = unsafe extern "system" fn(
        filter: *const i8,
        layer: u32,
        priority: i16,
        flags: u64,
    ) -> *mut std::ffi::c_void;

    type WinDivertRecvFn = unsafe extern "system" fn(
        handle: *mut std::ffi::c_void,
        p_packet: *mut u8,
        packet_len: u32,
        p_addr: *mut u8,
        p_read_len: *mut u32,
    ) -> i32;

    type WinDivertSendFn = unsafe extern "system" fn(
        handle: *mut std::ffi::c_void,
        p_packet: *const u8,
        packet_len: u32,
        p_addr: *const u8,
        p_send_len: *mut u32,
    ) -> i32;

    // Dynamically load WinDivert.dll or WinDivert64.dll from exe dir or PATH
    let mut h_module = std::ptr::null_mut();
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
        let dll_name = CString::new(path.as_str()).unwrap();
        let handle = unsafe { windows_sys::Win32::System::LibraryLoader::LoadLibraryA(dll_name.as_ptr() as *const u8) };
        if !handle.is_null() {
            h_module = handle;
            break;
        }
    }

    if h_module.is_null() {
        eprintln!("\n[ERR] WinDivert.dll not found in working directory or application path.");
        eprintln!("[ERR] Ensure WinDivert.dll and WinDivert64.sys are placed alongside rustrict.exe.\n");
        return;
    }

    let open_fn: WinDivertOpenFn = unsafe {
        let name = CString::new("WinDivertOpen").unwrap();
        let addr = windows_sys::Win32::System::LibraryLoader::GetProcAddress(h_module, name.as_ptr() as *const u8);
        if addr.is_none() { 
            eprintln!("[ERR] Symbol WinDivertOpen not found in WinDivert.dll");
            crate::platform::free_library(h_module);
            return; 
        }
        std::mem::transmute(addr)
    };

    let recv_fn: WinDivertRecvFn = unsafe {
        let name = CString::new("WinDivertRecv").unwrap();
        let addr = windows_sys::Win32::System::LibraryLoader::GetProcAddress(h_module, name.as_ptr() as *const u8);
        if addr.is_none() {
            crate::platform::free_library(h_module);
            return;
        }
        std::mem::transmute(addr)
    };

    let send_fn: WinDivertSendFn = unsafe {
        let name = CString::new("WinDivertSend").unwrap();
        let addr = windows_sys::Win32::System::LibraryLoader::GetProcAddress(h_module, name.as_ptr() as *const u8);
        if addr.is_none() {
            crate::platform::free_library(h_module);
            return;
        }
        std::mem::transmute(addr)
    };

    let close_fn: WinDivertCloseFn = unsafe {
        let name = CString::new("WinDivertClose").unwrap();
        let addr = windows_sys::Win32::System::LibraryLoader::GetProcAddress(h_module, name.as_ptr() as *const u8);
        if addr.is_none() {
            crate::platform::free_library(h_module);
            return;
        }
        std::mem::transmute(addr)
    };

    // Open WinDivert on forward layer: layer 1 = NETWORK_FORWARD
    let filter = CString::new("ip").unwrap();
    let handle = unsafe { open_fn(filter.as_ptr(), 1, 0, 0) };
    if handle.is_null() || handle == -1isize as *mut std::ffi::c_void {
        let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        eprintln!("\n[ERR] WinDivertOpen failed (Error Code: {}).", err);
        if err == 5 {
            eprintln!("[ERR] Administrator permissions required to start the WinDivert driver.\n");
        } else if err == 2 {
            eprintln!("[ERR] WinDivert64.sys driver file missing from application directory.\n");
        }
        unsafe { crate::platform::free_library(h_module); }
        return;
    }

    *active_handle.lock() = Some((WinDivertHandle(handle), close_fn));

    let mut packet_buf = vec![0u8; 65535];
    let mut addr_buf = [0u8; 128]; // WinDivertAddress structure
    let mut read_len: u32 = 0;

    while running.load(Ordering::Relaxed) {
        let res = unsafe {
            recv_fn(
                handle,
                packet_buf.as_mut_ptr(),
                packet_buf.len() as u32,
                addr_buf.as_mut_ptr(),
                &mut read_len as *mut u32,
            )
        };

        if res == 0 {
            if !running.load(Ordering::Relaxed) {
                break;
            }
            let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
            if err == 995 || err == 6 {
                // ERROR_OPERATION_ABORTED (995) or ERROR_INVALID_HANDLE (6)
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
            continue;
        }

        if read_len < 20 {
            continue;
        }

        // Parse IPv4 header
        let version = (packet_buf[0] >> 4) & 0x0f;
        if version != 4 {
            let _ = unsafe { send_fn(handle, packet_buf.as_ptr(), read_len, addr_buf.as_ptr(), std::ptr::null_mut()) };
            continue;
        }

        let src_ip = Ipv4Addr::new(packet_buf[12], packet_buf[13], packet_buf[14], packet_buf[15]);
        let dst_ip = Ipv4Addr::new(packet_buf[16], packet_buf[17], packet_buf[18], packet_buf[19]);
        let pkt_bits = (read_len as u64) * 8;

        let rule_map = rules.read();
        let src_rule = rule_map.get(&src_ip).cloned();
        let dst_rule = rule_map.get(&dst_ip).cloned();
        drop(rule_map);

        // Check Outbound (Upload)
        if let Some(rule) = src_rule {
            if rule.direction.includes_outgoing() {
                if rule.blocked {
                    continue; // Drop packet
                }
                if let Some(bucket) = rule.ul_bucket {
                    if !bucket.try_consume(pkt_bits) {
                        continue; // Exceeded limit: drop packet
                    }
                }
            }
        }

        // Check Inbound (Download)
        if let Some(rule) = dst_rule {
            if rule.direction.includes_incoming() {
                if rule.blocked {
                    continue; // Drop packet
                }
                if let Some(bucket) = rule.dl_bucket {
                    if !bucket.try_consume(pkt_bits) {
                        continue; // Exceeded limit: drop packet
                    }
                }
            }
        }

        // Check Resilience / Fault Injection Profiles
        let fault_map = fault_profiles.read();
        let src_fault = fault_map.get(&src_ip).cloned();
        let dst_fault = fault_map.get(&dst_ip).cloned();
        drop(fault_map);

        if let Some(ref fault) = src_fault {
            if fault.should_drop() {
                continue; // Simulated packet drop
            }
        }
        if let Some(ref fault) = dst_fault {
            if fault.should_drop() {
                continue; // Simulated packet drop
            }
        }

        let delay = match (src_fault, dst_fault) {
            (Some(f1), Some(f2)) => f1.compute_delay().max(f2.compute_delay()),
            (Some(f), None) | (None, Some(f)) => f.compute_delay(),
            (None, None) => std::time::Duration::ZERO,
        };

        if !delay.is_zero() {
            std::thread::sleep(delay);
        }

        // Forward allowed packet
        let _ = unsafe {
            send_fn(
                handle,
                packet_buf.as_ptr(),
                read_len,
                addr_buf.as_ptr(),
                std::ptr::null_mut(),
            )
        };

    }

    let should_close = active_handle.lock().take().is_some();
    if should_close {
        unsafe { close_fn(handle); }
    }
    unsafe { crate::platform::free_library(h_module); }
}
