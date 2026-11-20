use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

pub static LIMITER_ACTIVATION_COUNT: AtomicU64 = AtomicU64::new(0);

pub fn limiter_activation_count() -> u64 {
    LIMITER_ACTIVATION_COUNT.load(Ordering::SeqCst)
}

pub fn reset_limiter_activation_count() {
    LIMITER_ACTIVATION_COUNT.store(0, Ordering::SeqCst);
}

use crate::limiter::fault::FaultProfile;
use crate::limiter::token_bucket::{SharedTokenBucket, TokenResult};
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
    has_faults: Arc<AtomicBool>,
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
            has_faults: Arc::new(AtomicBool::new(false)),
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
        LIMITER_ACTIVATION_COUNT.fetch_add(1, Ordering::SeqCst);
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
        LIMITER_ACTIVATION_COUNT.fetch_add(1, Ordering::SeqCst);
        self.start_worker();
    }

    pub fn unlimit(&self, ip: &Ipv4Addr) {
        self.rules.write().remove(ip);
        let mut fp = self.fault_profiles.write();
        fp.remove(ip);
        self.has_faults.store(!fp.is_empty(), Ordering::Relaxed);
        drop(fp);
        if self.rules.read().is_empty() && self.fault_profiles.read().is_empty() {
            self.stop();
        }
    }

    pub fn set_fault(&self, ip: Ipv4Addr, profile: FaultProfile) {
        self.fault_profiles.write().insert(ip, profile);
        self.has_faults.store(true, Ordering::Relaxed);
        LIMITER_ACTIVATION_COUNT.fetch_add(1, Ordering::SeqCst);
        self.start_worker();
    }

    pub fn clear_fault(&self, ip: &Ipv4Addr) {
        let mut fp = self.fault_profiles.write();
        fp.remove(ip);
        self.has_faults.store(!fp.is_empty(), Ordering::Relaxed);
        drop(fp);
        if self.rules.read().is_empty() && self.fault_profiles.read().is_empty() {
            self.stop();
        }
    }

    pub fn get_fault(&self, ip: &Ipv4Addr) -> Option<FaultProfile> {
        self.fault_profiles.read().get(ip).cloned()
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some((h, close_fn)) = self.active_handle.lock().take() {
            unsafe {
                close_fn(h.0);
            }
        }
    }

    fn start_worker(&self) {
        if self.running.swap(true, Ordering::SeqCst) {
            return; // Already running
        }

        let rules = Arc::clone(&self.rules);
        let fault_profiles = Arc::clone(&self.fault_profiles);
        let has_faults = Arc::clone(&self.has_faults);
        let running = Arc::clone(&self.running);
        let active_handle = Arc::clone(&self.active_handle);

        thread::spawn(move || {
            run_windivert_loop(rules, fault_profiles, has_faults, running, active_handle);
        });
    }
}

impl Drop for TrafficLimiter {
    fn drop(&mut self) {
        // Only run destructive teardown when the last clone drops
        if Arc::strong_count(&self.running) <= 1 {
            self.stop();
        }
    }
}

struct DelayedPacket {
    data: Vec<u8>,
    addr: [u8; 128],
    send_at: Instant,
}

fn run_windivert_loop(
    rules: Arc<RwLock<HashMap<Ipv4Addr, HostLimitRule>>>,
    fault_profiles: Arc<RwLock<HashMap<Ipv4Addr, FaultProfile>>>,
    has_faults: Arc<AtomicBool>,
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
        p_read_len: *mut u32,
        p_addr: *mut u8,
    ) -> i32;

    type WinDivertSendFn = unsafe extern "system" fn(
        handle: *mut std::ffi::c_void,
        p_packet: *const u8,
        packet_len: u32,
        p_send_len: *mut u32,
        p_addr: *const u8,
    ) -> i32;

    // Dynamically load WinDivert.dll or WinDivert64.dll from exe dir or PATH
    let mut h_module = std::ptr::null_mut();
    let mut candidate_paths = vec!["WinDivert.dll".to_string(), "WinDivert64.dll".to_string()];

    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(parent) = exe_path.parent() {
            candidate_paths.push(parent.join("WinDivert.dll").to_string_lossy().to_string());
            candidate_paths.push(parent.join("WinDivert64.dll").to_string_lossy().to_string());
        }
    }

    for path in &candidate_paths {
        let dll_name = CString::new(path.as_str()).unwrap();
        let handle = unsafe {
            windows_sys::Win32::System::LibraryLoader::LoadLibraryA(dll_name.as_ptr() as *const u8)
        };
        if !handle.is_null() {
            h_module = handle;
            break;
        }
    }

    if h_module.is_null() {
        eprintln!("\n[ERR] WinDivert.dll not found in working directory or application path.");
        eprintln!(
            "[ERR] Ensure WinDivert.dll and WinDivert64.sys are placed alongside rustrict.exe.\n"
        );
        running.store(false, Ordering::SeqCst);
        return;
    }

    let open_fn: WinDivertOpenFn = unsafe {
        let name = CString::new("WinDivertOpen").unwrap();
        let addr = windows_sys::Win32::System::LibraryLoader::GetProcAddress(
            h_module,
            name.as_ptr() as *const u8,
        );
        if addr.is_none() {
            eprintln!("[ERR] Symbol WinDivertOpen not found in WinDivert.dll");
            running.store(false, Ordering::SeqCst);
            crate::platform::free_library(h_module);
            return;
        }
        std::mem::transmute(addr)
    };

    let recv_fn: WinDivertRecvFn = unsafe {
        let name = CString::new("WinDivertRecv").unwrap();
        let addr = windows_sys::Win32::System::LibraryLoader::GetProcAddress(
            h_module,
            name.as_ptr() as *const u8,
        );
        if addr.is_none() {
            running.store(false, Ordering::SeqCst);
            crate::platform::free_library(h_module);
            return;
        }
        std::mem::transmute(addr)
    };

    let send_fn: WinDivertSendFn = unsafe {
        let name = CString::new("WinDivertSend").unwrap();
        let addr = windows_sys::Win32::System::LibraryLoader::GetProcAddress(
            h_module,
            name.as_ptr() as *const u8,
        );
        if addr.is_none() {
            running.store(false, Ordering::SeqCst);
            crate::platform::free_library(h_module);
            return;
        }
        std::mem::transmute(addr)
    };

    let close_fn: WinDivertCloseFn = unsafe {
        let name = CString::new("WinDivertClose").unwrap();
        let addr = windows_sys::Win32::System::LibraryLoader::GetProcAddress(
            h_module,
            name.as_ptr() as *const u8,
        );
        if addr.is_none() {
            running.store(false, Ordering::SeqCst);
            crate::platform::free_library(h_module);
            return;
        }
        std::mem::transmute(addr)
    };

    // Open WinDivert on forward layer: layer 1 = NETWORK_FORWARD
    // Using filter "true" captures all forwarded network traffic (IPv4 + IPv6)
    let filter = CString::new("true").unwrap();
    let handle = unsafe { open_fn(filter.as_ptr(), 1, 0, 0) };
    if handle.is_null() || handle == -1isize as *mut std::ffi::c_void {
        let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        eprintln!("\n[ERR] WinDivertOpen failed (Error Code: {}).", err);
        if err == 5 {
            eprintln!("[ERR] Administrator permissions required to start the WinDivert driver.\n");
        } else if err == 2 {
            eprintln!("[ERR] WinDivert64.sys driver file missing from application directory.\n");
        }
        running.store(false, Ordering::SeqCst);
        unsafe {
            crate::platform::free_library(h_module);
        }
        return;
    }

    *active_handle.lock() = Some((WinDivertHandle(handle), close_fn));

    // Spawn non-blocking background worker for delayed packets so the main receive loop is never stalled.
    // Bounded channel (512 slots) prevents unbounded memory growth under packet flood.
    let (delay_tx, delay_rx) = std::sync::mpsc::sync_channel::<DelayedPacket>(512);
    let delay_running = Arc::clone(&running);
    let handle_usize = handle as usize;
    let delay_worker = thread::spawn(move || {
        let h = handle_usize as *mut std::ffi::c_void;
        while delay_running.load(Ordering::Relaxed) {
            if let Ok(pkt) = delay_rx.recv_timeout(Duration::from_millis(20)) {
                let now = Instant::now();
                if pkt.send_at > now {
                    let sleep_dur = (pkt.send_at - now).min(Duration::from_millis(50));
                    thread::sleep(sleep_dur);
                }
                if delay_running.load(Ordering::Relaxed) {
                    let _ = unsafe {
                        send_fn(
                            h,
                            pkt.data.as_ptr(),
                            pkt.data.len() as u32,
                            std::ptr::null_mut(),
                            pkt.addr.as_ptr(),
                        )
                    };
                }
            }
        }
    });

    let mut packet_buf = vec![0u8; 65535];
    let mut addr_buf = [0u8; 128]; // WinDivertAddress structure
    let mut read_len: u32 = 0;

    while running.load(Ordering::Relaxed) {
        let res = unsafe {
            recv_fn(
                handle,
                packet_buf.as_mut_ptr(),
                packet_buf.len() as u32,
                &mut read_len as *mut u32,
                addr_buf.as_mut_ptr(),
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
            // Drop non-IPv4 (such as IPv6) forwarded packets to eliminate IPv6 leak/bypass
            continue;
        }

        let src_ip = Ipv4Addr::new(
            packet_buf[12],
            packet_buf[13],
            packet_buf[14],
            packet_buf[15],
        );
        let dst_ip = Ipv4Addr::new(
            packet_buf[16],
            packet_buf[17],
            packet_buf[18],
            packet_buf[19],
        );
        // Layer 2 + Layer 1 framing overhead: 14 (Ethernet MAC header) + 4 (FCS) + 8 (preamble/SFD) + 12 (IFG) = 38 bytes
        let pkt_bits = ((read_len as u64) + 38) * 8;
        let ihl = ((packet_buf[0] & 0x0f) * 4) as usize;
        let protocol = packet_buf[9];

        // Detect pure TCP ACKs (zero payload) or TCP control packets (SYN/FIN/RST)
        // to preserve connection handshakes and reverse ACK clocks without rate penalty
        let is_tcp_control = if protocol == 6 && (read_len as usize) >= (ihl + 20) {
            let tcp_offset = (((packet_buf[ihl + 12] >> 4) & 0x0f) * 4) as usize;
            let flags = packet_buf[ihl + 13];
            let has_ack = (flags & 0x10) != 0;
            let has_syn = (flags & 0x02) != 0;
            let has_fin = (flags & 0x01) != 0;
            let has_rst = (flags & 0x04) != 0;
            let total_ip_len = u16::from_be_bytes([packet_buf[2], packet_buf[3]]) as usize;
            let is_pure_ack = has_ack && !has_syn && !has_fin && (total_ip_len <= (ihl + tcp_offset));
            is_pure_ack || has_syn || has_rst
        } else {
            false
        };

        let mut pacing_delay = Duration::ZERO;
        let mut drop_packet = false;

        // Zero-allocation rule inspection: inspect rule by reference while holding short read lock
        {
            let rule_map = rules.read();
            if let Some(rule) = rule_map.get(&src_ip) {
                if rule.direction.includes_outgoing() {
                    if rule.blocked {
                        drop_packet = true;
                    } else if !is_tcp_control {
                        if let Some(ref bucket) = rule.ul_bucket {
                            match bucket.consume_or_wait(pkt_bits) {
                                TokenResult::Immediate => {}
                                TokenResult::Delay(d) => pacing_delay = pacing_delay.max(d),
                                TokenResult::Drop => drop_packet = true,
                            }
                        }
                    }
                }
            }

            if !drop_packet {
                if let Some(rule) = rule_map.get(&dst_ip) {
                    if rule.direction.includes_incoming() {
                        if rule.blocked {
                            drop_packet = true;
                        } else if !is_tcp_control {
                            if let Some(ref bucket) = rule.dl_bucket {
                                match bucket.consume_or_wait(pkt_bits) {
                                    TokenResult::Immediate => {}
                                    TokenResult::Delay(d) => pacing_delay = pacing_delay.max(d),
                                    TokenResult::Drop => drop_packet = true,
                                }
                            }
                        }
                    }
                }
            }
        }

        if drop_packet {
            continue; // Drop packet immediately
        }

        // Check Resilience / Fault Injection Profiles only if faults are actively configured
        let fault_delay = if has_faults.load(Ordering::Relaxed) {
            let fault_map = fault_profiles.read();
            let src_fault = fault_map.get(&src_ip);
            let dst_fault = fault_map.get(&dst_ip);

            if let Some(fault) = src_fault {
                if fault.should_drop() {
                    continue;
                }
            }
            if let Some(fault) = dst_fault {
                if fault.should_drop() {
                    continue;
                }
            }

            match (src_fault, dst_fault) {
                (Some(f1), Some(f2)) => f1.compute_delay().max(f2.compute_delay()),
                (Some(f), None) | (None, Some(f)) => f.compute_delay(),
                (None, None) => Duration::ZERO,
            }
        } else {
            Duration::ZERO
        };

        let total_delay = pacing_delay.max(fault_delay);

        if !total_delay.is_zero() {
            // Offload delayed/paced packet to background queue without blocking the forward loop.
            // If the pacing queue is full (512 slots), drop to signal congestion naturally.
            let _ = delay_tx.try_send(DelayedPacket {
                data: packet_buf[..read_len as usize].to_vec(),
                addr: addr_buf,
                send_at: Instant::now() + total_delay,
            });
            continue;
        }

        // Forward allowed packet immediately
        let _ = unsafe {
            send_fn(
                handle,
                packet_buf.as_ptr(),
                read_len,
                std::ptr::null_mut(),
                addr_buf.as_ptr(),
            )
        };
    }

    let _ = delay_worker.join();

    let should_close = active_handle.lock().take().is_some();
    if should_close {
        unsafe {
            close_fn(handle);
        }
    }
    unsafe {
        crate::platform::free_library(h_module);
    }
}
