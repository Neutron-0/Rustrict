use std::collections::HashMap;
use std::ffi::CString;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use parking_lot::RwLock;
use crate::types::MacAddress;

pub struct PassiveIdentitySniffer {
    entries: Arc<RwLock<HashMap<Ipv4Addr, (MacAddress, String)>>>,
    running: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl PassiveIdentitySniffer {
    pub fn new(device_path: &str) -> Self {
        let entries = Arc::new(RwLock::new(HashMap::new()));
        let running = Arc::new(AtomicBool::new(true));

        let entries_clone = Arc::clone(&entries);
        let running_clone = Arc::clone(&running);
        let dev_str = device_path.to_string();

        let handle = thread::spawn(move || {
            run_passive_loop(&dev_str, entries_clone, running_clone);
        });

        Self {
            entries,
            running,
            handle: Some(handle),
        }
    }

    pub fn get_name(&self, ip: Ipv4Addr) -> Option<String> {
        self.entries.read().get(&ip).map(|(_, name)| name.clone())
    }

    pub fn get_all_entries(&self) -> Vec<(Ipv4Addr, MacAddress, String)> {
        self.entries
            .read()
            .iter()
            .map(|(&ip, (mac, name))| (ip, *mac, name.clone()))
            .collect()
    }

    pub fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for PassiveIdentitySniffer {
    fn drop(&mut self) {
        self.stop();
    }
}

fn run_passive_loop(
    device_path: &str,
    entries: Arc<RwLock<HashMap<Ipv4Addr, (MacAddress, String)>>>,
    running: Arc<AtomicBool>,
) {
    type PcapOpenLiveFn = unsafe extern "C" fn(
        device: *const i8,
        snaplen: i32,
        promisc: i32,
        to_ms: i32,
        errbuf: *mut i8,
    ) -> *mut std::ffi::c_void;

    type PcapNextExFn = unsafe extern "C" fn(
        p: *mut std::ffi::c_void,
        pkt_header: *mut *mut std::ffi::c_void,
        pkt_data: *mut *const u8,
    ) -> i32;

    type PcapCloseFn = unsafe extern "C" fn(p: *mut std::ffi::c_void);

    let dll_name = CString::new("wpcap.dll").unwrap();
    let h_module = unsafe {
        windows_sys::Win32::System::LibraryLoader::LoadLibraryA(dll_name.as_ptr() as *const u8)
    };
    if h_module.is_null() {
        return;
    }

    let open_fn: PcapOpenLiveFn = unsafe {
        let name = CString::new("pcap_open_live").unwrap();
        let addr = windows_sys::Win32::System::LibraryLoader::GetProcAddress(h_module, name.as_ptr() as *const u8);
        if addr.is_none() { return; }
        std::mem::transmute(addr)
    };

    let next_ex_fn: PcapNextExFn = unsafe {
        let name = CString::new("pcap_next_ex").unwrap();
        let addr = windows_sys::Win32::System::LibraryLoader::GetProcAddress(h_module, name.as_ptr() as *const u8);
        if addr.is_none() { return; }
        std::mem::transmute(addr)
    };

    let close_fn: PcapCloseFn = unsafe {
        let name = CString::new("pcap_close").unwrap();
        let addr = windows_sys::Win32::System::LibraryLoader::GetProcAddress(h_module, name.as_ptr() as *const u8);
        if addr.is_none() { return; }
        std::mem::transmute(addr)
    };

    let c_dev = CString::new(device_path).unwrap();
    let mut errbuf = [0i8; 256];
    // Open with 200ms timeout for non-blocking loop
    let pcap_handle = unsafe { open_fn(c_dev.as_ptr(), 1500, 1, 200, errbuf.as_mut_ptr()) };
    if pcap_handle.is_null() {
        return;
    }

    while running.load(Ordering::Relaxed) {
        let mut header_ptr: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut data_ptr: *const u8 = std::ptr::null();

        let res = unsafe { next_ex_fn(pcap_handle, &mut header_ptr, &mut data_ptr) };
        if res == 1 && !data_ptr.is_null() && !header_ptr.is_null() {
            let caplen = unsafe { *(header_ptr.offset(8) as *const u32) } as usize;
            let pkt_slice = unsafe { std::slice::from_raw_parts(data_ptr, caplen) };

            if let Some((ip, mac, hostname)) = parse_dhcp_or_broadcast(pkt_slice) {
                entries.write().insert(ip, (mac, hostname));
            }
        }
    }

    unsafe { close_fn(pcap_handle); }
}

/// Parses DHCP Option 12 (Host Name) or NetBIOS Host Announcements
pub fn parse_dhcp_or_broadcast(data: &[u8]) -> Option<(Ipv4Addr, MacAddress, String)> {
    // Ethernet header: 14 bytes
    if data.len() < 14 + 20 + 8 {
        return None;
    }

    let eth_proto = u16::from_be_bytes([data[12], data[13]]);
    if eth_proto != 0x0800 {
        return None; // IPv4 only
    }

    let src_mac = MacAddress([data[6], data[7], data[8], data[9], data[10], data[11]]);

    let ip_data = &data[14..];
    let ip_proto = ip_data[9];
    if ip_proto != 17 {
        return None; // UDP only
    }

    let src_ip = Ipv4Addr::new(ip_data[12], ip_data[13], ip_data[14], ip_data[15]);

    let ip_hl = ((ip_data[0] & 0x0f) * 4) as usize;
    if ip_data.len() < ip_hl + 8 {
        return None;
    }

    let udp_data = &ip_data[ip_hl..];
    let src_port = u16::from_be_bytes([udp_data[0], udp_data[1]]);
    let dst_port = u16::from_be_bytes([udp_data[2], udp_data[3]]);
    let udp_payload = &udp_data[8..];

    // Check DHCP (ports 67 or 68)
    if (src_port == 67 || src_port == 68 || dst_port == 67 || dst_port == 68) && udp_payload.len() > 240 {
        // DHCP Magic Cookie: 0x63, 0x82, 0x53, 0x63 at offset 236
        if &udp_payload[236..240] == &[0x63, 0x82, 0x53, 0x63] {
            // Client IP at offset 12 (ciaddr) or yiaddr at offset 16
            let ciaddr = Ipv4Addr::new(udp_payload[12], udp_payload[13], udp_payload[14], udp_payload[15]);
            let yiaddr = Ipv4Addr::new(udp_payload[16], udp_payload[17], udp_payload[18], udp_payload[19]);
            let target_ip = if ciaddr != Ipv4Addr::UNSPECIFIED {
                ciaddr
            } else if yiaddr != Ipv4Addr::UNSPECIFIED {
                yiaddr
            } else {
                src_ip
            };

            // Traverse Options starting at offset 240
            let mut opt_idx = 240;
            while opt_idx + 2 <= udp_payload.len() {
                let tag = udp_payload[opt_idx];
                if tag == 255 {
                    break; // End of options
                }
                if tag == 0 {
                    opt_idx += 1; // Pad
                    continue;
                }

                let opt_len = udp_payload[opt_idx + 1] as usize;
                opt_idx += 2;

                if opt_idx + opt_len > udp_payload.len() {
                    break;
                }

                // Option 12: Host Name
                if tag == 12 && opt_len > 0 && opt_len < 64 {
                    let host_bytes = &udp_payload[opt_idx..opt_idx + opt_len];
                    let name = String::from_utf8_lossy(host_bytes).trim().to_string();
                    if !name.is_empty() && target_ip != Ipv4Addr::UNSPECIFIED {
                        return Some((target_ip, src_mac, name));
                    }
                }

                opt_idx += opt_len;
            }
        }
    }

    None
}
