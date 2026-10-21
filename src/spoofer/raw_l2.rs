use std::ffi::CString;
use crate::types::MacAddress;

type PcapOpenLiveFn = unsafe extern "C" fn(
    device: *const i8,
    snaplen: i32,
    promisc: i32,
    to_ms: i32,
    errbuf: *mut i8,
) -> *mut std::ffi::c_void;

type PcapSendPacketFn = unsafe extern "C" fn(
    handle: *mut std::ffi::c_void,
    buf: *const u8,
    size: i32,
) -> i32;

type PcapCloseFn = unsafe extern "C" fn(handle: *mut std::ffi::c_void);

#[repr(C)]
struct PcapIf {
    next: *mut PcapIf,
    name: *const i8,
    description: *const i8,
    addresses: *mut std::ffi::c_void,
    flags: u32,
}

type PcapFindAllDevsFn = unsafe extern "C" fn(
    alldevsp: *mut *mut PcapIf,
    errbuf: *mut i8,
) -> i32;

type PcapFreeAllDevsFn = unsafe extern "C" fn(alldevs: *mut PcapIf);

pub struct RawL2Sender {
    handle: *mut std::ffi::c_void,
    send_fn: PcapSendPacketFn,
    close_fn: PcapCloseFn,
    h_module: *mut std::ffi::c_void,
}

unsafe impl Send for RawL2Sender {}
unsafe impl Sync for RawL2Sender {}

impl RawL2Sender {
    pub fn open(iface_name: &str) -> Result<Self, String> {
        let dll_name = CString::new("wpcap.dll").unwrap();
        let h_module = unsafe {
            windows_sys::Win32::System::LibraryLoader::LoadLibraryA(dll_name.as_ptr() as *const u8)
        };

        if h_module.is_null() {
            return Err("Npcap (wpcap.dll) is not loaded or missing. Install Npcap in WinPcap mode.".into());
        }

        let open_fn: PcapOpenLiveFn = unsafe {
            let name = CString::new("pcap_open_live").unwrap();
            let addr = windows_sys::Win32::System::LibraryLoader::GetProcAddress(h_module, name.as_ptr() as *const u8);
            match addr {
                Some(f) => std::mem::transmute::<unsafe extern "system" fn() -> isize, PcapOpenLiveFn>(f),
                None => {
                    crate::platform::free_library(h_module);
                    return Err("pcap_open_live symbol not found".into());
                }
            }
        };

        let send_fn: PcapSendPacketFn = unsafe {
            let name = CString::new("pcap_sendpacket").unwrap();
            let addr = windows_sys::Win32::System::LibraryLoader::GetProcAddress(h_module, name.as_ptr() as *const u8);
            match addr {
                Some(f) => std::mem::transmute::<unsafe extern "system" fn() -> isize, PcapSendPacketFn>(f),
                None => {
                    crate::platform::free_library(h_module);
                    return Err("pcap_sendpacket symbol not found".into());
                }
            }
        };

        let close_fn: PcapCloseFn = unsafe {
            let name = CString::new("pcap_close").unwrap();
            let addr = windows_sys::Win32::System::LibraryLoader::GetProcAddress(h_module, name.as_ptr() as *const u8);
            match addr {
                Some(f) => std::mem::transmute::<unsafe extern "system" fn() -> isize, PcapCloseFn>(f),
                None => {
                    crate::platform::free_library(h_module);
                    return Err("pcap_close symbol not found".into());
                }
            }
        };

        // Try standard device format: \Device\NPF_{GUID} or adapter name
        let dev_str = if iface_name.starts_with(r"\Device\NPF_") {
            iface_name.to_string()
        } else {
            // Try prefixing
            format!(r"\Device\NPF_{}", iface_name)
        };

        let c_dev = CString::new(dev_str).unwrap();
        let mut errbuf = [0i8; 256];

        let handle = unsafe { open_fn(c_dev.as_ptr(), 65535, 1, 1000, errbuf.as_mut_ptr()) };
        if !handle.is_null() {
            return Ok(Self { handle, send_fn, close_fn, h_module });
        }

        // Fallback 1: Try raw name without prefix
        let c_dev_raw = CString::new(iface_name).unwrap();
        let handle_raw = unsafe { open_fn(c_dev_raw.as_ptr(), 65535, 1, 1000, errbuf.as_mut_ptr()) };
        if !handle_raw.is_null() {
            return Ok(Self { handle: handle_raw, send_fn, close_fn, h_module });
        }

        // Fallback 2: Enumerate all Npcap adapters using pcap_findalldevs safely
        // Strictly verify adapter name or description matches iface_name to prevent binding wrong adapters
        let find_name = CString::new("pcap_findalldevs").unwrap();
        let find_addr = unsafe { windows_sys::Win32::System::LibraryLoader::GetProcAddress(h_module, find_name.as_ptr() as *const u8) };
        let free_name = CString::new("pcap_freealldevs").unwrap();
        let free_addr = unsafe { windows_sys::Win32::System::LibraryLoader::GetProcAddress(h_module, free_name.as_ptr() as *const u8) };

        if let Some(find_ptr) = find_addr {
            let find_fn: PcapFindAllDevsFn = unsafe { std::mem::transmute(find_ptr) };
            let free_fn_opt: Option<PcapFreeAllDevsFn> = free_addr.map(|ptr| unsafe { std::mem::transmute(ptr) });
            let mut alldevs: *mut PcapIf = std::ptr::null_mut();

            if unsafe { find_fn(&mut alldevs, errbuf.as_mut_ptr()) } == 0 && !alldevs.is_null() {
                let mut curr = alldevs;
                let mut found_handle = std::ptr::null_mut();
                let clean_iface = iface_name.trim_start_matches(r"\Device\NPF_").to_lowercase();

                while !curr.is_null() {
                    let dev_name_ptr = unsafe { (*curr).name };
                    let desc_ptr = unsafe { (*curr).description };

                    let mut matches = false;
                    if !dev_name_ptr.is_null() {
                        let dev_s = unsafe { std::ffi::CStr::from_ptr(dev_name_ptr) }.to_string_lossy().to_lowercase();
                        if !clean_iface.is_empty() && (dev_s.contains(&clean_iface) || clean_iface.contains(dev_s.trim_start_matches(r"\device\npf_"))) {
                            matches = true;
                        }
                    }
                    if !matches && !desc_ptr.is_null() {
                        let desc_s = unsafe { std::ffi::CStr::from_ptr(desc_ptr) }.to_string_lossy().to_lowercase();
                        if !clean_iface.is_empty() && (desc_s.contains(&clean_iface) || clean_iface.contains(&desc_s)) {
                            matches = true;
                        }
                    }

                    if matches && !dev_name_ptr.is_null() {
                        let dev_h = unsafe { open_fn(dev_name_ptr, 65535, 1, 1000, errbuf.as_mut_ptr()) };
                        if !dev_h.is_null() {
                            found_handle = dev_h;
                            break;
                        }
                    }
                    curr = unsafe { (*curr).next };
                }

                if let Some(free_fn) = free_fn_opt {
                    unsafe { free_fn(alldevs); }
                }

                if !found_handle.is_null() {
                    return Ok(Self { handle: found_handle, send_fn, close_fn, h_module });
                }
            }
        }

        let err_bytes: Vec<u8> = errbuf.iter().map(|&b| b as u8).take_while(|&b| b != 0).collect();
        let err_msg = String::from_utf8_lossy(&err_bytes);
        unsafe { crate::platform::free_library(h_module); }
        Err(format!("Could not open Npcap interface ({}) err: {}", iface_name, err_msg))
    }

    pub fn send_frame(&self, frame: &[u8]) -> Result<(), String> {
        let res = unsafe { (self.send_fn)(self.handle, frame.as_ptr(), frame.len() as i32) };
        if res != 0 {
            return Err("Failed to send raw packet".into());
        }
        Ok(())
    }
}

impl Drop for RawL2Sender {
    fn drop(&mut self) {
        unsafe {
            (self.close_fn)(self.handle);
            if !self.h_module.is_null() {
                crate::platform::free_library(self.h_module);
            }
        }
    }
}

/// Builds a 42-byte Ethernet + ARP Reply frame
pub fn craft_arp_reply(
    dst_mac: MacAddress,
    src_mac: MacAddress,
    sender_ip: std::net::Ipv4Addr,
    sender_mac: MacAddress,
    target_ip: std::net::Ipv4Addr,
    target_mac: MacAddress,
) -> [u8; 42] {
    let mut pkt = [0u8; 42];

    // Ethernet Header (14 bytes)
    pkt[0..6].copy_from_slice(&dst_mac.0);
    pkt[6..12].copy_from_slice(&src_mac.0);
    pkt[12..14].copy_from_slice(&[0x08, 0x06]); // EtherType = ARP (0x0806)

    // ARP Header (28 bytes)
    pkt[14..16].copy_from_slice(&[0x00, 0x01]); // Hardware Type = Ethernet (1)
    pkt[16..18].copy_from_slice(&[0x08, 0x00]); // Protocol Type = IPv4 (0x0800)
    pkt[18] = 6;                                // Hardware Address Length (6)
    pkt[19] = 4;                                // Protocol Address Length (4)
    pkt[20..22].copy_from_slice(&[0x00, 0x02]); // Operation = Reply (2)

    // Sender Hardware & IP
    pkt[22..28].copy_from_slice(&sender_mac.0);
    pkt[28..32].copy_from_slice(&sender_ip.octets());

    // Target Hardware & IP
    pkt[32..38].copy_from_slice(&target_mac.0);
    pkt[38..42].copy_from_slice(&target_ip.octets());

    pkt
}

/// Builds a 42-byte Ethernet + ARP Request frame
pub fn craft_arp_request(
    src_mac: MacAddress,
    src_ip: std::net::Ipv4Addr,
    target_ip: std::net::Ipv4Addr,
) -> [u8; 42] {
    let mut pkt = [0u8; 42];

    // Ethernet Header (14 bytes)
    pkt[0..6].copy_from_slice(&MacAddress::BROADCAST.0);
    pkt[6..12].copy_from_slice(&src_mac.0);
    pkt[12..14].copy_from_slice(&[0x08, 0x06]); // EtherType = ARP (0x0806)

    // ARP Header (28 bytes)
    pkt[14..16].copy_from_slice(&[0x00, 0x01]); // Hardware Type = Ethernet (1)
    pkt[16..18].copy_from_slice(&[0x08, 0x00]); // Protocol Type = IPv4 (0x0800)
    pkt[18] = 6;                                // Hardware Address Length (6)
    pkt[19] = 4;                                // Protocol Address Length (4)
    pkt[20..22].copy_from_slice(&[0x00, 0x01]); // Operation = Request (1)

    // Sender Hardware & IP
    pkt[22..28].copy_from_slice(&src_mac.0);
    pkt[28..32].copy_from_slice(&src_ip.octets());

    // Target Hardware & IP
    pkt[32..38].copy_from_slice(&MacAddress::ZERO.0);
    pkt[38..42].copy_from_slice(&target_ip.octets());

    pkt
}

/// Parses an incoming raw Ethernet frame for an ARP Reply, returning (sender_ip, sender_mac)
pub fn parse_arp_reply(frame: &[u8]) -> Option<(std::net::Ipv4Addr, MacAddress)> {
    if frame.len() < 42 {
        return None;
    }
    // EtherType == ARP (0x0806)
    if frame[12] != 0x08 || frame[13] != 0x06 {
        return None;
    }
    // Operation == Reply (2)
    if frame[20] != 0x00 || frame[21] != 0x02 {
        return None;
    }
    let sender_mac = MacAddress([frame[22], frame[23], frame[24], frame[25], frame[26], frame[27]]);
    let sender_ip = std::net::Ipv4Addr::new(frame[28], frame[29], frame[30], frame[31]);
    Some((sender_ip, sender_mac))
}
