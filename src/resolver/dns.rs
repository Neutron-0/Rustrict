use std::net::Ipv4Addr;

/// Performs reverse DNS lookup using native Windows WinSock getnameinfo
pub fn query_reverse_dns(ip: Ipv4Addr) -> Option<String> {
    use windows_sys::Win32::Networking::WinSock::{
        getnameinfo, SOCKADDR, SOCKADDR_IN, NI_NAMEREQD,
    };

    let mut sa: SOCKADDR_IN = unsafe { std::mem::zeroed() };
    sa.sin_family = 2; // AF_INET
    sa.sin_addr.S_un.S_addr = u32::from_ne_bytes(ip.octets());

    let mut host_buf = [0u8; 256];

    let res = unsafe {
        getnameinfo(
            &sa as *const _ as *const SOCKADDR,
            std::mem::size_of::<SOCKADDR_IN>() as i32,
            host_buf.as_mut_ptr(),
            host_buf.len() as u32,
            std::ptr::null_mut(),
            0,
            NI_NAMEREQD as i32,
        )
    };

    if res == 0 {
        if let Some(pos) = host_buf.iter().position(|&b| b == 0) {
            let s = String::from_utf8_lossy(&host_buf[..pos]).trim().to_string();
            if !s.is_empty() && s != ip.to_string() {
                return Some(s);
            }
        }
    }
    None
}
