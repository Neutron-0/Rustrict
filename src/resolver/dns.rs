use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::time::Duration;

/// Queries the local router gateway DNS server directly over UDP (port 53) with a strict bounded timeout.
/// This completely bypasses Windows OS `getnameinfo` and the `dnscache` service RPC queue,
/// preventing multi-second thread blocking and system unresponsiveness during large subnet scans.
pub fn query_reverse_dns_via_gateway(ip: Ipv4Addr, gateway_ip: Ipv4Addr) -> Option<String> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.set_read_timeout(Some(Duration::from_millis(45))).ok()?;

    let octets = ip.octets();
    let ptr_name = format!(
        "{}.{}.{}.{}.in-addr.arpa",
        octets[3], octets[2], octets[1], octets[0]
    );

    let mut packet = Vec::with_capacity(128);
    // DNS Header
    let tx_id = 0x5a31u16.to_be_bytes();
    packet.extend_from_slice(&[
        tx_id[0], tx_id[1], // Transaction ID
        0x01, 0x00,         // Flags: Standard query, recursion desired
        0x00, 0x01,         // Questions: 1
        0x00, 0x00,         // Answer RRs: 0
        0x00, 0x00,         // Authority RRs: 0
        0x00, 0x00,         // Additional RRs: 0
    ]);

    for part in ptr_name.split('.') {
        packet.push(part.len() as u8);
        packet.extend_from_slice(part.as_bytes());
    }
    packet.push(0x00);
    packet.extend_from_slice(&[0x00, 0x0c, 0x00, 0x01]); // PTR (12), IN (1)

    let target = SocketAddrV4::new(gateway_ip, 53);
    socket.send_to(&packet, target).ok()?;

    let mut buf = [0u8; 1024];
    if let Ok((len, from)) = socket.recv_from(&mut buf) {
        if from.ip() == std::net::IpAddr::V4(gateway_ip)
            && len > 12
            && buf[0] == tx_id[0]
            && buf[1] == tx_id[1]
        {
            return crate::resolver::llmnr::parse_llmnr_response(&buf[..len]);
        }
    }
    None
}

/// Performs reverse DNS lookup using native Windows WinSock getnameinfo
pub fn query_reverse_dns(ip: Ipv4Addr) -> Option<String> {
    use windows_sys::Win32::Networking::WinSock::{
        getnameinfo, NI_NAMEREQD, SOCKADDR, SOCKADDR_IN,
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
