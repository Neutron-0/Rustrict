use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::time::Duration;

/// Queries LLMNR (UDP 5355) link-local resolution
pub fn query_llmnr(ip: Ipv4Addr) -> Option<String> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.set_read_timeout(Some(Duration::from_millis(60))).ok()?;

    let octets = ip.octets();
    let ptr_name = format!("{}.{}.{}.{}.in-addr.arpa", octets[3], octets[2], octets[1], octets[0]);

    let mut packet = Vec::with_capacity(128);
    // Header
    packet.extend_from_slice(&[
        0x12, 0x34, // ID
        0x00, 0x00, // Standard Query
        0x00, 0x01, // Questions: 1
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
    ]);

    for part in ptr_name.split('.') {
        packet.push(part.len() as u8);
        packet.extend_from_slice(part.as_bytes());
    }
    packet.push(0x00);
    packet.extend_from_slice(&[0x00, 0x0c, 0x00, 0x01]); // PTR, IN

    let target = SocketAddrV4::new(ip, 5355);
    socket.send_to(&packet, target).ok()?;

    let mut buf = [0u8; 1024];
    if let Ok((len, _)) = socket.recv_from(&mut buf) {
        if len > 12 {
            let ancount = u16::from_be_bytes([buf[6], buf[7]]);
            if ancount > 0 {
                // Extract hostname if present
                for window in buf[12..len].windows(4) {
                    if window.iter().all(|&b| b.is_ascii_alphanumeric() || b == b'-') {
                        let name = String::from_utf8_lossy(window).to_string();
                        return Some(name);
                    }
                }
            }
        }
    }

    None
}
