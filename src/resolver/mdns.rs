use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::time::Duration;

/// Queries mDNS (UDP 5353) to resolve Apple, Android, Linux, and IoT device names
pub fn query_mdns(ip: Ipv4Addr) -> Option<String> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.set_read_timeout(Some(Duration::from_millis(70))).ok()?;

    let octets = ip.octets();
    let ptr_name = format!("{}.{}.{}.{}.in-addr.arpa", octets[3], octets[2], octets[1], octets[0]);

    // Send reverse PTR query as well as workstation query
    for query_domain in [&ptr_name, "_workstation._tcp.local"] {
        let mut packet = Vec::with_capacity(128);
        packet.extend_from_slice(&[
            0x00, 0x00, // ID
            0x00, 0x00, // Flags
            0x00, 0x01, // Questions: 1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);

        for part in query_domain.split('.') {
            packet.push(part.len() as u8);
            packet.extend_from_slice(part.as_bytes());
        }
        packet.push(0x00);
        packet.extend_from_slice(&[0x00, 0x0c, 0x00, 0x01]); // PTR, IN

        let unicast_addr = SocketAddrV4::new(ip, 5353);
        let _ = socket.send_to(&packet, unicast_addr);

        let mut buf = [0u8; 2048];
        if let Ok((len, from)) = socket.recv_from(&mut buf) {
            if from.ip() == std::net::IpAddr::V4(ip) && len > 12 {
                if let Some(name) = parse_dns_name(&buf[..len]) {
                    return Some(name);
                }
            }
        }
    }

    None
}

fn parse_dns_name(buf: &[u8]) -> Option<String> {
    // Search for ".local" in response bytes
    let local_bytes = b".local";
    let pos = buf.windows(local_bytes.len()).position(|w| w == local_bytes)?;

    // Scan backwards from position to find the length of the leading label
    let mut start = pos;
    while start > 0 && buf[start - 1] >= 0x20 && buf[start - 1] < 0x7f && buf[start - 1] != b'.' {
        start -= 1;
    }

    if start < pos {
        let name = String::from_utf8_lossy(&buf[start..pos]).trim().to_string();
        if !name.is_empty() && name.len() > 1 && !name.starts_with('_') {
            return Some(format!("{}.local", name));
        }
    }

    None
}
