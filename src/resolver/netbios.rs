use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::time::Duration;

/// Queries NetBIOS Name Service (UDP 137) to get the Windows/Samba machine name
pub fn query_netbios(ip: Ipv4Addr) -> Option<String> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.set_read_timeout(Some(Duration::from_millis(80))).ok()?;

    // NBNS Node Status Query Packet
    let mut packet = Vec::with_capacity(50);
    // Header
    packet.extend_from_slice(&[
        0x80, 0x01, // Transaction ID
        0x00, 0x00, // Flags
        0x00, 0x01, // Questions: 1
        0x00, 0x00, // Answer RRs: 0
        0x00, 0x00, // Authority RRs: 0
        0x00, 0x00, // Additional RRs: 0
    ]);
    // Encoded wildcard name "*"
    packet.push(0x20); // Length: 32
    packet.extend_from_slice(b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    packet.push(0x00); // Terminating null
    // Type & Class
    packet.extend_from_slice(&[
        0x00, 0x21, // Type: NBSTAT
        0x00, 0x01, // Class: IN
    ]);

    let target = SocketAddrV4::new(ip, 137);
    socket.send_to(&packet, target).ok()?;

    let mut buf = [0u8; 1024];
    let (len, src) = socket.recv_from(&mut buf).ok()?;

    // Verify source IP matches targeted endpoint
    if src != SocketAddr::V4(target) {
        return None;
    }

    if len < 63 {
        return None;
    }

    // Verify transaction ID matches
    if buf[0] != 0x80 || buf[1] != 0x01 {
        return None;
    }

    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;

    if ancount == 0 {
        return None;
    }

    // In standard Node Status responses with 1 echoed question:
    // Header: 12 bytes
    // Question: 38 bytes (1 + 32 + 1 + 2 + 2)
    // Answer RR header: 2 (compressed name ptr) + 2 (type) + 2 (class) + 4 (ttl) + 2 (rdlen) = 12 bytes
    // RDATA begins at byte 62. The first byte of RDATA is num_names.
    let base_offset = if qdcount == 1 { 62 } else { 24 };

    if len > base_offset {
        let num_names = buf[base_offset] as usize;
        let mut offset = base_offset + 1;
        for _ in 0..num_names {
            if offset + 18 <= len {
                let name_bytes = &buf[offset..offset + 15];
                let name_type = buf[offset + 15];
                let flags = u16::from_be_bytes([buf[offset + 16], buf[offset + 17]]);
                let is_group = (flags & 0x8000) != 0;

                // name_type 0x00 = Workstation/computer name (unique)
                if name_type == 0x00 && !is_group {
                    let name = String::from_utf8_lossy(name_bytes).trim().to_string();
                    if !name.is_empty() && !name.starts_with("IS~") {
                        return Some(name);
                    }
                }
                offset += 18;
            }
        }
    }

    None
}
