use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
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
    let (len, _) = socket.recv_from(&mut buf).ok()?;

    if len > 57 {
        let num_names = buf[56] as usize;
        let mut offset = 57;
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
