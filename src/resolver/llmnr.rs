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
            return parse_llmnr_response(&buf[..len]);
        }
    }

    None
}

/// Parses a DNS/LLMNR response buffer and extracts PTR answer hostname
pub fn parse_llmnr_response(buf: &[u8]) -> Option<String> {
    if buf.len() < 12 {
        return None;
    }

    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    if ancount == 0 {
        return None;
    }

    let mut offset = 12;
    // Skip question section
    for _ in 0..qdcount {
        offset = skip_dns_name(buf, offset)?;
        if offset + 4 > buf.len() {
            return None;
        }
        offset += 4; // Skip QTYPE and QCLASS
    }

    // Parse answers
    for _ in 0..ancount {
        if offset >= buf.len() {
            break;
        }
        offset = skip_dns_name(buf, offset)?;
        if offset + 10 > buf.len() {
            return None;
        }

        let rtype = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let rdlength = u16::from_be_bytes([buf[offset + 8], buf[offset + 9]]) as usize;
        offset += 10;

        if offset + rdlength > buf.len() {
            return None;
        }

        if rtype == 12 {
            // Type 12 = PTR record
            if let Some(hostname) = decode_dns_labels(buf, offset) {
                let clean = hostname.trim_end_matches('.').to_string();
                if !clean.is_empty() {
                    let host = clean.split('.').next().unwrap_or(&clean);
                    if !host.is_empty() && !host.eq_ignore_ascii_case("in-addr") && !host.eq_ignore_ascii_case("arpa") {
                        return Some(host.to_string());
                    }
                }
            }
        }
        offset += rdlength;
    }

    None
}

fn skip_dns_name(buf: &[u8], mut offset: usize) -> Option<usize> {
    while offset < buf.len() {
        let len = buf[offset] as usize;
        if len == 0 {
            return Some(offset + 1);
        }
        if (len & 0xc0) == 0xc0 {
            return Some(offset + 2);
        }
        offset += 1 + len;
    }
    None
}

fn decode_dns_labels(buf: &[u8], start: usize) -> Option<String> {
    let mut labels = Vec::new();
    let mut curr = start;
    let mut jumps = 0;

    while curr < buf.len() && jumps < 10 {
        let len = buf[curr] as usize;
        if len == 0 {
            break;
        }
        if (len & 0xc0) == 0xc0 {
            if curr + 1 >= buf.len() {
                return None;
            }
            let ptr = ((len & 0x3f) << 8) | (buf[curr + 1] as usize);
            curr = ptr;
            jumps += 1;
            continue;
        }
        curr += 1;
        if curr + len > buf.len() {
            return None;
        }
        let label = String::from_utf8_lossy(&buf[curr..curr + len]);
        labels.push(label.to_string());
        curr += len;
    }

    if !labels.is_empty() {
        Some(labels.join("."))
    } else {
        None
    }
}
