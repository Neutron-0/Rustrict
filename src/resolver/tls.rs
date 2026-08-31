use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};
use std::time::Duration;

/// Probes TCP ports 3389 (Windows RDP) and 443 (HTTPS) with a fast TLS ClientHello.
/// Extracts the Subject Common Name (CN) from the server's X.509 certificate.
/// On Windows, RDP generates a self-signed certificate whose CN is the exact computer name.
pub fn probe_tls_certificate(ip: Ipv4Addr) -> Option<String> {
    for port in [3389, 443] {
        let addr = SocketAddrV4::new(ip, port);
        if let Ok(mut stream) = TcpStream::connect_timeout(
            &std::net::SocketAddr::V4(addr),
            Duration::from_millis(60),
        ) {
            let _ = stream.set_read_timeout(Some(Duration::from_millis(80)));
            let _ = stream.set_write_timeout(Some(Duration::from_millis(80)));

            use std::io::{Read, Write};

            // Standard TLS 1.2 ClientHello
            let client_hello: &[u8] = &[
                0x16,       // Content Type: Handshake (22)
                0x03, 0x01, // Version: TLS 1.0 (Record layer)
                0x00, 0x55, // Length: 85 bytes
                0x01,       // Handshake Type: Client Hello (1)
                0x00, 0x00, 0x51, // Handshake Length: 81 bytes
                0x03, 0x03, // Handshake Version: TLS 1.2 (0x0303)
                // Random (32 bytes)
                0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
                0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
                0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
                0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
                0x00,       // Session ID Length: 0
                // Cipher Suites Length: 4 (2 suites)
                0x00, 0x04,
                0xc0, 0x2f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                0x00, 0x9c, // TLS_RSA_WITH_AES_128_GCM_SHA256
                0x01, 0x00, // Compression: 1 method, null (0)
                // Extensions Length: 36
                0x00, 0x24,
                // Supported Groups (Elliptic Curves)
                0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18,
                // EC Point Formats
                0x00, 0x0b, 0x00, 0x02, 0x01, 0x00,
                // Signature Algorithms
                0x00, 0x0d, 0x00, 0x10, 0x00, 0x0e, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01,
                0x02, 0x01, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03,
            ];

            if stream.write_all(client_hello).is_ok() {
                let mut buf = vec![0u8; 4096];
                if let Ok(n) = stream.read(&mut buf) {
                    if let Some(cn) = extract_x509_cn(&buf[..n]) {
                        return Some(cn);
                    }
                }
            }
        }
    }
    None
}

/// Searches a TLS response buffer for the X.509 Common Name OID (2.5.4.3: 0x55, 0x04, 0x03)
pub fn extract_x509_cn(data: &[u8]) -> Option<String> {
    let cn_oid = &[0x55, 0x04, 0x03];
    let pos = data.windows(cn_oid.len()).position(|w| w == cn_oid)?;

    // After OID (3 bytes), ASN.1 specifies string tag (0x13 = PrintableString, 0x0c = UTF8String, 0x1e = BMPString)
    let rem = &data[pos + 3..];
    if rem.len() < 3 {
        return None;
    }

    let tag = rem[0];
    let len = rem[1] as usize;

    if rem.len() < 2 + len || len == 0 || len > 64 {
        return None;
    }

    let str_bytes = &rem[2..2 + len];

    let name = match tag {
        0x13 | 0x0c | 0x16 => {
            // PrintableString / UTF8String / IA5String
            String::from_utf8_lossy(str_bytes).trim().to_string()
        }
        0x1e => {
            // BMPString (UTF-16BE)
            let u16_chars: Vec<u16> = str_bytes
                .chunks_exact(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&u16_chars).trim().to_string()
        }
        _ => return None,
    };

    if !name.is_empty() && !name.contains('\0') {
        Some(name)
    } else {
        None
    }
}
