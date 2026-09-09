use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::time::Duration;

use crate::core::assessment::{AuditFinding, AuditSeverity};

/// Audits TLS security posture on a target port
pub fn audit_tls_posture(ip: Ipv4Addr, port: u16) -> Vec<AuditFinding> {
    let mut findings = Vec::new();
    let addr = SocketAddr::V4(SocketAddrV4::new(ip, port));

    let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(1000)) else {
        return findings;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(1500)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(1000)));

    // 1. Send TLS 1.0 ClientHello to test whether server accepts deprecated legacy versions
    let client_hello = craft_tls_client_hello(0x03, 0x01); // TLS 1.0
    if stream.write_all(&client_hello).is_err() {
        return findings;
    }

    let mut buf = vec![0u8; 4096];
    let Ok(n) = stream.read(&mut buf) else {
        return findings;
    };

    if n < 9 {
        return findings;
    }

    // Check TLS Record Header: ContentType = 22 (Handshake), Version = 0x0301/0x0302/0x0303
    if buf[0] != 22 {
        return findings;
    }

    // Handshake Type: 2 = ServerHello
    if n > 5 && buf[5] == 2 {
        // ServerHello version at offset 9..11
        if n >= 11 {
            let server_version = u16::from_be_bytes([buf[9], buf[10]]);
            match server_version {
                0x0300 => {
                    findings.push(AuditFinding::new(
                        "SEC-TLS-SSL3",
                        "SSL 3.0 Deprecated Protocol Negotiated",
                        ip,
                        Some(port),
                        AuditSeverity::Critical,
                        "The server negotiated legacy SSL 3.0, vulnerable to POODLE and known cryptographic breaks.",
                        "Disable SSL 3.0 in server schannel/openssl configurations. Enforce TLS 1.2 or TLS 1.3.",
                    ));
                }
                0x0301 => {
                    findings.push(AuditFinding::new(
                        "SEC-TLS-1.0",
                        "TLS 1.0 Deprecated Protocol Negotiated",
                        ip,
                        Some(port),
                        AuditSeverity::High,
                        "The server negotiated deprecated TLS 1.0, which lacks modern AEAD cipher suites and is prohibited by PCI-DSS.",
                        "Disable TLS 1.0 and require TLS 1.2 or TLS 1.3.",
                    ));
                }
                0x0302 => {
                    findings.push(AuditFinding::new(
                        "SEC-TLS-1.1",
                        "TLS 1.1 Deprecated Protocol Negotiated",
                        ip,
                        Some(port),
                        AuditSeverity::Medium,
                        "The server negotiated deprecated TLS 1.1.",
                        "Migrate to TLS 1.2 or TLS 1.3.",
                    ));
                }
                0x0303 | 0x0304 => {
                    findings.push(AuditFinding::new(
                        "SEC-TLS-MODERN",
                        "Modern TLS Protocol Supported",
                        ip,
                        Some(port),
                        AuditSeverity::Info,
                        "The server negotiated TLS 1.2 / TLS 1.3.",
                        "Maintain current protocol configurations.",
                    ));
                }
                _ => {}
            }

            // Check cipher suite at offset: SessionID length is at 43
            if n > 43 {
                let session_id_len = buf[43] as usize;
                let cipher_offset = 44 + session_id_len;
                if cipher_offset + 2 <= n {
                    let cipher = u16::from_be_bytes([buf[cipher_offset], buf[cipher_offset + 1]]);
                    // Check for RC4, 3DES, or NULL ciphers
                    if is_weak_cipher(cipher) {
                        findings.push(AuditFinding::new(
                            "SEC-TLS-WEAK-CIPHER",
                            "Insecure / Weak Cipher Suite Accepted",
                            ip,
                            Some(port),
                            AuditSeverity::High,
                            &format!("Server selected weak cipher suite (0x{:04x}) susceptible to known cryptanalytic attacks.", cipher),
                            "Disable RC4, 3DES (Sweet32), and CBC-mode ciphers in favor of AES-GCM or CHACHA20-POLY1305.",
                        ));
                    }
                }
            }
        }
    }

    findings
}

fn is_weak_cipher(cipher: u16) -> bool {
    matches!(
        cipher,
        0x0004 | 0x0005 // RC4
        | 0x000A | 0x0013 | 0x0016 // 3DES
        | 0x0001 | 0x0002 // NULL
        | 0x0003 | 0x0006 | 0x0007 // DES / Export
    )
}

fn craft_tls_client_hello(major: u8, minor: u8) -> Vec<u8> {
    let mut packet = Vec::with_capacity(128);

    // TLS Plaintext Record
    packet.push(22); // ContentType: Handshake
    packet.extend_from_slice(&[major, minor]); // Version

    // Handshake length placeholder at [3..5]
    let handshake_start = packet.len();
    packet.extend_from_slice(&[0x00, 0x00]);

    // Handshake Type: ClientHello (1)
    packet.push(1);
    // Handshake length (3 bytes) placeholder
    let body_len_start = packet.len();
    packet.extend_from_slice(&[0x00, 0x00, 0x00]);

    let body_start = packet.len();
    // Client Version
    packet.extend_from_slice(&[major, minor]);
    // Random (32 bytes)
    packet.extend_from_slice(&[0xaa; 32]);
    // Session ID Length (0)
    packet.push(0);

    // Cipher Suites
    let ciphers: &[u16] = &[
        0x0004, // RC4-MD5
        0x0005, // RC4-SHA
        0x000A, // 3DES-EDE-CBC-SHA
        0x002F, // AES128-SHA
        0x0035, // AES256-SHA
        0xC013, // ECDHE-RSA-AES128-SHA
        0xC014, // ECDHE-RSA-AES256-SHA
        0xC02F, // ECDHE-RSA-AES128-GCM-SHA256
        0xC030, // ECDHE-RSA-AES256-GCM-SHA384
    ];
    packet.extend_from_slice(&((ciphers.len() * 2) as u16).to_be_bytes());
    for &c in ciphers {
        packet.extend_from_slice(&c.to_be_bytes());
    }

    // Compression Methods: 1 method, 0 (null)
    packet.push(1);
    packet.push(0);

    let body_len = (packet.len() - body_start) as u32;
    packet[body_len_start..body_len_start + 3].copy_from_slice(&body_len.to_be_bytes()[1..4]);

    let handshake_len = (packet.len() - (handshake_start + 2)) as u16;
    packet[handshake_start..handshake_start + 2].copy_from_slice(&handshake_len.to_be_bytes());

    packet
}
