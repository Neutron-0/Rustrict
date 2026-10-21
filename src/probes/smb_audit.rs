use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::time::Duration;

use crate::core::assessment::{AuditFinding, AuditSeverity};

/// Audits SMB configuration, signing posture, and SMBv1 exposure on TCP 445
pub fn audit_smb_posture(ip: Ipv4Addr) -> Vec<AuditFinding> {
    let mut findings = Vec::new();
    let addr = SocketAddr::V4(SocketAddrV4::new(ip, 445));

    // Test 1: SMB2 / SMB3 Negotiate Protocol & Signing Check
    if let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(800)) {
        let _ = stream.set_read_timeout(Some(Duration::from_millis(1200)));
        let _ = stream.set_write_timeout(Some(Duration::from_millis(800)));

        let smb2_negotiate = craft_smb2_negotiate();
        if stream.write_all(&smb2_negotiate).is_ok() {
            let mut buf = vec![0u8; 1024];
            if let Ok(n) = stream.read(&mut buf) {
                // Check NetBIOS Header (4 bytes) + SMB2 Header (64 bytes)
                // SMB2 Magic: 0xFE, 'S', 'M', 'B' at offset 4
                if n >= 68 && &buf[4..8] == b"\xfeSMB" {
                    // Command at offset 16..18: 0 = Negotiate
                    let command = u16::from_le_bytes([buf[16], buf[17]]);
                    if command == 0 {
                        // SMB2 Negotiate Response body starts at offset 4 + 64 = 68
                        // SecurityMode is at offset 68 + 2 = 70 (2 bytes)
                        if n >= 72 {
                            let security_mode = u16::from_le_bytes([buf[70], buf[71]]);
                            let signing_required = (security_mode & 0x02) != 0;

                            if !signing_required {
                                findings.push(AuditFinding::new(
                                    "SEC-SMB-SIGNING-OPTIONAL",
                                    "SMB Message Signing is Not Enforced",
                                    ip,
                                    Some(445),
                                    AuditSeverity::High,
                                    "SMB signing is optional or disabled on this endpoint. The machine is vulnerable to NTLM Relay attacks and network MITM packet manipulation.",
                                    "Enable 'Microsoft network server: Digitally sign communications (always)' in Group Policy / Secpol.msc.",
                                ));
                            } else {
                                findings.push(AuditFinding::new(
                                    "SEC-SMB-SIGNING-ENFORCED",
                                    "SMB Message Signing Enforced",
                                    ip,
                                    Some(445),
                                    AuditSeverity::Info,
                                    "SMB message signing is strictly required by the server.",
                                    "Configuration compliant with hardening baselines.",
                                ));
                            }

                            // Dialect Revision at offset 68 + 4 = 72
                            if n >= 74 {
                                let dialect = u16::from_le_bytes([buf[72], buf[73]]);
                                let dialect_str = match dialect {
                                    0x0202 => "SMB 2.0.2",
                                    0x0210 => "SMB 2.1",
                                    0x0300 => "SMB 3.0",
                                    0x0302 => "SMB 3.0.2",
                                    0x0311 => "SMB 3.1.1",
                                    _ => "SMB 2.x/3.x",
                                };
                                findings.push(AuditFinding::new(
                                    "SEC-SMB-DIALECT",
                                    &format!("Negotiated Dialect: {}", dialect_str),
                                    ip,
                                    Some(445),
                                    AuditSeverity::Info,
                                    &format!("Endpoint accepted modern dialect 0x{:04x} ({}).", dialect, dialect_str),
                                    "Ensure SMBv1 remains disabled across the network.",
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    // Test 2: SMBv1 Probe
    if let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(800)) {
        let _ = stream.set_read_timeout(Some(Duration::from_millis(1200)));
        let smb1_negotiate = craft_smb1_negotiate();
        if stream.write_all(&smb1_negotiate).is_ok() {
            let mut buf = vec![0u8; 512];
            if let Ok(n) = stream.read(&mut buf) {
                // SMB1 Magic: 0xFF, 'S', 'M', 'B' at offset 4
                if n >= 36 && &buf[4..8] == b"\xffSMB" {
                    findings.push(AuditFinding::new(
                        "SEC-SMB-V1-ENABLED",
                        "Legacy SMBv1 Protocol Supported",
                        ip,
                        Some(445),
                        AuditSeverity::Critical,
                        "Endpoint responded to legacy SMBv1 negotiation. SMBv1 lacks modern integrity controls and is notoriously vulnerable to remote code execution (e.g. MS17-010 / EternalBlue).",
                        "Disable SMBv1 immediately: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol",
                    ));
                }
            }
        }
    }

    findings
}

fn craft_smb2_negotiate() -> Vec<u8> {
    let mut packet = Vec::with_capacity(128);

    // NetBIOS Session Service Header (4 bytes) - length will be filled in
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    // SMB2 Header (64 bytes)
    packet.extend_from_slice(b"\xfeSMB"); // Protocol ID
    packet.extend_from_slice(&64u16.to_le_bytes()); // StructureSize = 64
    packet.extend_from_slice(&0u16.to_le_bytes());  // CreditCharge = 0
    packet.extend_from_slice(&0u32.to_le_bytes());  // Status = 0
    packet.extend_from_slice(&0u16.to_le_bytes());  // Command = 0 (Negotiate)
    packet.extend_from_slice(&0u16.to_le_bytes());  // CreditsRequested = 0
    packet.extend_from_slice(&0u32.to_le_bytes());  // Flags = 0
    packet.extend_from_slice(&0u32.to_le_bytes());  // NextCommand = 0
    packet.extend_from_slice(&1u64.to_le_bytes());  // MessageId = 1
    packet.extend_from_slice(&0u32.to_le_bytes());  // Reserved / ProcessId
    packet.extend_from_slice(&0u32.to_le_bytes());  // TreeId = 0
    packet.extend_from_slice(&0u64.to_le_bytes());  // SessionId = 0
    packet.extend_from_slice(&[0u8; 16]);          // Signature

    // SMB2 Negotiate Request Body (36 bytes + dialects)
    packet.extend_from_slice(&36u16.to_le_bytes()); // StructureSize = 36
    packet.extend_from_slice(&4u16.to_le_bytes());  // DialectCount = 4
    packet.extend_from_slice(&0x01u16.to_le_bytes()); // SecurityMode = 1 (Signing Enabled)
    packet.extend_from_slice(&0u16.to_le_bytes());  // Reserved
    packet.extend_from_slice(&0u32.to_le_bytes());  // Capabilities = 0
    packet.extend_from_slice(&[0xaa; 16]);         // ClientGuid (16 random bytes)
    packet.extend_from_slice(&0u64.to_le_bytes());  // ClientStartTime

    // Dialects: SMB 2.0.2, 2.1, 3.0, 3.0.2 (Do not advertise 3.1.1 without negotiate contexts)
    packet.extend_from_slice(&0x0202u16.to_le_bytes());
    packet.extend_from_slice(&0x0210u16.to_le_bytes());
    packet.extend_from_slice(&0x0300u16.to_le_bytes());
    packet.extend_from_slice(&0x0302u16.to_le_bytes());

    // Update NetBIOS Length (big-endian 3-byte integer at [1..4])
    let netbios_len = (packet.len() - 4) as u32;
    packet[1] = ((netbios_len >> 16) & 0xFF) as u8;
    packet[2] = ((netbios_len >> 8) & 0xFF) as u8;
    packet[3] = (netbios_len & 0xFF) as u8;

    packet
}

fn craft_smb1_negotiate() -> Vec<u8> {
    let mut packet = Vec::with_capacity(64);
    // NetBIOS Header
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x2f]);

    // SMB1 Header (32 bytes)
    packet.extend_from_slice(b"\xffSMB");
    packet.push(0x72); // Command: Negotiate Protocol
    packet.extend_from_slice(&[0x00; 4]); // Status = Success
    packet.push(0x18); // Flags
    packet.extend_from_slice(&[0x01, 0x28]); // Flags2
    packet.extend_from_slice(&[0x00; 12]); // PID high, Signature, Reserved
    packet.extend_from_slice(&[0x00, 0x00]); // TID
    packet.extend_from_slice(&[0x2f, 0x4b]); // PID
    packet.extend_from_slice(&[0x00, 0x00]); // UID
    packet.extend_from_slice(&[0x00, 0x00]); // MID

    // Word Count
    packet.push(0);
    // Byte Count
    let dialect = b"\x02NT LM 0.12\x00";
    packet.extend_from_slice(&(dialect.len() as u16).to_le_bytes());
    packet.extend_from_slice(dialect);

    let len = (packet.len() - 4) as u32;
    packet[1] = ((len >> 16) & 0xFF) as u8;
    packet[2] = ((len >> 8) & 0xFF) as u8;
    packet[3] = (len & 0xFF) as u8;

    packet
}
