use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};
use std::time::Duration;

/// Probes TCP port 445 (SMB) or 139 with an unauthenticated SMB Negotiate / NTLMSSP Type 1 request.
/// Modern Windows laptops return an NTLM Type 2 Challenge containing target info:
/// - MsvAvNbComputerName (NetBIOS machine name, e.g. "DESKTOP-ABC1234")
/// - MsvAvDnsComputerName (DNS hostname)
/// - MsvAvNbDomainName (Workgroup or Domain name)
pub fn probe_smb_ntlm(ip: Ipv4Addr) -> Option<String> {
    let addr = SocketAddrV4::new(ip, 445);
    let mut stream = TcpStream::connect_timeout(
        &std::net::SocketAddr::V4(addr),
        Duration::from_millis(70),
    ).ok()?;

    let _ = stream.set_read_timeout(Some(Duration::from_millis(80)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(80)));

    use std::io::{Read, Write};

    // 1. Send SMB1/SMB2 Negotiate Protocol Request
    // SMB2 Negotiate Protocol packet with dialect 0x0202 (SMB 2.0.2)
    let smb2_negotiate: &[u8] = &[
        // NetBIOS Session Service: Length 0x000044
        0x00, 0x00, 0x00, 0x44,
        // SMB2 Header
        0xfe, b'S', b'M', b'B', // Protocol Id: \xfeSMB
        0x40, 0x00,             // Header Length: 64
        0x00, 0x00,             // Credit Charge
        0x00, 0x00,             // Channel Sequence / Reserved
        0x00, 0x00,             // Status: 0
        0x00, 0x00,             // Command: Negotiate (0)
        0x00, 0x00,             // Credits Requested
        0x00, 0x00, 0x00, 0x00, // Flags
        0x00, 0x00, 0x00, 0x00, // Next Command
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Message Id: 0
        0xfe, 0xff, 0x00, 0x00, // Process Id
        0x00, 0x00, 0x00, 0x00, // Tree Id
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Session Id
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature
        // SMB2 Negotiate Request Body (36 bytes)
        0x24, 0x00,             // StructureSize: 36
        0x02, 0x00,             // DialectCount: 2
        0x01, 0x00,             // SecurityMode: Signing enabled
        0x00, 0x00,             // Reserved
        0x00, 0x00, 0x00, 0x00, // Capabilities
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ClientGuid
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // NegotiateContext
        // Dialects: SMB 2.0.2 (0x0202), SMB 2.1 (0x0210)
        0x02, 0x02,
        0x10, 0x02,
    ];

    if stream.write_all(smb2_negotiate).is_err() {
        return None;
    }

    let mut buf = vec![0u8; 1024];
    let n = stream.read(&mut buf).ok()?;
    if n < 68 {
        return None;
    }

    // Verify SMB2 reply
    if &buf[4..8] != b"\xfeSMB" {
        return None;
    }

    // Extract Session Id from Negotiate Response to use in Session Setup
    let session_id = [
        buf[44], buf[45], buf[46], buf[47],
        buf[48], buf[49], buf[50], buf[51],
    ];

    // 2. Send SMB2 Session Setup Request containing NTLMSSP NEGOTIATE (Type 1)
    // NTLMSSP Negotiate payload:
    let ntlm_negotiate: &[u8] = &[
        b'N', b'T', b'L', b'M', b'S', b'S', b'P', 0x00, // Signature: NTLMSSP
        0x01, 0x00, 0x00, 0x00,                         // Type: 1 (Negotiate)
        // Flags: Negotiate Unicode, OEM, Request Target, NTLM, Workstation Supplied, Domain Supplied
        0x07, 0x82, 0x08, 0x62,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Domain
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Workstation
    ];

    // Build SMB2 Session Setup Header + Body
    let mut setup_pkt = Vec::with_capacity(128);
    // NetBIOS placeholder (4 bytes)
    setup_pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    // SMB2 Header
    setup_pkt.extend_from_slice(&[
        0xfe, b'S', b'M', b'B',
        0x40, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x01, 0x00,             // Command: Session Setup (1)
        0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Message Id: 1
        0xfe, 0xff, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ]);
    setup_pkt.extend_from_slice(&session_id);
    setup_pkt.extend_from_slice(&[0x00; 16]); // Signature

    // Body: Session Setup
    let sec_offset = 64 + 24; // 88
    let sec_len = ntlm_negotiate.len() as u16;
    setup_pkt.extend_from_slice(&[
        0x19, 0x00,                         // StructureSize: 25
        0x00,                               // Flags
        0x01,                               // SecurityMode
        0x00, 0x00, 0x00, 0x00,             // Capabilities
        0x00, 0x00, 0x00, 0x00,             // Channel
        (sec_offset & 0xff) as u8, ((sec_offset >> 8) & 0xff) as u8, // SecurityBufferOffset
        (sec_len & 0xff) as u8, ((sec_len >> 8) & 0xff) as u8,       // SecurityBufferLength
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,             // PreviousSessionId
    ]);
    setup_pkt.extend_from_slice(ntlm_negotiate);

    // Update NetBIOS length
    let netbios_len = (setup_pkt.len() - 4) as u32;
    setup_pkt[0] = ((netbios_len >> 24) & 0xff) as u8;
    setup_pkt[1] = ((netbios_len >> 16) & 0xff) as u8;
    setup_pkt[2] = ((netbios_len >> 8) & 0xff) as u8;
    setup_pkt[3] = (netbios_len & 0xff) as u8;

    if stream.write_all(&setup_pkt).is_err() {
        return None;
    }

    let mut resp = vec![0u8; 2048];
    let resp_n = stream.read(&mut resp).ok()?;
    if resp_n < 100 {
        return None;
    }

    // 3. Search for NTLMSSP Challenge (Type 2) in response
    parse_ntlmssp_challenge(&resp[..resp_n])
}

/// Parses NTLMSSP Type 2 challenge bytes to extract NetBIOS computer name and DNS hostname
pub fn parse_ntlmssp_challenge(data: &[u8]) -> Option<String> {
    // Look for "NTLMSSP\0\x02\x00\x00\x00"
    let ntlm_sig = b"NTLMSSP\x00\x02\x00\x00\x00";
    let pos = data.windows(ntlm_sig.len()).position(|w| w == ntlm_sig)?;

    let challenge = &data[pos..];
    if challenge.len() < 48 {
        return None;
    }

    // Target Info Fields at challenge offset 40 (length: u16, max_len: u16, offset: u32)
    let target_info_len = u16::from_le_bytes([challenge[40], challenge[41]]) as usize;
    let target_info_offset = u32::from_le_bytes([
        challenge[44], challenge[45], challenge[46], challenge[47],
    ]) as usize;

    if target_info_offset + target_info_len > challenge.len() {
        return None;
    }

    let target_info = &challenge[target_info_offset..target_info_offset + target_info_len];

    // Target Info is an array of AV_PAIR:
    // AvId: u16 (0x0001 = MsvAvNbComputerName, 0x0003 = MsvAvDnsComputerName, 0x0000 = EOL)
    // AvLen: u16
    // Value: UTF-16LE bytes
    let mut i = 0;
    let mut nb_computer_name = None;
    let mut dns_computer_name = None;

    while i + 4 <= target_info.len() {
        let avid = u16::from_le_bytes([target_info[i], target_info[i + 1]]);
        let avlen = u16::from_le_bytes([target_info[i + 2], target_info[i + 3]]) as usize;
        i += 4;

        if avid == 0 {
            break; // EOL
        }

        if i + avlen > target_info.len() {
            break;
        }

        let val_bytes = &target_info[i..i + avlen];
        i += avlen;

        // Decode UTF-16LE string
        let u16_chars: Vec<u16> = val_bytes
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();
        let decoded = String::from_utf16_lossy(&u16_chars);

        match avid {
            0x0001 => {
                // MsvAvNbComputerName
                if !decoded.trim().is_empty() {
                    nb_computer_name = Some(decoded.trim().to_string());
                }
            }
            0x0003 => {
                // MsvAvDnsComputerName
                if !decoded.trim().is_empty() {
                    dns_computer_name = Some(decoded.trim().to_string());
                }
            }
            _ => {}
        }
    }

    dns_computer_name.or(nb_computer_name)
}
