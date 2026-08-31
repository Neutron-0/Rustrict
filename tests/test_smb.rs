use rustrict::resolver::smb::parse_ntlmssp_challenge;

#[test]
fn test_ntlmssp_challenge_parsing() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&[0x00; 16]); // NetBIOS/SMB prefix padding

    let ntlm_start = payload.len();
    payload.extend_from_slice(b"NTLMSSP\x00\x02\x00\x00\x00"); // 12 bytes
    // Target Name Fields: len=8, max_len=8, offset will be 48
    payload.extend_from_slice(&[0x08, 0x00, 0x08, 0x00, 0x30, 0x00, 0x00, 0x00]); // 8 bytes
    // Negotiate Flags (4 bytes)
    payload.extend_from_slice(&[0x05, 0x82, 0x89, 0xe2]);
    // Server Challenge (8 bytes)
    payload.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    // Reserved (8 bytes)
    payload.extend_from_slice(&[0x00; 8]);

    // Construct Target Info AV_PAIRs
    let comp_name = "VICTIM-LAPTOP";
    let u16_name: Vec<u8> = comp_name
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();

    let mut target_info = Vec::new();
    target_info.extend_from_slice(&1u16.to_le_bytes()); // MsvAvNbComputerName (0x0001)
    target_info.extend_from_slice(&(u16_name.len() as u16).to_le_bytes());
    target_info.extend_from_slice(&u16_name);
    target_info.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // EOL

    // Target Info offset is at 40 relative to NTLMSSP start
    // Target Name ("WORKGROUP") has 8 bytes, placed at offset 48..56
    // Target Info is placed at offset 56 relative to NTLMSSP start
    let target_info_offset = 56u32;
    let target_info_len = target_info.len() as u16;

    payload.extend_from_slice(&target_info_len.to_le_bytes());
    payload.extend_from_slice(&target_info_len.to_le_bytes());
    payload.extend_from_slice(&target_info_offset.to_le_bytes());

    // Target Name at offset 48
    payload.extend_from_slice(b"WORKGROU"); // 8 bytes

    // Target Info at offset 56
    payload.extend_from_slice(&target_info);

    assert_eq!(payload.len() - ntlm_start, 56 + target_info.len());

    let parsed = parse_ntlmssp_challenge(&payload);
    assert_eq!(parsed, Some("VICTIM-LAPTOP".to_string()));
}
