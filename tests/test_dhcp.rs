use rustrict::resolver::passive::parse_dhcp_or_broadcast;
use std::net::Ipv4Addr;

#[test]
fn test_dhcp_option12_parsing() {
    let mut packet = Vec::new();
    // Ethernet header (14 bytes)
    packet.extend_from_slice(&[0x00; 12]);
    packet.extend_from_slice(&[0x08, 0x00]); // IPv4

    // IPv4 header (20 bytes)
    packet.push(0x45); // Version 4, IHL 5 (20 bytes)
    packet.push(0x00);
    packet.extend_from_slice(&[0x01, 0x20]); // Total len: 288
    packet.extend_from_slice(&[0x00; 5]);
    packet.push(17); // UDP (17)
    packet.extend_from_slice(&[0x00, 0x00]); // Checksum
    // Src IP: 192.168.18.55
    packet.extend_from_slice(&[192, 168, 18, 55]);
    // Dst IP: 255.255.255.255
    packet.extend_from_slice(&[255, 255, 255, 255]);

    // UDP header (8 bytes)
    packet.extend_from_slice(&[0x00, 0x44]); // Src port 68
    packet.extend_from_slice(&[0x00, 0x43]); // Dst port 67
    packet.extend_from_slice(&[0x01, 0x0c]); // UDP len: 268
    packet.extend_from_slice(&[0x00, 0x00]);

    // DHCP body (240 bytes minimum + options)
    let mut dhcp_body = vec![0u8; 240];
    dhcp_body[0] = 1; // BOOTREQUEST
    // ciaddr at 12: 192.168.18.55
    dhcp_body[12] = 192;
    dhcp_body[13] = 168;
    dhcp_body[14] = 18;
    dhcp_body[15] = 55;
    // Magic cookie at 236: 0x63, 0x82, 0x53, 0x63
    dhcp_body[236] = 0x63;
    dhcp_body[237] = 0x82;
    dhcp_body[238] = 0x53;
    dhcp_body[239] = 0x63;

    packet.extend_from_slice(&dhcp_body);

    // Option 53: DHCP Request (tag 53, len 1, value 3)
    packet.extend_from_slice(&[53, 1, 3]);

    // Option 12: Host Name (tag 12, len 15, value "Johns-MacBook-Pro")
    let hostname = "Johns-MacBook-Pro";
    packet.push(12);
    packet.push(hostname.len() as u8);
    packet.extend_from_slice(hostname.as_bytes());

    // End Option (255)
    packet.push(255);

    let parsed = parse_dhcp_or_broadcast(&packet);
    assert_eq!(
        parsed,
        Some((
            Ipv4Addr::new(192, 168, 18, 55),
            rustrict::types::MacAddress::ZERO,
            "Johns-MacBook-Pro".to_string()
        ))
    );
}
