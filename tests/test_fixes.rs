use std::net::Ipv4Addr;
use rustrict::gateway::soap::SoapClient;
use rustrict::resolver::extract_html_title;
use rustrict::resolver::llmnr::parse_llmnr_response;
use rustrict::resolver::mdns::parse_dns_name;
use rustrict::types::{BitRate, Direction, Host, MacAddress, NameSource};
use rustrict::state::PersistentState;

#[test]
fn test_soap_prefixed_tags() {
    // Real-world UPnP / TR-064 SOAP responses heavily use namespace prefixes on tags
    let xml = r#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <u:GetGenericHostEntryResponse xmlns:u="urn:schemas-upnp-org:service:LANHostConfigManagement:1">
      <u:NewIPAddress>192.168.1.150</u:NewIPAddress>
      <u:NewMACAddress>00:11:22:33:44:55</u:NewMACAddress>
      <u:NewHostName>Office-Workstation</u:NewHostName>
      <u:NewInterfaceType>Ethernet</u:NewInterfaceType>
      <u:NewActive>1</u:NewActive>
    </u:GetGenericHostEntryResponse>
  </s:Body>
</s:Envelope>"#;

    assert_eq!(
        SoapClient::extract_tag_value(xml, "NewIPAddress"),
        Some("192.168.1.150".to_string())
    );
    assert_eq!(
        SoapClient::extract_tag_value(xml, "NewMACAddress"),
        Some("00:11:22:33:44:55".to_string())
    );
    assert_eq!(
        SoapClient::extract_tag_value(xml, "NewHostName"),
        Some("Office-Workstation".to_string())
    );
}

#[test]
fn test_extract_html_title_with_unicode_and_case() {
    // UTF-8 characters prior to <title> must not cause byte-boundary slicing panics
    let html = "HTTP/1.1 200 OK\r\n\r\n<html><head><!-- Über schöne Grüße 🚀 --><TITLE> Router Setup Page </TITLE></head></html>";
    assert_eq!(extract_html_title(html), Some("Router Setup Page".to_string()));

    let empty_title = "<html><head><title>   </title></head></html>";
    assert_eq!(extract_html_title(empty_title), None);

    let no_title = "<html><head>No title here</head></html>";
    assert_eq!(extract_html_title(no_title), None);
}

#[test]
fn test_llmnr_ptr_response_parsing() {
    let mut packet = Vec::new();
    // Header (12 bytes)
    packet.extend_from_slice(&[0x12, 0x34]); // ID
    packet.extend_from_slice(&[0x84, 0x00]); // Flags: Response, Authoritative
    packet.extend_from_slice(&[0x00, 0x01]); // QDCOUNT: 1 question
    packet.extend_from_slice(&[0x00, 0x01]); // ANCOUNT: 1 answer
    packet.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
    packet.extend_from_slice(&[0x00, 0x00]); // ARCOUNT

    // Question: 100.18.168.192.in-addr.arpa, Type PTR, Class IN
    for part in ["100", "18", "168", "192", "in-addr", "arpa"] {
        packet.push(part.len() as u8);
        packet.extend_from_slice(part.as_bytes());
    }
    packet.push(0x00); // End of qname
    packet.extend_from_slice(&[0x00, 0x0c, 0x00, 0x01]); // Type PTR (12), Class IN (1)

    // Answer: Pointer to Question name (0xc00c)
    packet.extend_from_slice(&[0xc0, 0x0c]); // Compression pointer to offset 12
    packet.extend_from_slice(&[0x00, 0x0c]); // Type PTR (12)
    packet.extend_from_slice(&[0x00, 0x01]); // Class IN (1)
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x1e]); // TTL 30s

    // RDATA: "Gaming-Rig.local"
    let mut rdata = Vec::new();
    rdata.push(10);
    rdata.extend_from_slice(b"Gaming-Rig");
    rdata.push(5);
    rdata.extend_from_slice(b"local");
    rdata.push(0x00);

    packet.extend_from_slice(&(rdata.len() as u16).to_be_bytes()); // RDLength
    packet.extend_from_slice(&rdata);

    let parsed = parse_llmnr_response(&packet);
    // Must extract "Gaming-Rig", and NOT "addr" or "arpa" from the question!
    assert_eq!(parsed, Some("Gaming-Rig".to_string()));
}

#[test]
fn test_mdns_parsing_with_question_echo() {
    // In mDNS, the question section echoes "_workstation._tcp.local"
    // followed by the answer section containing "MacBook-Pro.local".
    let mut buf = Vec::new();
    // Prefix question
    buf.extend_from_slice(b"\x0c_workstation\x04_tcp\x05local\x00");
    // Some answer headers
    buf.extend_from_slice(&[0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x12]);
    // Answer name
    buf.extend_from_slice(b"\x0bMacBook-Pro\x05local\x00");

    let parsed = parse_dns_name(&buf);
    assert_eq!(parsed, Some("MacBook-Pro.local".to_string()));
}

#[test]
fn test_bitrate_overflow_protection() {
    // Normal rates
    assert_eq!(BitRate::from_str_custom("500kbit").unwrap().0, 500_000);
    assert_eq!(BitRate::from_str_custom("100mbit").unwrap().0, 100_000_000);
    assert_eq!(BitRate::from_str_custom("10gbit").unwrap().0, 10_000_000_000);

    // Astronomical number that would overflow u64 when multiplied by 1_000_000_000
    let huge = "9999999999999999999gbit";
    let res = BitRate::from_str_custom(huge);
    assert!(res.is_err());
}

#[test]
fn test_persistent_state_both_directions_serialization() {
    let mut state = PersistentState::default();
    let ip = Ipv4Addr::new(10, 0, 0, 42);
    let host = Host::with_source(
        1,
        ip,
        MacAddress([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc]),
        "Smart-Camera".to_string(),
        NameSource::Manual,
        "Tuya".to_string(),
    );

    // Save with Direction::Both
    state.add_blocked(&host, Direction::Both);

    // Serialize to JSON and deserialize back to verify exact roundtrip
    let json = serde_json::to_string(&state).unwrap();
    let loaded: PersistentState = serde_json::from_str(&json).unwrap();

    assert!(loaded.is_blocked(&ip));
    assert_eq!(loaded.get_direction(&ip), Direction::Both);
}

#[test]
fn test_scan_range_bounded_protection() {
    let scanner = rustrict::scanner::SubnetScanner::new(
        Ipv4Addr::new(192, 168, 1, 10),
        Ipv4Addr::new(255, 255, 255, 0),
        Ipv4Addr::new(192, 168, 1, 1),
    );

    // Inverted range should return empty vec immediately
    let res = scanner.scan_range(
        Ipv4Addr::new(192, 168, 1, 100),
        Ipv4Addr::new(192, 168, 1, 10),
        true,
        |_, _, _| {},
    );
    assert!(res.is_empty());
}

#[test]
fn test_check_environment_diagnostics() {
    let env = rustrict::platform::check_environment();
    // Verify diagnostics execute and populate fields without panicking
    assert!(!env.npcap_details.is_empty());
    assert!(!env.windivert_details.is_empty());
}
