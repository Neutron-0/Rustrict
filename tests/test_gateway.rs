use std::net::Ipv4Addr;
use std::str::FromStr;
use rustrict::gateway::hosts::GatewayHostEntry;
use rustrict::gateway::soap::SoapClient;
use rustrict::gateway::ssdp::SsdpScanner;
use rustrict::types::MacAddress;

#[test]
fn test_soap_extract_tag_value() {
    let xml = r#"
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <u:GetGenericHostEntryResponse xmlns:u="urn:schemas-upnp-org:service:LANHostConfigManagement:1">
      <NewIPAddress>192.168.18.77</NewIPAddress>
      <NewAddressSource>DHCP</NewAddressSource>
      <NewMACAddress>3c:22:fb:4a:12:ef</NewMACAddress>
      <NewHostName>Lakshyas-iPhone</NewHostName>
      <NewInterfaceType>802.11</NewInterfaceType>
      <NewActive>1</NewActive>
    </u:GetGenericHostEntryResponse>
  </s:Body>
</s:Envelope>"#;

    assert_eq!(
        SoapClient::extract_tag_value(xml, "NewIPAddress"),
        Some("192.168.18.77".to_string())
    );
    assert_eq!(
        SoapClient::extract_tag_value(xml, "NewMACAddress"),
        Some("3c:22:fb:4a:12:ef".to_string())
    );
    assert_eq!(
        SoapClient::extract_tag_value(xml, "NewHostName"),
        Some("Lakshyas-iPhone".to_string())
    );
    assert_eq!(
        SoapClient::extract_tag_value(xml, "NewInterfaceType"),
        Some("802.11".to_string())
    );
    assert_eq!(
        SoapClient::extract_tag_value(xml, "NewActive"),
        Some("1".to_string())
    );
}

#[test]
fn test_soap_extract_missing_tag() {
    let xml = "<root><item>test</item></root>";
    assert_eq!(SoapClient::extract_tag_value(xml, "NonExistent"), None);
}

#[test]
fn test_ssdp_header_parsing() {
    let headers = "HTTP/1.1 200 OK\r\n\
CACHE-CONTROL: max-age=1800\r\n\
DATE: Mon, 31 Aug 2026 21:00:00 GMT\r\n\
LOCATION: http://192.168.18.1:49152/rootDesc.xml\r\n\
SERVER: Linux/3.10.0 UPnP/1.0 IGD/1.0\r\n\
ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
USN: uuid:12345678-1234-1234-1234-123456789abc\r\n\r\n";

    assert_eq!(
        SsdpScanner::parse_header_value(headers, "LOCATION"),
        Some("http://192.168.18.1:49152/rootDesc.xml".to_string())
    );
    assert_eq!(
        SsdpScanner::parse_header_value(headers, "SERVER"),
        Some("Linux/3.10.0 UPnP/1.0 IGD/1.0".to_string())
    );
    assert_eq!(
        SsdpScanner::parse_header_value(headers, "NonExistent"),
        None
    );
}

#[test]
fn test_gateway_host_entry_construction() {
    let ip = Ipv4Addr::new(192, 168, 18, 99);
    let mac = MacAddress::from_str("a4:83:e7:21:00:19").unwrap();
    let entry = GatewayHostEntry::new(
        ip,
        mac,
        "Samsung-Smart-TV".to_string(),
        "802.11".to_string(),
        true,
    );

    assert_eq!(entry.ip, ip);
    assert_eq!(entry.mac, mac);
    assert_eq!(entry.hostname, "Samsung-Smart-TV");
    assert!(entry.active);
}
