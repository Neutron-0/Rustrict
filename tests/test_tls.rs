use rustrict::resolver::tls::extract_x509_cn;

#[test]
fn test_x509_cn_extraction() {
    let mut cert_data = Vec::new();
    cert_data.extend_from_slice(&[0x30, 0x82, 0x01, 0x00]); // Sequence
    // Common Name OID (2.5.4.3: 0x55, 0x04, 0x03)
    cert_data.extend_from_slice(&[0x55, 0x04, 0x03]);
    // PrintableString tag (0x13), length 14, value "DESKTOP-LAPTOP"
    let host = "DESKTOP-LAPTOP";
    cert_data.push(0x13);
    cert_data.push(host.len() as u8);
    cert_data.extend_from_slice(host.as_bytes());

    let extracted = extract_x509_cn(&cert_data);
    assert_eq!(extracted, Some("DESKTOP-LAPTOP".to_string()));
}
