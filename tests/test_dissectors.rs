use rustrict::monitor::dns_dissector::DnsDissector;
use rustrict::monitor::tls_sni::TlsSniDissector;

#[test]
fn test_dns_dissector_query_parsing() {
    // Standard DNS query for "api.github.com" (type A = 1)
    let mut dns_packet = vec![
        0x12, 0x34, // Transaction ID: 0x1234
        0x01, 0x00, // Standard query flags
        0x00, 0x01, // Questions: 1
        0x00, 0x00, // Answer RRs: 0
        0x00, 0x00, // Authority RRs: 0
        0x00, 0x00, // Additional RRs: 0
        // QNAME: 3 "api" 6 "github" 3 "com" 0
        0x03, b'a', b'p', b'i',
        0x06, b'g', b'i', b't', b'h', b'u', b'b',
        0x03, b'c', b'o', b'm',
        0x00,
        0x00, 0x01, // Type: A (1)
        0x00, 0x01, // Class: IN (1)
    ];

    let query = DnsDissector::parse_query(&dns_packet).expect("Should parse DNS query");
    assert_eq!(query.tx_id, 0x1234);
    assert_eq!(query.qname, "api.github.com");
    assert_eq!(query.qtype, 1);

    // Malformed packet check
    dns_packet.truncate(8);
    assert!(DnsDissector::parse_query(&dns_packet).is_none());
}

#[test]
fn test_tls_sni_dissector() {
    // Handcrafted TLS 1.2 / 1.3 ClientHello with SNI "rust-lang.org"
    let sni = "rust-lang.org";
    let sni_bytes = sni.as_bytes();

    let mut ext_data = Vec::new();
    // server_name_list_length (2 bytes)
    ext_data.extend_from_slice(&((sni_bytes.len() + 3) as u16).to_be_bytes());
    ext_data.push(0x00); // name_type: host_name
    ext_data.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
    ext_data.extend_from_slice(sni_bytes);

    let mut extensions = Vec::new();
    extensions.extend_from_slice(&0x0000u16.to_be_bytes()); // ext_type: server_name (0)
    extensions.extend_from_slice(&(ext_data.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&ext_data);

    let mut client_hello = Vec::new();
    client_hello.extend_from_slice(&[0x03, 0x03]); // Client version TLS 1.2
    client_hello.extend_from_slice(&[0u8; 32]);    // Client random (32 bytes)
    client_hello.push(0x00);                       // Session ID length: 0
    client_hello.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // Cipher suites: len 2, TLS_AES_128_GCM_SHA256
    client_hello.extend_from_slice(&[0x01, 0x00]); // Compression methods: len 1, 0x00
    client_hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    client_hello.extend_from_slice(&extensions);

    let mut handshake = Vec::new();
    handshake.push(0x01); // Handshake Type: ClientHello (1)
    let ch_len = client_hello.len() as u32;
    handshake.push((ch_len >> 16) as u8);
    handshake.push((ch_len >> 8) as u8);
    handshake.push(ch_len as u8);
    handshake.extend_from_slice(&client_hello);

    let mut record = Vec::new();
    record.push(0x16); // ContentType: Handshake (22)
    record.extend_from_slice(&[0x03, 0x01]); // Version TLS 1.0 (record layer)
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);

    let extracted = TlsSniDissector::extract_sni(&record).expect("Should extract SNI");
    assert_eq!(extracted, "rust-lang.org");

    // Invalid non-TLS packet check
    assert!(TlsSniDissector::extract_sni(b"GET / HTTP/1.1\r\n").is_none());
}
