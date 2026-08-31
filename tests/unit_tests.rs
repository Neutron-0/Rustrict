use std::net::Ipv4Addr;
use std::str::FromStr;

use rustrict::limiter::TokenBucket;
use rustrict::resolver::oui;
use rustrict::spoofer::craft_arp_reply;
use rustrict::types::{BitRate, MacAddress};
use rustrict::wireless::{craft_deauth_frame, is_eapol_frame};

#[test]
fn test_mac_address_formatting() {
    let mac = MacAddress([0xec, 0x02, 0x73, 0xcb, 0x84, 0x00]);
    assert_eq!(mac.to_string(), "ec:02:73:cb:84:00");

    let parsed = MacAddress::from_str("ec:02:73:cb:84:00").unwrap();
    assert_eq!(mac, parsed);

    let parsed_dash = MacAddress::from_str("EC-02-73-CB-84-00").unwrap();
    assert_eq!(mac, parsed_dash);
}

#[test]
fn test_oui_vendor_lookup() {
    let tplink_mac = MacAddress([0xec, 0x02, 0x73, 0x11, 0x22, 0x33]);
    assert_eq!(oui::lookup_vendor(&tplink_mac), "TP-Link");

    let apple_mac = MacAddress([0xa4, 0x83, 0xe7, 0x11, 0x22, 0x33]);
    assert_eq!(oui::lookup_vendor(&apple_mac), "Apple");

    let samsung_mac = MacAddress([0x50, 0x56, 0xbf, 0x11, 0x22, 0x33]);
    assert_eq!(oui::lookup_vendor(&samsung_mac), "Samsung");

    let generic_mac = MacAddress([0x00, 0x00, 0x01, 0x11, 0x22, 0x33]);
    assert_eq!(oui::lookup_vendor(&generic_mac), "Generic Network Device");

    let randomized_mac = MacAddress([0xaa, 0xbb, 0xcc, 0x11, 0x22, 0x33]);
    assert_eq!(oui::lookup_vendor(&randomized_mac), "Private/Randomized MAC");
}

#[test]
fn test_bitrate_parsing() {
    let rate_k = BitRate::from_str_custom("250kbit").unwrap();
    assert_eq!(rate_k.0, 250_000);
    assert_eq!(rate_k.to_string(), "250.0kbit");

    let rate_m = BitRate::from_str_custom("10mbit").unwrap();
    assert_eq!(rate_m.0, 10_000_000);
    assert_eq!(rate_m.to_string(), "10.0mbit");

    let rate_g = BitRate::from_str_custom("1gbit").unwrap();
    assert_eq!(rate_g.0, 1_000_000_000);
    assert_eq!(rate_g.to_string(), "1.0gbit");
}

#[test]
fn test_token_bucket() {
    let mut bucket = TokenBucket::new(100_000, Some(100_000));
    assert!(bucket.try_consume(50_000));
    assert!(bucket.try_consume(50_000));
    assert!(!bucket.try_consume(10_000)); // Out of tokens

    std::thread::sleep(std::time::Duration::from_millis(150));
    assert!(bucket.try_consume(10_000)); // Refilled
}

#[test]
fn test_craft_arp_reply() {
    let dst_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let src_mac = MacAddress([0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
    let sender_ip = Ipv4Addr::new(192, 168, 1, 1);
    let target_ip = Ipv4Addr::new(192, 168, 1, 50);

    let pkt = craft_arp_reply(dst_mac, src_mac, sender_ip, src_mac, target_ip, dst_mac);
    assert_eq!(pkt.len(), 42);

    // Check Ethernet EtherType = ARP (0x0806)
    assert_eq!(pkt[12], 0x08);
    assert_eq!(pkt[13], 0x06);

    // Check ARP Opcode = Reply (2)
    assert_eq!(pkt[20], 0x00);
    assert_eq!(pkt[21], 0x02);
}

#[test]
fn test_craft_deauth_frame() {
    let client = MacAddress([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    let ap = MacAddress([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);

    let frame = craft_deauth_frame(client, ap, 7);
    assert_eq!(frame.len(), 26);

    // Check Frame Control (Management / Deauth)
    assert_eq!(frame[0], 0xc0);
    assert_eq!(frame[1], 0x00);

    // Check Reason Code (7)
    assert_eq!(frame[24], 0x07);
    assert_eq!(frame[25], 0x00);
}

#[test]
fn test_eapol_frame_detection() {
    let dummy_data = vec![0xaa, 0xbb, 0x88, 0x8e, 0x01, 0x02];
    assert!(is_eapol_frame(&dummy_data));

    let normal_ip_data = vec![0xaa, 0xbb, 0x08, 0x00, 0x45, 0x00];
    assert!(!is_eapol_frame(&normal_ip_data));
}
