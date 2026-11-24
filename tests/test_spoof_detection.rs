use rustrict::defense::arp_detector::{ArpAlert, ArpSpoofDetector};
use rustrict::defense::dhcp_detector::{DhcpAlert, RogueDhcpDetector};
use rustrict::types::MacAddress;
use std::net::Ipv4Addr;

#[test]
fn test_arp_spoof_detector_alerts_on_mac_flip() {
    let mut detector = ArpSpoofDetector::new();
    let gw_ip = Ipv4Addr::new(192, 168, 1, 1);
    let legitimate_gw_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x01]);
    let attacker_mac = MacAddress([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

    // 1. Initial valid binding
    assert_eq!(detector.process_arp_entry(gw_ip, legitimate_gw_mac, 100), None);

    // 2. Same valid MAC is harmless
    assert_eq!(detector.process_arp_entry(gw_ip, legitimate_gw_mac, 105), None);

    // 3. Attacker claims gateway IP with a different MAC -> Alert!
    let alert = detector.process_arp_entry(gw_ip, attacker_mac, 110);
    assert!(alert.is_some());
    match alert.unwrap() {
        ArpAlert::ConflictingMacMapping { ip, old_mac, new_mac } => {
            assert_eq!(ip, gw_ip);
            assert_eq!(old_mac, legitimate_gw_mac);
            assert_eq!(new_mac, attacker_mac);
        }
    }
}

#[test]
fn test_rogue_dhcp_detector() {
    let authorized_dhcp = Ipv4Addr::new(192, 168, 1, 1);
    let rogue_dhcp = Ipv4Addr::new(192, 168, 1, 99);
    let detector = RogueDhcpDetector::new(authorized_dhcp);

    // Authorized DHCP offer
    assert_eq!(detector.process_dhcp_offer(authorized_dhcp), None);

    // Rogue DHCP offer -> Alert!
    let alert = detector.process_dhcp_offer(rogue_dhcp);
    assert!(alert.is_some());
    match alert.unwrap() {
        DhcpAlert::RogueServerDetected { rogue_ip, expected_ip } => {
            assert_eq!(rogue_ip, rogue_dhcp);
            assert_eq!(expected_ip, authorized_dhcp);
        }
    }
}
