use rustrict::resilience::arp_guard::ArpGuard;
use rustrict::types::MacAddress;
use std::net::Ipv4Addr;

#[test]
fn test_arp_guard_neighbor_entry_creation() {
    let guard = ArpGuard::new(
        Ipv4Addr::new(192, 168, 1, 1),
        MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
    );
    let cmd = guard.format_netsh_lock_command("Wi-Fi");
    assert!(cmd.contains("add neighbors"));
    assert!(cmd.contains("192.168.1.1"));
    assert!(cmd.contains("00-11-22-33-44-55"));
}

#[test]
fn test_arp_guard_detection_and_healing() {
    let genuine_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let attacker_mac = MacAddress([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
    let gateway_ip = Ipv4Addr::new(192, 168, 1, 1);
    let guard = ArpGuard::new(gateway_ip, genuine_mac);

    // 1. Clean cache matches genuine MAC
    let clean_cache = vec![(gateway_ip, genuine_mac)];
    assert!(guard.is_cache_healthy(&clean_cache));

    // 2. Poisoned cache with rogue MAC detected as compromised
    let poisoned_cache = vec![(gateway_ip, attacker_mac)];
    assert!(!guard.is_cache_healthy(&poisoned_cache));

    // 3. Generates corrective Gratuitous ARP reply frame for healing
    let garp = guard.craft_healing_garp_reply();
    assert_eq!(garp.len(), 42); // Standard Ethernet (14) + ARP (28)
}
