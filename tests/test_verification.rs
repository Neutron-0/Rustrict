use rustrict::core::scope::{Ipv4Cidr, ScopeManager};
use rustrict::limiter::token_bucket::TokenBucket;
use rustrict::scanner::arp::SubnetScanner;
use rustrict::spoofer::engine::BLACKHOLE_MAC;
use rustrict::spoofer::raw_l2::{craft_arp_reply, parse_arp_reply};
use rustrict::state::PersistentState;
use rustrict::types::{Direction, Host, MacAddress};
use std::net::Ipv4Addr;
use std::time::Duration;

#[test]
fn test_blackhole_mac_spec_and_properties() {
    // BLACKHOLE_MAC: 02:bf:00:00:00:01
    assert_eq!(BLACKHOLE_MAC.0, [0x02, 0xbf, 0x00, 0x00, 0x00, 0x01]);

    // 1. Unicast check: least significant bit of first octet must be 0 (0 = Unicast, 1 = Multicast/Broadcast)
    assert_eq!(
        BLACKHOLE_MAC.0[0] & 0x01,
        0,
        "Blackhole MAC must be a UNICAST MAC so switches drop it rather than flooding all ports"
    );

    // 2. Locally Administered check: second least significant bit of first octet must be 1 (0 = Globally Unique, 2 = Locally Administered)
    assert_eq!(BLACKHOLE_MAC.0[0] & 0x02, 2, "Blackhole MAC must be locally administered to avoid OUI collisions with legitimate hardware");

    // 3. Must never equal broadcast or zero
    assert_ne!(BLACKHOLE_MAC, MacAddress::BROADCAST);
    assert_ne!(BLACKHOLE_MAC, MacAddress::ZERO);
}

#[test]
fn test_blocked_vs_limited_arp_frame_crafting() {
    let local_mac = MacAddress([0x10, 0x20, 0x30, 0x40, 0x50, 0x60]);
    let gateway_mac = MacAddress([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    let gateway_ip = Ipv4Addr::new(192, 168, 1, 1);

    let victim_mac = MacAddress([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
    let victim_ip = Ipv4Addr::new(192, 168, 1, 100);

    // --- Scenario A: Device is BLOCKED ---
    // Target must be told Gateway is at BLACKHOLE_MAC, transmitted with host local_mac
    let pkt_to_victim_blocked = craft_arp_reply(
        victim_mac,
        local_mac,
        gateway_ip,
        BLACKHOLE_MAC,
        victim_ip,
        victim_mac,
    );

    let parsed_victim = parse_arp_reply(&pkt_to_victim_blocked).expect("Must parse as ARP reply");
    assert_eq!(parsed_victim.0, gateway_ip);
    assert_eq!(
        parsed_victim.1, BLACKHOLE_MAC,
        "Victim must map Gateway IP to BLACKHOLE_MAC"
    );
    // Verify Ethernet source and destination headers (source must be transmitting local_mac)
    assert_eq!(&pkt_to_victim_blocked[0..6], &victim_mac.0);
    assert_eq!(&pkt_to_victim_blocked[6..12], &local_mac.0);

    // Gateway must be told Victim is at BLACKHOLE_MAC, transmitted with host local_mac
    let pkt_to_gw_blocked = craft_arp_reply(
        gateway_mac,
        local_mac,
        victim_ip,
        BLACKHOLE_MAC,
        gateway_ip,
        gateway_mac,
    );

    let parsed_gw = parse_arp_reply(&pkt_to_gw_blocked).expect("Must parse as ARP reply");
    assert_eq!(parsed_gw.0, victim_ip);
    assert_eq!(
        parsed_gw.1, BLACKHOLE_MAC,
        "Gateway must map Victim IP to BLACKHOLE_MAC"
    );
    assert_eq!(&pkt_to_gw_blocked[0..6], &gateway_mac.0);
    assert_eq!(&pkt_to_gw_blocked[6..12], &local_mac.0);

    // --- Scenario B: Device is LIMITED (MITM mode) ---
    // Target must be told Gateway is at local_mac
    let pkt_to_victim_limited = craft_arp_reply(
        victim_mac, local_mac, gateway_ip, local_mac, victim_ip, victim_mac,
    );
    let parsed_victim_mitm =
        parse_arp_reply(&pkt_to_victim_limited).expect("Must parse as ARP reply");
    assert_eq!(parsed_victim_mitm.0, gateway_ip);
    assert_eq!(
        parsed_victim_mitm.1, local_mac,
        "In limited mode, victim maps Gateway IP to host local_mac"
    );

    // Gateway must be told Victim is at local_mac
    let pkt_to_gw_limited = craft_arp_reply(
        gateway_mac,
        local_mac,
        victim_ip,
        local_mac,
        gateway_ip,
        gateway_mac,
    );
    let parsed_gw_mitm = parse_arp_reply(&pkt_to_gw_limited).expect("Must parse as ARP reply");
    assert_eq!(parsed_gw_mitm.0, victim_ip);
    assert_eq!(
        parsed_gw_mitm.1, local_mac,
        "In limited mode, gateway maps Victim IP to host local_mac"
    );
}

#[test]
fn test_spoofer_mode_toggle_and_properties() {
    use rustrict::spoofer::{ArpSpoofer, SpooferMode};

    let local_mac = MacAddress([0x10, 0x20, 0x30, 0x40, 0x50, 0x60]);
    let gateway_mac = MacAddress([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    let gateway_ip = Ipv4Addr::new(192, 168, 1, 1);

    let spoofer = ArpSpoofer::new_inactive(local_mac, gateway_ip, gateway_mac);
    assert_eq!(spoofer.mode(), SpooferMode::Blackhole);

    spoofer.set_mode(SpooferMode::Mitm);
    assert_eq!(spoofer.mode(), SpooferMode::Mitm);

    spoofer.set_mode(SpooferMode::Blackhole);
    assert_eq!(spoofer.mode(), SpooferMode::Blackhole);
}

#[test]
fn test_token_bucket_shaping_and_refill() {
    // 80,000 bps = 10,000 bytes per second
    let rate = 80_000u64;
    let mut tb = TokenBucket::new(rate, None);

    // Initially, capacity is 2x rate = 160,000 bits (20,000 bytes)
    // Try to consume 1,500 byte packet (12,000 bits) -> should succeed
    assert!(
        tb.try_consume(12_000),
        "Initial tokens must allow first packet"
    );

    // Repeatedly consume to exhaust tokens
    for _ in 0..12 {
        tb.try_consume(12_000);
    }

    // Now tokens should be exhausted
    let consumed_when_empty = tb.try_consume(100_000);
    assert!(
        !consumed_when_empty,
        "Should drop packet when tokens are exhausted"
    );

    // Sleep 150ms to allow refill: 80,000 * 0.150s = 12,000 bits
    std::thread::sleep(Duration::from_millis(150));
    assert!(tb.try_consume(8_000), "Tokens must replenish over time");
}

#[test]
fn test_scope_manager_persistence_and_enforcement() {
    let mut scope = ScopeManager::default();
    let cidr = "192.168.1.0/24".parse::<Ipv4Cidr>().unwrap();
    scope.add_cidr_direct(cidr);
    scope.set_strict(true);

    let excluded_ip = Ipv4Addr::new(192, 168, 1, 254);
    scope.exclude_ip(excluded_ip);

    let excluded_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    scope.exclude_mac(excluded_mac);

    // 1. Authorized target within subnet
    let valid_ip = Ipv4Addr::new(192, 168, 1, 50);
    let valid_mac = MacAddress([0xaa, 0xbb, 0xcc, 0x01, 0x02, 0x03]);
    assert!(scope.validate_target(&valid_ip, Some(&valid_mac)).is_ok());

    // 2. Out-of-scope target in strict mode -> rejected
    let external_ip = Ipv4Addr::new(10, 0, 0, 1);
    assert!(scope.validate_target(&external_ip, None).is_err());

    // 3. Excluded IP in scope -> rejected
    assert!(scope.validate_target(&excluded_ip, None).is_err());

    // 4. Excluded MAC in scope -> rejected
    assert!(scope
        .validate_target(&valid_ip, Some(&excluded_mac))
        .is_err());

    // Test persistence round-trip in PersistentState
    let mut state = PersistentState {
        scope: Some(scope.clone()),
        ..Default::default()
    };
    let host = Host::with_source(
        1,
        valid_ip,
        valid_mac,
        "TestVictim".into(),
        rustrict::types::NameSource::Manual,
        "Apple".into(),
    );
    state.add_blocked(&host, Direction::Both);

    let serialized = serde_json::to_string(&state).expect("Serialization must succeed");
    let deserialized: PersistentState =
        serde_json::from_str(&serialized).expect("Deserialization must succeed");

    assert_eq!(deserialized.blocked_hosts.len(), 1);
    assert_eq!(deserialized.blocked_hosts[0].ip, valid_ip);
    assert_eq!(deserialized.blocked_hosts[0].mac, valid_mac.to_string());

    let restored_scope = deserialized.scope.expect("Scope must be restored");
    assert!(restored_scope
        .validate_target(&valid_ip, Some(&valid_mac))
        .is_ok());
    assert!(restored_scope.validate_target(&external_ip, None).is_err());
    assert!(restored_scope.validate_target(&excluded_ip, None).is_err());
}

#[test]
fn test_subnet_scanner_rfc3021_and_range_clamping() {
    let local_ip = Ipv4Addr::new(10, 0, 0, 1);
    let gateway_ip = Ipv4Addr::new(10, 0, 0, 2);

    // RFC 3021 /31 subnet (netmask 255.255.255.254) has exactly 2 hosts (10.0.0.0 and 10.0.0.1)
    let netmask_31 = Ipv4Addr::new(255, 255, 255, 254);
    let scanner_31 = SubnetScanner::new_safe_test(local_ip, netmask_31, gateway_ip);
    let range_31 = scanner_31.calculate_subnet_ip_range();
    assert_eq!(range_31.len(), 2);
    assert_eq!(range_31[0], Ipv4Addr::new(10, 0, 0, 0));
    assert_eq!(range_31[1], Ipv4Addr::new(10, 0, 0, 1));
    let hosts_31 = scanner_31.scan_subnet(true, |_, _, _| {});
    assert!(hosts_31.len() <= 2);

    // /32 single-host subnet (netmask 255.255.255.255)
    let netmask_32 = Ipv4Addr::new(255, 255, 255, 255);
    let scanner_32 = SubnetScanner::new_safe_test(local_ip, netmask_32, gateway_ip);
    let range_32 = scanner_32.calculate_subnet_ip_range();
    assert_eq!(range_32.len(), 1);
    assert_eq!(range_32[0], Ipv4Addr::new(10, 0, 0, 1));
    let hosts_32 = scanner_32.scan_subnet(true, |_, _, _| {});
    assert!(hosts_32.len() <= 1);

    // Giant range scan: should clamp to max_hosts (65534) and not overflow u32
    let start_ip = Ipv4Addr::new(10, 0, 0, 0);
    let end_ip = Ipv4Addr::new(10, 255, 255, 255);
    let scanner = SubnetScanner::new_safe_test(local_ip, Ipv4Addr::new(255, 255, 0, 0), gateway_ip);
    let empty_range = scanner.scan_range(end_ip, start_ip, true, |_, _, _| {});
    assert_eq!(empty_range.len(), 0);

    let bounded = scanner.calculate_bounded_range(start_ip, end_ip);
    assert_eq!(bounded.len(), 65534);
}
