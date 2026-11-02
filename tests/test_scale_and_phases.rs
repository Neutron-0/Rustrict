use rustrict::scanner::arp::{MockNetworkProbe, SubnetScanner};
use rustrict::spoofer::{ArpSpoofer, SpooferMode, BLACKHOLE_MAC};
use rustrict::types::{Host, HostStatus, MacAddress};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

#[test]
fn test_500_hosts_scan_phases_and_progress() {
    let local_ip = Ipv4Addr::new(10, 76, 112, 10);
    let netmask = Ipv4Addr::new(255, 255, 254, 0); // /23 (510 hosts)
    let gateway_ip = Ipv4Addr::new(10, 76, 112, 1);

    // Simulate 500 distinct hosts on the subnet
    let mut simulated_hosts = HashMap::new();
    let start_u32 = u32::from(Ipv4Addr::new(10, 76, 112, 2));
    for i in 0..500 {
        let ip = Ipv4Addr::from(start_u32 + i);
        let mac = MacAddress([0x00, 0x11, 0x22, ((i >> 16) & 0xff) as u8, ((i >> 8) & 0xff) as u8, (i & 0xff) as u8]);
        simulated_hosts.insert(ip, mac);
    }

    let probe = Arc::new(MockNetworkProbe::new(simulated_hosts));
    let scanner = SubnetScanner::new_with_probe(local_ip, netmask, gateway_ip, None, probe);

    let arp_progress_calls = Arc::new(AtomicUsize::new(0));
    let resolve_progress_calls = Arc::new(AtomicUsize::new(0));
    let last_resolved_count = Arc::new(AtomicUsize::new(0));

    let arp_cb = {
        let calls = Arc::clone(&arp_progress_calls);
        move |_scanned, _total, _disc| {
            calls.fetch_add(1, Ordering::Relaxed);
        }
    };

    let resolve_cb = {
        let calls = Arc::clone(&resolve_progress_calls);
        let last_res = Arc::clone(&last_resolved_count);
        move |resolved, total| {
            calls.fetch_add(1, Ordering::Relaxed);
            last_res.store(resolved, Ordering::Relaxed);
            assert!(resolved <= total);
        }
    };

    let start = Ipv4Addr::new(10, 76, 112, 2);
    let end = Ipv4Addr::from(start_u32 + 499);
    let discovered = scanner.scan_range_with_phases(start, end, true, arp_cb, resolve_cb);

    assert_eq!(discovered.len(), 500);
    assert!(arp_progress_calls.load(Ordering::Relaxed) > 0);
    assert!(resolve_progress_calls.load(Ordering::Relaxed) > 0);
    assert_eq!(last_resolved_count.load(Ordering::Relaxed), 500);

    // Verify ordering by IP address ascending
    for i in 0..499 {
        assert!(u32::from(discovered[i].ip) < u32::from(discovered[i + 1].ip));
        assert_eq!(discovered[i].id, i);
    }
}

#[test]
fn test_adaptive_spoofer_high_density_targets() {
    let local_mac = MacAddress([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
    let gateway_ip = Ipv4Addr::new(192, 168, 1, 1);
    let gateway_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

    let spoofer = ArpSpoofer::new_with_dummy_sender_for_testing(local_mac, gateway_ip, gateway_mac);

    // Add 100 targets
    for i in 2..=101 {
        let ip = Ipv4Addr::new(192, 168, 1, i);
        let mac = MacAddress([0x00, 0x50, 0x56, 0x00, 0x00, i]);
        let mut host = Host::new(i as usize, ip, mac, format!("Host-{}", i), "Vendor".into());
        host.status = HostStatus::Blocked(rustrict::types::Direction::Both);
        assert!(spoofer.add(host).is_ok());
    }

    assert_eq!(spoofer.target_count(), 100);

    // Mode toggle between Mitm and Blackhole
    spoofer.set_mode(SpooferMode::Blackhole);
    assert_eq!(spoofer.mode(), SpooferMode::Blackhole);
    assert_eq!(BLACKHOLE_MAC, MacAddress([0x02, 0xbf, 0x00, 0x00, 0x00, 0x01]));

    spoofer.set_mode(SpooferMode::Mitm);
    assert_eq!(spoofer.mode(), SpooferMode::Mitm);

    // Clean teardown
    spoofer.stop();
    assert_eq!(spoofer.target_count(), 0);
}
