use rustrict::types::{Host, MacAddress, NameSource};
use std::net::Ipv4Addr;

/// Mirrors target resolution logic for unit testing
fn resolve_test_targets(hosts: &[Host], arg: &str) -> Result<Vec<usize>, String> {
    let trimmed = arg.trim();
    if trimmed.eq_ignore_ascii_case("all") {
        if hosts.is_empty() {
            return Err("No devices in inventory. Run 'scan' or 'add <ip>' first.".to_string());
        }
        return Ok(hosts.iter().map(|h| h.id).collect());
    }

    let mut ids = Vec::new();
    for token in trimmed.split(',') {
        let t = token.trim();
        if t.is_empty() {
            continue;
        }

        if let Ok(id) = t.parse::<usize>() {
            if hosts.iter().any(|h| h.id == id) {
                if !ids.contains(&id) {
                    ids.push(id);
                }
            } else {
                return Err(format!("Device with ID {} not found in known hosts table.", id));
            }
        } else if let Ok(ip) = t.parse::<Ipv4Addr>() {
            let matches: Vec<usize> = hosts
                .iter()
                .filter(|h| h.ip == ip)
                .map(|h| h.id)
                .collect();

            if matches.is_empty() {
                return Err(format!(
                    "Device with IP {} is not in the known hosts table. Run 'scan' or use 'add {}' first.",
                    ip, ip
                ));
            } else if matches.len() > 1 {
                return Err(format!(
                    "Ambiguous identifier: IP {} maps to multiple devices (IDs: {:?}). Specify target by unique Device ID.",
                    ip, matches
                ));
            } else {
                let id = matches[0];
                if !ids.contains(&id) {
                    ids.push(id);
                }
            }
        } else {
            return Err(format!(
                "Invalid device identifier '{}'. Expected a Device ID (e.g. 1) or IPv4 address (e.g. 192.168.18.50).",
                t
            ));
        }
    }

    if ids.is_empty() {
        return Err("No valid device targets specified.".to_string());
    }

    Ok(ids)
}

fn sample_hosts() -> Vec<Host> {
    vec![
        Host::with_source(
            0,
            Ipv4Addr::new(192, 168, 18, 1),
            MacAddress([0xec, 0x02, 0x73, 0xcb, 0x84, 0x00]),
            "Router".to_string(),
            NameSource::Gateway,
            "TP-Link".to_string(),
        ),
        Host::with_source(
            1,
            Ipv4Addr::new(192, 168, 18, 32),
            MacAddress([0x64, 0x4e, 0xd7, 0x11, 0x22, 0x33]),
            "NEO".to_string(),
            NameSource::Local,
            "Local Host".to_string(),
        ),
        Host::with_source(
            2,
            Ipv4Addr::new(192, 168, 18, 50),
            MacAddress([0x08, 0xf9, 0x7e, 0x38, 0x8a, 0xbf]),
            "Johns-MacBook".to_string(),
            NameSource::Dhcp,
            "Apple".to_string(),
        ),
    ]
}

#[test]
fn test_resolve_by_id() {
    let hosts = sample_hosts();
    assert_eq!(resolve_test_targets(&hosts, "0"), Ok(vec![0]));
    assert_eq!(resolve_test_targets(&hosts, "2"), Ok(vec![2]));
    assert_eq!(resolve_test_targets(&hosts, "0,2"), Ok(vec![0, 2]));
}

#[test]
fn test_resolve_by_ip() {
    let hosts = sample_hosts();
    assert_eq!(resolve_test_targets(&hosts, "192.168.18.1"), Ok(vec![0]));
    assert_eq!(resolve_test_targets(&hosts, "192.168.18.50"), Ok(vec![2]));
}

#[test]
fn test_resolve_mixed_id_and_ip() {
    let hosts = sample_hosts();
    assert_eq!(resolve_test_targets(&hosts, "0,192.168.18.50,1"), Ok(vec![0, 2, 1]));
}

#[test]
fn test_resolve_all() {
    let hosts = sample_hosts();
    assert_eq!(resolve_test_targets(&hosts, "all"), Ok(vec![0, 1, 2]));
    assert_eq!(resolve_test_targets(&hosts, "ALL"), Ok(vec![0, 1, 2]));
}

#[test]
fn test_resolve_deduplication() {
    let hosts = sample_hosts();
    // Same target specified by ID and IP should be deduplicated
    assert_eq!(resolve_test_targets(&hosts, "2,192.168.18.50,2"), Ok(vec![2]));
}

#[test]
fn test_resolve_unknown_ip() {
    let hosts = sample_hosts();
    let res = resolve_test_targets(&hosts, "192.168.18.99");
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert!(err.contains("192.168.18.99 is not in the known hosts table"));
}

#[test]
fn test_resolve_unknown_id() {
    let hosts = sample_hosts();
    let res = resolve_test_targets(&hosts, "99");
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert!(err.contains("Device with ID 99 not found"));
}

#[test]
fn test_resolve_ambiguous_ip() {
    let mut hosts = sample_hosts();
    // Insert a second host sharing the same IP (e.g. historical record)
    hosts.push(Host::with_source(
        3,
        Ipv4Addr::new(192, 168, 18, 50),
        MacAddress([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
        "Old-Lease".to_string(),
        NameSource::Unresolved,
        "Unknown".to_string(),
    ));

    let res = resolve_test_targets(&hosts, "192.168.18.50");
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert!(err.contains("Ambiguous identifier: IP 192.168.18.50 maps to multiple devices"));
}

#[test]
fn test_resolve_invalid_syntax() {
    let hosts = sample_hosts();
    let res = resolve_test_targets(&hosts, "random_garbage");
    assert!(res.is_err());
    let err = res.unwrap_err();
    assert!(err.contains("Invalid device identifier 'random_garbage'"));
}

#[test]
fn test_non_destructive_upsert() {
    let mut current_hosts = sample_hosts();

    // Re-scan finds host 0 and host 1, but host 2 was temporarily asleep
    // and a new host 3 was discovered
    let new_scan = vec![
        Host::with_source(
            0,
            Ipv4Addr::new(192, 168, 18, 1),
            MacAddress([0xec, 0x02, 0x73, 0xcb, 0x84, 0x00]),
            "Router".to_string(),
            NameSource::Gateway,
            "TP-Link".to_string(),
        ),
        Host::with_source(
            1,
            Ipv4Addr::new(192, 168, 18, 70),
            MacAddress([0x24, 0xb2, 0xb9, 0x11, 0x22, 0x33]),
            "New-Phone".to_string(),
            NameSource::Dhcp,
            "OnePlus".to_string(),
        ),
    ];

    // Non-destructive upsert
    for new_h in new_scan {
        if let Some(existing) = current_hosts.iter_mut().find(|h| {
            (h.mac != MacAddress::ZERO && h.mac == new_h.mac) || h.ip == new_h.ip
        }) {
            existing.ip = new_h.ip;
            if new_h.name_source != NameSource::Unresolved {
                existing.name = new_h.name;
                existing.name_source = new_h.name_source;
            }
        } else {
            let id = current_hosts.len();
            let mut added = new_h;
            added.id = id;
            current_hosts.push(added);
        }
    }

    // Host 2 (Johns-MacBook) must still be preserved!
    assert!(current_hosts.iter().any(|h| h.name == "Johns-MacBook"));
    // New phone must be added!
    assert!(current_hosts.iter().any(|h| h.name == "New-Phone"));
    // Total should be 4
    assert_eq!(current_hosts.len(), 4);
}

#[test]
fn test_fresh_rescan_prunes_unmanaged_but_preserves_blocked() {
    let mut current_hosts = sample_hosts();

    // Mark host 2 as persistently blocked
    current_hosts[2].status = rustrict::types::HostStatus::Blocked(rustrict::types::Direction::Both);
    current_hosts[2].persistent_block = true;

    // Fresh scan only discovers router (192.168.18.1)
    let new_scan = vec![
        Host::with_source(
            0,
            Ipv4Addr::new(192, 168, 18, 1),
            MacAddress([0xec, 0x02, 0x73, 0xcb, 0x84, 0x00]),
            "Router".to_string(),
            NameSource::Gateway,
            "TP-Link".to_string(),
        ),
    ];

    // Simulate reconcile_hosts(new_scan, is_fresh = true)
    let is_fresh = true;
    if is_fresh {
        current_hosts.retain(|h| {
            h.persistent_block
                || h.status != rustrict::types::HostStatus::Free
                || new_scan.iter().any(|nh| nh.ip == h.ip || (nh.mac != MacAddress::ZERO && nh.mac == h.mac))
        });
    }

    // Update reachability flags
    for h in &mut current_hosts {
        let is_alive = new_scan.iter().any(|nh| nh.ip == h.ip || (nh.mac != MacAddress::ZERO && nh.mac == h.mac));
        h.online = is_alive;
    }

    // Host 1 (NEO / unmanaged) should be pruned because it wasn't in fresh scan!
    assert!(!current_hosts.iter().any(|h| h.ip == Ipv4Addr::new(192, 168, 18, 32)));

    // Host 2 (Blocked) MUST be preserved even though it wasn't in the scan!
    let blocked_host = current_hosts.iter().find(|h| h.ip == Ipv4Addr::new(192, 168, 18, 50)).unwrap();
    assert!(blocked_host.persistent_block);
    assert_eq!(blocked_host.status, rustrict::types::HostStatus::Blocked(rustrict::types::Direction::Both));
    // And its live state correctly reflects offline
    assert!(!blocked_host.online);

    // Host 0 (Router) is online
    let router = current_hosts.iter().find(|h| h.ip == Ipv4Addr::new(192, 168, 18, 1)).unwrap();
    assert!(router.online);
}

#[test]
fn test_persistent_state_roundtrip() {
    let mut state = rustrict::state::PersistentState::default();
    let test_ip = Ipv4Addr::new(192, 168, 18, 88);
    let host = Host::with_source(
        0,
        test_ip,
        MacAddress([1, 2, 3, 4, 5, 6]),
        "Target-PC".to_string(),
        NameSource::Manual,
        "Dell".to_string(),
    );

    state.add_blocked(&host, rustrict::types::Direction::Outgoing);
    assert!(state.is_blocked(&test_ip));
    assert_eq!(state.get_direction(&test_ip), rustrict::types::Direction::Outgoing);

    state.remove_blocked(&test_ip);
    assert!(!state.is_blocked(&test_ip));
}
