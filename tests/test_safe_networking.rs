use rustrict::core::{
    restore_persistent_blocks_with, Ipv4Cidr, PersistentBlockActivator, ScopeManager,
    ScopedForwardingEnabler,
};
use rustrict::monitor::nic::{
    evaluate_health_classification, parse_adapters_csv, parse_statistics_csv, run_nic_cli,
    sample_nic_health, NicAdapterInfo, NicHealthClassification, NicRawStats, NicTelemetryProvider,
};
#[allow(deprecated)]
use rustrict::platform::{enable_ip_forwarding, CommandRunner, ForwardingManager};
use rustrict::scanner::{MockNetworkProbe, SubnetScanner};
use rustrict::state::PersistentBlockedHost;
use rustrict::types::{Direction, Host, HostStatus};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[test]
fn test_subnet_scanner_boundary_calculations_send_zero_probes() {
    let local_ip = Ipv4Addr::new(192, 168, 1, 10);
    let netmask = Ipv4Addr::new(255, 255, 255, 0);
    let gateway_ip = Ipv4Addr::new(192, 168, 1, 1);

    let probe = Arc::new(MockNetworkProbe::new(HashMap::new()));
    let scanner = SubnetScanner::new_with_probe(local_ip, netmask, gateway_ip, None, probe.clone());

    // 1. Calculate /24 subnet range
    let range = scanner.calculate_subnet_ip_range();
    assert_eq!(range.len(), 254);
    assert_eq!(range[0], Ipv4Addr::new(192, 168, 1, 1));
    assert_eq!(range[253], Ipv4Addr::new(192, 168, 1, 254));

    // 2. Calculate /31 range
    let scanner_31 = SubnetScanner::new_with_probe(
        local_ip,
        Ipv4Addr::new(255, 255, 255, 254),
        gateway_ip,
        None,
        probe.clone(),
    );
    let range_31 = scanner_31.calculate_subnet_ip_range();
    assert_eq!(range_31.len(), 2);

    // 3. Calculate /32 range
    let scanner_32 = SubnetScanner::new_with_probe(
        local_ip,
        Ipv4Addr::new(255, 255, 255, 255),
        gateway_ip,
        None,
        probe.clone(),
    );
    let range_32 = scanner_32.calculate_subnet_ip_range();
    assert_eq!(range_32.len(), 1);

    // 4. Calculate bounded range with clamping and inversion protection
    let bounded = scanner
        .calculate_bounded_range(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 255, 255, 255));
    assert_eq!(bounded.len(), 65534);

    let inverted = scanner.calculate_bounded_range(
        Ipv4Addr::new(192, 168, 1, 50),
        Ipv4Addr::new(192, 168, 1, 10),
    );
    assert!(inverted.is_empty());

    // MUST verify strictly 0 ARP probes were invoked
    assert_eq!(
        probe.arp_calls.load(Ordering::SeqCst),
        0,
        "Subnet calculation and range planning must never issue live network probes"
    );
}

#[test]
fn test_subnet_scanner_scan_with_noop_probe_is_hermetic() {
    let local_ip = Ipv4Addr::new(172, 16, 0, 5);
    let netmask = Ipv4Addr::new(255, 255, 255, 0);
    let gateway_ip = Ipv4Addr::new(172, 16, 0, 1);

    let scanner = SubnetScanner::new_safe_test(local_ip, netmask, gateway_ip);
    let hosts = scanner.scan_range(
        Ipv4Addr::new(172, 16, 0, 1),
        Ipv4Addr::new(172, 16, 0, 3),
        true,
        |_, _, _| {},
    );

    // Safe test probe returns empty ARP cache and None for probes, so no hosts returned
    assert!(hosts.is_empty());
}

struct TestMockRunner {
    state: parking_lot::Mutex<String>,
    commands: parking_lot::Mutex<Vec<String>>,
}

impl TestMockRunner {
    fn new(initial_state: &str) -> Self {
        Self {
            state: parking_lot::Mutex::new(initial_state.to_string()),
            commands: parking_lot::Mutex::new(Vec::new()),
        }
    }
}

impl CommandRunner for TestMockRunner {
    fn run_powershell(&self, command: &str) -> Result<String, String> {
        self.commands.lock().push(command.to_string());
        if command.contains("Get-NetIPInterface") {
            Ok(self.state.lock().clone())
        } else if command.contains("Set-NetIPInterface") {
            if command.contains("-Forwarding Enabled") {
                *self.state.lock() = "Enabled".to_string();
            } else if command.contains("-Forwarding Disabled") {
                *self.state.lock() = "Disabled".to_string();
            }
            Ok(String::new())
        } else {
            Ok(String::new())
        }
    }
}

#[test]
fn test_scoped_forwarding_lifecycle_guarantees() {
    let manager = ForwardingManager::new();
    let runner_disabled = TestMockRunner::new("Disabled");
    let iface = "EthernetAdaptX";

    // Step 1: Initial query returns false
    let initial = manager
        .query_interface_forwarding_with(&runner_disabled, iface)
        .unwrap();
    assert!(!initial);

    // Step 2: Ensure enabled -> mutates state
    let mutated = manager
        .ensure_scoped_forwarding_enabled_with(&runner_disabled, iface)
        .unwrap();
    assert!(mutated);
    assert_eq!(*runner_disabled.state.lock(), "Enabled");

    // Step 3: Cleanup -> restores to Disabled
    manager.cleanup_forwarding_with(&runner_disabled);
    assert_eq!(*runner_disabled.state.lock(), "Disabled");

    // Case B: Interface originally Enabled
    let runner_enabled = TestMockRunner::new("Enabled");
    let iface_b = "PreconfiguredHyperV";

    let mutated_b = manager
        .ensure_scoped_forwarding_enabled_with(&runner_enabled, iface_b)
        .unwrap();
    assert!(!mutated_b, "Must not mutate interface if already enabled");
    assert_eq!(*runner_enabled.state.lock(), "Enabled");

    let cmds_before = runner_enabled.commands.lock().len();
    manager.cleanup_forwarding_with(&runner_enabled);
    let cmds_after = runner_enabled.commands.lock().len();
    assert_eq!(
        cmds_before, cmds_after,
        "Cleanup must issue 0 commands when interface was already enabled"
    );
    assert_eq!(*runner_enabled.state.lock(), "Enabled");
}

#[test]
fn test_unscoped_forwarding_is_disallowed() {
    #[allow(deprecated)]
    let res = enable_ip_forwarding();
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("disallowed for safety"));
}

struct MockFailingForwardingEnabler;
impl ScopedForwardingEnabler for MockFailingForwardingEnabler {
    fn ensure_forwarding_enabled(&self, _iface_name: &str) -> Result<bool, String> {
        Err("PowerShell execution policy prevented Set-NetIPInterface".into())
    }
}

struct MockRecordingActivator {
    activated_targets: Vec<(Ipv4Addr, Direction)>,
}

impl PersistentBlockActivator for MockRecordingActivator {
    fn is_injection_ready(&self) -> bool {
        true
    }

    fn activate(&mut self, host: &Host, dir: Direction) -> Result<(), String> {
        self.activated_targets.push((host.ip, dir));
        Ok(())
    }
}

#[test]
fn test_persistent_block_fail_closed_on_forwarding_failure() {
    let params = rustrict::core::RestorationNetworkParams {
        iface_ip: Ipv4Addr::new(192, 168, 1, 10),
        iface_mac: "00:11:22:33:44:02".parse().unwrap(),
        iface_name: "EthernetAdaptZ",
        gateway_ip: Ipv4Addr::new(192, 168, 1, 1),
        gateway_mac: "00:11:22:33:44:01".parse().unwrap(),
    };

    let mut scope = ScopeManager::new();
    let cidr = Ipv4Cidr::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap();
    scope.add_cidr_direct(cidr);
    scope.set_strict(true);

    let enabler = MockFailingForwardingEnabler;
    let mut activator = MockRecordingActivator {
        activated_targets: Vec::new(),
    };

    let blocked_records = vec![
        PersistentBlockedHost {
            ip: Ipv4Addr::new(192, 168, 1, 45),
            mac: "00:aa:bb:cc:dd:45".into(),
            name: "PersistentTarget1".into(),
            direction: "both".into(),
        },
        PersistentBlockedHost {
            ip: Ipv4Addr::new(192, 168, 1, 46),
            mac: "00:aa:bb:cc:dd:46".into(),
            name: "PersistentTarget2".into(),
            direction: "incoming".into(),
        },
    ];

    let report = restore_persistent_blocks_with(
        &blocked_records,
        |_| Direction::Both,
        &params,
        &scope,
        &enabler,
        &mut activator,
    );

    // Fail-closed invariants:
    // 1. Zero targets activated in spoofer/limiter
    assert_eq!(activator.activated_targets.len(), 0);
    assert_eq!(report.activated_targets.len(), 0);

    // 2. Both targets restored in inventory with PersistedInactive status
    assert_eq!(report.inactive_targets.len(), 2);
    assert_eq!(report.restored_hosts.len(), 2);
    assert_eq!(
        report.restored_hosts[0].status,
        HostStatus::PersistedInactive(Direction::Both)
    );
    assert_eq!(
        report.restored_hosts[1].status,
        HostStatus::PersistedInactive(Direction::Both)
    );
    assert!(report.restored_hosts[0].persistent_block);
    assert!(report.restored_hosts[1].persistent_block);

    // 3. Failure reason clearly reported
    assert!(report.failure_reason.is_some());
    assert!(report
        .failure_reason
        .unwrap()
        .contains("execution policy prevented"));
}

#[test]
fn test_cleanup_forwarding_report_structured_visibility() {
    let manager = ForwardingManager::new();
    let runner = TestMockRunner::new("Disabled");

    // Mutate state
    manager
        .ensure_scoped_forwarding_enabled_with(&runner, "Eth0")
        .unwrap();

    let report = manager.cleanup_forwarding_with(&runner);
    assert!(report.is_success());
    assert_eq!(report.restored_interfaces, vec!["Eth0".to_string()]);
    assert_eq!(report.failed_interfaces.len(), 0);
}

#[derive(Clone)]
struct TestTelemetryProvider {
    adapters: Vec<NicAdapterInfo>,
    samples: Arc<parking_lot::Mutex<Vec<Vec<NicRawStats>>>>,
    cursor: Arc<AtomicUsize>,
}

impl TestTelemetryProvider {
    fn new(adapters: Vec<NicAdapterInfo>, samples: Vec<Vec<NicRawStats>>) -> Self {
        Self {
            adapters,
            samples: Arc::new(parking_lot::Mutex::new(samples)),
            cursor: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl NicTelemetryProvider for TestTelemetryProvider {
    fn query_adapters(&self) -> Result<Vec<NicAdapterInfo>, String> {
        Ok(self.adapters.clone())
    }

    fn query_statistics(&self) -> Result<Vec<NicRawStats>, String> {
        let idx = self.cursor.fetch_add(1, Ordering::SeqCst);
        let s = self.samples.lock();
        if idx < s.len() {
            Ok(s[idx].clone())
        } else if let Some(last) = s.last() {
            Ok(last.clone())
        } else {
            Ok(Vec::new())
        }
    }
}

#[test]
fn test_nic_health_classification_and_telemetry() {
    let adapter_up = NicAdapterInfo {
        name: "Wi-Fi".into(),
        interface_index: 12,
        description: "Intel Wi-Fi 6 AX200".into(),
        status: "Up".into(),
        link_speed_str: "1.2 Gbps".into(),
        link_speed_bps: 1_200_000_000,
    };

    // 1. Normal classification (< 70% utilization, 0 errors, full telemetry)
    let (class_norm, _) =
        evaluate_health_classification(&adapter_up, 15.0, 5.0, Some(0), Some(0), Some(0), Some(0));
    assert_eq!(class_norm, NicHealthClassification::Normal);

    // 2. Incomplete telemetry (missing counter) must NEVER produce Normal
    let (class_inc, reason_inc) =
        evaluate_health_classification(&adapter_up, 15.0, 5.0, None, Some(0), Some(0), Some(0));
    assert_eq!(class_inc, NicHealthClassification::Degraded);
    assert!(reason_inc.contains("Incomplete telemetry"));

    // 3. Elevated classification (70% - 90%)
    let (class_elev, _) =
        evaluate_health_classification(&adapter_up, 78.5, 10.0, Some(0), Some(0), Some(0), Some(0));
    assert_eq!(class_elev, NicHealthClassification::Elevated);

    // 4. Saturated classification (>= 90%)
    let (class_sat, _) =
        evaluate_health_classification(&adapter_up, 94.2, 85.0, Some(0), Some(0), Some(0), Some(0));
    assert_eq!(class_sat, NicHealthClassification::Saturated);

    // 5. Degraded classification on error or discard
    let (class_deg_err, _) =
        evaluate_health_classification(&adapter_up, 5.0, 5.0, Some(1), Some(0), Some(0), Some(0));
    assert_eq!(class_deg_err, NicHealthClassification::Degraded);

    let (class_deg_disc, _) =
        evaluate_health_classification(&adapter_up, 5.0, 5.0, Some(0), Some(0), Some(3), Some(0));
    assert_eq!(class_deg_disc, NicHealthClassification::Degraded);

    // 6. Unavailable on disconnected status
    let mut adapter_disc = adapter_up.clone();
    adapter_disc.status = "Disconnected".into();
    let (class_unavail, _) =
        evaluate_health_classification(&adapter_disc, 0.0, 0.0, Some(0), Some(0), Some(0), Some(0));
    assert_eq!(class_unavail, NicHealthClassification::Unavailable);

    // 7. Unavailable on zero link speed
    let mut adapter_zero = adapter_up.clone();
    adapter_zero.link_speed_bps = 0;
    let (class_zero, _) =
        evaluate_health_classification(&adapter_zero, 0.0, 0.0, Some(0), Some(0), Some(0), Some(0));
    assert_eq!(class_zero, NicHealthClassification::Unavailable);
}

#[test]
fn test_nic_sample_sampling_window_and_wraparound() {
    let adapter = NicAdapterInfo {
        name: "Ethernet".into(),
        interface_index: 5,
        description: "PCIe Gigabit Controller".into(),
        status: "Up".into(),
        link_speed_str: "1 Gbps".into(),
        link_speed_bps: 1_000_000_000,
    };

    // Simulated 50ms sampling interval with normal counter deltas
    let s0 = vec![NicRawStats::new("Ethernet", 50_000, 20_000, 0, 0, 0, 0)];
    let s1 = vec![NicRawStats::new("Ethernet", 100_000, 40_000, 0, 0, 0, 0)];

    let provider = TestTelemetryProvider::new(vec![adapter.clone()], vec![s0, s1]);
    let report = sample_nic_health(&provider, Some("Ethernet"), Duration::from_millis(50)).unwrap();

    assert!(report.telemetry_valid);
    assert!(!report.counter_reset_detected);
    assert_eq!(report.rx_bytes_delta, Some(50_000));
    assert_eq!(report.tx_bytes_delta, Some(20_000));
    assert_eq!(report.classification, NicHealthClassification::Normal);

    // Simulated wraparound / counter reset
    let s_wrap0 = vec![NicRawStats::new("Ethernet", 100_000, 100_000, 0, 0, 0, 0)];
    let s_wrap1 = vec![NicRawStats::new("Ethernet", 1_000, 500, 0, 0, 0, 0)];

    let wrap_provider = TestTelemetryProvider::new(vec![adapter], vec![s_wrap0, s_wrap1]);
    let wrap_report =
        sample_nic_health(&wrap_provider, Some("Ethernet"), Duration::from_millis(10)).unwrap();

    assert!(wrap_report.counter_reset_detected);
    assert!(!wrap_report.telemetry_valid);
    assert_eq!(wrap_report.rx_bytes_delta, None);
    assert_eq!(wrap_report.tx_bytes_delta, None);
    assert_eq!(
        wrap_report.classification,
        NicHealthClassification::Degraded
    );
}

#[test]
fn test_adapters_and_stats_csv_parsing() {
    let adapter_csv = r#""Name","InterfaceIndex","InterfaceDescription","Status","LinkSpeed"
"Wi-Fi","16","MediaTek Wi-Fi 6E MT7922 (RZ616) 160MHz PCIe Adapter","Up","1.2 Gbps"
"Local Area Connection","15","TAP-ProtonVPN Windows Adapter V9","Disconnected","1 Gbps"
"Ethernet","10","Realtek Gaming GbE Family Controller","Disconnected","0 bps"
"#;
    let adapters = parse_adapters_csv(adapter_csv).unwrap();
    assert_eq!(adapters.len(), 3);
    assert_eq!(adapters[0].name, "Wi-Fi");
    assert_eq!(adapters[0].interface_index, 16);
    assert_eq!(adapters[0].status, "Up");
    assert_eq!(adapters[0].link_speed_bps, 1_200_000_000);

    assert_eq!(adapters[1].name, "Local Area Connection");
    assert_eq!(adapters[1].status, "Disconnected");

    assert_eq!(adapters[2].name, "Ethernet");
    assert_eq!(adapters[2].link_speed_bps, 0);

    let stats_csv = r#""Name","ReceivedBytes","SentBytes","ReceivedDiscardedPackets","ReceivedPacketErrors","OutboundDiscardedPackets","OutboundPacketErrors"
"Wi-Fi","24289016","117956511","0","0","0","0"
"Ethernet","0","0","0","0","0","0"
"#;
    let stats = parse_statistics_csv(stats_csv).unwrap();
    assert_eq!(stats.len(), 2);
    assert_eq!(stats[0].name, "Wi-Fi");
    assert_eq!(stats[0].received_bytes, Some(24289016));
    assert_eq!(stats[0].sent_bytes, Some(117956511));
    assert_eq!(stats[0].received_discarded, Some(0));
}

#[test]
fn test_standalone_nic_dispatch_runs_hermetic_without_network() {
    let adapter = NicAdapterInfo {
        name: "Wi-Fi".into(),
        interface_index: 16,
        description: "Test Wi-Fi Adapter".into(),
        status: "Up".into(),
        link_speed_str: "1 Gbps".into(),
        link_speed_bps: 1_000_000_000,
    };
    let s0 = vec![NicRawStats::new("Wi-Fi", 1_000, 2_000, 0, 0, 0, 0)];
    let s1 = vec![NicRawStats::new("Wi-Fi", 3_000, 4_000, 0, 0, 0, 0)];

    let provider = TestTelemetryProvider::new(vec![adapter], vec![s0, s1]);

    // Test list
    let res_list = run_nic_cli(&provider, None, &["list"]);
    assert!(res_list.is_ok());

    // Test help
    let res_help = run_nic_cli(&provider, None, &["help"]);
    assert!(res_help.is_ok());

    // Test health sampling
    let res_health = run_nic_cli(&provider, Some("Wi-Fi"), &["health"]);
    assert!(res_health.is_ok());
}

struct MockSuccessForwardingEnabler;
impl ScopedForwardingEnabler for MockSuccessForwardingEnabler {
    fn ensure_forwarding_enabled(&self, _iface_name: &str) -> Result<bool, String> {
        Ok(true)
    }
}

#[test]
fn test_persistent_block_rejects_subnet_network_and_directed_broadcast_targets() {
    let params = rustrict::core::RestorationNetworkParams {
        iface_ip: Ipv4Addr::new(192, 168, 1, 10),
        iface_mac: "00:11:22:33:44:02".parse().unwrap(),
        iface_name: "EthernetAdaptZ",
        gateway_ip: Ipv4Addr::new(192, 168, 1, 1),
        gateway_mac: "00:11:22:33:44:01".parse().unwrap(),
    };

    let mut scope = ScopeManager::new();
    let cidr = Ipv4Cidr::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap();
    scope.add_cidr_direct(cidr);
    scope.set_strict(true);

    let enabler = MockSuccessForwardingEnabler;
    let mut activator = MockRecordingActivator {
        activated_targets: Vec::new(),
    };

    let blocked_records = vec![
        // Valid host
        PersistentBlockedHost {
            ip: Ipv4Addr::new(192, 168, 1, 55),
            mac: "00:aa:bb:cc:dd:55".into(),
            name: "ValidHost".into(),
            direction: "both".into(),
        },
        // Subnet network identifier -> must be rejected
        PersistentBlockedHost {
            ip: Ipv4Addr::new(192, 168, 1, 0),
            mac: "00:aa:bb:cc:dd:00".into(),
            name: "NetworkIdHost".into(),
            direction: "both".into(),
        },
        // Directed broadcast -> must be rejected
        PersistentBlockedHost {
            ip: Ipv4Addr::new(192, 168, 1, 255),
            mac: "00:aa:bb:cc:dd:ff".into(),
            name: "DirectedBcastHost".into(),
            direction: "both".into(),
        },
    ];

    let report = restore_persistent_blocks_with(
        &blocked_records,
        |_| Direction::Both,
        &params,
        &scope,
        &enabler,
        &mut activator,
    );

    // Invariants:
    // 1. Only the valid host was activated
    assert_eq!(activator.activated_targets.len(), 1);
    assert_eq!(
        activator.activated_targets[0].0,
        Ipv4Addr::new(192, 168, 1, 55)
    );
    assert_eq!(report.activated_targets.len(), 1);

    // 2. Both network and broadcast were skipped with reasons
    assert_eq!(report.skipped_targets.len(), 2);
    let skipped_ips: Vec<Ipv4Addr> = report.skipped_targets.iter().map(|(ip, _)| *ip).collect();
    assert!(skipped_ips.contains(&Ipv4Addr::new(192, 168, 1, 0)));
    assert!(skipped_ips.contains(&Ipv4Addr::new(192, 168, 1, 255)));

    // 3. Stored records are completely untouched
    assert_eq!(blocked_records.len(), 3);
}

#[test]
fn test_persistent_block_accepts_31_point_to_point_endpoints() {
    let params = rustrict::core::RestorationNetworkParams {
        iface_ip: Ipv4Addr::new(172, 16, 0, 10),
        iface_mac: "00:11:22:33:44:02".parse().unwrap(),
        iface_name: "PointToPointAdapt",
        gateway_ip: Ipv4Addr::new(172, 16, 0, 99),
        gateway_mac: "00:11:22:33:44:01".parse().unwrap(),
    };

    let mut scope = ScopeManager::new();
    // RFC 3021 /31 subnet
    let cidr = Ipv4Cidr::new(Ipv4Addr::new(172, 16, 0, 0), 31).unwrap();
    scope.add_cidr_direct(cidr);
    scope.set_strict(true);

    let enabler = MockSuccessForwardingEnabler;
    let mut activator = MockRecordingActivator {
        activated_targets: Vec::new(),
    };

    let blocked_records = vec![
        PersistentBlockedHost {
            ip: Ipv4Addr::new(172, 16, 0, 0),
            mac: "00:aa:bb:cc:dd:10".into(),
            name: "Endpoint0".into(),
            direction: "both".into(),
        },
        PersistentBlockedHost {
            ip: Ipv4Addr::new(172, 16, 0, 1),
            mac: "00:aa:bb:cc:dd:11".into(),
            name: "Endpoint1".into(),
            direction: "both".into(),
        },
    ];

    let report = restore_persistent_blocks_with(
        &blocked_records,
        |_| Direction::Both,
        &params,
        &scope,
        &enabler,
        &mut activator,
    );

    // Under RFC 3021, both 0 and 1 are valid host endpoints and must be activated
    assert_eq!(activator.activated_targets.len(), 2);
    assert_eq!(report.activated_targets.len(), 2);
    assert_eq!(report.skipped_targets.len(), 0);
}
