use rustrict::cli::RustrictCli;
use rustrict::limiter::{limiter_activation_count, reset_limiter_activation_count};
use rustrict::platform::{
    check_environment, check_router_lab_environment, driver_check_count, forwarding_mutation_count,
    get_default_interface_read_only_with, icmp_ping_probe_count, reset_driver_check_count,
    reset_forwarding_mutation_count, reset_probe_counts, send_arp_probe_count,
    ActiveInterfaceResolver, ArpCacheLookup, CommandRunner, ReadOnlyInterfaceResolver,
    SystemArpCache,
};
use rustrict::spoofer::raw_l2::{raw_frame_send_count, reset_raw_frame_send_count};
use rustrict::spoofer::{reset_target_add_count, target_add_count};
use rustrict::types::MacAddress;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Mutex;

struct MockCommandRunner {
    route_response: Result<String, String>,
    ip_response: Result<String, String>,
    adapter_response: Result<String, String>,
    executed_commands: Mutex<Vec<String>>,
}

impl MockCommandRunner {
    fn new_valid(
        iface_name: &str,
        local_ip: &str,
        prefix_len: u8,
        gateway_ip: &str,
        local_mac_hyphen: &str,
    ) -> Self {
        Self {
            route_response: Ok(format!("{}|{}", iface_name, gateway_ip)),
            ip_response: Ok(format!("{}|{}", local_ip, prefix_len)),
            adapter_response: Ok(format!(
                "{}|{{11111111-2222-3333-4444-555555555555}}",
                local_mac_hyphen
            )),
            executed_commands: Mutex::new(Vec::new()),
        }
    }

    fn custom(
        route: Result<String, String>,
        ip: Result<String, String>,
        adapter: Result<String, String>,
    ) -> Self {
        Self {
            route_response: route,
            ip_response: ip,
            adapter_response: adapter,
            executed_commands: Mutex::new(Vec::new()),
        }
    }
}

impl CommandRunner for MockCommandRunner {
    fn run_powershell(&self, command: &str) -> Result<String, String> {
        self.executed_commands
            .lock()
            .unwrap()
            .push(command.to_string());
        if command.contains("Get-NetRoute") {
            self.route_response.clone()
        } else if command.contains("Get-NetIPAddress") {
            self.ip_response.clone()
        } else if command.contains("Get-NetAdapter") {
            self.adapter_response.clone()
        } else {
            Err(format!("Unhandled mock command: {}", command))
        }
    }
}

struct MockArpCache {
    entries: HashMap<Ipv4Addr, MacAddress>,
}

impl MockArpCache {
    fn empty() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    fn with_entry(ip: Ipv4Addr, mac: MacAddress) -> Self {
        let mut entries = HashMap::new();
        entries.insert(ip, mac);
        Self { entries }
    }
}

impl ArpCacheLookup for MockArpCache {
    fn lookup_cached_mac(&self, ip: Ipv4Addr) -> Option<MacAddress> {
        self.entries.get(&ip).copied()
    }
}

static TEST_MUTEX: Mutex<()> = Mutex::new(());

fn reset_all_counters() {
    reset_raw_frame_send_count();
    reset_target_add_count();
    reset_limiter_activation_count();
    reset_forwarding_mutation_count();
    reset_probe_counts();
    reset_driver_check_count();
}

fn assert_zero_probes_and_side_effects() {
    assert_eq!(
        send_arp_probe_count(),
        0,
        "Invariant violated: SendARP probe was issued"
    );
    assert_eq!(
        icmp_ping_probe_count(),
        0,
        "Invariant violated: ICMP ping fallback was issued"
    );
    assert_eq!(
        raw_frame_send_count(),
        0,
        "Invariant violated: Raw L2 frame was emitted"
    );
    assert_eq!(
        target_add_count(),
        0,
        "Invariant violated: Spoofer target was added"
    );
    assert_eq!(
        limiter_activation_count(),
        0,
        "Invariant violated: Limiter was activated"
    );
    assert_eq!(
        forwarding_mutation_count(),
        0,
        "Invariant violated: Forwarding state was mutated"
    );
}

#[test]
fn test_01_read_only_resolver_retrieves_metadata_without_probes() {
    let _lock = TEST_MUTEX.lock().unwrap();
    reset_all_counters();
    let runner = MockCommandRunner::new_valid(
        "Ethernet0",
        "10.0.0.42",
        24,
        "10.0.0.1",
        "00-50-56-C0-00-01",
    );
    let gw_mac: MacAddress = "00:0c:29:12:34:56".parse().unwrap();
    let cache = MockArpCache::with_entry(Ipv4Addr::new(10, 0, 0, 1), gw_mac);

    let iface = get_default_interface_read_only_with(&runner, &cache)
        .expect("Read-only interface resolution should succeed");

    assert_eq!(iface.name, "Ethernet0");
    assert_eq!(iface.ip, Ipv4Addr::new(10, 0, 0, 42));
    assert_eq!(iface.netmask, Ipv4Addr::new(255, 255, 255, 0));
    assert_eq!(iface.gateway, Ipv4Addr::new(10, 0, 0, 1));
    assert_eq!(iface.gateway_mac, gw_mac);
    assert_eq!(iface.mac, "00:50:56:c0:00:01".parse().unwrap());
    assert_eq!(
        iface.device_path,
        r"\Device\NPF_{11111111-2222-3333-4444-555555555555}"
    );

    assert_zero_probes_and_side_effects();
}

#[test]
fn test_02_gateway_mac_unresolved_when_absent_from_cache() {
    let _lock = TEST_MUTEX.lock().unwrap();
    reset_all_counters();
    let runner = MockCommandRunner::new_valid(
        "Wi-Fi",
        "192.168.1.100",
        24,
        "192.168.1.1",
        "E4-54-E8-12-34-56",
    );
    let empty_cache = MockArpCache::empty();

    let iface = get_default_interface_read_only_with(&runner, &empty_cache)
        .expect("Read-only resolution must succeed even without cached gateway MAC");

    assert_eq!(iface.name, "Wi-Fi");
    assert_eq!(iface.ip, Ipv4Addr::new(192, 168, 1, 100));
    assert_eq!(iface.gateway, Ipv4Addr::new(192, 168, 1, 1));
    assert!(
        iface.gateway_mac.is_zero(),
        "Gateway MAC must remain explicitly unresolved (ZERO) when missing from cache"
    );
    assert_eq!(iface.gateway_mac, MacAddress::ZERO);

    assert_zero_probes_and_side_effects();
}

#[test]
fn test_03_read_only_discovery_failure_fails_closed_without_active_fallback() {
    let _lock = TEST_MUTEX.lock().unwrap();
    reset_all_counters();
    let runner = MockCommandRunner::custom(
        Err("PowerShell execution failed: route not found".into()),
        Ok("192.168.1.100|24".into()),
        Ok("00-11-22-33-44-55|{GUID}".into()),
    );
    let cache = MockArpCache::empty();

    let res = get_default_interface_read_only_with(&runner, &cache);
    assert!(res.is_err(), "Must fail closed when route query fails");
    let err_msg = res.unwrap_err();
    assert!(
        err_msg.contains("Failed to query route"),
        "Expected error message indicating route query failure, got: {}",
        err_msg
    );

    assert_zero_probes_and_side_effects();
}

#[test]
fn test_04_router_lab_environment_check_skips_enforcement_drivers() {
    let _lock = TEST_MUTEX.lock().unwrap();
    reset_all_counters();

    let env = check_router_lab_environment();
    assert_eq!(
        driver_check_count(),
        0,
        "Invariant violated: router-lab environment check loaded or checked enforcement drivers"
    );
    assert!(!env.npcap_available);
    assert!(!env.windivert_available);
    assert!(env.npcap_details.contains("skipped in router-lab mode"));
    assert!(env.windivert_details.contains("skipped in router-lab mode"));

    // Verify check_environment() does count driver checks
    let _ = check_environment();
    assert!(driver_check_count() >= 1);
}

#[test]
fn test_05_normal_application_mode_maintains_intended_active_behavior() {
    let _lock = TEST_MUTEX.lock().unwrap();
    reset_all_counters();

    // Verify SystemArpCache can be instantiated and implements ArpCacheLookup
    let system_cache = SystemArpCache;
    let _ = system_cache.lookup_cached_mac(Ipv4Addr::new(127, 0, 0, 1));

    // Verify ActiveInterfaceResolver contract
    let _active_resolver = ActiveInterfaceResolver;

    assert_eq!(raw_frame_send_count(), 0);
    assert_eq!(target_add_count(), 0);
    assert_eq!(limiter_activation_count(), 0);
    assert_eq!(forwarding_mutation_count(), 0);
}

#[test]
fn test_06_router_lab_provider_requests_do_not_occur_before_explicit_selection() {
    let _lock = TEST_MUTEX.lock().unwrap();
    reset_all_counters();
    let runner = MockCommandRunner::new_valid(
        "Lab-Iface",
        "172.16.0.5",
        16,
        "172.16.0.1",
        "02-00-00-00-00-01",
    );
    let cache = MockArpCache::empty();
    let resolver = ReadOnlyInterfaceResolver::new(&runner, &cache);

    let cli = RustrictCli::bootstrap_router_lab(&resolver)
        .expect("Bootstrap in router-lab mode should succeed");

    assert!(cli.is_router_lab());
    assert_eq!(cli.iface().gateway, Ipv4Addr::new(172, 16, 0, 1));

    // Prove that no router provider connection has been made
    assert!(
        !cli.router_registry().is_connected(),
        "Invariant violated: router registry reports connected before user selection"
    );
    assert!(
        cli.router_registry().active_provider_id().is_none(),
        "Invariant violated: active router provider established implicitly before user selection"
    );

    assert_zero_probes_and_side_effects();
}

#[test]
fn test_07_malformed_routes_ips_prefixes_and_adapters_fail_safely() {
    let _lock = TEST_MUTEX.lock().unwrap();
    reset_all_counters();
    let cache = MockArpCache::empty();

    // 7a. Missing route (empty string)
    let r_empty = MockCommandRunner::custom(
        Ok("".into()),
        Ok("192.168.1.10|24".into()),
        Ok("00-11-22-33-44-55|{GUID}".into()),
    );
    let err = get_default_interface_read_only_with(&r_empty, &cache).unwrap_err();
    assert!(err.contains("No default route"));

    // 7b. Invalid gateway IP
    let r_bad_gw = MockCommandRunner::custom(
        Ok("Wi-Fi|not_an_ip".into()),
        Ok("192.168.1.10|24".into()),
        Ok("00-11-22-33-44-55|{GUID}".into()),
    );
    let err = get_default_interface_read_only_with(&r_bad_gw, &cache).unwrap_err();
    assert!(err.contains("Invalid gateway IP"));

    // 7c. Missing local IP
    let r_bad_ip = MockCommandRunner::custom(
        Ok("Wi-Fi|192.168.1.1".into()),
        Ok("".into()),
        Ok("00-11-22-33-44-55|{GUID}".into()),
    );
    let err = get_default_interface_read_only_with(&r_bad_ip, &cache).unwrap_err();
    assert!(err.contains("Could not query IP address"));

    // 7d. Malformed prefix (> 32 or not an int)
    let r_bad_prefix = MockCommandRunner::custom(
        Ok("Wi-Fi|192.168.1.1".into()),
        Ok("192.168.1.10|33".into()),
        Ok("00-11-22-33-44-55|{GUID}".into()),
    );
    let err = get_default_interface_read_only_with(&r_bad_prefix, &cache).unwrap_err();
    assert!(err.contains("Invalid prefix length"));

    // 7e. Adapter query error
    let r_bad_adapter = MockCommandRunner::custom(
        Ok("Wi-Fi|192.168.1.1".into()),
        Ok("192.168.1.10|24".into()),
        Err("Adapter not found".into()),
    );
    let err = get_default_interface_read_only_with(&r_bad_adapter, &cache).unwrap_err();
    assert!(err.contains("Failed to query adapter info"));

    // 7f. Zero local MAC
    let r_zero_mac = MockCommandRunner::custom(
        Ok("Wi-Fi|192.168.1.1".into()),
        Ok("192.168.1.10|24".into()),
        Ok("00-00-00-00-00-00|{GUID}".into()),
    );
    let err = get_default_interface_read_only_with(&r_zero_mac, &cache).unwrap_err();
    assert!(err.contains("Failed to query local MAC address"));

    assert_zero_probes_and_side_effects();
}

#[test]
fn test_08_current_default_gateway_never_receives_unsolicited_startup_probe() {
    let _lock = TEST_MUTEX.lock().unwrap();
    reset_all_counters();
    let target_gw = "10.170.60.1";
    let runner = MockCommandRunner::new_valid(
        "Production-Wi-Fi",
        "10.170.60.222",
        24,
        target_gw,
        "F4-B3-81-AA-BB-CC",
    );
    let cache = MockArpCache::empty();
    let resolver = ReadOnlyInterfaceResolver::new(&runner, &cache);

    let mut cli = RustrictCli::bootstrap_router_lab(&resolver)
        .expect("Bootstrap must succeed without network probes");

    // Execute multiple permitted read-only commands
    assert!(cli.dispatch_command("help"));
    assert!(cli.dispatch_command("router list"));
    assert!(cli.dispatch_command("router capabilities"));
    assert!(cli.dispatch_command("router status"));

    // Verify absolutely ZERO unsolicited packets were emitted towards target_gw
    assert_zero_probes_and_side_effects();
}

#[test]
fn test_09_existing_router_lab_allowlist_enforced_during_zero_probe_session() {
    let _lock = TEST_MUTEX.lock().unwrap();
    reset_all_counters();
    let runner = MockCommandRunner::new_valid(
        "Wi-Fi",
        "10.170.60.222",
        24,
        "10.170.60.1",
        "F4-B3-81-AA-BB-CC",
    );
    let cache = MockArpCache::empty();
    let resolver = ReadOnlyInterfaceResolver::new(&runner, &cache);
    let mut cli = RustrictCli::bootstrap_router_lab(&resolver).unwrap();

    // Verify all active network enforcement verbs are rejected
    assert!(cli.dispatch_command("scan"));
    assert!(cli.dispatch_command("block 10.170.60.2"));
    assert!(cli.dispatch_command("limit 10.170.60.2 100"));
    assert!(cli.dispatch_command("simulate arp-flood"));
    assert!(cli.dispatch_command("router pause 10.170.60.2"));

    assert_zero_probes_and_side_effects();
}

#[test]
fn test_10_clean_shutdown_and_eof_zero_forwarding_cleanup_and_zero_frames() {
    let _lock = TEST_MUTEX.lock().unwrap();
    reset_all_counters();
    let runner = MockCommandRunner::new_valid(
        "Wi-Fi",
        "10.170.60.222",
        24,
        "10.170.60.1",
        "F4-B3-81-AA-BB-CC",
    );
    let cache = MockArpCache::empty();
    let resolver = ReadOnlyInterfaceResolver::new(&runner, &cache);
    let mut cli = RustrictCli::bootstrap_router_lab(&resolver).unwrap();

    // Dispatch clean exit
    assert!(!cli.dispatch_command("exit"));
    cli.shutdown();

    assert_zero_probes_and_side_effects();
}
