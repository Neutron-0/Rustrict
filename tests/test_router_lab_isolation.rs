use rustrict::cli::RustrictCli;
use rustrict::gateway::admin::{
    MockRouterAdminProvider, MockSshExecutor, OpenWrtAdminProvider, SshConfig, SshOpenWrtTransport,
};
use rustrict::limiter::{limiter_activation_count, reset_limiter_activation_count};
use rustrict::platform::{forwarding_mutation_count, reset_forwarding_mutation_count};
use rustrict::spoofer::raw_l2::{raw_frame_send_count, reset_raw_frame_send_count};
use rustrict::spoofer::{reset_target_add_count, target_add_count};
use rustrict::types::{MacAddress, NetworkInterface};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

fn make_test_iface() -> NetworkInterface {
    NetworkInterface {
        name: "test_router_lab_iface".into(),
        description: "Loopback Interface for Router-Lab Isolation Testing".into(),
        ip: Ipv4Addr::new(192, 168, 1, 50),
        netmask: Ipv4Addr::new(255, 255, 255, 0),
        gateway: Ipv4Addr::new(192, 168, 1, 1),
        gateway_mac: MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
        mac: MacAddress([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]),
        device_path: "\\Device\\NPF_Loopback".into(),
    }
}

fn reset_all_side_effect_counters() {
    reset_raw_frame_send_count();
    reset_target_add_count();
    reset_limiter_activation_count();
    reset_forwarding_mutation_count();
}

fn assert_zero_side_effects() {
    assert_eq!(
        raw_frame_send_count(),
        0,
        "Invariant violated: raw frame sends detected in read-only router-lab path"
    );
    assert_eq!(
        target_add_count(),
        0,
        "Invariant violated: spoofer target additions detected in read-only router-lab path"
    );
    assert_eq!(
        limiter_activation_count(),
        0,
        "Invariant violated: limiter activations detected in read-only router-lab path"
    );
    assert_eq!(
        forwarding_mutation_count(),
        0,
        "Invariant violated: OS forwarding mutations detected in read-only router-lab path"
    );
}

#[test]
fn test_01_router_lab_rejects_scan_ports_audit_add() {
    reset_all_side_effect_counters();
    let mut cli = RustrictCli::new_router_lab(make_test_iface());

    // Dispatcher checks
    assert!(cli.is_command_allowed_in_router_lab(&["scan"]).is_err());
    assert!(cli
        .is_command_allowed_in_router_lab(&["ports", "1"])
        .is_err());
    assert!(cli
        .is_command_allowed_in_router_lab(&["audit", "1"])
        .is_err());
    assert!(cli
        .is_command_allowed_in_router_lab(&["add", "192.168.1.99"])
        .is_err());

    // Interactive dispatch execution
    assert!(cli.dispatch_command("scan"));
    assert!(cli.dispatch_command("scan --fresh"));
    assert!(cli.dispatch_command("ports 1"));
    assert!(cli.dispatch_command("audit 1"));
    assert!(cli.dispatch_command("add 192.168.1.99"));

    // Direct handler execution must also fail closed
    cli.handle_scan(&[]);
    cli.handle_scan(&["--fresh"]);
    cli.handle_ports(&["1"]);
    cli.handle_audit(&["1"]);
    cli.handle_add(&["192.168.1.99"]);

    assert_zero_side_effects();
}

#[test]
fn test_02_router_lab_rejects_scope_mutations_and_free() {
    reset_all_side_effect_counters();
    let mut cli = RustrictCli::new_router_lab(make_test_iface());

    assert!(cli
        .is_command_allowed_in_router_lab(&["scope", "add", "10.0.0.0/8"])
        .is_err());
    assert!(cli
        .is_command_allowed_in_router_lab(&["scope", "remove", "192.168.1.0/24"])
        .is_err());
    assert!(cli
        .is_command_allowed_in_router_lab(&["scope", "strict", "off"])
        .is_err());
    assert!(cli
        .is_command_allowed_in_router_lab(&["free", "1"])
        .is_err());
    assert!(cli
        .is_command_allowed_in_router_lab(&["free", "all"])
        .is_err());

    // Execution must not change scope or invoke restorative ARP packets
    let initial_scope_cidrs = cli.scope().allowed_cidrs.clone();
    assert!(cli.dispatch_command("scope add 10.0.0.0/8"));
    assert!(cli.dispatch_command("scope remove 192.168.1.0/24"));
    assert!(cli.dispatch_command("scope strict off"));
    assert!(cli.dispatch_command("free all"));

    cli.handle_scope(&["add", "10.0.0.0/8"]);
    cli.handle_free(&["all"]);

    assert_eq!(cli.scope().allowed_cidrs, initial_scope_cidrs);
    assert_zero_side_effects();
}

#[test]
fn test_03_router_lab_rejects_block_limit_simulate() {
    reset_all_side_effect_counters();
    let mut cli = RustrictCli::new_router_lab(make_test_iface());

    assert!(cli
        .is_command_allowed_in_router_lab(&["block", "1"])
        .is_err());
    assert!(cli
        .is_command_allowed_in_router_lab(&["block", "all"])
        .is_err());
    assert!(cli
        .is_command_allowed_in_router_lab(&["limit", "1", "200kbit"])
        .is_err());
    assert!(cli
        .is_command_allowed_in_router_lab(&["simulate", "1", "drop", "50"])
        .is_err());

    assert!(cli.dispatch_command("block 1"));
    assert!(cli.dispatch_command("limit 1 200kbit"));
    assert!(cli.dispatch_command("simulate 1 drop 50"));

    cli.handle_block(&["1"]);
    cli.handle_limit(&["1", "200kbit"]);
    cli.handle_simulate(&["1", "drop", "50"]);

    assert_zero_side_effects();
}

#[test]
fn test_04_router_lab_rejects_router_pause_adjust_resume() {
    reset_all_side_effect_counters();
    let mut cli = RustrictCli::new_router_lab(make_test_iface());

    assert!(cli
        .is_command_allowed_in_router_lab(&["router", "pause", "all"])
        .is_err());
    assert!(cli
        .is_command_allowed_in_router_lab(&["router", "adjust", "all", "--duration", "300"])
        .is_err());
    assert!(cli
        .is_command_allowed_in_router_lab(&["router", "resume", "all"])
        .is_err());
    assert!(cli
        .is_command_allowed_in_router_lab(&["router", "refresh"])
        .is_err());
    assert!(cli
        .is_command_allowed_in_router_lab(&["router", "reconcile"])
        .is_err());

    assert!(cli.dispatch_command("router pause all"));
    assert!(cli.dispatch_command("router adjust all --duration 300"));
    assert!(cli.dispatch_command("router resume all"));
    assert!(cli.dispatch_command("router refresh"));

    cli.handle_router(&["pause", "all"]);
    cli.handle_router(&["adjust", "all", "--duration", "300"]);
    cli.handle_router(&["resume", "all"]);
    cli.handle_router(&["refresh"]);

    assert_zero_side_effects();
}

#[test]
fn test_05_adding_yes_flag_cannot_bypass_router_lab_policy() {
    reset_all_side_effect_counters();
    let mut cli = RustrictCli::new_router_lab(make_test_iface());

    // Both with dispatcher and direct handler invocation
    assert!(cli
        .is_command_allowed_in_router_lab(&["router", "pause", "all", "--yes"])
        .is_err());
    assert!(cli
        .is_command_allowed_in_router_lab(&["router", "resume", "all", "--yes"])
        .is_err());
    assert!(cli
        .is_command_allowed_in_router_lab(&[
            "router",
            "adjust",
            "all",
            "--duration",
            "300",
            "--yes"
        ])
        .is_err());

    assert!(cli.dispatch_command("router pause all --yes"));
    assert!(cli.dispatch_command("router resume all --yes"));
    assert!(cli.dispatch_command("router adjust all --duration 300 --yes"));

    cli.handle_router(&["pause", "all", "--yes"]);
    cli.handle_router(&["resume", "all", "--yes"]);
    cli.handle_router(&["adjust", "all", "--duration", "300", "--yes"]);

    assert_zero_side_effects();
}

#[test]
fn test_06_rejected_commands_perform_zero_side_effects() {
    reset_all_side_effect_counters();
    let mut cli = RustrictCli::new_router_lab(make_test_iface());

    let disallowed = vec![
        "scan",
        "scan --fresh",
        "ports 1",
        "audit 1",
        "add 192.168.1.100",
        "scope add 10.0.0.0/8",
        "scope remove 192.168.1.0/24",
        "scope strict on",
        "free 1",
        "free all",
        "block 1",
        "block all",
        "limit 1 500kbit",
        "simulate 1 drop 20",
        "export json",
        "router pause 1",
        "router pause all --yes",
        "router resume 1",
        "router resume all --yes",
        "router adjust 1 --duration 60",
        "router refresh",
        "router connect mock",
        "invalid_random_cmd",
    ];

    for cmd in disallowed {
        assert!(
            cli.dispatch_command(cmd),
            "Command '{}' must be handled without crash",
            cmd
        );
    }

    assert_zero_side_effects();
}

#[test]
fn test_07_valid_read_only_commands_remain_available() {
    reset_all_side_effect_counters();
    let mut cli = RustrictCli::new_router_lab(make_test_iface());

    let allowed = vec![
        vec!["help"],
        vec!["?"],
        vec!["clear"],
        vec!["cls"],
        vec!["hosts"],
        vec!["router", "providers"],
        vec!["router", "capabilities"],
        vec!["router", "caps"],
        vec!["router", "status"],
        vec!["router", "diagnostics"],
        vec!["router", "diag"],
        vec!["router", "devices"],
        vec!["router", "clients"],
        vec!["router", "inventory"],
        vec!["router", "policies"],
        vec!["router", "history"],
        vec!["router", "records"],
        vec!["router", "preview", "all"],
        vec!["router", "disconnect"],
        vec!["nic", "list"],
        vec!["exit"],
        vec!["quit"],
    ];

    for cmd in allowed {
        assert!(
            cli.is_command_allowed_in_router_lab(&cmd).is_ok(),
            "Expected read-only command '{:?}' to be allowed in router-lab mode",
            cmd
        );
    }

    // Execute allowed read-only commands through dispatcher
    assert!(cli.dispatch_command("hosts"));
    assert!(cli.dispatch_command("router providers"));
    assert!(cli.dispatch_command("router status"));
    assert!(cli.dispatch_command("router capabilities"));
    assert!(cli.dispatch_command("router devices"));
    assert!(cli.dispatch_command("router preview all"));
    assert!(cli.dispatch_command("router disconnect"));

    assert_zero_side_effects();
}

#[test]
fn test_08_connecting_to_real_provider_establishes_session_safely() {
    reset_all_side_effect_counters();
    let mut cli = RustrictCli::new_router_lab(make_test_iface());

    let mock_executor = MockSshExecutor::default();
    let ssh_config = SshConfig::new(Ipv4Addr::new(192, 168, 1, 1))
        .with_port(22)
        .with_username("root")
        .with_connect_timeout(Duration::from_secs(5));

    let transport = SshOpenWrtTransport::with_executor(ssh_config, Arc::new(mock_executor));
    let provider = Arc::new(
        OpenWrtAdminProvider::new(Ipv4Addr::new(192, 168, 1, 1), "ssh://192.168.1.1:22")
            .with_transport(Box::new(transport)),
    );

    // Explicit connect through registry
    assert!(cli
        .router_registry()
        .connect("openwrt-ssh", provider, "ssh://192.168.1.1:22")
        .is_ok());

    let status = cli.router_registry().get_status();
    assert!(status.is_connected);
    assert_eq!(status.provider_id.as_deref(), Some("openwrt-ssh"));

    // Diagnostic queries
    assert!(cli.dispatch_command("router status"));
    assert!(cli.dispatch_command("router capabilities"));

    assert_zero_side_effects();
}

#[test]
fn test_09_mock_mode_cannot_be_misrepresented_as_physical_validation() {
    reset_all_side_effect_counters();
    let mut cli = RustrictCli::new_router_lab(make_test_iface());

    // In router-lab mode, router connect mock is strictly rejected
    assert!(cli
        .is_command_allowed_in_router_lab(&["router", "connect", "mock"])
        .is_err());
    assert!(cli.dispatch_command("router connect mock"));
    cli.handle_router(&["connect", "mock"]);
    assert!(
        !cli.router_registry().is_connected(),
        "Mock provider must not connect in router-lab mode"
    );

    // Outside router-lab mode, mock provider can be connected but is visibly marked as [SIMULATED]
    let normal_cli = RustrictCli::new_for_testing();
    let mock = Arc::new(MockRouterAdminProvider::new(Ipv4Addr::new(127, 0, 0, 1)));
    let _ = normal_cli
        .router_registry()
        .connect("mock", mock, "internal://mock");
    let status = normal_cli.router_registry().get_status();
    assert_eq!(status.provider_id.as_deref(), Some("mock"));
    // Provider ID is mock, preventing misrepresentation

    assert_zero_side_effects();
}

#[test]
fn test_10_router_disconnect_does_not_fall_back_to_arp_or_local_enforcement() {
    reset_all_side_effect_counters();
    let mut cli = RustrictCli::new_router_lab(make_test_iface());

    let mock_executor = MockSshExecutor::default();
    let ssh_config = SshConfig::new(Ipv4Addr::new(192, 168, 1, 1))
        .with_port(22)
        .with_username("root")
        .with_connect_timeout(Duration::from_secs(5));

    let transport = SshOpenWrtTransport::with_executor(ssh_config, Arc::new(mock_executor));
    let provider = Arc::new(
        OpenWrtAdminProvider::new(Ipv4Addr::new(192, 168, 1, 1), "ssh://192.168.1.1:22")
            .with_transport(Box::new(transport)),
    );

    assert!(cli
        .router_registry()
        .connect("openwrt-ssh", provider, "ssh://192.168.1.1:22")
        .is_ok());
    assert!(cli.router_registry().is_connected());

    // Disconnect
    assert!(cli.dispatch_command("router disconnect"));
    assert!(!cli.router_registry().is_connected());

    // Disconnect must NEVER activate local enforcement or ARP
    assert_zero_side_effects();
}

#[test]
fn test_11_evidence_export_and_offline_validation_do_not_mutate_router() {
    reset_all_side_effect_counters();
    let mut cli = RustrictCli::new_router_lab(make_test_iface());

    let temp_evidence =
        std::env::temp_dir().join(format!("test_evidence_{}.json", std::process::id()));
    let temp_str = temp_evidence.to_str().unwrap().replace('\\', "/");

    let cmd = format!("router export-evidence {} --overwrite", temp_str);
    assert!(cli.dispatch_command(&cmd));

    assert!(temp_evidence.exists(), "Evidence bundle file should exist");

    // Validate offline
    let val_cmd = format!("router validate-evidence {}", temp_str);
    assert!(cli.dispatch_command(&val_cmd));

    let _ = std::fs::remove_file(&temp_evidence);

    assert_zero_side_effects();
}

#[test]
fn test_12_provider_transport_failures_fail_safely() {
    reset_all_side_effect_counters();
    let cli = RustrictCli::new_router_lab(make_test_iface());

    let mock_executor = MockSshExecutor::default();
    mock_executor
        .simulate_auth_failure
        .store(true, std::sync::atomic::Ordering::SeqCst);

    let ssh_config = SshConfig::new(Ipv4Addr::new(192, 168, 1, 1))
        .with_port(22)
        .with_username("root")
        .with_connect_timeout(Duration::from_secs(5));

    let transport = SshOpenWrtTransport::with_executor(ssh_config, Arc::new(mock_executor));
    let provider = OpenWrtAdminProvider::new(Ipv4Addr::new(192, 168, 1, 1), "ssh://192.168.1.1:22")
        .with_transport(Box::new(transport));

    let login_res = provider.login();
    assert!(login_res.is_err(), "Authentication failure must return Err");

    // Failed provider must not connect or fall back to ARP
    assert!(!cli.router_registry().is_connected());
    assert_zero_side_effects();
}

#[test]
fn test_13_normal_cli_retains_intended_behavior() {
    reset_all_side_effect_counters();
    let cli = RustrictCli::new_for_testing();

    // In normal mode, commands are not rejected by is_command_allowed_in_router_lab
    assert!(cli.is_command_allowed_in_router_lab(&["scan"]).is_ok());
    assert!(cli
        .is_command_allowed_in_router_lab(&["block", "1"])
        .is_ok());
    assert!(cli
        .is_command_allowed_in_router_lab(&["limit", "1", "200kbit"])
        .is_ok());
    assert!(cli
        .is_command_allowed_in_router_lab(&["router", "pause", "all"])
        .is_ok());

    assert_zero_side_effects();
}

#[test]
fn test_14_exit_command_causes_clean_shutdown() {
    reset_all_side_effect_counters();
    let mut cli = RustrictCli::new_router_lab(make_test_iface());

    // dispatch_command returns false on quit/exit, breaking the REPL loop cleanly
    assert!(!cli.dispatch_command("exit"));
    assert!(!cli.dispatch_command("quit"));

    assert_zero_side_effects();
}

#[test]
fn test_15_router_lab_startup_in_unprivileged_process_never_initializes_drivers() {
    reset_all_side_effect_counters();
    let cli = RustrictCli::new_router_lab(make_test_iface());

    // Verify drivers are completely inactive
    assert!(
        !cli.spoofer().has_sender(),
        "Spoofer raw sender must be None in router-lab mode"
    );
    assert_eq!(
        cli.spoofer().target_count(),
        0,
        "Spoofer target count must be 0 in router-lab mode"
    );
    assert_zero_side_effects();
}

#[test]
fn test_16_strict_counter_verification_proves_zero_side_effects() {
    reset_all_side_effect_counters();
    let mut cli = RustrictCli::new_router_lab(make_test_iface());

    // Execute full sequence of allowable and blocked operations
    cli.dispatch_command("hosts");
    cli.dispatch_command("router providers");
    cli.dispatch_command("router status");
    cli.dispatch_command("router capabilities");
    cli.dispatch_command("router devices");
    cli.dispatch_command("router preview all");
    cli.dispatch_command("router disconnect");
    cli.dispatch_command("scan");
    cli.dispatch_command("block 1");
    cli.dispatch_command("limit 1 200kbit");
    cli.dispatch_command("simulate 1 drop 20");
    cli.dispatch_command("free 1");
    cli.dispatch_command("router pause all --yes");
    cli.dispatch_command("router resume all --yes");
    cli.dispatch_command("router adjust all --duration 300 --yes");
    cli.dispatch_command("router refresh");
    cli.dispatch_command("router connect mock");

    // All instrumented counters must remain strictly zero
    assert_eq!(raw_frame_send_count(), 0);
    assert_eq!(target_add_count(), 0);
    assert_eq!(limiter_activation_count(), 0);
    assert_eq!(forwarding_mutation_count(), 0);
}
