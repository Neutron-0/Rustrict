mod support;

use std::net::Ipv4Addr;
use std::sync::Arc;

use rustrict::cli::RustrictCli;
use rustrict::gateway::admin::{OpenWrtAdminProvider, RouterCredentials};
use rustrict::types::{Host, HostStatus, MacAddress};
use support::RouterEmulator;

fn setup_cli_with_emulator() -> (RustrictCli, RouterEmulator) {
    let emulator = RouterEmulator::start();
    let gw_ip = Ipv4Addr::new(127, 0, 0, 1);
    let ubus_url = format!("{}/ubus", emulator.endpoint());

    let provider = OpenWrtAdminProvider::new(gw_ip, &ubus_url);
    provider.set_credentials(RouterCredentials::new("root", "admin_password"));

    let mut cli = RustrictCli::new_for_testing();
    let _ = cli
        .router_registry()
        .connect("openwrt-http", Arc::new(provider), &ubus_url);

    // Register a test host in CLI inventory
    let target_ip = Ipv4Addr::new(192, 168, 1, 50);
    let target_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x50]);
    let mut host = Host::new(
        0,
        target_ip,
        target_mac,
        "Test Device".into(),
        "Test Vendor".into(),
    );
    host.online = true;
    host.status = HostStatus::Free;
    cli.add_host(host);

    (cli, emulator)
}

#[test]
fn test_cli_pause_confirmed_yes() {
    let (mut cli, emulator) = setup_cli_with_emulator();

    // Administrator answers 'yes' to the mutation prompt
    cli.add_simulated_input("yes");
    cli.handle_router(&["pause", "192.168.1.50"]);

    // Verify router mutation was confirmed and executed
    let state = emulator.state();
    assert_eq!(
        state.openwrt_rules.len(),
        1,
        "Policy must be enforced when confirmed with 'yes'"
    );
}

#[test]
fn test_cli_pause_cancelled_by_admin() {
    let (mut cli, emulator) = setup_cli_with_emulator();

    // Administrator answers 'N' (cancel)
    cli.add_simulated_input("N");
    cli.handle_router(&["pause", "192.168.1.50"]);

    // Hard safety assertion: Zero router mutations performed when cancelled
    let state = emulator.state();
    assert_eq!(
        state.openwrt_rules.len(),
        0,
        "Zero router mutations must be executed when cancelled"
    );
}

#[test]
fn test_cli_pause_cancelled_empty_input() {
    let (mut cli, emulator) = setup_cli_with_emulator();

    // Administrator presses Enter without typing 'yes' (defaults to No)
    cli.add_simulated_input("");
    cli.handle_router(&["pause", "192.168.1.50"]);

    let state = emulator.state();
    assert_eq!(
        state.openwrt_rules.len(),
        0,
        "Empty response must default to cancel"
    );
}

#[test]
fn test_cli_pause_auto_confirm_yes_flag() {
    let (mut cli, emulator) = setup_cli_with_emulator();

    // Use explicit non-interactive --yes flag (requires zero stdin input)
    cli.handle_router(&["pause", "192.168.1.50", "--yes"]);

    let state = emulator.state();
    assert_eq!(
        state.openwrt_rules.len(),
        1,
        "--yes flag must bypass interactive confirmation prompt"
    );
}

#[test]
fn test_cli_resume_confirmed_y() {
    let (mut cli, emulator) = setup_cli_with_emulator();

    // Apply policy first with --yes
    cli.handle_router(&["pause", "192.168.1.50", "--yes"]);
    assert_eq!(emulator.state().openwrt_rules.len(), 1);

    // Now resume with interactive confirmation 'y'
    cli.add_simulated_input("y");
    cli.handle_router(&["resume", "192.168.1.50"]);

    // Verify policy was revoked
    assert_eq!(
        emulator.state().openwrt_rules.len(),
        0,
        "Policy must be revoked when confirmed with 'y'"
    );
}

#[test]
fn test_cli_resume_cancelled_no() {
    let (mut cli, emulator) = setup_cli_with_emulator();

    // Apply policy first
    cli.handle_router(&["pause", "192.168.1.50", "--yes"]);
    assert_eq!(emulator.state().openwrt_rules.len(), 1);

    // Attempt resume but cancel with 'no'
    cli.add_simulated_input("no");
    cli.handle_router(&["resume", "192.168.1.50"]);

    // Hard safety assertion: rule remains active on router because revocation was cancelled
    assert_eq!(
        emulator.state().openwrt_rules.len(),
        1,
        "Rule must remain active when resumption is cancelled"
    );
}

#[test]
fn test_cli_adjust_confirmed_yes() {
    let (mut cli, emulator) = setup_cli_with_emulator();

    // Apply policy first
    cli.handle_router(&["pause", "192.168.1.50", "--yes"]);
    assert_eq!(emulator.state().openwrt_rules.len(), 1);

    // Adjust duration with confirmation 'yes'
    cli.add_simulated_input("yes");
    cli.handle_router(&["adjust", "192.168.1.50", "--duration", "3600"]);

    // Verify policy remains active with adjusted rule
    assert_eq!(emulator.state().openwrt_rules.len(), 1);
}

#[test]
fn test_cli_adjust_cancelled_no() {
    let (mut cli, emulator) = setup_cli_with_emulator();

    // Apply policy first
    cli.handle_router(&["pause", "192.168.1.50", "--yes"]);
    assert_eq!(emulator.state().openwrt_rules.len(), 1);

    // Attempt adjustment but cancel
    cli.add_simulated_input("n");
    cli.handle_router(&["adjust", "192.168.1.50", "--duration", "3600"]);

    // Rule remains intact without adjustment
    assert_eq!(emulator.state().openwrt_rules.len(), 1);
}

#[test]
fn test_cli_mock_mode_notice() {
    let mut cli = RustrictCli::new_for_testing();
    cli.handle_router(&["connect", "mock"]);
    let target_ip = Ipv4Addr::new(192, 168, 1, 99);
    let target_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x99]);
    let mut host = Host::new(
        0,
        target_ip,
        target_mac,
        "Mock Device".into(),
        "Mock Vendor".into(),
    );
    host.online = true;
    host.status = HostStatus::Free;
    cli.add_host(host);

    cli.add_simulated_input("yes");
    cli.handle_router(&["pause", "192.168.1.99"]);
    let pols = cli
        .policy_engine()
        .query_active_policies()
        .expect("Query active");
    assert!(
        !pols.is_empty(),
        "Mock mode successfully creates policy in mock store"
    );
}

#[test]
fn test_cli_validate_evidence_command() {
    let mut cli = RustrictCli::new_for_testing();
    cli.handle_router(&["connect", "mock"]);

    let temp_file = std::env::temp_dir().join(format!("cli_val_{}.json", std::process::id()));
    cli.policy_engine()
        .export_evidence_bundle(&temp_file, false)
        .expect("Export bundle");

    // Command should parse, validate, and report with 0 network calls
    cli.handle_router(&["validate-evidence", temp_file.to_str().unwrap()]);
    cli.handle_router(&["validate", temp_file.to_str().unwrap()]);

    let _ = std::fs::remove_file(temp_file);
}
