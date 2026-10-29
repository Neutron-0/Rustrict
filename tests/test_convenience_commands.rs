use rustrict::cli::RustrictCli;
use std::net::Ipv4Addr;

#[test]
fn test_scope_add_all_authorizes_all_private_networks() {
    let mut cli = RustrictCli::new_for_testing();

    // Execute `scope add all`
    cli.dispatch_command("scope add all");

    let scope = cli.scope();
    let cidrs = &scope.allowed_cidrs;

    // Verify all standard RFC 1918 + carrier subnets are present
    assert!(cidrs
        .iter()
        .any(|c| c.network == Ipv4Addr::new(10, 0, 0, 0) && c.prefix == 8));
    assert!(cidrs
        .iter()
        .any(|c| c.network == Ipv4Addr::new(172, 16, 0, 0) && c.prefix == 12));
    assert!(cidrs
        .iter()
        .any(|c| c.network == Ipv4Addr::new(192, 168, 0, 0) && c.prefix == 16));
    assert!(cidrs
        .iter()
        .any(|c| c.network == Ipv4Addr::new(100, 64, 0, 0) && c.prefix == 10));
    assert!(cidrs
        .iter()
        .any(|c| c.network == Ipv4Addr::new(169, 254, 0, 0) && c.prefix == 16));

    // Verify targets across different subnets are now in scope
    let target1 = Ipv4Addr::new(192, 168, 36, 84);
    let target2 = Ipv4Addr::new(192, 168, 39, 250);
    let target3 = Ipv4Addr::new(10, 76, 113, 26);
    assert!(cidrs.iter().any(|c| c.contains(&target1)));
    assert!(cidrs.iter().any(|c| c.contains(&target2)));
    assert!(cidrs.iter().any(|c| c.contains(&target3)));
}

#[test]
fn test_scope_all_alias() {
    let mut cli = RustrictCli::new_for_testing();
    cli.dispatch_command("scope all");

    let scope = cli.scope();
    assert!(scope
        .allowed_cidrs
        .iter()
        .any(|c| c.network == Ipv4Addr::new(192, 168, 0, 0)));
}

#[test]
fn test_scope_smart_cidr_parsing() {
    let mut cli = RustrictCli::new_for_testing();

    // Adding without explicit prefix should automatically deduce /24 for .0 subnets
    cli.dispatch_command("scope add 192.168.36.0");
    let scope = cli.scope();
    assert!(scope
        .allowed_cidrs
        .iter()
        .any(|c| c.network == Ipv4Addr::new(192, 168, 36, 0) && c.prefix == 24));

    // Adding a single host IP should automatically deduce /32
    cli.dispatch_command("scope add 192.168.39.250");
    let scope = cli.scope();
    assert!(scope
        .allowed_cidrs
        .iter()
        .any(|c| c.network == Ipv4Addr::new(192, 168, 39, 250) && c.prefix == 32));
}

#[test]
fn test_scope_strict_shortcuts_on_off() {
    let mut cli = RustrictCli::new_for_testing();

    cli.dispatch_command("scope off");
    assert!(!cli.scope().strict_mode);

    cli.dispatch_command("scope on");
    assert!(cli.scope().strict_mode);
}

#[test]
fn test_scope_reset_and_clear() {
    let mut cli = RustrictCli::new_for_testing();
    cli.dispatch_command("scope all");
    assert!(cli.scope().allowed_cidrs.len() >= 5);

    cli.dispatch_command("scope clear");
    assert_eq!(cli.scope().allowed_cidrs.len(), 0);

    let iface_ip = cli.iface().ip;
    cli.dispatch_command("scope reset");
    assert_eq!(cli.scope().allowed_cidrs.len(), 1);
    assert!(cli.scope().allowed_cidrs[0].contains(&iface_ip));
}

#[test]
fn test_status_command_safe_execution() {
    let cli = RustrictCli::new_for_testing();
    cli.handle_status();
}

#[test]
fn test_host_aliases_dispatch() {
    let mut cli = RustrictCli::new_for_testing();
    assert!(cli.dispatch_command("hosts"));
    assert!(cli.dispatch_command("devices"));
    assert!(cli.dispatch_command("targets"));
    assert!(cli.dispatch_command("list"));
    assert!(cli.dispatch_command("ls"));
}

#[test]
fn test_state_status_and_clear() {
    let mut cli = RustrictCli::new_for_testing();
    assert!(cli.dispatch_command("state status"));
    assert!(cli.dispatch_command("state clear"));
}

#[test]
fn test_upgrade_and_update_command_dispatch() {
    let mut cli = RustrictCli::new_for_testing();
    assert!(cli.dispatch_command("upgrade"));
    assert!(cli.dispatch_command("update"));
}

#[test]
fn test_blockmode_command_dispatch() {
    use rustrict::spoofer::SpooferMode;

    let mut cli = RustrictCli::new_for_testing();
    assert_eq!(cli.spoofer().mode(), SpooferMode::Mitm);

    assert!(cli.dispatch_command("blockmode"));
    assert!(cli.dispatch_command("blockmode blackhole"));
    assert_eq!(cli.spoofer().mode(), SpooferMode::Blackhole);

    assert!(cli.dispatch_command("spoofer mitm"));
    assert_eq!(cli.spoofer().mode(), SpooferMode::Mitm);

    assert!(cli.dispatch_command("blockmode invalid_mode"));
}

#[test]
fn test_offline_interface_properties() {
    let offline_iface = rustrict::platform::get_offline_interface();
    assert_eq!(offline_iface.name, "Offline-Decoupled");
    assert_eq!(offline_iface.ip, std::net::Ipv4Addr::new(127, 0, 0, 1));
    assert_eq!(offline_iface.device_path, "offline");

    let mut cli = RustrictCli::new_offline(offline_iface);
    assert!(cli.is_router_lab());
    assert!(cli.dispatch_command("status"));
    assert!(cli.dispatch_command("scope"));
    assert!(!cli.dispatch_command("exit"));
}
