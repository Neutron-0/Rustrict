use rustrict::cli::RustrictCli;

#[test]
fn test_cli_resilience_and_tunnel_dispatch() {
    let mut cli = RustrictCli::new_for_testing();

    // 1. Resilience commands
    assert!(cli.dispatch_command("resilience status"));
    assert!(cli.dispatch_command("resilience on"));
    assert!(cli.dispatch_command("resilience off"));

    // 2. Tunnel commands
    assert!(cli.dispatch_command("tunnel status"));
    assert!(cli.dispatch_command("tunnel up 192.168.1.1:51820"));
    assert!(cli.dispatch_command("tunnel down"));

    // 3. Router Infrastructure commands
    assert!(cli.dispatch_command("router dhcp"));
    assert!(cli.dispatch_command("router nat"));
    assert!(cli.dispatch_command("router backup"));
    assert!(cli.dispatch_command("router diff"));
}
