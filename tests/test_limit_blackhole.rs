use rustrict::cli::RustrictCli;
use rustrict::spoofer::SpooferMode;

#[test]
fn test_limit_rejected_in_blackhole_mode() {
    let mut cli = RustrictCli::new_for_testing();
    // Default mode is MITM
    assert_eq!(cli.spoofer().mode(), SpooferMode::Mitm);

    // Switch to Blackhole mode
    cli.dispatch_command("mode blackhole");
    assert_eq!(cli.spoofer().mode(), SpooferMode::Blackhole);

    // In blackhole mode, limit command should be rejected
    assert!(cli.dispatch_command("limit 1 500kbit"));

    // Switch back to MITM mode
    cli.dispatch_command("mode mitm");
    assert_eq!(cli.spoofer().mode(), SpooferMode::Mitm);
}
