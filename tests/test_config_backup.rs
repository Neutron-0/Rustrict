use rustrict::gateway::admin::config_backup::ConfigBackupEngine;

#[test]
fn test_config_backup_diff_and_serialization() {
    let raw_v1 = "interface eth0\n  ip address 192.168.1.1/24\n  dhcp-server enable\n";
    let raw_v2 = "interface eth0\n  ip address 192.168.1.1/24\n  dhcp-server disable\n  firewall drop all\n";

    let snap1 = ConfigBackupEngine::create_snapshot(raw_v1, "OpenWrt");
    let snap2 = ConfigBackupEngine::create_snapshot(raw_v2, "OpenWrt");

    assert_eq!(snap1.provider_name, "OpenWrt");
    assert!(!snap1.sha256.is_empty());
    assert_ne!(snap1.sha256, snap2.sha256);

    // Compute diff
    let diff = ConfigBackupEngine::compute_diff(&snap1, &snap2);
    assert!(!diff.identical);
    assert_eq!(diff.removed_lines, vec!["  dhcp-server enable"]);
    assert_eq!(diff.added_lines, vec!["  dhcp-server disable", "  firewall drop all"]);

    // Test identical diff
    let diff_self = ConfigBackupEngine::compute_diff(&snap1, &snap1);
    assert!(diff_self.identical);
    assert!(diff_self.added_lines.is_empty());
    assert!(diff_self.removed_lines.is_empty());
}
