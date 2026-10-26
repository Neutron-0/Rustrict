use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use rustrict::gateway::admin::{
    escape_posix_single_quotes, find_ssh_client, validate_ip_str, validate_mac_str,
    validate_policy_id, validate_shell_arg, AdminError, MockSshExecutor, OpenWrtAdminProvider,
    OperationPlanRequest, PolicyDuration, PolicyPersistence, PolicyScope, ProcessSshExecutor,
    RouterAdminProvider, SshCommandExecutor, SshConfig, SshOpenWrtTransport,
};

fn create_mock_ssh_openwrt() -> (OpenWrtAdminProvider, MockSshExecutor) {
    let mock_executor = MockSshExecutor::default();
    let gw_ip = Ipv4Addr::new(192, 168, 1, 1);
    let ssh_config = SshConfig::new(gw_ip)
        .with_port(22)
        .with_username("root")
        .with_connect_timeout(Duration::from_secs(5));

    let transport = SshOpenWrtTransport::with_executor(ssh_config, Arc::new(mock_executor.clone()));
    let provider = OpenWrtAdminProvider::new(gw_ip, "ssh://192.168.1.1:22")
        .with_transport(Box::new(transport));

    (provider, mock_executor)
}

#[test]
fn test_ssh_client_discovery() {
    let result = find_ssh_client();
    // On Windows with OpenSSH installed, this will succeed.
    // If not installed on non-standard environment, it returns the expected error message.
    match result {
        Ok(path) => {
            assert!(path.exists(), "Discovered SSH client binary must exist");
            #[cfg(windows)]
            assert!(
                path.to_string_lossy().to_lowercase().ends_with("ssh.exe"),
                "Executable must be ssh.exe"
            );
        }
        Err(e) => {
            assert!(
                e.to_string().contains("OpenSSH client not found"),
                "Expected OpenSSH missing client message, got: {:?}",
                e
            );
        }
    }

    // Explicitly test missing client error formatting
    let missing_executor = ProcessSshExecutor::with_custom_client(PathBuf::from(
        "C:\\fake_path\\non_existent_ssh.exe",
    ));
    let config = SshConfig::new(Ipv4Addr::new(192, 168, 1, 1));
    let err = missing_executor
        .execute(&config, "id -u")
        .expect_err("Execution with missing client must fail");
    assert!(
        matches!(err, AdminError::CommunicationError(_)),
        "Expected CommunicationError for missing binary, got: {:?}",
        err
    );
    assert!(err
        .to_string()
        .contains("Configured SSH executable not found"));
}

#[test]
fn test_ssh_host_key_strict_checking_and_mismatch_rejection() {
    let (provider, executor) = create_mock_ssh_openwrt();

    // Simulate host key mismatch or untrusted host
    executor
        .simulate_host_key_mismatch
        .store(true, Ordering::SeqCst);

    let err = provider
        .login()
        .expect_err("Host key mismatch must strictly abort connection");
    assert!(
        matches!(err, AdminError::AuthenticationFailed(_)),
        "Expected AuthenticationFailed, got: {:?}",
        err
    );
    assert!(err
        .to_string()
        .contains("Host key mismatch or untrusted host"));
    assert!(!provider.is_authenticated());
}

#[test]
fn test_ssh_public_key_authentication_failure() {
    let (provider, executor) = create_mock_ssh_openwrt();

    // Simulate key rejection (Permission denied)
    executor.simulate_auth_failure.store(true, Ordering::SeqCst);

    let err = provider
        .login()
        .expect_err("Rejected public key must fail authentication");
    assert!(
        matches!(err, AdminError::AuthenticationFailed(_)),
        "Expected AuthenticationFailed, got: {:?}",
        err
    );
    assert!(err.to_string().contains("Permission denied"));
    assert!(!provider.is_authenticated());
}

#[test]
fn test_ssh_non_root_user_privilege_rejection() {
    let (provider, executor) = create_mock_ssh_openwrt();

    // Simulate non-root user (e.g. UID 1000)
    executor.simulate_non_root.store(true, Ordering::SeqCst);

    let err = provider
        .login()
        .expect_err("Non-root SSH user must be rejected for router firewall administration");
    assert!(
        matches!(err, AdminError::AuthenticationFailed(_)),
        "Expected AuthenticationFailed, got: {:?}",
        err
    );
    assert!(err.to_string().contains("requires root privileges"));
    assert!(!provider.is_authenticated());
}

#[test]
fn test_ssh_router_identity_verification_and_mismatch() {
    let (provider, _executor) = create_mock_ssh_openwrt();
    provider.login().unwrap();

    let id = provider
        .detect_identity()
        .expect("Identity check should succeed for OpenWrt");
    assert_eq!(id.manufacturer.as_deref(), Some("OpenWrt Community"));
    assert_eq!(
        id.model_name.as_deref(),
        Some("Ubiquiti UniFi / OpenWrt One")
    );
    assert_eq!(id.firmware_version.as_deref(), Some("23.05.2"));

    // Simulate target running non-OpenWrt firmware
    let (provider2, exec2) = create_mock_ssh_openwrt();
    exec2.simulate_non_openwrt.store(true, Ordering::SeqCst);
    provider2.login().unwrap();
    let err = provider2
        .detect_identity()
        .expect_err("Non-OpenWrt firmware must be rejected");
    assert!(
        matches!(err, AdminError::IdentityMismatch(_)),
        "Expected IdentityMismatch, got: {:?}",
        err
    );
}

#[test]
fn test_ssh_command_argument_validation_and_injection_resistance() {
    // Shell argument metacharacter rejection
    assert!(validate_shell_arg("192.168.1.1").is_ok());
    assert!(validate_shell_arg("cfg_rustrict_rule").is_ok());

    assert!(validate_shell_arg("192.168.1.1; rm -rf /").is_err());
    assert!(validate_shell_arg("192.168.1.1 && whoami").is_err());
    assert!(validate_shell_arg("192.168.1.1 | cat /etc/passwd").is_err());
    assert!(validate_shell_arg("$(whoami)").is_err());
    assert!(validate_shell_arg("`whoami`").is_err());
    assert!(validate_shell_arg("param\nmalicious").is_err());
    assert!(validate_shell_arg("param\0null").is_err());

    // Strict IP parsing
    assert!(validate_ip_str("192.168.1.50").is_ok());
    assert!(validate_ip_str("192.168.1.50; reboot").is_err());
    assert!(validate_ip_str("192.168.1.500").is_err());

    // Strict MAC parsing
    assert!(validate_mac_str("00:11:22:33:44:55").is_ok());
    assert!(validate_mac_str("00:11:22:33:44:55$(id)").is_err());

    // Strict Policy ID
    assert!(validate_policy_id("rustrict_pause_192_168_1_50").is_ok());
    assert!(validate_policy_id("rule-123").is_ok());
    assert!(validate_policy_id("rule; cat /etc/shadow").is_err());
    assert!(validate_policy_id("").is_err());

    // POSIX single quote escaping
    assert_eq!(escape_posix_single_quotes("normal"), "normal");
    assert_eq!(escape_posix_single_quotes("it's cool"), "it'\\''s cool");
    assert_eq!(escape_posix_single_quotes("'test'"), "'\\''test'\\''");
}

#[test]
fn test_ssh_remote_command_timeout_and_exit_code() {
    let (provider, executor) = create_mock_ssh_openwrt();

    // Timeout
    executor.simulate_timeout.store(true, Ordering::SeqCst);
    let err = provider.login().expect_err("Timeout should fail login");
    assert!(
        matches!(err, AdminError::Timeout(_)),
        "Expected Timeout, got: {:?}",
        err
    );

    // Command failure
    let (provider2, exec2) = create_mock_ssh_openwrt();
    exec2.simulate_command_error.store(true, Ordering::SeqCst);
    provider2.login().unwrap();
    let session = "ssh_authenticated_root_session";
    let watchdog_err = provider2
        .ensure_router_watchdog(session)
        .expect_err("Write error must fail watchdog installation");
    assert!(
        matches!(watchdog_err, AdminError::UnsupportedOperation(_)),
        "Expected UnsupportedOperation on write failure, got: {:?}",
        watchdog_err
    );
}

#[test]
fn test_ssh_watchdog_dedicated_location_and_markers() {
    let (provider, executor) = create_mock_ssh_openwrt();
    provider.login().unwrap();

    let target_ip = Ipv4Addr::new(192, 168, 1, 75);
    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![target_ip]),
        PolicyDuration::Temporary(Duration::from_secs(300)),
        PolicyPersistence::RouterPersistent,
    );

    let active = provider
        .apply_policy(&req)
        .expect("Temporary policy creation should succeed");
    assert!(active.autonomous_recovery);

    // Verify script at /etc/rustrict/watchdog.sh
    let script = executor.watchdog_script_content.read().clone().unwrap();
    assert!(script.contains("Rustrict"));

    // Verify crontab entry with identifiable markers
    let crontab = executor.crontab_content.read().clone();
    assert!(crontab.contains("# BEGIN RUSTRICT WATCHDOG"));
    assert!(crontab.contains("/etc/rustrict/watchdog.sh"));
    assert!(crontab.contains("# END RUSTRICT WATCHDOG"));
}

#[test]
fn test_ssh_watchdog_update_and_removal_preserves_unrelated_jobs() {
    let (provider, executor) = create_mock_ssh_openwrt();
    provider.login().unwrap();

    // Injected user cron jobs
    *executor.crontab_content.write() =
        "0 4 * * * /sbin/reboot\n15 2 * * * /usr/bin/backup.sh\n".to_string();

    let session = "ssh_authenticated_root_session";
    provider
        .ensure_router_watchdog(session)
        .expect("Watchdog install should succeed");

    // Verify watchdog added without deleting user jobs
    {
        let crontab = executor.crontab_content.read().clone();
        assert!(crontab.contains("0 4 * * * /sbin/reboot"));
        assert!(crontab.contains("15 2 * * * /usr/bin/backup.sh"));
        assert!(crontab.contains("# BEGIN RUSTRICT WATCHDOG"));
    }

    // Re-run ensure_router_watchdog (idempotent update)
    provider
        .ensure_router_watchdog(session)
        .expect("Watchdog update should be idempotent");

    {
        let crontab = executor.crontab_content.read().clone();
        // Ensure not duplicated
        let begin_count = crontab.matches("# BEGIN RUSTRICT WATCHDOG").count();
        assert_eq!(begin_count, 1, "Watchdog marker must not be duplicated");
        assert!(crontab.contains("0 4 * * * /sbin/reboot"));
        assert!(crontab.contains("15 2 * * * /usr/bin/backup.sh"));
    }

    // Uninstall watchdog
    provider
        .uninstall_router_watchdog(session)
        .expect("Watchdog uninstall should succeed");

    {
        let crontab = executor.crontab_content.read().clone();
        assert!(!crontab.contains("# BEGIN RUSTRICT WATCHDOG"));
        assert!(!crontab.contains("watchdog.sh"));
        assert!(
            crontab.contains("0 4 * * * /sbin/reboot"),
            "User reboot job must be preserved"
        );
        assert!(
            crontab.contains("15 2 * * * /usr/bin/backup.sh"),
            "User backup job must be preserved"
        );
    }
}

#[test]
fn test_ssh_watchdog_failed_installation_fails_closed() {
    let (provider, executor) = create_mock_ssh_openwrt();
    provider.login().unwrap();

    // Simulate read-only filesystem or permission error when writing script
    executor
        .simulate_command_error
        .store(true, Ordering::SeqCst);

    let target_ip = Ipv4Addr::new(192, 168, 1, 82);
    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![target_ip]),
        PolicyDuration::Temporary(Duration::from_secs(300)),
        PolicyPersistence::RouterPersistent,
    );

    let err = provider
        .apply_policy(&req)
        .expect_err("Timed policy must fail closed if watchdog cannot be installed");
    assert!(
        matches!(err, AdminError::UnsupportedOperation(_)),
        "Expected UnsupportedOperation, got: {:?}",
        err
    );

    // Verify zero firewall rules were committed
    let rules = executor.firewall_rules.read();
    assert!(rules.is_empty(), "Fail-closed guarantee: zero rules added");
}

#[test]
fn test_ssh_router_reboot_autonomous_recovery() {
    let (provider, executor) = create_mock_ssh_openwrt();
    provider.login().unwrap();

    let target_ip = Ipv4Addr::new(192, 168, 1, 88);
    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![target_ip]),
        PolicyDuration::Temporary(Duration::from_secs(10)),
        PolicyPersistence::RouterPersistent,
    );

    let active = provider.apply_policy(&req).unwrap();
    let exp_unix = active.expires_at_unix.unwrap();

    // Active rule exists
    assert!(!executor.firewall_rules.read().is_empty());

    // Router reboots AFTER expiration timestamp has elapsed
    executor.simulate_reboot_cycle(exp_unix + 30);

    // Expired rule was purged by router-resident watchdog
    assert!(
        executor.firewall_rules.read().is_empty(),
        "Router watchdog must purge expired rule after reboot"
    );
}

#[test]
fn test_ssh_apply_resume_and_preservation_of_unrelated_rules() {
    let (provider, executor) = create_mock_ssh_openwrt();
    provider.login().unwrap();

    // Custom user firewall rule
    executor.firewall_rules.write().insert(
        "cfg_allow_custom_ssh".to_string(),
        serde_json::json!({
            "name": "Allow-Custom-SSH",
            "src": "wan",
            "proto": "tcp",
            "dest_port": "2222",
            "target": "ACCEPT"
        }),
    );

    // Apply multiple Rustrict pause policies
    let req1 = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![Ipv4Addr::new(192, 168, 1, 101)]),
        PolicyDuration::Indefinite,
        PolicyPersistence::RouterPersistent,
    );
    provider.apply_policy(&req1).unwrap();

    let req2 = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![Ipv4Addr::new(192, 168, 1, 102)]),
        PolicyDuration::Indefinite,
        PolicyPersistence::RouterPersistent,
    );
    provider.apply_policy(&req2).unwrap();

    assert_eq!(executor.firewall_rules.read().len(), 3);

    // Resume all Rustrict policies
    let resumed = provider.resume_all().expect("Resume all should succeed");
    assert_eq!(resumed.len(), 2);

    // Verify user rule was preserved intact
    let remaining = executor.firewall_rules.read();
    assert_eq!(remaining.len(), 1);
    assert!(remaining.contains_key("cfg_allow_custom_ssh"));
}

#[test]
fn test_ssh_transaction_rollback_on_commit_error() {
    let (provider, executor) = create_mock_ssh_openwrt();
    provider.login().unwrap();

    // Force commit error to simulate NVRAM / disk failure
    executor
        .simulate_command_error
        .store(true, Ordering::SeqCst);

    let target_ip = Ipv4Addr::new(192, 168, 1, 115);
    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![target_ip]),
        PolicyDuration::Indefinite,
        PolicyPersistence::VolatileSession,
    );

    let err = provider
        .apply_policy(&req)
        .expect_err("Commit failure must fail transaction");
    assert!(
        matches!(err, AdminError::TransactionFailed(_)),
        "Expected TransactionFailed, got: {:?}",
        err
    );

    // Rollback ensures zero residual rules
    let rules = executor.firewall_rules.read();
    assert!(rules.is_empty(), "Rollback must leave zero residual rules");
}

#[test]
fn test_ssh_adjust_policy_duration_lifecycle() {
    let (provider, _executor) = create_mock_ssh_openwrt();
    provider.login().unwrap();

    let target_ip = Ipv4Addr::new(192, 168, 1, 120);
    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![target_ip]),
        PolicyDuration::Temporary(Duration::from_secs(300)),
        PolicyPersistence::RouterPersistent,
    );

    let active = provider.apply_policy(&req).unwrap();
    let initial_exp = active.expires_at_unix.unwrap();

    // Extend to 1800s
    let scope = PolicyScope::SpecificTargets(vec![target_ip]);
    let extended = provider
        .adjust_policy_duration(
            &scope,
            &PolicyDuration::Temporary(Duration::from_secs(1800)),
        )
        .expect("Duration extension should succeed");

    assert!(extended.expires_at_unix.unwrap() > initial_exp);

    // Adjust to Indefinite
    let indefinite = provider
        .adjust_policy_duration(&scope, &PolicyDuration::Indefinite)
        .expect("Indefinite adjustment should succeed");
    assert!(indefinite.expires_at_unix.is_none());
}

#[test]
fn test_ssh_lockout_prevention() {
    let (provider, _executor) = create_mock_ssh_openwrt();
    provider.login().unwrap();

    // Target is router management IP
    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![Ipv4Addr::new(192, 168, 1, 1)]),
        PolicyDuration::Indefinite,
        PolicyPersistence::VolatileSession,
    );

    let err = provider
        .plan_operation(&req)
        .expect_err("Router IP target must trigger lockout prevention");
    assert!(
        matches!(err, AdminError::LockoutPrevented(_)),
        "Expected LockoutPrevented, got: {:?}",
        err
    );
}

#[test]
fn test_ssh_transport_capabilities_distinction() {
    let (provider, _executor) = create_mock_ssh_openwrt();

    // Before authentication
    assert_eq!(provider.name(), "OpenWrt-SSH");
    assert!(!provider.is_authenticated());

    let caps_unauthed = provider.inspect_capabilities();
    let auth_cap = format!("{:?}", caps_unauthed.authenticated_admin_interfaces);
    assert!(auth_cap.contains("Requires SSH public-key authentication with root privileges"));

    // After authentication
    provider.login().unwrap();
    assert!(provider.is_authenticated());

    let caps_authed = provider.inspect_capabilities();
    let auth_cap_authed = format!("{:?}", caps_authed.authenticated_admin_interfaces);
    assert!(auth_cap_authed.contains("Implemented"));
}

#[test]
fn test_ssh_oversized_output_with_continued_pipe_draining() {
    let (provider, executor) = create_mock_ssh_openwrt();
    provider.login().unwrap();

    // Simulate oversized remote command output that triggers truncation
    executor
        .simulate_oversized_output
        .store(true, Ordering::SeqCst);

    let err = provider
        .reconcile_policies()
        .expect_err("Oversized output must be rejected as an unparseable truncated response");

    match err {
        AdminError::CommunicationError(msg) => {
            assert!(
                msg.contains("exceeded maximum buffer limit") || msg.contains("truncated"),
                "Error message should mention buffer limit/truncation: {}",
                msg
            );
        }
        other => panic!("Expected CommunicationError, got: {:?}", other),
    }
}
