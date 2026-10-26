use serde_json::json;
use std::net::Ipv4Addr;
use std::sync::atomic::Ordering;
use std::time::Duration;

use rustrict::gateway::admin::{
    AdminError, CapabilityClassification, MikroTikAdminProvider, MockMikroTikTransport,
    OperationPlanRequest, PolicyDuration, PolicyPersistence, PolicyScope, RouterAdminProvider,
    RouterCredentials,
};
use rustrict::types::MacAddress;

fn create_mock_mikrotik() -> (MikroTikAdminProvider, MockMikroTikTransport) {
    let mock_transport = MockMikroTikTransport::default();
    let gw_ip = Ipv4Addr::new(192, 168, 1, 1);
    let provider = MikroTikAdminProvider::new(gw_ip, "https://192.168.1.1:443/rest")
        .with_transport(Box::new(mock_transport.clone()));
    provider.set_credentials(RouterCredentials::new("admin", "admin_password"));
    (provider, mock_transport)
}

#[test]
fn test_mikrotik_auth_success() {
    let (provider, _transport) = create_mock_mikrotik();

    assert!(provider.is_authenticated());
    let login_res = provider.login();
    assert!(
        login_res.is_ok(),
        "Login should succeed with valid credentials"
    );
    assert!(provider.is_authenticated());
}

#[test]
fn test_mikrotik_auth_failure() {
    let mock_transport = MockMikroTikTransport::default();
    let gw_ip = Ipv4Addr::new(192, 168, 1, 1);
    let provider = MikroTikAdminProvider::new(gw_ip, "https://192.168.1.1:443/rest")
        .with_transport(Box::new(mock_transport.clone()));

    // Invalid password
    provider.set_credentials(RouterCredentials::new("admin", "wrong_password"));
    let err = provider
        .login()
        .expect_err("Login should fail with wrong password");
    assert!(
        matches!(err, AdminError::AuthenticationFailed(_)),
        "Expected AuthenticationFailed, got: {:?}",
        err
    );

    // Simulated 401 Unauthorized
    mock_transport
        .simulate_auth_fail
        .store(true, Ordering::SeqCst);
    provider.set_credentials(RouterCredentials::new("admin", "admin_password"));
    let err2 = provider
        .login()
        .expect_err("Should fail when simulated 401 is active");
    assert!(matches!(err2, AdminError::AuthenticationFailed(_)));
}

#[test]
fn test_mikrotik_tls_cert_error_rejection() {
    let (provider, transport) = create_mock_mikrotik();

    // Router presents an invalid / self-signed certificate without user pinning
    transport
        .simulate_tls_cert_error
        .store(true, Ordering::SeqCst);

    let err = provider
        .login()
        .expect_err("Connection must fail if TLS cert is untrusted");
    assert!(
        matches!(err, AdminError::CommunicationError(_)),
        "Expected CommunicationError due to TLS rejection, got: {:?}",
        err
    );
    let err_msg = format!("{}", err);
    assert!(
        err_msg.contains("TLS certificate validation failed"),
        "Error message must specify TLS validation failure: {}",
        err_msg
    );
}

#[test]
fn test_mikrotik_identity_verification_and_mismatch() {
    let (provider, transport) = create_mock_mikrotik();

    let identity = provider
        .detect_identity()
        .expect("Identity probe should succeed");
    assert_eq!(identity.ip, Ipv4Addr::new(192, 168, 1, 1));
    assert_eq!(identity.manufacturer.as_deref(), Some("MikroTik"));
    assert_eq!(identity.model_name.as_deref(), Some("RB5009UG+S+IN"));
    assert_eq!(
        identity.firmware_version.as_deref(),
        Some("7.14.3 (stable)")
    );

    // Mismatched non-MikroTik platform (e.g. GenericRTOS)
    transport
        .simulate_non_mikrotik
        .store(true, Ordering::SeqCst);
    let mismatch_provider = MikroTikAdminProvider::new(
        Ipv4Addr::new(192, 168, 1, 1),
        "https://192.168.1.1:443/rest",
    )
    .with_transport(Box::new(transport));
    mismatch_provider.set_credentials(RouterCredentials::new("admin", "admin_password"));

    let err = mismatch_provider
        .detect_identity()
        .expect_err("Should reject non-MikroTik platform");
    assert!(
        matches!(err, AdminError::IdentityMismatch(_)),
        "Expected IdentityMismatch error, got: {:?}",
        err
    );
}

#[test]
fn test_mikrotik_capability_discovery() {
    let mock_transport = MockMikroTikTransport::default();
    let gw_ip = Ipv4Addr::new(192, 168, 1, 1);
    let unauthed_provider = MikroTikAdminProvider::new(gw_ip, "https://192.168.1.1:443/rest")
        .with_transport(Box::new(mock_transport));

    let unauthed_caps = unauthed_provider.inspect_capabilities();
    assert!(matches!(
        unauthed_caps.network_wide_access_policy,
        CapabilityClassification::Unknown(_)
    ));

    let (provider, _transport) = create_mock_mikrotik();
    let caps = provider.inspect_capabilities();

    assert_eq!(
        caps.per_device_access_policy,
        CapabilityClassification::Implemented
    );
    assert_eq!(
        caps.network_wide_access_policy,
        CapabilityClassification::Implemented
    );
    assert_eq!(
        caps.timed_policy_auto_recovery,
        CapabilityClassification::Implemented
    );
    assert_eq!(
        caps.persistence_after_app_exit,
        CapabilityClassification::Implemented
    );
    assert_eq!(
        caps.persistence_after_host_shutdown,
        CapabilityClassification::Implemented
    );
}

#[test]
fn test_mikrotik_ipv4_and_ipv6_policy_planning() {
    let (provider, _transport) = create_mock_mikrotik();

    let target_ip = Ipv4Addr::new(192, 168, 1, 100);
    let mac: MacAddress = "00:11:22:33:44:55".parse().unwrap();

    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![target_ip]),
        PolicyDuration::Temporary(Duration::from_secs(600)),
        PolicyPersistence::RouterPersistent,
    )
    .with_macs(vec![mac]);

    let plan = provider
        .plan_operation(&req)
        .expect("Planning should succeed");

    assert_eq!(plan.target_scope, req.scope);
    assert_eq!(plan.target_count, 1);
    assert!(plan.management_plane_safe);
    assert!(plan.auth_established);
    assert!(plan
        .expected_lan_impact
        .contains("Router input chain untouched"));
    assert!(plan
        .expected_wan_impact
        .contains("ICMP network-unreachable"));
    assert!(plan.recovery_mechanism.contains("Autonomous RouterOS"));
}

#[test]
fn test_mikrotik_wired_and_wireless_forward_chain_isolation() {
    let (provider, transport) = create_mock_mikrotik();

    let target_ip = Ipv4Addr::new(192, 168, 1, 45);
    let target_mac: MacAddress = "00:AA:BB:CC:DD:EE".parse().unwrap();

    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![target_ip]),
        PolicyDuration::Indefinite,
        PolicyPersistence::RouterPersistent,
    )
    .with_macs(vec![target_mac]);

    let active = provider
        .apply_policy(&req)
        .expect("Policy application should succeed");
    assert_eq!(active.scope, req.scope);

    // Verify created rule in mock state
    let rules = transport.firewall_rules.read();
    assert_eq!(
        rules.len(),
        1,
        "Exactly one firewall rule should be present"
    );
    let rule = &rules[0];

    // Chain must be forward (L3 transit), never input (management)
    assert_eq!(rule.get("chain").and_then(|v| v.as_str()), Some("forward"));
    assert_eq!(rule.get("action").and_then(|v| v.as_str()), Some("reject"));
    assert_eq!(
        rule.get("reject-with").and_then(|v| v.as_str()),
        Some("icmp-network-unreachable")
    );
    assert_eq!(
        rule.get("src-address").and_then(|v| v.as_str()),
        Some("192.168.1.45")
    );
    assert_eq!(
        rule.get("src-mac-address").and_then(|v| v.as_str()),
        Some("00:aa:bb:cc:dd:ee")
    );

    let comment = rule.get("comment").and_then(|v| v.as_str()).unwrap_or("");
    assert!(comment.contains("rustrict:pol="));
}

#[test]
fn test_mikrotik_unsupported_resource_handling() {
    let (provider, transport) = create_mock_mikrotik();

    // Simulate 404 on optional resource
    transport
        .simulate_unsupported_resource
        .store(true, Ordering::SeqCst);

    // Capability inspection handles unsupported resource without failing or panicking
    let caps = provider.inspect_capabilities();
    assert_eq!(
        caps.per_device_access_policy,
        CapabilityClassification::Implemented
    );
}

#[test]
fn test_mikrotik_lockout_prevention() {
    let (provider, _transport) = create_mock_mikrotik();

    let router_ip = Ipv4Addr::new(192, 168, 1, 1);
    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![router_ip]),
        PolicyDuration::Indefinite,
        PolicyPersistence::RouterPersistent,
    );

    // Dry-run plan must reject targeting router IP
    let plan_err = provider
        .plan_operation(&req)
        .expect_err("Should prevent lockout during planning");
    assert!(
        matches!(plan_err, AdminError::LockoutPrevented(_)),
        "Expected LockoutPrevented, got: {:?}",
        plan_err
    );

    // Execution must reject targeting router IP
    let apply_err = provider
        .apply_policy(&req)
        .expect_err("Should prevent lockout during application");
    assert!(
        matches!(apply_err, AdminError::LockoutPrevented(_)),
        "Expected LockoutPrevented, got: {:?}",
        apply_err
    );
}

#[test]
fn test_mikrotik_apply_and_resume_device_policy() {
    let (provider, transport) = create_mock_mikrotik();

    let target_ip = Ipv4Addr::new(192, 168, 1, 77);
    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![target_ip]),
        PolicyDuration::Temporary(Duration::from_secs(300)),
        PolicyPersistence::RouterPersistent,
    );

    provider.apply_policy(&req).expect("Apply should succeed");

    // Watchdog script and scheduler must be installed for temporary policies
    assert!(
        provider
            .is_watchdog_installed()
            .expect("Watchdog status check should succeed"),
        "Watchdog should be installed"
    );

    let policies = provider
        .reconcile_policies()
        .expect("Reconcile should succeed");
    assert_eq!(policies.len(), 1);
    assert_eq!(policies[0].scope, req.scope);

    // Resume the policy
    let resumed = provider
        .resume_policy(&req.scope)
        .expect("Resume should succeed");
    assert_eq!(resumed.len(), 1);

    // Verify firewall rules are now empty
    let rules = transport.firewall_rules.read();
    assert!(rules.is_empty(), "All rustrict rules should be removed");
}

#[test]
fn test_mikrotik_adjust_policy_duration_lifecycle() {
    let (provider, transport) = create_mock_mikrotik();

    let target_ip = Ipv4Addr::new(192, 168, 1, 88);
    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![target_ip]),
        PolicyDuration::Temporary(Duration::from_secs(300)),
        PolicyPersistence::RouterPersistent,
    );

    provider.apply_policy(&req).expect("Apply should succeed");

    // Adjust duration to 900s
    let new_dur = PolicyDuration::Temporary(Duration::from_secs(900));
    let updated = provider
        .adjust_policy_duration(&req.scope, &new_dur)
        .expect("Adjust duration should succeed");
    assert!(updated.expires_at_unix.is_some());

    // Check updated comment in firewall rule
    {
        let rules = transport.firewall_rules.read();
        assert_eq!(rules.len(), 1);
        let comment = rules[0]
            .get("comment")
            .and_then(|c| c.as_str())
            .unwrap_or("");
        assert!(comment.contains("rustrict:pol="));
    }

    // Adjust duration to Indefinite
    let indefinite_dur = PolicyDuration::Indefinite;
    let updated_indefinite = provider
        .adjust_policy_duration(&req.scope, &indefinite_dur)
        .expect("Adjust duration to indefinite should succeed");
    assert!(updated_indefinite.expires_at_unix.is_none());
}

#[test]
fn test_mikrotik_autonomous_watchdog_installation_and_idempotency() {
    let (provider, transport) = create_mock_mikrotik();

    assert!(!provider.is_watchdog_installed().unwrap());

    provider
        .ensure_router_watchdog()
        .expect("First installation should succeed");
    assert!(provider.is_watchdog_installed().unwrap());

    // Verify script and scheduler exist in mock state
    {
        let scripts = transport.scripts.read();
        assert!(scripts
            .iter()
            .any(|s| s.get("name").and_then(|n| n.as_str()) == Some("rustrict_watchdog")));
        let schedulers = transport.schedulers.read();
        assert!(schedulers
            .iter()
            .any(|s| s.get("name").and_then(|n| n.as_str()) == Some("rustrict_watchdog_sched")));
    }

    // Call again to verify idempotency (no duplicate entries)
    provider
        .ensure_router_watchdog()
        .expect("Second installation should be idempotent");
    {
        let scripts = transport.scripts.read();
        let watchdog_scripts: Vec<_> = scripts
            .iter()
            .filter(|s| s.get("name").and_then(|n| n.as_str()) == Some("rustrict_watchdog"))
            .collect();
        assert_eq!(watchdog_scripts.len(), 1, "Script should not be duplicated");

        let schedulers = transport.schedulers.read();
        let watchdog_scheds: Vec<_> = schedulers
            .iter()
            .filter(|s| s.get("name").and_then(|n| n.as_str()) == Some("rustrict_watchdog_sched"))
            .collect();
        assert_eq!(
            watchdog_scheds.len(),
            1,
            "Scheduler should not be duplicated"
        );
    }
}

#[test]
fn test_mikrotik_rejection_when_autonomous_recovery_unsupported() {
    let (provider, transport) = create_mock_mikrotik();

    // RouterOS user account lacks script/scheduler write permissions (HTTP 403)
    transport
        .autonomous_recovery_supported
        .store(false, Ordering::SeqCst);

    let target_ip = Ipv4Addr::new(192, 168, 1, 99);
    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![target_ip]),
        PolicyDuration::Temporary(Duration::from_secs(300)),
        PolicyPersistence::RouterPersistent,
    );

    // Temporary policy must fail closed and NOT leave un-expirable rules
    let err = provider
        .apply_policy(&req)
        .expect_err("Temporary policy must be rejected if recovery unsupported");
    assert!(
        matches!(
            err,
            AdminError::UnsupportedOperation(_) | AdminError::AuthenticationFailed(_)
        ),
        "Expected error rejecting temporary policy, got: {:?}",
        err
    );

    // Verify no rules were leaked into firewall
    let rules = transport.firewall_rules.read();
    assert!(
        rules.is_empty(),
        "No firewall rules should be present after fail-closed rejection"
    );
}

#[test]
fn test_mikrotik_router_reboot_autonomous_expiration() {
    let (provider, transport) = create_mock_mikrotik();

    let target_ip = Ipv4Addr::new(192, 168, 1, 105);
    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![target_ip]),
        PolicyDuration::Temporary(Duration::from_secs(10)),
        PolicyPersistence::RouterPersistent,
    );

    provider.apply_policy(&req).expect("Apply should succeed");
    assert_eq!(transport.firewall_rules.read().len(), 1);

    // Simulate router reboot after 20 seconds (policy has expired while controller was off)
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    transport.simulate_reboot_cycle(now + 20);

    // Verify router-resident scheduler unblocked the rule autonomously
    let rules = transport.firewall_rules.read();
    assert!(
        rules.is_empty(),
        "Expired rule should be removed by router reboot scheduler cycle"
    );

    let policies = provider
        .reconcile_policies()
        .expect("Reconcile should succeed");
    assert!(policies.is_empty());
}

#[test]
fn test_mikrotik_resume_all_preserves_unrelated_rules() {
    let (provider, transport) = create_mock_mikrotik();

    // Pre-existing user-defined firewall rules
    transport.firewall_rules.write().push(json!({
        ".id": "*1",
        "chain": "forward",
        "action": "drop",
        "src-address": "10.0.0.99",
        "comment": "Pre-existing user rule: drop scanner"
    }));

    // Apply rustrict policy
    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![Ipv4Addr::new(192, 168, 1, 200)]),
        PolicyDuration::Indefinite,
        PolicyPersistence::RouterPersistent,
    );
    provider.apply_policy(&req).expect("Apply should succeed");

    assert_eq!(transport.firewall_rules.read().len(), 2);

    // Revoke all rustrict policies
    let resumed = provider.resume_all().expect("Resume all should succeed");
    assert_eq!(resumed.len(), 1);

    // Pre-existing user rule MUST remain untouched
    let rules = transport.firewall_rules.read();
    assert_eq!(rules.len(), 1, "Only pre-existing rule should remain");
    assert_eq!(
        rules[0].get("comment").and_then(|c| c.as_str()),
        Some("Pre-existing user rule: drop scanner")
    );
}

#[test]
fn test_mikrotik_partial_transaction_failure_and_rollback() {
    let (provider, transport) = create_mock_mikrotik();

    // Pre-existing user rule
    transport.firewall_rules.write().push(json!({
        ".id": "*1",
        "chain": "forward",
        "action": "accept",
        "comment": "Default LAN forward"
    }));

    // Simulate failure during rule insertion
    transport
        .simulate_partial_failure
        .store(true, Ordering::SeqCst);

    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![Ipv4Addr::new(192, 168, 1, 150)]),
        PolicyDuration::Indefinite,
        PolicyPersistence::RouterPersistent,
    );

    let err = provider
        .apply_policy(&req)
        .expect_err("Should fail when transaction encounters error");
    assert!(
        matches!(err, AdminError::TransactionFailed(_)),
        "Expected TransactionFailed, got: {:?}",
        err
    );

    // Verify no orphaned rustrict rules were left behind
    let rules = transport.firewall_rules.read();
    assert_eq!(rules.len(), 1);
    assert_eq!(
        rules[0].get("comment").and_then(|c| c.as_str()),
        Some("Default LAN forward")
    );
}

#[test]
fn test_mikrotik_uninstall_watchdog_preserves_unrelated_schedulers() {
    let (provider, transport) = create_mock_mikrotik();

    // User's custom script and scheduler
    transport.scripts.write().push(json!({
        ".id": "*s_custom",
        "name": "backup_config",
        "source": "/system backup save name=daily"
    }));
    transport.schedulers.write().push(json!({
        ".id": "*sc_custom",
        "name": "daily_backup_schedule",
        "interval": "1d",
        "on-event": "backup_config"
    }));

    // Install Rustrict watchdog
    provider
        .ensure_router_watchdog()
        .expect("Install watchdog should succeed");
    assert_eq!(transport.scripts.read().len(), 2);
    assert_eq!(transport.schedulers.read().len(), 2);

    // Uninstall Rustrict watchdog
    provider
        .uninstall_router_watchdog()
        .expect("Uninstall watchdog should succeed");

    // Rustrict watchdog must be gone, but user custom scripts & schedules preserved
    {
        let scripts = transport.scripts.read();
        assert_eq!(scripts.len(), 1);
        assert_eq!(
            scripts[0].get("name").and_then(|n| n.as_str()),
            Some("backup_config")
        );

        let scheds = transport.schedulers.read();
        assert_eq!(scheds.len(), 1);
        assert_eq!(
            scheds[0].get("name").and_then(|n| n.as_str()),
            Some("daily_backup_schedule")
        );
    }
}

#[test]
fn test_mikrotik_multi_target_policy_enforcement_and_recovery() {
    let (provider, transport) = create_mock_mikrotik();

    let target1 = Ipv4Addr::new(192, 168, 1, 201);
    let target2 = Ipv4Addr::new(192, 168, 1, 202);
    let target3 = Ipv4Addr::new(192, 168, 1, 203);
    let targets = vec![target1, target2, target3];

    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(targets.clone()),
        PolicyDuration::Indefinite,
        PolicyPersistence::VolatileSession,
    );

    let active = provider
        .apply_policy(&req)
        .expect("Multi-target policy application must succeed");
    assert_eq!(active.policy_id, "rustrict_pause_multi_192_168_1_201");

    // Verify rules were posted for ALL 3 targets
    {
        let rules = transport.firewall_rules.read();
        assert_eq!(
            rules.len(),
            3,
            "Firewall must contain exactly 3 rules for 3 targets"
        );
        let ips: Vec<String> = rules
            .iter()
            .map(|r| r["src-address"].as_str().unwrap().to_string())
            .collect();
        assert!(ips.contains(&"192.168.1.201".to_string()));
        assert!(ips.contains(&"192.168.1.202".to_string()));
        assert!(ips.contains(&"192.168.1.203".to_string()));
    }

    // Resume the multi-target policy
    let resumed = provider
        .resume_policy(&PolicyScope::SpecificTargets(targets))
        .expect("Multi-target resume must succeed");
    assert_eq!(resumed.len(), 3);

    // Verify all 3 rules were removed
    {
        let rules = transport.firewall_rules.read();
        assert!(rules.is_empty(), "All multi-target rules must be removed");
    }
}

#[test]
fn test_mikrotik_ipv6_honesty_check() {
    let (provider, _transport) = create_mock_mikrotik();
    let caps = provider.inspect_capabilities();

    // SEC-04 Verification: IPv6 policy enforcement must accurately report NotImplemented
    assert_eq!(
        caps.ipv6_policy_enforcement,
        CapabilityClassification::NotImplemented
    );
}

#[test]
fn test_mikrotik_rollback_failure_reporting() {
    use rustrict::gateway::admin::mikrotik::MikroTikTransport;

    struct RollbackFailTransport {
        inner: MockMikroTikTransport,
    }
    impl MikroTikTransport for RollbackFailTransport {
        fn transport_name(&self) -> &'static str {
            "Mock-RollbackFail"
        }
        fn request(
            &self,
            endpoint: &str,
            method: &str,
            path: &str,
            body: Option<serde_json::Value>,
            creds: Option<&RouterCredentials>,
        ) -> Result<serde_json::Value, AdminError> {
            if method == "POST" && path == "/rest/ip/firewall/filter" {
                let rules_count = self.inner.firewall_rules.read().len();
                if rules_count >= 1 {
                    return Err(AdminError::CommunicationError(
                        "Target 2 POST failed".into(),
                    ));
                }
                return self.inner.request(endpoint, method, path, body, creds);
            }
            if method == "DELETE" {
                return Err(AdminError::CommunicationError(
                    "Router unreachable during rollback DELETE".into(),
                ));
            }
            self.inner.request(endpoint, method, path, body, creds)
        }
    }

    let fail_transport = RollbackFailTransport {
        inner: MockMikroTikTransport::default(),
    };
    let fail_provider =
        MikroTikAdminProvider::new(Ipv4Addr::new(192, 168, 88, 1), "https://192.168.88.1")
            .with_transport(Box::new(fail_transport));
    fail_provider.set_credentials(RouterCredentials::new("admin", "admin_password"));

    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![
            Ipv4Addr::new(192, 168, 88, 10),
            Ipv4Addr::new(192, 168, 88, 20),
        ]),
        PolicyDuration::Indefinite,
        PolicyPersistence::VolatileSession,
    );

    let err = fail_provider
        .apply_policy(&req)
        .expect_err("Must report rollback failure");
    match err {
        AdminError::RollbackFailed {
            applied_targets,
            failed_target,
            original_error,
            rollback_errors,
        } => {
            assert_eq!(applied_targets, vec!["192.168.88.10".to_string()]);
            assert_eq!(failed_target, "192.168.88.20");
            assert!(original_error.contains("Target 2 POST failed"));
            assert_eq!(rollback_errors.len(), 1);
            assert!(rollback_errors[0].contains("Router unreachable during rollback"));
        }
        other => panic!("Expected RollbackFailed, got: {:?}", other),
    }
}
