use std::net::Ipv4Addr;
use std::sync::atomic::Ordering;
use std::time::Duration;

use rustrict::gateway::admin::{
    AdminError, MockOpenWrtTransport, OpenWrtAdminProvider, OperationPlanRequest, PolicyDuration,
    PolicyPersistence, PolicyScope, RouterAdminProvider, RouterCredentials,
};
use rustrict::types::MacAddress;

fn create_mock_openwrt() -> (OpenWrtAdminProvider, MockOpenWrtTransport) {
    let mock_transport = MockOpenWrtTransport::default();
    let gw_ip = Ipv4Addr::new(192, 168, 1, 1);
    let provider = OpenWrtAdminProvider::new(gw_ip, "http://192.168.1.1:80/ubus")
        .with_transport(Box::new(mock_transport.clone()));
    provider.set_credentials(RouterCredentials::new("root", "admin_password"));
    (provider, mock_transport)
}

#[test]
fn test_openwrt_auth_success() {
    let (provider, _transport) = create_mock_openwrt();

    assert!(!provider.is_authenticated());
    let token = provider
        .login()
        .expect("Login should succeed with valid credentials");
    assert!(!token.is_empty());
    assert!(provider.is_authenticated());
}

#[test]
fn test_openwrt_auth_failure() {
    let mock_transport = MockOpenWrtTransport::default();
    let gw_ip = Ipv4Addr::new(192, 168, 1, 1);
    let provider = OpenWrtAdminProvider::new(gw_ip, "http://192.168.1.1:80/ubus")
        .with_transport(Box::new(mock_transport.clone()));

    // Invalid password
    provider.set_credentials(RouterCredentials::new("root", "wrong_password"));

    let err = provider
        .login()
        .expect_err("Login should fail with wrong password");
    assert!(
        matches!(err, AdminError::AuthenticationFailed(_)),
        "Expected AuthenticationFailed, got: {:?}",
        err
    );
    assert!(!provider.is_authenticated());

    // Simulated ubus permission denied
    mock_transport
        .simulate_auth_fail
        .store(true, Ordering::SeqCst);
    provider.set_credentials(RouterCredentials::new("root", "admin_password"));
    let err2 = provider
        .login()
        .expect_err("Should fail when simulated auth error is active");
    assert!(matches!(err2, AdminError::AuthenticationFailed(_)));
}

#[test]
fn test_openwrt_identity_verification() {
    let (provider, _transport) = create_mock_openwrt();

    let identity = provider
        .detect_identity()
        .expect("Identity probe should succeed");
    assert_eq!(identity.ip, Ipv4Addr::new(192, 168, 1, 1));
    assert_eq!(identity.manufacturer.as_deref(), Some("OpenWrt Community"));
    assert_eq!(
        identity.model_name.as_deref(),
        Some("Ubiquiti UniFi / OpenWrt One")
    );
    assert_eq!(identity.firmware_version.as_deref(), Some("23.05.2"));
}

#[test]
fn test_openwrt_unsupported_firmware_rejection() {
    let (provider, transport) = create_mock_openwrt();
    transport.simulate_non_openwrt.store(true, Ordering::SeqCst);

    let err = provider
        .detect_identity()
        .expect_err("Non-OpenWrt firmware should be rejected");
    assert!(
        matches!(err, AdminError::IdentityMismatch(_)),
        "Expected IdentityMismatch for non-OpenWrt firmware, got: {:?}",
        err
    );
}

#[test]
fn test_openwrt_api_timeout() {
    let (provider, transport) = create_mock_openwrt();
    transport.simulate_timeout.store(true, Ordering::SeqCst);

    let err = provider
        .login()
        .expect_err("Timeout should be triggered on network stall");
    assert!(
        matches!(err, AdminError::Timeout(_)),
        "Expected Timeout, got: {:?}",
        err
    );
}

#[test]
fn test_openwrt_ipv4_and_ipv6_policy_planning() {
    let (provider, _transport) = create_mock_openwrt();
    provider.login().unwrap();

    let target_ip = Ipv4Addr::new(192, 168, 1, 45);
    let target_mac: MacAddress = "00:11:22:33:44:55".parse().unwrap();

    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![target_ip]),
        PolicyDuration::Temporary(Duration::from_secs(600)),
        PolicyPersistence::VolatileSession,
    )
    .with_macs(vec![target_mac]);

    let plan = provider.plan_operation(&req).expect("Plan should succeed");

    assert!(plan.is_dry_run);
    assert!(plan.management_plane_safe);
    assert_eq!(plan.target_count, 1);
    assert!(plan.expected_lan_impact.contains("100% accessible"));
    assert!(plan
        .supported_capabilities
        .iter()
        .any(|c| c.contains("Dual-Stack")));
}

#[test]
fn test_openwrt_lockout_prevention() {
    let (provider, _transport) = create_mock_openwrt();
    provider.login().unwrap();

    // Target is the router itself
    let gw_ip = Ipv4Addr::new(192, 168, 1, 1);
    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![gw_ip]),
        PolicyDuration::Indefinite,
        PolicyPersistence::VolatileSession,
    );

    let err = provider
        .plan_operation(&req)
        .expect_err("Targeting router IP must trigger lockout prevention");
    assert!(
        matches!(err, AdminError::LockoutPrevented(_)),
        "Expected LockoutPrevented, got: {:?}",
        err
    );
}

#[test]
fn test_openwrt_apply_and_resume_device_policy() {
    let (provider, transport) = create_mock_openwrt();
    provider.login().unwrap();

    let target_ip = Ipv4Addr::new(192, 168, 1, 77);
    let target_mac: MacAddress = "3c:22:fb:4a:12:ef".parse().unwrap();

    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![target_ip]),
        PolicyDuration::Temporary(Duration::from_secs(300)),
        PolicyPersistence::RouterPersistent,
    )
    .with_macs(vec![target_mac]);

    // Apply policy
    let active = provider
        .apply_policy(&req)
        .expect("Policy application should succeed");
    assert_eq!(active.policy_id, "rustrict_pause_192_168_1_77");
    assert!(active.expires_at_unix.is_some());

    // Verify mock UCI state has the injected rule
    {
        let uci_state = transport.uci_firewall_state.read();
        assert!(!uci_state.is_empty());
        let rule = uci_state
            .get("cfg_rustrict_pause_192_168_1_77")
            .expect("Rule must exist in UCI state");
        assert_eq!(rule["src"], "lan");
        assert_eq!(rule["dest"], "wan");
        assert_eq!(rule["target"], "REJECT");
        assert_eq!(rule["src_ip"], "192.168.1.77");
        assert_eq!(rule["src_mac"], "3c:22:fb:4a:12:ef");
    }

    // Query active policies
    let queried = provider
        .query_active_policies()
        .expect("Query active policies should succeed");
    assert_eq!(queried.len(), 1);
    assert_eq!(queried[0].policy_id, "rustrict_pause_192_168_1_77");

    // Resume policy
    let resumed = provider
        .resume_policy(&PolicyScope::SpecificTargets(vec![target_ip]))
        .expect("Resume should succeed");
    assert_eq!(resumed, vec!["rustrict_pause_192_168_1_77"]);

    // Verify rule was removed from UCI state
    {
        let uci_state = transport.uci_firewall_state.read();
        assert!(
            uci_state.is_empty(),
            "UCI state should be empty after resume"
        );
    }
}

#[test]
fn test_openwrt_network_wide_policy_lifecycle() {
    let (provider, transport) = create_mock_openwrt();
    provider.login().unwrap();

    let req = OperationPlanRequest::new(
        PolicyScope::NetworkWide,
        PolicyDuration::Indefinite,
        PolicyPersistence::VolatileSession,
    );

    // Apply network-wide policy
    let active = provider
        .apply_policy(&req)
        .expect("Global pause should succeed");
    assert_eq!(active.policy_id, "rustrict_pause_network_wide");

    // Verify mock UCI state
    {
        let uci_state = transport.uci_firewall_state.read();
        let rule = uci_state
            .get("cfg_rustrict_pause_network_wide")
            .expect("Global rule must exist in UCI");
        assert_eq!(rule["src"], "lan");
        assert_eq!(rule["dest"], "wan");
        assert_eq!(rule["target"], "REJECT");
    }

    // Resume network-wide
    let resumed = provider
        .resume_policy(&PolicyScope::NetworkWide)
        .expect("Global resume should succeed");
    assert!(resumed.contains(&"rustrict_pause_network_wide".to_string()));

    // Verify UCI state empty
    {
        let uci_state = transport.uci_firewall_state.read();
        assert!(uci_state.is_empty());
    }
}

#[test]
fn test_openwrt_reconcile_expired_timed_policy() {
    let (provider, transport) = create_mock_openwrt();
    provider.login().unwrap();

    // Inject an expired rule into mock UCI state directly (expired at unix 1000)
    {
        let mut uci_state = transport.uci_firewall_state.write();
        uci_state.insert(
            "cfg_rustrict_pause_192_168_1_99".to_string(),
            serde_json::json!({
                "name": "rustrict_pause_192_168_1_99",
                "src": "lan",
                "dest": "wan",
                "target": "REJECT",
                "src_ip": "192.168.1.99",
                "comment": "rustrict:pol=rustrict_pause_192_168_1_99:app=500:exp=1000"
            }),
        );
    }

    // Reconciliation should purge the expired rule
    let remaining = provider
        .reconcile_policies()
        .expect("Reconciliation should succeed");
    assert!(
        remaining.is_empty(),
        "Expired policy should have been automatically purged"
    );

    // Verify mock UCI state was cleaned up
    {
        let uci_state = transport.uci_firewall_state.read();
        assert!(
            uci_state.is_empty(),
            "Expired section must be deleted from OpenWrt UCI"
        );
    }
}

#[test]
fn test_openwrt_resume_not_found() {
    let (provider, _transport) = create_mock_openwrt();
    provider.login().unwrap();

    let target_ip = Ipv4Addr::new(192, 168, 1, 99);
    let err = provider
        .resume_policy(&PolicyScope::SpecificTargets(vec![target_ip]))
        .expect_err("Resuming non-existent policy should return PolicyNotFound");
    assert!(
        matches!(err, AdminError::PolicyNotFound(_)),
        "Expected PolicyNotFound, got: {:?}",
        err
    );
}

#[test]
fn test_protected_credentials_and_zeroization() {
    let creds = RouterCredentials::new("root", "SuperSecretPassword123!");
    assert_eq!(creds.username, "root");
    assert_eq!(creds.password.expose(), "SuperSecretPassword123!");

    // Display & Debug must NOT reveal password
    let debug_str = format!("{:?}", creds);
    assert!(!debug_str.contains("SuperSecretPassword123!"));
    assert!(debug_str.contains("[REDACTED]"));

    let display_str = format!("{}", creds.password);
    assert_eq!(display_str, "[REDACTED]");

    // DPAPI Roundtrip
    let raw = "test_user:test_secret_pass";
    let encrypted = rustrict::gateway::admin::dpapi_encrypt(raw.as_bytes())
        .expect("DPAPI encrypt should succeed");
    assert_ne!(encrypted, raw.as_bytes());

    let decrypted =
        rustrict::gateway::admin::dpapi_decrypt(&encrypted).expect("DPAPI decrypt should succeed");
    assert_eq!(decrypted, raw.as_bytes());
}

#[test]
fn test_openwrt_autonomous_watchdog_installation() {
    let (provider, transport) = create_mock_openwrt();
    provider.login().unwrap();

    let target_ip = Ipv4Addr::new(192, 168, 1, 55);
    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![target_ip]),
        PolicyDuration::Temporary(Duration::from_secs(300)),
        PolicyPersistence::RouterPersistent,
    );

    let active = provider
        .apply_policy(&req)
        .expect("Timed policy should succeed");
    assert!(active.autonomous_recovery);

    // Verify crontab on router now contains the watchdog script
    let crontab = transport.crontab_state.read().clone().unwrap_or_default();
    assert!(crontab.contains("rustrict_pause"));
    assert!(crontab.contains("/etc/init.d/firewall reload"));
}

#[test]
fn test_openwrt_rejection_when_autonomous_recovery_unsupported() {
    let (provider, transport) = create_mock_openwrt();
    provider.login().unwrap();

    // Disable autonomous recovery capability on transport
    transport
        .autonomous_recovery_supported
        .store(false, Ordering::SeqCst);

    let target_ip = Ipv4Addr::new(192, 168, 1, 60);
    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![target_ip]),
        PolicyDuration::Temporary(Duration::from_secs(300)),
        PolicyPersistence::RouterPersistent,
    );

    let err = provider
        .apply_policy(&req)
        .expect_err("Timed policy must be rejected if autonomous recovery cannot be established");
    assert!(
        matches!(err, AdminError::UnsupportedOperation(_)),
        "Expected UnsupportedOperation, got: {:?}",
        err
    );
    assert!(err
        .to_string()
        .contains("Autonomous router-side recovery could not be established"));

    // Verify zero firewall rules were committed to router state (fail-closed)
    let uci_state = transport.uci_firewall_state.read();
    assert!(
        uci_state.is_empty(),
        "No rules should be added when recovery fails"
    );
}

#[test]
fn test_openwrt_router_reboot_autonomous_expiration() {
    let (provider, transport) = create_mock_openwrt();
    provider.login().unwrap();

    let target_ip = Ipv4Addr::new(192, 168, 1, 65);
    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![target_ip]),
        PolicyDuration::Temporary(Duration::from_secs(10)),
        PolicyPersistence::RouterPersistent,
    );

    let active = provider.apply_policy(&req).expect("Apply should succeed");
    let exp_unix = active.expires_at_unix.expect("Should have expiration");

    // Before expiration: rule exists in router state
    {
        let uci_state = transport.uci_firewall_state.read();
        assert!(!uci_state.is_empty());
    }

    // Simulate router rebooting AFTER the expiration timestamp (e.g. exp_unix + 15)
    // The router's resident crontab watchdog runs on system boot and deletes the rule
    transport.simulate_reboot_cycle(exp_unix + 15);

    // Rule is autonomously gone from router state without Rustrict having to run reconcile!
    {
        let uci_state = transport.uci_firewall_state.read();
        assert!(
            uci_state.is_empty(),
            "Router crontab watchdog must purge expired rule after reboot"
        );
    }
}

#[test]
fn test_openwrt_adjust_policy_duration_lifecycle() {
    let (provider, transport) = create_mock_openwrt();
    provider.login().unwrap();

    let target_ip = Ipv4Addr::new(192, 168, 1, 70);
    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![target_ip]),
        PolicyDuration::Temporary(Duration::from_secs(300)),
        PolicyPersistence::RouterPersistent,
    );

    let active = provider.apply_policy(&req).unwrap();
    let initial_exp = active.expires_at_unix.unwrap();

    // Extend policy to 1200 seconds
    let scope = PolicyScope::SpecificTargets(vec![target_ip]);
    let extended = provider
        .adjust_policy_duration(
            &scope,
            &PolicyDuration::Temporary(Duration::from_secs(1200)),
        )
        .expect("Duration adjustment should succeed");

    assert!(extended.expires_at_unix.unwrap() > initial_exp);

    // Verify comment was updated in mock UCI state
    {
        let uci_state = transport.uci_firewall_state.read();
        let rule = uci_state.get("cfg_rustrict_pause_192_168_1_70").unwrap();
        let comment = rule["comment"].as_str().unwrap();
        assert!(comment.contains(&format!("exp={}", extended.expires_at_unix.unwrap())));
    }

    // Change policy to Indefinite
    let indefinite = provider
        .adjust_policy_duration(&scope, &PolicyDuration::Indefinite)
        .expect("Adjustment to indefinite should succeed");
    assert!(indefinite.expires_at_unix.is_none());
}

#[test]
fn test_openwrt_interrupted_transaction_rollback() {
    let (provider, transport) = create_mock_openwrt();
    provider.login().unwrap();

    // Force commit failure to simulate power loss or disk write error during commit
    transport
        .simulate_partial_failure
        .store(true, Ordering::SeqCst);

    let target_ip = Ipv4Addr::new(192, 168, 1, 80);
    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![target_ip]),
        PolicyDuration::Indefinite,
        PolicyPersistence::VolatileSession,
    );

    let err = provider
        .apply_policy(&req)
        .expect_err("Commit failure must fail the transaction");
    assert!(
        matches!(err, AdminError::TransactionFailed(_)),
        "Expected TransactionFailed, got: {:?}",
        err
    );

    // Verify transaction rollback cleaned up uncommitted state
    let uci_state = transport.uci_firewall_state.read();
    assert!(
        uci_state.is_empty(),
        "Transaction rollback must leave zero residual rules"
    );
}

#[test]
fn test_openwrt_resume_all_preserves_unrelated_rules() {
    let (provider, transport) = create_mock_openwrt();
    provider.login().unwrap();

    // Inject an unrelated user rule into UCI state (e.g. custom SSH access rule)
    {
        let mut uci_state = transport.uci_firewall_state.write();
        uci_state.insert(
            "cfg_user_custom_ssh".to_string(),
            serde_json::json!({
                "name": "Allow-Custom-SSH",
                "src": "wan",
                "proto": "tcp",
                "dest_port": "2222",
                "target": "ACCEPT"
            }),
        );
    }

    // Apply multiple Rustrict pause policies
    let req1 = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![Ipv4Addr::new(192, 168, 1, 110)]),
        PolicyDuration::Indefinite,
        PolicyPersistence::RouterPersistent,
    );
    let req2 = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![Ipv4Addr::new(192, 168, 1, 120)]),
        PolicyDuration::Indefinite,
        PolicyPersistence::RouterPersistent,
    );
    provider.apply_policy(&req1).unwrap();
    provider.apply_policy(&req2).unwrap();

    // Call resume_all
    let resumed = provider.resume_all().expect("resume_all should succeed");
    assert_eq!(resumed.len(), 2);

    // Verify that ALL Rustrict rules were removed, but the user's custom rule was preserved!
    {
        let uci_state = transport.uci_firewall_state.read();
        assert_eq!(
            uci_state.len(),
            1,
            "Only the user custom rule should remain"
        );
        assert!(uci_state.contains_key("cfg_user_custom_ssh"));
        let custom_rule = &uci_state["cfg_user_custom_ssh"];
        assert_eq!(custom_rule["name"], "Allow-Custom-SSH");
        assert_eq!(custom_rule["target"], "ACCEPT");
    }
}

#[test]
fn test_openwrt_multi_target_policy_enforcement_and_recovery() {
    let (provider, transport) = create_mock_openwrt();
    provider.login().unwrap();

    let target1 = Ipv4Addr::new(192, 168, 1, 101);
    let target2 = Ipv4Addr::new(192, 168, 1, 102);
    let target3 = Ipv4Addr::new(192, 168, 1, 103);
    let targets = vec![target1, target2, target3];

    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(targets.clone()),
        PolicyDuration::Indefinite,
        PolicyPersistence::VolatileSession,
    );

    let active = provider
        .apply_policy(&req)
        .expect("Multi-target policy application must succeed");
    assert_eq!(active.policy_id, "rustrict_pause_multi_192_168_1_101");

    // Verify rules were created for ALL 3 targets
    {
        let uci_state = transport.uci_firewall_state.read();
        assert!(uci_state.contains_key("cfg_rustrict_pause_192_168_1_101"));
        assert!(uci_state.contains_key("cfg_rustrict_pause_192_168_1_102"));
        assert!(uci_state.contains_key("cfg_rustrict_pause_192_168_1_103"));

        assert_eq!(
            uci_state["cfg_rustrict_pause_192_168_1_101"]["src_ip"],
            "192.168.1.101"
        );
        assert_eq!(
            uci_state["cfg_rustrict_pause_192_168_1_102"]["src_ip"],
            "192.168.1.102"
        );
        assert_eq!(
            uci_state["cfg_rustrict_pause_192_168_1_103"]["src_ip"],
            "192.168.1.103"
        );
    }

    // Resume the multi-target policy
    let resumed = provider
        .resume_policy(&PolicyScope::SpecificTargets(targets))
        .expect("Multi-target resume must succeed");
    assert_eq!(resumed.len(), 3);

    // Verify all rules were cleaned up
    {
        let uci_state = transport.uci_firewall_state.read();
        assert!(!uci_state.contains_key("cfg_rustrict_pause_192_168_1_101"));
        assert!(!uci_state.contains_key("cfg_rustrict_pause_192_168_1_102"));
        assert!(!uci_state.contains_key("cfg_rustrict_pause_192_168_1_103"));
    }
}

#[test]
fn test_openwrt_oversized_http_response_rejection() {
    use rustrict::gateway::admin::openwrt::{HttpOpenWrtTransport, OpenWrtTransport};
    use std::io::{Read, Write};
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").expect("Must bind localhost listener");
    let port = listener.local_addr().unwrap().port();

    let server_handle = std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut req_buf = [0u8; 1024];
            let _ = stream.read(&mut req_buf);

            // Send HTTP response headers followed by 2.5 MiB of data (exceeding 2 MiB limit)
            let header =
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2621440\r\n\r\n";
            let _ = stream.write_all(header);
            let chunk = [b'A'; 65536]; // 64 KiB
            for _ in 0..40 {
                if stream.write_all(&chunk).is_err() {
                    break;
                }
            }
        }
    });

    let transport = HttpOpenWrtTransport::default();
    let endpoint = format!("http://127.0.0.1:{}/ubus", port);
    let err = transport
        .call(
            &endpoint,
            "system",
            "info",
            serde_json::json!({}),
            "session",
        )
        .expect_err("Oversized HTTP response must be rejected");

    match err {
        AdminError::CommunicationError(msg) => {
            assert!(
                msg.contains("exceeded maximum buffer limit"),
                "Error should state buffer limit exceeded: {}",
                msg
            );
        }
        other => panic!("Expected CommunicationError, got: {:?}", other),
    }

    let _ = server_handle.join();
}

#[test]
fn test_openwrt_unexpected_http_redirect_rejection() {
    use rustrict::gateway::admin::openwrt::{HttpOpenWrtTransport, OpenWrtTransport};
    use std::io::{Read, Write};
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").expect("Must bind localhost listener");
    let port = listener.local_addr().unwrap().port();

    let server_handle = std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut req_buf = [0u8; 1024];
            let _ = stream.read(&mut req_buf);

            let resp = b"HTTP/1.1 302 Found\r\nLocation: http://untrusted.host.internal/evil\r\nContent-Length: 0\r\n\r\n";
            let _ = stream.write_all(resp);
        }
    });

    let transport = HttpOpenWrtTransport::default();
    let endpoint = format!("http://127.0.0.1:{}/ubus", port);
    let err = transport
        .call(
            &endpoint,
            "system",
            "info",
            serde_json::json!({}),
            "session",
        )
        .expect_err("HTTP redirect must be rejected to prevent credential forwarding");

    match err {
        AdminError::SecurityViolation(msg) => {
            assert!(
                msg.contains("Unexpected HTTP redirect"),
                "Error should mention unexpected redirect: {}",
                msg
            );
        }
        other => panic!("Expected SecurityViolation, got: {:?}", other),
    }

    let _ = server_handle.join();
}
