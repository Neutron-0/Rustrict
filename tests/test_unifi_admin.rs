use serde_json::json;
use std::net::Ipv4Addr;
use std::sync::atomic::Ordering;
use std::time::Duration;

use rustrict::gateway::admin::{
    AdminError, CapabilityClassification, MockUnifiTransport, OperationPlanRequest, PolicyDuration,
    PolicyPersistence, PolicyScope, RouterAdminProvider, RouterCredentials, UnifiAdminProvider,
};
use rustrict::types::MacAddress;

fn create_mock_unifi() -> (UnifiAdminProvider, MockUnifiTransport) {
    let mock_transport = MockUnifiTransport::default();
    let gw_ip = Ipv4Addr::new(192, 168, 1, 1);
    let provider = UnifiAdminProvider::new(gw_ip, "https://192.168.1.1:443")
        .with_site("default")
        .with_transport(Box::new(mock_transport.clone()));
    provider.set_credentials(RouterCredentials::new("admin", "admin_password"));
    (provider, mock_transport)
}

#[test]
fn test_unifi_auth_success() {
    let (provider, _transport) = create_mock_unifi();

    assert!(provider.is_authenticated());
    let login_res = provider.login();
    assert!(
        login_res.is_ok(),
        "Login should succeed with valid credentials"
    );
    assert!(provider.is_authenticated());
}

#[test]
fn test_unifi_auth_failure() {
    let mock_transport = MockUnifiTransport::default();
    let gw_ip = Ipv4Addr::new(192, 168, 1, 1);
    let provider = UnifiAdminProvider::new(gw_ip, "https://192.168.1.1:443")
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
fn test_unifi_permission_denied() {
    let (provider, transport) = create_mock_unifi();

    // 403 Forbidden: User account lacks administrator privileges
    transport
        .simulate_permission_denied
        .store(true, Ordering::SeqCst);

    let err = provider
        .login()
        .expect_err("Should fail when user lacks privileges");
    assert!(
        matches!(err, AdminError::AuthenticationFailed(_)),
        "Expected AuthenticationFailed for 403, got: {:?}",
        err
    );
    let msg = format!("{}", err);
    assert!(msg.contains("Permission Denied") || msg.contains("privileges"));
}

#[test]
fn test_unifi_tls_cert_error_rejection() {
    let (provider, transport) = create_mock_unifi();

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
fn test_unifi_identity_verification_and_mismatch() {
    let (provider, transport) = create_mock_unifi();

    let identity = provider
        .detect_identity()
        .expect("Identity probe should succeed");
    assert_eq!(identity.ip, Ipv4Addr::new(192, 168, 1, 1));
    assert_eq!(identity.manufacturer.as_deref(), Some("Ubiquiti Networks"));
    assert_eq!(
        identity.model_name.as_deref(),
        Some("UniFi Dream Machine Pro")
    );
    assert_eq!(identity.firmware_version.as_deref(), Some("8.0.28"));

    // Mismatched non-UniFi device
    transport.simulate_non_unifi.store(true, Ordering::SeqCst);
    let mismatch_provider =
        UnifiAdminProvider::new(Ipv4Addr::new(192, 168, 1, 1), "https://192.168.1.1:443")
            .with_transport(Box::new(transport));
    mismatch_provider.set_credentials(RouterCredentials::new("admin", "admin_password"));

    let err = mismatch_provider
        .detect_identity()
        .expect_err("Should reject non-UniFi device");
    assert!(
        matches!(err, AdminError::IdentityMismatch(_)),
        "Expected IdentityMismatch error, got: {:?}",
        err
    );
}

#[test]
fn test_unifi_site_selection_and_discovery() {
    let (provider, _transport) = create_mock_unifi();

    assert_eq!(provider.site(), "default");

    let sites = provider
        .list_sites()
        .expect("Site discovery should succeed");
    assert!(sites.contains(&"default".to_string()));
    assert!(sites.contains(&"branch_office".to_string()));

    // Switch to branch office site
    provider.set_site("branch_office");
    assert_eq!(provider.site(), "branch_office");
    assert!(provider
        .build_api_path("stat/sysinfo")
        .contains("/s/branch_office/"));
}

#[test]
fn test_unifi_connected_client_inventory() {
    let (provider, _transport) = create_mock_unifi();

    let clients = provider
        .list_connected_clients()
        .expect("Client inventory query should succeed");
    assert_eq!(clients.len(), 2);

    // Wired client
    let wired = clients
        .iter()
        .find(|c| c.is_wired)
        .expect("Should find wired client");
    assert_eq!(wired.ip, Some(Ipv4Addr::new(192, 168, 1, 100)));
    assert_eq!(
        wired.mac,
        "00:11:22:33:44:55".parse::<MacAddress>().unwrap()
    );
    assert_eq!(wired.name.as_deref(), Some("Workstation-Office"));

    // Wireless client
    let wireless = clients
        .iter()
        .find(|c| !c.is_wired)
        .expect("Should find wireless client");
    assert_eq!(wireless.ip, Some(Ipv4Addr::new(192, 168, 1, 101)));
    assert_eq!(
        wireless.mac,
        "aa:bb:cc:dd:ee:ff".parse::<MacAddress>().unwrap()
    );
    assert_eq!(wireless.name.as_deref(), Some("Tablet-WiFi"));
}

#[test]
fn test_unifi_capability_discovery() {
    let mock_transport = MockUnifiTransport::default();
    let gw_ip = Ipv4Addr::new(192, 168, 1, 1);
    let unauthed_provider = UnifiAdminProvider::new(gw_ip, "https://192.168.1.1:443")
        .with_transport(Box::new(mock_transport));

    let unauthed_caps = unauthed_provider.inspect_capabilities();
    assert!(matches!(
        unauthed_caps.network_wide_access_policy,
        CapabilityClassification::Unknown(_)
    ));

    let (provider, _transport) = create_mock_unifi();
    let caps = provider.inspect_capabilities();

    assert_eq!(
        caps.read_only_discovery,
        CapabilityClassification::Implemented
    );
    assert_eq!(caps.host_inventory, CapabilityClassification::Implemented);
    assert_eq!(
        caps.ipv4_policy_enforcement,
        CapabilityClassification::Implemented
    );
    assert_eq!(
        caps.ipv6_policy_enforcement,
        CapabilityClassification::Implemented
    );
    assert_eq!(
        caps.per_device_access_policy,
        CapabilityClassification::Implemented
    );
    assert_eq!(
        caps.network_wide_access_policy,
        CapabilityClassification::Implemented
    );
    assert_eq!(
        caps.authenticated_admin_interfaces,
        CapabilityClassification::Implemented
    );
    assert_eq!(
        caps.timed_policy_auto_recovery,
        CapabilityClassification::NotImplemented
    );
}

#[test]
fn test_unifi_apply_and_resume_device_policy() {
    let (provider, transport) = create_mock_unifi();

    let target_ip = Ipv4Addr::new(192, 168, 1, 100);
    let target_mac: MacAddress = "00:11:22:33:44:55".parse().unwrap();

    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![target_ip]),
        PolicyDuration::Indefinite,
        PolicyPersistence::RouterPersistent,
    )
    .with_macs(vec![target_mac]);

    // Apply policy
    let active = provider.apply_policy(&req).expect("Apply should succeed");
    assert_eq!(active.scope, req.scope);

    // Verify created Traffic Rule in controller mock state
    {
        let rules = transport.traffic_rules.read();
        assert_eq!(rules.len(), 1);
        let rule = &rules[0];
        assert_eq!(rule.get("action").and_then(|a| a.as_str()), Some("BLOCK"));
        assert_eq!(
            rule.get("traffic").and_then(|t| t.as_str()),
            Some("INTERNET")
        );
        assert_eq!(rule.get("enabled").and_then(|e| e.as_bool()), Some(true));

        let targets = rule
            .get("target_devices")
            .and_then(|t| t.as_array())
            .unwrap();
        assert!(targets
            .iter()
            .any(
                |t| t.get("matching_target").and_then(|m| m.as_str()) == Some("IP")
                    && t.get("value").and_then(|v| v.as_str()) == Some("192.168.1.100")
            ));
        assert!(targets
            .iter()
            .any(
                |t| t.get("matching_target").and_then(|m| m.as_str()) == Some("MAC")
                    && t.get("value").and_then(|v| v.as_str()) == Some("00:11:22:33:44:55")
            ));
    }

    // Query active policies
    let policies = provider
        .query_active_policies()
        .expect("Query active should succeed");
    assert_eq!(policies.len(), 1);
    assert_eq!(policies[0].scope, req.scope);

    // Resume policy
    let resumed = provider
        .resume_policy(&req.scope)
        .expect("Resume should succeed");
    assert_eq!(resumed.len(), 1);

    // Verify rule removed from controller
    assert!(transport.traffic_rules.read().is_empty());
}

#[test]
fn test_unifi_temporary_policy_rejected_without_autonomous_recovery() {
    let (provider, _transport) = create_mock_unifi();

    let target_ip = Ipv4Addr::new(192, 168, 1, 100);
    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![target_ip]),
        PolicyDuration::Temporary(Duration::from_secs(10)),
        PolicyPersistence::RouterPersistent,
    );

    let err = provider
        .apply_policy(&req)
        .expect_err("Temporary policy must be rejected on UniFi");
    match err {
        AdminError::UnsupportedOperation(msg) => {
            assert!(msg.contains("autonomous scheduler"));
        }
        other => panic!("Expected UnsupportedOperation, got {:?}", other),
    }
}

#[test]
fn test_unifi_reconcile_policies_cleans_legacy_expired_rules() {
    let (provider, transport) = create_mock_unifi();

    let past_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 10;

    // Simulate an existing rule in UniFi Controller with expired timestamp
    transport.traffic_rules.write().push(json!({
        "_id": "legacy_rule_123",
        "action": "BLOCK",
        "description": format!("Rustrict:pol=rustrict_pause_192_168_1_100:app={}:exp={}", past_time - 10, past_time),
        "target_devices": [{"matching_target": "IP", "value": "192.168.1.100"}],
        "traffic": "INTERNET",
        "enabled": true
    }));

    // Reconcile after expiration automatically purges expired rule
    let active_after = provider
        .reconcile_policies()
        .expect("Reconcile should succeed");
    assert!(active_after.is_empty(), "Expired policy should be purged");
    assert!(
        transport.traffic_rules.read().is_empty(),
        "Expired rule should be deleted from UniFi Controller"
    );
}

#[test]
fn test_unifi_adjust_policy_duration() {
    let (provider, transport) = create_mock_unifi();

    let target_ip = Ipv4Addr::new(192, 168, 1, 100);
    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![target_ip]),
        PolicyDuration::Indefinite,
        PolicyPersistence::RouterPersistent,
    );

    provider.apply_policy(&req).expect("Apply should succeed");

    // Adjusting to Temporary is rejected because UniFi lacks autonomous router-side scheduler
    let new_dur = PolicyDuration::Temporary(Duration::from_secs(900));
    let err = provider
        .adjust_policy_duration(&req.scope, &new_dur)
        .expect_err("Adjust to temporary must fail closed");
    match err {
        AdminError::UnsupportedOperation(msg) => {
            assert!(msg.contains("autonomous controller-resident scheduler"));
        }
        other => panic!("Expected UnsupportedOperation, got {:?}", other),
    }

    // Adjust to Indefinite succeeds
    let updated_indefinite = provider
        .adjust_policy_duration(&req.scope, &PolicyDuration::Indefinite)
        .expect("Adjust to indefinite should succeed");
    assert!(updated_indefinite.expires_at_unix.is_none());

    let rules = transport.traffic_rules.read();
    assert_eq!(rules.len(), 1);
    let desc = rules[0]
        .get("description")
        .and_then(|d| d.as_str())
        .unwrap();
    assert!(desc.contains("exp=0"));
}

#[test]
fn test_unifi_network_wide_policy_lifecycle() {
    let (provider, transport) = create_mock_unifi();

    let req = OperationPlanRequest::new(
        PolicyScope::NetworkWide,
        PolicyDuration::Indefinite,
        PolicyPersistence::RouterPersistent,
    );

    let plan = provider.plan_operation(&req).expect("Plan should succeed");
    assert_eq!(plan.target_scope, PolicyScope::NetworkWide);
    assert!(plan.management_plane_safe);

    // Apply network-wide policy
    let active = provider
        .apply_policy(&req)
        .expect("Apply network-wide should succeed");
    assert_eq!(active.scope, PolicyScope::NetworkWide);

    // Verify rule created targeting ALL_DEVICES
    {
        let rules = transport.traffic_rules.read();
        assert_eq!(rules.len(), 1);
        let targets = rules[0]
            .get("target_devices")
            .and_then(|t| t.as_array())
            .unwrap();
        assert_eq!(
            targets[0].get("matching_target").and_then(|m| m.as_str()),
            Some("ALL_DEVICES")
        );
    }

    // Resume network-wide
    let resumed = provider
        .resume_policy(&PolicyScope::NetworkWide)
        .expect("Resume network-wide should succeed");
    assert_eq!(resumed.len(), 1);
    assert!(transport.traffic_rules.read().is_empty());
}

#[test]
fn test_unifi_lockout_prevention() {
    let (provider, _transport) = create_mock_unifi();

    let router_ip = Ipv4Addr::new(192, 168, 1, 1);
    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![router_ip]),
        PolicyDuration::Indefinite,
        PolicyPersistence::RouterPersistent,
    );

    // Dry-run plan must prevent lockout
    let plan_err = provider
        .plan_operation(&req)
        .expect_err("Should prevent lockout during planning");
    assert!(matches!(plan_err, AdminError::LockoutPrevented(_)));

    // Application must prevent lockout
    let apply_err = provider
        .apply_policy(&req)
        .expect_err("Should prevent lockout during execution");
    assert!(matches!(apply_err, AdminError::LockoutPrevented(_)));
}

#[test]
fn test_unifi_preserves_unrelated_rules() {
    let (provider, transport) = create_mock_unifi();

    // Pre-existing user traffic rule
    transport.traffic_rules.write().push(json!({
        "_id": "rule_user_custom",
        "description": "User custom rule: Block Tor & P2P",
        "action": "BLOCK",
        "traffic": "INTERNET",
        "enabled": true
    }));

    // Apply Rustrict policy
    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![Ipv4Addr::new(192, 168, 1, 100)]),
        PolicyDuration::Indefinite,
        PolicyPersistence::RouterPersistent,
    );
    provider.apply_policy(&req).expect("Apply should succeed");
    assert_eq!(transport.traffic_rules.read().len(), 2);

    // Resume Rustrict policy
    let resumed = provider
        .resume_policy(&req.scope)
        .expect("Resume should succeed");
    assert_eq!(resumed.len(), 1);

    // User rule must remain intact
    let rules = transport.traffic_rules.read();
    assert_eq!(rules.len(), 1);
    assert_eq!(
        rules[0].get("description").and_then(|d| d.as_str()),
        Some("User custom rule: Block Tor & P2P")
    );
}

#[test]
fn test_unifi_missing_trafficrules_resource() {
    let (provider, transport) = create_mock_unifi();

    // Controller firmware lacks modern Traffic Rules API (HTTP 404)
    transport
        .simulate_missing_trafficrules
        .store(true, Ordering::SeqCst);

    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![Ipv4Addr::new(192, 168, 1, 100)]),
        PolicyDuration::Indefinite,
        PolicyPersistence::RouterPersistent,
    );

    let err = provider
        .apply_policy(&req)
        .expect_err("Should fail when traffic rules API is unavailable");
    assert!(
        matches!(err, AdminError::UnsupportedOperation(_)),
        "Expected UnsupportedOperation, got: {:?}",
        err
    );
}

#[test]
fn test_unifi_partial_transaction_failure_and_rollback() {
    let (provider, transport) = create_mock_unifi();

    transport
        .simulate_partial_failure
        .store(true, Ordering::SeqCst);

    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![Ipv4Addr::new(192, 168, 1, 100)]),
        PolicyDuration::Indefinite,
        PolicyPersistence::RouterPersistent,
    );

    let err = provider
        .apply_policy(&req)
        .expect_err("Should fail when database commit fails");
    assert!(
        matches!(err, AdminError::TransactionFailed(_)),
        "Expected TransactionFailed, got: {:?}",
        err
    );
    assert!(transport.traffic_rules.read().is_empty());
}

#[test]
fn test_unifi_api_timeout_handling() {
    let (provider, transport) = create_mock_unifi();

    transport.simulate_timeout.store(true, Ordering::SeqCst);

    let err = provider
        .detect_identity()
        .expect_err("Should time out when transport is unresponsive");
    assert!(
        matches!(err, AdminError::Timeout(_)),
        "Expected Timeout, got: {:?}",
        err
    );
}

#[test]
fn test_unifi_curl_transport_payload_isolation_and_cleanup() {
    use rustrict::gateway::admin::AutoCleanFile;

    let json_payload = b"{\"action\":\"BLOCK\",\"traffic\":\"INTERNET\"}";
    let file_path;
    {
        let guard = AutoCleanFile::create("rustrict_unifi_test", ".json", json_payload)
            .expect("Failed to create temporary JSON payload file");
        file_path = guard.path().to_path_buf();
        assert!(file_path.exists());
        let read = std::fs::read(&file_path).unwrap();
        assert_eq!(read, json_payload);
    }
    // Verifies RAII cleanup on drop
    assert!(
        !file_path.exists(),
        "Payload temporary file must be cleanly deleted on drop"
    );
}
