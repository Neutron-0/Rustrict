use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use rustrict::gateway::admin::{
    AdminError, CapabilityClassification, MockRouterAdminProvider, OperationPlanRequest,
    PolicyDuration, PolicyLifecycleState, PolicyPersistence, PolicyScope, RouterAdminProvider,
    RouterRegistry,
};

#[test]
fn test_registry_registration_and_inventory() {
    let gateway_ip = Ipv4Addr::new(192, 168, 1, 1);
    let registry = RouterRegistry::new(gateway_ip);

    let providers = registry.list_providers();
    assert_eq!(
        providers.len(),
        6,
        "Must register all 6 supported router providers"
    );

    let ids: Vec<&str> = providers.iter().map(|p| p.id.as_str()).collect();
    assert!(ids.contains(&"openwrt-http"));
    assert!(ids.contains(&"openwrt-ssh"));
    assert!(ids.contains(&"mikrotik-rest"));
    assert!(ids.contains(&"avm-tr064"));
    assert!(ids.contains(&"unifi-rest"));
    assert!(ids.contains(&"mock"));

    // 1. OpenWrt HTTP
    let owrt = registry
        .get_descriptor("openwrt-http")
        .expect("openwrt-http must exist");
    assert_eq!(owrt.vendor, "OpenWrt");
    assert_eq!(owrt.default_port, 80);
    assert_eq!(
        owrt.capabilities.timed_policy_auto_recovery,
        CapabilityClassification::Implemented
    );
    assert_eq!(
        owrt.capabilities.ipv6_policy_enforcement,
        CapabilityClassification::Implemented
    );

    // 2. OpenWrt SSH
    let owrt_ssh = registry
        .get_descriptor("openwrt-ssh")
        .expect("openwrt-ssh must exist");
    assert_eq!(owrt_ssh.vendor, "OpenWrt");
    assert_eq!(owrt_ssh.default_port, 22);
    assert_eq!(
        owrt_ssh.capabilities.timed_policy_auto_recovery,
        CapabilityClassification::Implemented
    );

    // 3. MikroTik RouterOS REST
    let mt = registry
        .get_descriptor("mikrotik-rest")
        .expect("mikrotik-rest must exist");
    assert_eq!(mt.vendor, "MikroTik");
    assert_eq!(mt.default_port, 443);
    assert_eq!(
        mt.capabilities.timed_policy_auto_recovery,
        CapabilityClassification::Implemented
    );
    assert_eq!(
        mt.capabilities.ipv6_policy_enforcement,
        CapabilityClassification::NotImplemented
    );

    // 4. AVM FRITZ!Box TR-064
    let avm = registry
        .get_descriptor("avm-tr064")
        .expect("avm-tr064 must exist");
    assert_eq!(avm.vendor, "AVM");
    assert_eq!(avm.default_port, 49000);
    assert_eq!(
        avm.capabilities.timed_policy_auto_recovery,
        CapabilityClassification::NotImplemented
    );
    assert_eq!(
        avm.capabilities.ipv6_policy_enforcement,
        CapabilityClassification::NotImplemented
    );

    // 5. Ubiquiti UniFi REST
    let unifi = registry
        .get_descriptor("unifi-rest")
        .expect("unifi-rest must exist");
    assert_eq!(unifi.vendor, "Ubiquiti");
    assert_eq!(unifi.default_port, 8443);
    assert_eq!(
        unifi.capabilities.timed_policy_auto_recovery,
        CapabilityClassification::NotImplemented
    );
    assert_eq!(
        unifi.capabilities.ipv6_policy_enforcement,
        CapabilityClassification::Implemented
    );

    // 6. Mock In-Memory
    let mock = registry.get_descriptor("mock").expect("mock must exist");
    assert_eq!(mock.vendor, "Rustrict Mock");
    assert_eq!(mock.default_port, 0);
}

#[test]
fn test_registry_explicit_provider_selection_and_status() {
    let gateway_ip = Ipv4Addr::new(192, 168, 1, 1);
    let registry = RouterRegistry::new(gateway_ip);

    // Initial state: not connected
    assert!(!registry.is_connected());
    assert_eq!(registry.active_provider_id(), None);
    let status_before = registry.get_status();
    assert!(!status_before.is_connected);
    assert_eq!(status_before.provider_id, None);

    // Explicit connect
    let mock_provider = Arc::new(MockRouterAdminProvider::new(gateway_ip));
    let identity = registry
        .connect("mock", mock_provider.clone(), "internal://mock-test")
        .expect("Connect to mock should succeed");

    assert_eq!(identity.ip, gateway_ip);
    assert!(registry.is_connected());
    assert_eq!(registry.active_provider_id(), Some("mock".to_string()));

    let status_after = registry.get_status();
    assert!(status_after.is_connected);
    assert_eq!(status_after.provider_id, Some("mock".to_string()));
    assert_eq!(
        status_after.endpoint,
        Some("internal://mock-test".to_string())
    );
    assert!(status_after.is_authenticated);

    // Query through RouterAdminProvider interface of registry
    let queried_id = registry
        .detect_identity()
        .expect("Detect identity should succeed");
    assert_eq!(queried_id.ip, gateway_ip);

    let caps = registry.inspect_capabilities();
    assert!(caps.ipv4_policy_enforcement.is_operational());
}

#[test]
fn test_registry_disconnect_behavior_fails_closed() {
    let gateway_ip = Ipv4Addr::new(192, 168, 1, 1);
    let registry = RouterRegistry::new(gateway_ip);

    let mock_provider = Arc::new(MockRouterAdminProvider::new(gateway_ip));
    registry
        .connect("mock", mock_provider, "internal://mock-test")
        .expect("Connect should succeed");
    assert!(registry.is_connected());

    // Disconnect
    registry.disconnect();

    // Verify completely disconnected without falling back
    assert!(!registry.is_connected());
    assert_eq!(registry.active_provider_id(), None);
    assert!(!registry.is_authenticated());

    let status = registry.get_status();
    assert!(!status.is_connected);
    assert_eq!(status.endpoint, None);

    // All queries and operations must fail closed with UnsupportedOperation
    match registry.detect_identity() {
        Err(AdminError::UnsupportedOperation(msg)) => {
            assert!(msg.contains("No router provider is currently connected"));
        }
        other => panic!("Expected UnsupportedOperation, got {:?}", other),
    }

    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![Ipv4Addr::new(192, 168, 1, 100)]),
        PolicyDuration::Indefinite,
        PolicyPersistence::VolatileSession,
    );

    match registry.plan_operation(&req) {
        Err(AdminError::UnsupportedOperation(msg)) => {
            assert!(msg.contains("No router provider is currently connected"));
        }
        other => panic!("Expected UnsupportedOperation, got {:?}", other),
    }

    match registry.apply_policy(&req) {
        Err(AdminError::UnsupportedOperation(msg)) => {
            assert!(msg.contains("No router provider is currently connected"));
        }
        other => panic!("Expected UnsupportedOperation, got {:?}", other),
    }

    match registry.resume_policy(&req.scope) {
        Err(AdminError::UnsupportedOperation(msg)) => {
            assert!(msg.contains("No router provider is currently connected"));
        }
        other => panic!("Expected UnsupportedOperation, got {:?}", other),
    }

    match registry.reconcile_policies() {
        Err(AdminError::UnsupportedOperation(msg)) => {
            assert!(msg.contains("No router provider is currently connected"));
        }
        other => panic!("Expected UnsupportedOperation, got {:?}", other),
    }

    match registry.adjust_policy_duration(&req.scope, &PolicyDuration::Indefinite) {
        Err(AdminError::UnsupportedOperation(msg)) => {
            assert!(msg.contains("No router provider is currently connected"));
        }
        other => panic!("Expected UnsupportedOperation, got {:?}", other),
    }

    match registry.resume_all() {
        Err(AdminError::UnsupportedOperation(msg)) => {
            assert!(msg.contains("No router provider is currently connected"));
        }
        other => panic!("Expected UnsupportedOperation, got {:?}", other),
    }

    // Capability inspection returns unconfigured matrix
    let caps = registry.inspect_capabilities();
    assert!(!caps.ipv4_policy_enforcement.is_operational());
    assert!(!caps.read_only_discovery.is_operational());
}

#[test]
fn test_registry_lockout_prevention_for_gateway_and_controller() {
    let gateway_ip = Ipv4Addr::new(192, 168, 1, 1);
    let controller_ip = Ipv4Addr::new(192, 168, 1, 50);

    let registry = RouterRegistry::new(gateway_ip);
    registry.set_controller_ip(controller_ip);

    let mock_provider = Arc::new(MockRouterAdminProvider::new(gateway_ip));
    registry
        .connect("mock", mock_provider, "internal://mock-test")
        .expect("Connect should succeed");

    // 1. Attempting to target router gateway IP directly
    let gateway_req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![gateway_ip]),
        PolicyDuration::Indefinite,
        PolicyPersistence::VolatileSession,
    );
    match registry.apply_policy(&gateway_req) {
        Err(AdminError::LockoutPrevented(msg)) => {
            assert!(msg.contains("router gateway management interface"));
        }
        other => panic!("Expected LockoutPrevented for gateway, got {:?}", other),
    }

    // 2. Attempting to target controller host IP directly
    let controller_req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![controller_ip]),
        PolicyDuration::Indefinite,
        PolicyPersistence::VolatileSession,
    );
    match registry.apply_policy(&controller_req) {
        Err(AdminError::LockoutPrevented(msg)) => {
            assert!(msg.contains("controller host IP"));
        }
        other => panic!("Expected LockoutPrevented for controller, got {:?}", other),
    }

    // 3. Mixed list containing controller IP among client IPs
    let mixed_req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![
            Ipv4Addr::new(192, 168, 1, 100),
            controller_ip,
            Ipv4Addr::new(192, 168, 1, 101),
        ]),
        PolicyDuration::Indefinite,
        PolicyPersistence::VolatileSession,
    );
    match registry.apply_policy(&mixed_req) {
        Err(AdminError::LockoutPrevented(msg)) => {
            assert!(msg.contains("controller host IP"));
        }
        other => panic!("Expected LockoutPrevented for mixed list, got {:?}", other),
    }

    // 4. Safe target succeeds
    let safe_req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![Ipv4Addr::new(192, 168, 1, 100)]),
        PolicyDuration::Indefinite,
        PolicyPersistence::VolatileSession,
    );
    assert!(registry.apply_policy(&safe_req).is_ok());
}

#[test]
fn test_registry_duplicate_policy_rejection() {
    let gateway_ip = Ipv4Addr::new(192, 168, 1, 1);
    let registry = RouterRegistry::new(gateway_ip);

    let mock_provider = Arc::new(MockRouterAdminProvider::new(gateway_ip));
    registry
        .connect("mock", mock_provider, "internal://mock-test")
        .expect("Connect should succeed");

    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![Ipv4Addr::new(192, 168, 1, 100)]),
        PolicyDuration::Indefinite,
        PolicyPersistence::VolatileSession,
    );

    // Initial application succeeds
    let status = registry
        .apply_policy(&req)
        .expect("First apply should succeed");
    assert_eq!(status.scope, req.scope);

    // Attempting duplicate apply for the same active scope must be rejected
    match registry.apply_policy(&req) {
        Err(AdminError::DuplicatePolicy(msg)) => {
            assert!(msg.contains("already active on the router"));
        }
        other => panic!("Expected DuplicatePolicy, got {:?}", other),
    }

    // After resuming, re-applying succeeds
    registry
        .resume_policy(&req.scope)
        .expect("Resume should succeed");
    assert!(registry.apply_policy(&req).is_ok());
}

#[test]
fn test_registry_policy_lifecycle_metadata_enrichment() {
    let gateway_ip = Ipv4Addr::new(192, 168, 1, 1);
    let registry = RouterRegistry::new(gateway_ip);

    let mock_provider = Arc::new(MockRouterAdminProvider::new(gateway_ip));
    registry
        .connect("mock", mock_provider, "internal://mock-test")
        .expect("Connect should succeed");

    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![Ipv4Addr::new(192, 168, 1, 100)]),
        PolicyDuration::Temporary(Duration::from_secs(300)),
        PolicyPersistence::RouterPersistent,
    );

    let applied = registry.apply_policy(&req).expect("Apply should succeed");
    assert_eq!(
        applied.provider_name.as_deref(),
        Some("MockRouterAdminProvider")
    );
    assert!(applied.router_identity.is_some());

    // Query active policies via registry
    let policies = registry
        .query_active_policies()
        .expect("Query active should succeed");
    assert_eq!(policies.len(), 1);
    assert_eq!(
        policies[0].provider_name.as_deref(),
        Some("MockRouterAdminProvider")
    );
    assert!(policies[0].router_identity.is_some());
    assert_eq!(policies[0].lifecycle_state, PolicyLifecycleState::Active);

    // Test all standardized lifecycle states formatting and representation
    let states = vec![
        (PolicyLifecycleState::Planned, "PLANNED"),
        (
            PolicyLifecycleState::PendingApplication,
            "PENDING APPLICATION",
        ),
        (PolicyLifecycleState::Active, "ACTIVE"),
        (
            PolicyLifecycleState::ExpiredPendingRecovery,
            "EXPIRED (Pending Recovery)",
        ),
        (
            PolicyLifecycleState::RecoveryInProgress,
            "RECOVERY IN PROGRESS",
        ),
        (PolicyLifecycleState::Recovered, "RECOVERED"),
        (
            PolicyLifecycleState::Failed("Connection dropped".into()),
            "FAILED: Connection dropped",
        ),
        (PolicyLifecycleState::Unknown, "UNKNOWN"),
    ];

    for (state, expected_display) in states {
        assert_eq!(format!("{}", state), expected_display);
    }
}

#[test]
fn test_registry_unrecognized_provider_rejected() {
    let gateway_ip = Ipv4Addr::new(192, 168, 1, 1);
    let registry = RouterRegistry::new(gateway_ip);

    let mock_provider = Arc::new(MockRouterAdminProvider::new(gateway_ip));
    let err = registry
        .connect("cisco-ios-xe", mock_provider, "https://192.168.1.1")
        .expect_err("Unrecognized provider ID must be rejected");

    match err {
        AdminError::UnsupportedOperation(msg) => {
            assert!(msg.contains("Unrecognized provider ID 'cisco-ios-xe'"));
        }
        other => panic!("Expected UnsupportedOperation, got {:?}", other),
    }
}
