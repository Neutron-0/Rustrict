use std::net::Ipv4Addr;
use std::time::Duration;

use rustrict::core::scope::{Ipv4Cidr, ScopeManager};
use rustrict::gateway::admin::{
    ActivePolicyStatus, AdminError, CapabilityClassification, MockRouterAdminProvider,
    OperationPlanRequest, PolicyDuration, PolicyPersistence, PolicyScope, RouterAdminProvider,
    RouterCapabilityMatrix,
};

#[test]
fn test_capability_classification_baseline() {
    let baseline = RouterCapabilityMatrix::current_rustrict_core_baseline();

    assert_eq!(
        baseline.read_only_discovery,
        CapabilityClassification::UnitTested
    );
    assert_eq!(
        baseline.host_inventory,
        CapabilityClassification::UnitTested
    );
    assert_eq!(
        baseline.device_identification_interface_type,
        CapabilityClassification::UnitTested
    );
    assert!(matches!(
        baseline.ipv4_policy_enforcement,
        CapabilityClassification::Conditional(_)
    ));
    assert_eq!(
        baseline.ipv6_policy_enforcement,
        CapabilityClassification::NotImplemented
    );
    assert!(matches!(
        baseline.per_device_access_policy,
        CapabilityClassification::Conditional(_)
    ));
    assert!(matches!(
        baseline.network_wide_access_policy,
        CapabilityClassification::Conditional(_)
    ));
    assert_eq!(
        baseline.authenticated_admin_interfaces,
        CapabilityClassification::NotImplemented
    );
    assert_eq!(
        baseline.timed_policy_auto_recovery,
        CapabilityClassification::NotImplemented
    );
    assert_eq!(
        baseline.persistence_after_app_exit,
        CapabilityClassification::NotImplemented
    );
    assert_eq!(
        baseline.persistence_after_host_shutdown,
        CapabilityClassification::NotImplemented
    );

    // Verify Display formatting adheres to required uppercase audit taxonomy
    assert_eq!(
        format!("{}", CapabilityClassification::Implemented),
        "IMPLEMENTED"
    );
    assert_eq!(
        format!("{}", CapabilityClassification::UnitTested),
        "UNIT-TESTED"
    );
    assert_eq!(
        format!("{}", CapabilityClassification::LabVerified),
        "LAB-VERIFIED"
    );
    assert_eq!(
        format!("{}", CapabilityClassification::RouterVerified),
        "ROUTER-VERIFIED"
    );
    assert_eq!(
        format!("{}", CapabilityClassification::Conditional("test".into())),
        "CONDITIONAL: test"
    );
    assert_eq!(
        format!("{}", CapabilityClassification::NotImplemented),
        "NOT IMPLEMENTED"
    );
    assert_eq!(
        format!("{}", CapabilityClassification::Unknown("test".into())),
        "UNKNOWN: test"
    );
}

#[test]
fn test_mock_provider_identity_detection() {
    let gw_ip = Ipv4Addr::new(192, 168, 1, 1);
    let provider = MockRouterAdminProvider::new(gw_ip);

    assert_eq!(provider.name(), "MockRouterAdminProvider");
    assert!(provider.is_authenticated());

    let identity = provider.detect_identity().expect("Identity should resolve");
    assert_eq!(identity.ip, gw_ip);
    assert_eq!(identity.manufacturer.as_deref(), Some("MockNetworks"));
}

#[test]
fn test_mock_provider_identity_mismatch_detection() {
    let gw_ip = Ipv4Addr::new(192, 168, 1, 1);
    let provider = MockRouterAdminProvider::new(gw_ip);
    provider.set_force_identity_mismatch(true);

    let err = provider
        .detect_identity()
        .expect_err("Should trigger identity mismatch");
    assert!(
        matches!(err, AdminError::IdentityMismatch(_)),
        "Expected IdentityMismatch error, got {:?}",
        err
    );

    // Operation planning must fail before planning if identity mismatch is active
    let req = OperationPlanRequest::new(
        PolicyScope::NetworkWide,
        PolicyDuration::Indefinite,
        PolicyPersistence::VolatileSession,
    );
    let plan_err = provider
        .plan_operation(&req)
        .expect_err("Planning should fail on identity mismatch");
    assert!(matches!(plan_err, AdminError::IdentityMismatch(_)));
}

#[test]
fn test_mock_provider_auth_failure() {
    let gw_ip = Ipv4Addr::new(192, 168, 1, 1);
    let provider = MockRouterAdminProvider::new(gw_ip);
    provider.set_authenticated(false);

    assert!(!provider.is_authenticated());

    let req = OperationPlanRequest::new(
        PolicyScope::NetworkWide,
        PolicyDuration::Indefinite,
        PolicyPersistence::VolatileSession,
    );
    let err = provider
        .plan_operation(&req)
        .expect_err("Planning should fail on auth error");
    assert!(
        matches!(err, AdminError::AuthenticationFailed(_)),
        "Expected AuthenticationFailed error, got {:?}",
        err
    );
}

#[test]
fn test_mock_provider_session_expired() {
    let gw_ip = Ipv4Addr::new(192, 168, 1, 1);
    let provider = MockRouterAdminProvider::new(gw_ip);
    provider.set_session_expired(true);

    let req = OperationPlanRequest::new(
        PolicyScope::NetworkWide,
        PolicyDuration::Indefinite,
        PolicyPersistence::VolatileSession,
    );
    let err = provider
        .plan_operation(&req)
        .expect_err("Planning should fail on expired session");
    assert!(
        matches!(err, AdminError::SessionExpired(_)),
        "Expected SessionExpired error, got {:?}",
        err
    );
}

#[test]
fn test_mock_provider_timeout_simulation() {
    let gw_ip = Ipv4Addr::new(192, 168, 1, 1);
    let provider = MockRouterAdminProvider::new(gw_ip);
    provider.set_force_timeout(true);

    let err = provider
        .detect_identity()
        .expect_err("Detect identity should time out");
    assert!(
        matches!(err, AdminError::Timeout(_)),
        "Expected Timeout error, got {:?}",
        err
    );

    let req = OperationPlanRequest::new(
        PolicyScope::NetworkWide,
        PolicyDuration::Indefinite,
        PolicyPersistence::VolatileSession,
    );
    let plan_err = provider
        .plan_operation(&req)
        .expect_err("Planning should time out");
    assert!(matches!(plan_err, AdminError::Timeout(_)));
}

#[test]
fn test_mock_provider_unsupported_operation() {
    let gw_ip = Ipv4Addr::new(192, 168, 1, 1);
    let provider = MockRouterAdminProvider::new(gw_ip).with_unsupported_state();

    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![Ipv4Addr::new(192, 168, 1, 55)]),
        PolicyDuration::Indefinite,
        PolicyPersistence::VolatileSession,
    );

    let err = provider
        .plan_operation(&req)
        .expect_err("Planning selective pause without capability should fail");
    assert!(
        matches!(err, AdminError::UnsupportedOperation(_)),
        "Expected UnsupportedOperation, got {:?}",
        err
    );
}

#[test]
fn test_mock_provider_dry_run_network_wide() {
    let gw_ip = Ipv4Addr::new(192, 168, 1, 1);
    let provider = MockRouterAdminProvider::new(gw_ip);

    let req = OperationPlanRequest::new(
        PolicyScope::NetworkWide,
        PolicyDuration::Temporary(Duration::from_secs(300)),
        PolicyPersistence::VolatileSession,
    );

    let plan = provider
        .plan_operation(&req)
        .expect("Dry run planning should succeed");

    assert!(plan.is_dry_run);
    assert!(plan.management_plane_safe);
    assert_eq!(plan.target_scope, PolicyScope::NetworkWide);
    assert_eq!(
        plan.duration,
        PolicyDuration::Temporary(Duration::from_secs(300))
    );
    assert_eq!(plan.persistence, PolicyPersistence::VolatileSession);
    assert!(
        plan.expected_lan_impact.contains("LAN communication")
            || plan.expected_lan_impact.contains("100% accessible")
    );
    assert!(
        plan.recovery_mechanism.contains("auto-expiration")
            || plan.recovery_mechanism.contains("watchdog")
    );
    assert!(!plan.uncertainties_and_risks.is_empty());
}

#[test]
fn test_mock_provider_dry_run_specific_targets() {
    let gw_ip = Ipv4Addr::new(192, 168, 1, 1);
    let provider = MockRouterAdminProvider::new(gw_ip);
    let target = Ipv4Addr::new(192, 168, 1, 42);

    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![target]),
        PolicyDuration::Indefinite,
        PolicyPersistence::RouterPersistent,
    );

    let plan = provider
        .plan_operation(&req)
        .expect("Dry run planning should succeed");

    assert!(plan.is_dry_run);
    assert!(plan.management_plane_safe);
    assert_eq!(plan.target_count, 1);
    assert_eq!(plan.persistence, PolicyPersistence::RouterPersistent);
}

#[test]
fn test_mock_provider_active_policies() {
    let gw_ip = Ipv4Addr::new(192, 168, 1, 1);
    let provider = MockRouterAdminProvider::new(gw_ip);

    // Initially empty
    let initial = provider
        .query_active_policies()
        .expect("Should query empty policies");
    assert!(initial.is_empty());

    // Inject simulated active policy
    let policy = ActivePolicyStatus::new(
        "pol-test-101",
        PolicyScope::NetworkWide,
        1700000000,
        Some(1700000300),
        false,
        "SimulatedGatewayIptables",
        true,
    );
    provider.add_mock_active_policy(policy);

    let active = provider
        .query_active_policies()
        .expect("Should query active policy");
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].policy_id, "pol-test-101");
    assert_eq!(active[0].scope, PolicyScope::NetworkWide);
    assert!(!active[0].is_persistent);

    provider.active_policies.write().clear();
    let after_clear = provider
        .query_active_policies()
        .expect("Should query cleared policies");
    assert!(after_clear.is_empty());
}

#[test]
fn test_scope_exclusion_integration() {
    let mut scope = ScopeManager::default();
    let cidr = "192.168.1.0/24".parse::<Ipv4Cidr>().unwrap();
    scope.add_cidr_direct(cidr);
    scope.set_strict(true);

    let allowed_target = Ipv4Addr::new(192, 168, 1, 50);
    let excluded_target = Ipv4Addr::new(192, 168, 1, 100);
    scope.exclude_ip(excluded_target);

    // Allowed target passes validation
    assert!(scope.validate_target(&allowed_target, None).is_ok());

    // Excluded target fails validation
    let err = scope.validate_target(&excluded_target, None);
    assert!(err.is_err(), "Excluded target must fail scope validation");
    let err_str = err.err().unwrap().to_string();
    assert!(
        err_str.contains("excluded"),
        "Unexpected error: {}",
        err_str
    );

    // Out of subnet target in strict mode fails
    let out_of_subnet = Ipv4Addr::new(10, 0, 0, 1);
    assert!(scope.validate_target(&out_of_subnet, None).is_err());
}

#[test]
fn test_startup_disconnected_and_explicit_mock_connection() {
    use rustrict::gateway::admin::{PolicyExecutionEngine, RouterRegistry};

    let gw = Ipv4Addr::new(192, 168, 1, 1);
    let registry = std::sync::Arc::new(RouterRegistry::new(gw));
    let engine = PolicyExecutionEngine::new(registry.clone());

    // SEC-02 Verification: Registry starts disconnected by default
    assert!(!registry.is_connected(), "Registry must start disconnected");
    assert!(registry.active_provider().is_none());
    assert!(registry.active_provider_id().is_none());

    // Policy requests fail closed when disconnected
    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![Ipv4Addr::new(192, 168, 1, 50)]),
        PolicyDuration::Indefinite,
        PolicyPersistence::VolatileSession,
    );
    let plan_res = engine.plan_policy(&req);
    assert!(
        plan_res.is_err(),
        "Planning must fail closed when disconnected"
    );
    let apply_res = engine.apply_policy(&req);
    assert!(
        apply_res.is_err(),
        "Applying policy must fail closed when disconnected"
    );

    // Explicit connection to mock provider
    let mock = std::sync::Arc::new(MockRouterAdminProvider::new(gw));
    let conn_res = registry.connect("mock", mock, "internal://mock");
    assert!(conn_res.is_ok(), "Explicit mock connection must succeed");
    assert!(registry.is_connected());
    assert_eq!(registry.active_provider_id().as_deref(), Some("mock"));
}
