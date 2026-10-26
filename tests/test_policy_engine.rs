use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use rustrict::gateway::admin::{
    sanitize_error, sanitize_text, AdminError, MockRouterAdminProvider, MockUnifiTransport,
    OperationPlanRequest, PolicyDuration, PolicyExecutionEngine, PolicyLifecycleState,
    PolicyPersistence, PolicyScope, RouterAdminProvider, RouterRegistry, UnifiAdminProvider,
};

#[test]
fn test_engine_initialization_and_status() {
    let gateway_ip = Ipv4Addr::new(192, 168, 1, 1);
    let registry = Arc::new(RouterRegistry::new(gateway_ip));
    let engine = PolicyExecutionEngine::new(registry.clone());

    // Disconnected state
    assert!(!engine.is_authenticated());
    assert!(engine.execution_history().is_empty());

    // Connect mock provider
    let mock = Arc::new(MockRouterAdminProvider::new(gateway_ip));
    registry
        .connect("mock", mock, "internal://mock")
        .expect("Connect should succeed");

    assert!(engine.is_authenticated());
    let id = engine
        .detect_identity()
        .expect("Detect identity should succeed");
    assert_eq!(id.ip, gateway_ip);

    let caps = engine.inspect_capabilities();
    assert!(caps.ipv4_policy_enforcement.is_operational());
}

#[test]
fn test_engine_fails_closed_when_disconnected() {
    let gateway_ip = Ipv4Addr::new(192, 168, 1, 1);
    let registry = Arc::new(RouterRegistry::new(gateway_ip));
    let engine = PolicyExecutionEngine::new(registry);

    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![Ipv4Addr::new(192, 168, 1, 100)]),
        PolicyDuration::Indefinite,
        PolicyPersistence::VolatileSession,
    );

    // Apply fails closed
    match engine.apply_policy(&req) {
        Err(AdminError::UnsupportedOperation(msg)) => {
            assert!(msg.contains("No router provider is currently connected"));
        }
        other => panic!("Expected UnsupportedOperation, got {:?}", other),
    }

    // Plan fails closed
    match engine.plan_policy(&req) {
        Err(AdminError::UnsupportedOperation(msg)) => {
            assert!(msg.contains("No router provider is currently connected"));
        }
        other => panic!("Expected UnsupportedOperation, got {:?}", other),
    }

    // Resume fails closed
    match engine.resume_policy(&req.scope) {
        Err(AdminError::UnsupportedOperation(msg)) => {
            assert!(msg.contains("No router provider is currently connected"));
        }
        other => panic!("Expected UnsupportedOperation, got {:?}", other),
    }

    // Adjust fails closed
    match engine.adjust_policy_duration(&req.scope, &PolicyDuration::Indefinite) {
        Err(AdminError::UnsupportedOperation(msg)) => {
            assert!(msg.contains("No router provider is currently connected"));
        }
        other => panic!("Expected UnsupportedOperation, got {:?}", other),
    }

    // Reconcile fails closed
    match engine.reconcile_policies() {
        Err(AdminError::UnsupportedOperation(msg)) => {
            assert!(msg.contains("No router provider is currently connected"));
        }
        other => panic!("Expected UnsupportedOperation, got {:?}", other),
    }
}

#[test]
fn test_engine_lockout_protection_for_gateway_and_controller() {
    let gateway_ip = Ipv4Addr::new(192, 168, 1, 1);
    let controller_ip = Ipv4Addr::new(192, 168, 1, 50);

    let registry = Arc::new(RouterRegistry::new(gateway_ip));
    registry.set_controller_ip(controller_ip);

    let mock = Arc::new(MockRouterAdminProvider::new(gateway_ip));
    registry
        .connect("mock", mock, "internal://mock")
        .expect("Connect should succeed");

    let engine = PolicyExecutionEngine::new(registry);

    // 1. Target matches gateway IP
    let req_gateway = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![gateway_ip]),
        PolicyDuration::Indefinite,
        PolicyPersistence::VolatileSession,
    );
    match engine.apply_policy(&req_gateway) {
        Err(AdminError::LockoutPrevented(msg)) => {
            assert!(msg.contains("router gateway management interface"));
        }
        other => panic!("Expected LockoutPrevented, got {:?}", other),
    }

    // 2. Target matches controller IP
    let req_ctrl = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![controller_ip]),
        PolicyDuration::Indefinite,
        PolicyPersistence::VolatileSession,
    );
    match engine.apply_policy(&req_ctrl) {
        Err(AdminError::LockoutPrevented(msg)) => {
            assert!(msg.contains("controller host IP"));
        }
        other => panic!("Expected LockoutPrevented, got {:?}", other),
    }

    // 3. Innocent target succeeds
    let req_ok = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![Ipv4Addr::new(192, 168, 1, 100)]),
        PolicyDuration::Indefinite,
        PolicyPersistence::VolatileSession,
    );
    assert!(engine.apply_policy(&req_ok).is_ok());
}

#[test]
fn test_engine_capability_preflight_rejection_of_temporary_policy() {
    let gateway_ip = Ipv4Addr::new(192, 168, 1, 1);
    let registry = Arc::new(RouterRegistry::new(gateway_ip));

    // Connect a mock UniFi provider (which does NOT support autonomous timed recovery)
    let mock_transport = Box::new(MockUnifiTransport::default());
    let unifi_provider = Arc::new(
        UnifiAdminProvider::new(gateway_ip, "https://192.168.1.1:443")
            .with_transport(mock_transport),
    );
    unifi_provider.set_credentials(rustrict::gateway::admin::RouterCredentials::new(
        "admin",
        "admin_password",
    ));

    registry
        .connect("unifi-rest", unifi_provider, "https://192.168.1.1:443")
        .expect("Connect to unifi should succeed");

    let engine = PolicyExecutionEngine::new(registry);

    // Request temporary policy
    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![Ipv4Addr::new(192, 168, 1, 100)]),
        PolicyDuration::Temporary(Duration::from_secs(600)),
        PolicyPersistence::RouterPersistent,
    );

    // Engine MUST reject before mutating router
    match engine.apply_policy(&req) {
        Err(AdminError::UnsupportedOperation(msg)) => {
            assert!(msg.contains("does not support autonomous router-side timed recovery"));
            assert!(msg.contains("unifi-rest"));
        }
        other => panic!("Expected UnsupportedOperation, got {:?}", other),
    }

    // Verify no policy was marked active or recorded in provider state
    let active = engine
        .query_active_policies()
        .expect("Query active should succeed");
    assert!(
        active.is_empty(),
        "No policy should be active after preflight rejection"
    );
}

#[test]
fn test_engine_duplicate_policy_rejection() {
    let gateway_ip = Ipv4Addr::new(192, 168, 1, 1);
    let registry = Arc::new(RouterRegistry::new(gateway_ip));
    let mock = Arc::new(MockRouterAdminProvider::new(gateway_ip));
    registry
        .connect("mock", mock, "internal://mock")
        .expect("Connect should succeed");

    let engine = PolicyExecutionEngine::new(registry);

    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![Ipv4Addr::new(192, 168, 1, 100)]),
        PolicyDuration::Indefinite,
        PolicyPersistence::VolatileSession,
    );

    let status = engine
        .apply_policy(&req)
        .expect("First apply should succeed");
    assert_eq!(status.scope, req.scope);

    // Duplicate apply must be rejected
    match engine.apply_policy(&req) {
        Err(AdminError::DuplicatePolicy(msg)) => {
            assert!(msg.contains("already active on the router"));
        }
        other => panic!("Expected DuplicatePolicy, got {:?}", other),
    }
}

#[test]
fn test_engine_no_policy_active_on_failure_and_history_logging() {
    let gateway_ip = Ipv4Addr::new(192, 168, 1, 1);
    let registry = Arc::new(RouterRegistry::new(gateway_ip));

    let mock = Arc::new(MockRouterAdminProvider::new(gateway_ip));

    registry
        .connect("mock", mock.clone(), "internal://mock")
        .expect("Connect should succeed");

    // Simulate error during mutation
    mock.set_simulate_transaction_failure(true);

    let engine = PolicyExecutionEngine::new(registry);

    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![Ipv4Addr::new(192, 168, 1, 100)]),
        PolicyDuration::Indefinite,
        PolicyPersistence::VolatileSession,
    );

    let err = engine
        .apply_policy(&req)
        .expect_err("Apply must fail due to simulated transaction failure");
    match err {
        AdminError::TransactionFailed(msg) => {
            assert!(msg.contains("Simulated transaction failure"));
        }
        other => panic!("Expected TransactionFailed, got {:?}", other),
    }

    // Verify policy is NOT active
    let active = engine
        .query_active_policies()
        .expect("Query should succeed");
    assert!(
        active.is_empty(),
        "Policy must NOT be reported as active when application fails"
    );

    // Verify execution history recorded the failure
    let history = engine.execution_history();
    assert_eq!(history.len(), 1);
    assert_eq!(
        history[0].initial_state,
        PolicyLifecycleState::PendingApplication
    );
    assert!(matches!(
        history[0].final_state,
        PolicyLifecycleState::Failed(_)
    ));
    assert!(history[0].error.is_some());
}

#[test]
fn test_credential_sanitization_in_errors_and_text() {
    let raw_err =
        "Failed communicating with router: password=MySecretAdminPassword123! token=bearer_xyz_789";
    let sanitized = sanitize_text(raw_err);
    assert!(!sanitized.contains("MySecretAdminPassword123!"));
    assert!(!sanitized.contains("bearer_xyz_789"));
    assert!(sanitized.contains("[REDACTED]"));

    let auth_header_err =
        "HTTP 401 Unauthorized for Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.secret";
    let sanitized_auth = sanitize_text(auth_header_err);
    assert!(!sanitized_auth.contains("eyJhbGciOiJIUzI1NiJ9.secret"));
    assert!(sanitized_auth.contains("[REDACTED]"));

    let typed_err = AdminError::AuthenticationFailed(
        "Invalid credentials: password: 'SuperSecretPassword' for user 'admin'".to_string(),
    );
    let sanitized_typed = sanitize_error(typed_err);
    match sanitized_typed {
        AdminError::AuthenticationFailed(msg) => {
            assert!(!msg.contains("SuperSecretPassword"));
            assert!(msg.contains("[REDACTED]"));
        }
        other => panic!("Expected AuthenticationFailed, got {:?}", other),
    }
}

#[test]
fn test_engine_lifecycle_tracking_through_full_cycle() {
    let gateway_ip = Ipv4Addr::new(192, 168, 1, 1);
    let registry = Arc::new(RouterRegistry::new(gateway_ip));
    let mock = Arc::new(MockRouterAdminProvider::new(gateway_ip));
    registry
        .connect("mock", mock, "internal://mock")
        .expect("Connect should succeed");

    let engine = PolicyExecutionEngine::new(registry);

    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![Ipv4Addr::new(192, 168, 1, 100)]),
        PolicyDuration::Temporary(Duration::from_secs(300)),
        PolicyPersistence::RouterPersistent,
    );

    // 1. Apply
    let applied = engine.apply_policy(&req).expect("Apply should succeed");
    assert_eq!(applied.lifecycle_state, PolicyLifecycleState::Active);
    assert_eq!(
        applied.provider_name.as_deref(),
        Some("Mock Router Provider")
    );

    // 2. Adjust
    let new_dur = PolicyDuration::Temporary(Duration::from_secs(900));
    let adjusted = engine
        .adjust_policy_duration(&req.scope, &new_dur)
        .expect("Adjust should succeed");
    assert_eq!(adjusted.lifecycle_state, PolicyLifecycleState::Active);

    // 3. Resume
    let resumed = engine
        .resume_policy(&req.scope)
        .expect("Resume should succeed");
    assert_eq!(resumed.len(), 1);

    // Check history contains all transitions
    let history = engine.execution_history();
    assert_eq!(history.len(), 3);
    assert_eq!(history[0].operation, "apply");
    assert_eq!(history[0].final_state, PolicyLifecycleState::Active);
    assert_eq!(history[1].operation, "adjust");
    assert_eq!(history[1].final_state, PolicyLifecycleState::Active);
    assert_eq!(history[2].operation, "resume");
    assert_eq!(history[2].final_state, PolicyLifecycleState::Recovered);
}
