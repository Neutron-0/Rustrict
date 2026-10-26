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
fn test_unicode_safe_redaction_and_offset_preservation() {
    let secret_markers = [
        "SecretPass123",
        "TurkishSecret123",
        "GermanSecret456",
        "GreekSecret789",
        "EmojiSecret999",
        "EndOfStringSecret",
        "PassOne",
        "TokenTwo",
        "SecretThree",
        "QuotedSecret",
        "SingleQuotedSecret",
        "SpacedSecret",
        "BearerSecretToken",
        "BasicEncodedSecret",
        "BearerInQuotes",
        "UrlPassword123",
        "QuerySecret456",
    ];

    // 1. ASCII preceded
    let t1 = "router=ok&password=SecretPass123";
    let s1 = sanitize_text(t1);
    assert!(s1.contains("password=[REDACTED]"));
    assert!(!s1.contains("SecretPass123"));

    // 2. Unicode characters whose lowercase conversion alters byte lengths
    // Turkish \u{0130} (İ) -> i\u{0307} in Unicode to_lowercase (2 bytes -> 3 bytes)
    let t2 = "Hata \u{0130}stanbul router: password=TurkishSecret123";
    let s2 = sanitize_text(t2);
    assert!(s2.contains("password=[REDACTED]"));
    assert!(s2.contains("\u{0130}stanbul"));
    assert!(!s2.contains("TurkishSecret123"));

    // German capital sharp S \u{1E9E} (ẞ) -> ß in Unicode to_lowercase (3 bytes -> 2 bytes)
    let t3 = "Fehler GRO\u{1E9E}: token=GermanSecret456";
    let s3 = sanitize_text(t3);
    assert!(s3.contains("token=[REDACTED]"));
    assert!(s3.contains("GRO\u{1E9E}"));
    assert!(!s3.contains("GermanSecret456"));

    // Greek capital Sigma \u{03A3}
    let t4 = "Router \u{03A3}: api_key=GreekSecret789";
    let s4 = sanitize_text(t4);
    assert!(s4.contains("api_key=[REDACTED]"));
    assert!(s4.contains("\u{03A3}"));
    assert!(!s4.contains("GreekSecret789"));

    // 3. Emoji and multibyte in adjacent diagnostic text
    let t5 = "🔑 Router auth failed: auth_token=EmojiSecret999 🚀 Please retry";
    let s5 = sanitize_text(t5);
    assert!(s5.contains("🔑 Router auth failed: auth_token=[REDACTED] 🚀 Please retry"));
    assert!(!s5.contains("EmojiSecret999"));

    // 4. Secret at the end of a string
    let t6 = "status=fail&pwd=EndOfStringSecret";
    let s6 = sanitize_text(t6);
    assert_eq!(s6, "status=fail&pwd=[REDACTED]");
    assert!(!s6.contains("EndOfStringSecret"));

    // 5. Multiple credentials in one message
    let t7 = "user=admin&password=PassOne&token=TokenTwo&secret=SecretThree&status=ok";
    let s7 = sanitize_text(t7);
    assert_eq!(
        s7,
        "user=admin&password=[REDACTED]&token=[REDACTED]&secret=[REDACTED]&status=ok"
    );
    assert!(!s7.contains("PassOne"));
    assert!(!s7.contains("TokenTwo"));
    assert!(!s7.contains("SecretThree"));

    // 6. Case variations and spacing variations
    let t8 = "Config: PASSWORD  :   \"QuotedSecret\", PassWd = 'SingleQuotedSecret', apikey = SpacedSecret";
    let s8 = sanitize_text(t8);
    assert!(s8.contains("PASSWORD  :   \"[REDACTED]\""));
    assert!(s8.contains("PassWd = '[REDACTED]'"));
    assert!(s8.contains("apikey = [REDACTED]"));
    assert!(!s8.contains("QuotedSecret"));
    assert!(!s8.contains("SingleQuotedSecret"));
    assert!(!s8.contains("SpacedSecret"));

    // 7. Authorization Bearer and Basic headers
    let t9 = "Headers: Authorization: Bearer BearerSecretToken, Authorization: Basic BasicEncodedSecret, BEARER \"BearerInQuotes\"";
    let s9 = sanitize_text(t9);
    assert!(s9.contains("Authorization: Bearer [REDACTED]"));
    assert!(s9.contains("Authorization: Basic [REDACTED]"));
    assert!(s9.contains("BEARER \"[REDACTED]\""));
    assert!(!s9.contains("BearerSecretToken"));
    assert!(!s9.contains("BasicEncodedSecret"));
    assert!(!s9.contains("BearerInQuotes"));

    // 8. URL userinfo credentials and query parameters
    let t10 = "Endpoint: https://admin:UrlPassword123@192.168.1.1:8443/api?token=QuerySecret456";
    let s10 = sanitize_text(t10);
    assert!(s10.contains("https://admin:[REDACTED]@192.168.1.1:8443/api?token=[REDACTED]"));
    assert!(!s10.contains("UrlPassword123"));
    assert!(!s10.contains("QuerySecret456"));

    // 9. Repeated sanitization (idempotency check)
    let s10_repeated = sanitize_text(&s10);
    assert_eq!(s10, s10_repeated);

    let repeated_raw = "password=[REDACTED]&token=[REDACTED]&secret=[REDACTED]";
    assert_eq!(sanitize_text(repeated_raw), repeated_raw);

    // Verify non-secret words containing substrings are preserved
    let non_secret = "Tokenizer processing 42 tokens for stakeholder with token_id=100";
    let s_non_secret = sanitize_text(non_secret);
    assert_eq!(s_non_secret, non_secret);

    // Double check none of the secret markers survived in any sanitized string
    let all_sanitized = format!("{s1} {s2} {s3} {s4} {s5} {s6} {s7} {s8} {s9} {s10}");
    for marker in &secret_markers {
        assert!(
            !all_sanitized.contains(marker),
            "Secret marker '{}' survived sanitization!",
            marker
        );
    }
}

#[test]
fn test_admin_error_sanitization_covers_all_variants_no_panic() {
    let variants = vec![
        AdminError::UnsupportedOperation("Unsupported: password=Secret1".to_string()),
        AdminError::AuthenticationFailed("Auth failed: token=Secret2".to_string()),
        AdminError::SessionExpired("Session expired: Bearer Secret3".to_string()),
        AdminError::IdentityMismatch("Mismatch at https://user:Secret4@router/".to_string()),
        AdminError::Timeout("Timeout with secret=Secret5".to_string()),
        AdminError::CommunicationError("Comm error: Basic Secret6".to_string()),
        AdminError::ScopeViolation("Scope invalid: api_key=Secret7".to_string()),
        AdminError::LockoutPrevented("Lockout check: pwd=Secret8".to_string()),
        AdminError::DuplicatePolicy("Duplicate: apikey=Secret9".to_string()),
        AdminError::PolicyNotFound("Policy 404: token=Secret10".to_string()),
        AdminError::TransactionFailed("Tx failed: password=Secret11".to_string()),
        AdminError::RollbackFailed {
            applied_targets: vec!["192.168.1.100?token=Secret12".to_string()],
            failed_target: "192.168.1.101?password=Secret13".to_string(),
            original_error: "Fail with Bearer Secret14".to_string(),
            rollback_errors: vec!["Rollback timeout: secret=Secret15".to_string()],
        },
        AdminError::SecurityViolation("Security violation: api-key=Secret16".to_string()),
    ];

    for err in variants {
        let sanitized = sanitize_error(err);
        let err_str = sanitized.to_string();
        for i in 1..=16 {
            let secret = format!("Secret{i}");
            assert!(
                !err_str.contains(&secret),
                "Secret '{}' leaked in AdminError display: {}",
                secret,
                err_str
            );
        }
        assert!(
            err_str.contains("[REDACTED]"),
            "Sanitized error did not contain [REDACTED]: {}",
            err_str
        );
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

#[test]
fn test_plan_policy_makes_zero_mutating_calls_and_preserves_clean_state() {
    let gateway_ip = Ipv4Addr::new(192, 168, 1, 1);
    let registry = Arc::new(RouterRegistry::new(gateway_ip));
    let engine = PolicyExecutionEngine::new(registry.clone());

    let mock = Arc::new(MockRouterAdminProvider::new(gateway_ip));
    registry
        .connect("mock", mock, "internal://mock")
        .expect("Connect mock");

    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![Ipv4Addr::new(192, 168, 1, 100)]),
        PolicyDuration::Temporary(Duration::from_secs(300)),
        PolicyPersistence::VolatileSession,
    );

    // Run plan
    let plan = engine.plan_policy(&req).expect("Plan should succeed");
    assert!(plan.is_dry_run);
    assert_eq!(plan.target_count, 1);

    // Verify zero mutations occurred
    assert!(engine.query_active_policies().expect("query").is_empty());
    assert!(engine.execution_history().is_empty());
    assert!(engine.store().historical_policies().is_empty());
}

#[test]
fn test_preflight_surfaces_prior_partial_failure_and_unknown_state() {
    let gateway_ip = Ipv4Addr::new(192, 168, 1, 1);
    let registry = Arc::new(RouterRegistry::new(gateway_ip));
    let engine = PolicyExecutionEngine::new(registry.clone());

    let mock = Arc::new(MockRouterAdminProvider::new(gateway_ip));
    registry
        .connect("mock", mock, "internal://mock")
        .expect("Connect mock");

    // Manually record an un-reconciled partial failure in store
    let partial_failure_policy = rustrict::gateway::admin::ActivePolicyStatus::new(
        "pol-unresolved-123",
        PolicyScope::SpecificTargets(vec![Ipv4Addr::new(192, 168, 1, 101)]),
        1700000000,
        None,
        false,
        "Firewall",
        false,
    )
    .with_state(PolicyLifecycleState::PartialFailure {
        applied_targets: vec!["192.168.1.101".into()],
        failed_target: "192.168.1.102".into(),
        rollback_errors: vec!["SSH timeout during rollback".into()],
    });

    engine
        .store()
        .update_policy_status(&partial_failure_policy)
        .expect("Record partial failure");

    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![Ipv4Addr::new(192, 168, 1, 200)]),
        PolicyDuration::Indefinite,
        PolicyPersistence::VolatileSession,
    );

    let plan = engine.plan_policy(&req).expect("Plan succeeds");
    let has_partial_warning = plan.uncertainties_and_risks.iter().any(|w| {
        w.contains("PRIOR UNRESOLVED PARTIAL FAILURE") && w.contains("pol-unresolved-123")
    });
    assert!(
        has_partial_warning,
        "Expected prior partial failure warning in plan risks: {:?}",
        plan.uncertainties_and_risks
    );

    let preflight = engine.preflight_mutation(&req).expect("Preflight succeeds");
    assert!(preflight.has_unreconciled_partial_failure);
    assert_eq!(preflight.prior_failures.len(), 1);
    assert!(preflight.prior_failures[0].contains("pol-unresolved-123"));
}

#[test]
fn test_preflight_surfaces_target_overlap_conflicts() {
    let gateway_ip = Ipv4Addr::new(192, 168, 1, 1);
    let registry = Arc::new(RouterRegistry::new(gateway_ip));
    let engine = PolicyExecutionEngine::new(registry.clone());

    let mock = Arc::new(MockRouterAdminProvider::new(gateway_ip));
    registry
        .connect("mock", mock, "internal://mock")
        .expect("Connect mock");

    // Apply an active policy on 192.168.1.100
    let target = Ipv4Addr::new(192, 168, 1, 100);
    let req1 = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![target]),
        PolicyDuration::Indefinite,
        PolicyPersistence::VolatileSession,
    );
    let active = engine.apply_policy(&req1).expect("Apply policy 1");
    assert_eq!(active.lifecycle_state, PolicyLifecycleState::Active);

    // Preflight for a second request that targets the same IP
    let plan = engine.plan_policy(&req1).expect("Plan policy");
    let has_overlap = plan
        .uncertainties_and_risks
        .iter()
        .any(|w| w.contains("TARGET OVERLAP") && w.contains("192.168.1.100"));
    assert!(
        has_overlap,
        "Expected TARGET OVERLAP warning in plan risks: {:?}",
        plan.uncertainties_and_risks
    );

    // Preflight for a network-wide request which overlaps with existing target
    let req_net = OperationPlanRequest::new(
        PolicyScope::NetworkWide,
        PolicyDuration::Indefinite,
        PolicyPersistence::VolatileSession,
    );
    let plan_net = engine.plan_policy(&req_net).expect("Plan net");
    let has_net_overlap = plan_net
        .uncertainties_and_risks
        .iter()
        .any(|w| w.contains("TARGET OVERLAP: Network-wide policy will overlap"));
    assert!(
        has_net_overlap,
        "Expected network-wide overlap warning in plan risks: {:?}",
        plan_net.uncertainties_and_risks
    );
}
