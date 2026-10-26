use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use rustrict::cli::table::{render_router_policy_detail, render_router_unified_policies_table};
use rustrict::gateway::admin::{
    ActivePolicyStatus, AdminError, MockOpenWrtTransport, MockRouterAdminProvider,
    MockUnifiTransport, OpenWrtAdminProvider, OperationPlanRequest, PolicyConfirmationState,
    PolicyDuration, PolicyExecutionEngine, PolicyLifecycleState, PolicyPersistence,
    PolicyRecoveryStatus, PolicyScope, RecoveryMechanism, RouterRegistry, UnifiAdminProvider,
    UnifiedPolicyEntry,
};

#[test]
fn test_policy_table_formatting_across_lifecycle_states() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let policies = vec![
        UnifiedPolicyEntry {
            policy_id: "pol-01-active".into(),
            provider_id: "mock".into(),
            provider_name: "Mock Provider".into(),
            scope: PolicyScope::SpecificTargets(vec![Ipv4Addr::new(192, 168, 1, 100)]),
            lifecycle_state: PolicyLifecycleState::Active,
            duration: PolicyDuration::Temporary(Duration::from_secs(300)),
            is_persistent: true,
            applied_at_unix: now - 60,
            expires_at_unix: Some(now + 240),
            enforcement_point: "Firewall Filter".into(),
            recovery_status: PolicyRecoveryStatus::InstalledAndConfirmed(
                RecoveryMechanism::RouterWatchdog,
            ),
            last_execution_result: Some("Active".into()),
            confirmation_state: PolicyConfirmationState::ProviderConfirmed,
        },
        UnifiedPolicyEntry {
            policy_id: "pol-02-planned".into(),
            provider_id: "openwrt-http".into(),
            provider_name: "OpenWrt HTTP".into(),
            scope: PolicyScope::NetworkWide,
            lifecycle_state: PolicyLifecycleState::Planned,
            duration: PolicyDuration::Indefinite,
            is_persistent: false,
            applied_at_unix: now,
            expires_at_unix: None,
            enforcement_point: "UCI Firewall".into(),
            recovery_status: PolicyRecoveryStatus::NotApplicable,
            last_execution_result: None,
            confirmation_state: PolicyConfirmationState::LocallyRecordedUnverified,
        },
        UnifiedPolicyEntry {
            policy_id: "pol-03-pending".into(),
            provider_id: "mikrotik-rest".into(),
            provider_name: "MikroTik REST".into(),
            scope: PolicyScope::SpecificTargets(vec![Ipv4Addr::new(192, 168, 1, 101)]),
            lifecycle_state: PolicyLifecycleState::PendingApplication,
            duration: PolicyDuration::Temporary(Duration::from_secs(600)),
            is_persistent: false,
            applied_at_unix: now,
            expires_at_unix: Some(now + 600),
            enforcement_point: "IP Firewall Filter".into(),
            recovery_status: PolicyRecoveryStatus::Pending,
            last_execution_result: None,
            confirmation_state: PolicyConfirmationState::LocallyRecordedUnverified,
        },
        UnifiedPolicyEntry {
            policy_id: "pol-04-expired".into(),
            provider_id: "openwrt-ssh".into(),
            provider_name: "OpenWrt SSH".into(),
            scope: PolicyScope::SpecificTargets(vec![Ipv4Addr::new(192, 168, 1, 102)]),
            lifecycle_state: PolicyLifecycleState::ExpiredPendingRecovery,
            duration: PolicyDuration::Temporary(Duration::from_secs(300)),
            is_persistent: true,
            applied_at_unix: now - 400,
            expires_at_unix: Some(now - 100),
            enforcement_point: "NFTables / UCI".into(),
            recovery_status: PolicyRecoveryStatus::InstalledAndConfirmed(
                RecoveryMechanism::RouterWatchdog,
            ),
            last_execution_result: Some("Deadline passed; watchdog pending execution".into()),
            confirmation_state: PolicyConfirmationState::ProviderConfirmed,
        },
        UnifiedPolicyEntry {
            policy_id: "pol-05-recovering".into(),
            provider_id: "mock".into(),
            provider_name: "Mock Provider".into(),
            scope: PolicyScope::SpecificTargets(vec![Ipv4Addr::new(192, 168, 1, 103)]),
            lifecycle_state: PolicyLifecycleState::RecoveryInProgress,
            duration: PolicyDuration::Indefinite,
            is_persistent: false,
            applied_at_unix: now - 500,
            expires_at_unix: None,
            enforcement_point: "Firewall".into(),
            recovery_status: PolicyRecoveryStatus::NotApplicable,
            last_execution_result: Some("Recovery in progress".into()),
            confirmation_state: PolicyConfirmationState::ProviderConfirmed,
        },
        UnifiedPolicyEntry {
            policy_id: "pol-06-recovered".into(),
            provider_id: "mock".into(),
            provider_name: "Mock Provider".into(),
            scope: PolicyScope::SpecificTargets(vec![Ipv4Addr::new(192, 168, 1, 104)]),
            lifecycle_state: PolicyLifecycleState::Recovered,
            duration: PolicyDuration::Indefinite,
            is_persistent: false,
            applied_at_unix: now - 600,
            expires_at_unix: None,
            enforcement_point: "Firewall".into(),
            recovery_status: PolicyRecoveryStatus::NotApplicable,
            last_execution_result: Some("Recovered".into()),
            confirmation_state: PolicyConfirmationState::LocallyRecordedRecovered,
        },
        UnifiedPolicyEntry {
            policy_id: "pol-07-failed".into(),
            provider_id: "unifi-rest".into(),
            provider_name: "UniFi Network".into(),
            scope: PolicyScope::SpecificTargets(vec![Ipv4Addr::new(192, 168, 1, 105)]),
            lifecycle_state: PolicyLifecycleState::Failed(
                "Network timeout connecting to controller".into(),
            ),
            duration: PolicyDuration::Temporary(Duration::from_secs(300)),
            is_persistent: false,
            applied_at_unix: now - 700,
            expires_at_unix: Some(now - 400),
            enforcement_point: "Traffic Rules".into(),
            recovery_status: PolicyRecoveryStatus::Failed(
                "Network timeout connecting to controller".into(),
            ),
            last_execution_result: Some("Failed: Network timeout connecting to controller".into()),
            confirmation_state: PolicyConfirmationState::LocallyRecordedFailed,
        },
        UnifiedPolicyEntry {
            policy_id: "pol-08-unknown".into(),
            provider_id: "mikrotik-rest".into(),
            provider_name: "MikroTik REST".into(),
            scope: PolicyScope::SpecificTargets(vec![Ipv4Addr::new(192, 168, 1, 106)]),
            lifecycle_state: PolicyLifecycleState::Unknown,
            duration: PolicyDuration::Temporary(Duration::from_secs(900)),
            is_persistent: true,
            applied_at_unix: now - 1000,
            expires_at_unix: Some(now - 100),
            enforcement_point: "IP Firewall".into(),
            recovery_status: PolicyRecoveryStatus::UnknownOrUnverified,
            last_execution_result: Some(
                "Startup reconciliation pending: local state not yet verified against live router"
                    .into(),
            ),
            confirmation_state: PolicyConfirmationState::LocallyRecordedUnverified,
        },
    ];

    // Rendering must execute cleanly across all lifecycle states without panic
    render_router_unified_policies_table(&policies);

    // Empty list must also render gracefully
    render_router_unified_policies_table(&[]);
}

#[test]
fn test_policy_detail_for_known_and_unknown_ids() {
    let gateway_ip = Ipv4Addr::new(192, 168, 1, 1);
    let registry = Arc::new(RouterRegistry::new(gateway_ip));
    let engine = PolicyExecutionEngine::new(registry.clone());

    let mock = Arc::new(MockRouterAdminProvider::new(gateway_ip));
    registry
        .connect("mock", mock, "internal://mock")
        .expect("Connect mock");

    // Apply a test policy
    let target_ip = Ipv4Addr::new(192, 168, 1, 120);
    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![target_ip]),
        PolicyDuration::Temporary(Duration::from_secs(300)),
        PolicyPersistence::RouterPersistent,
    );
    let active = engine.apply_policy(&req).expect("Apply policy");
    let policy_id = active.policy_id.clone();

    // Query detail for known ID
    let detail_opt = engine.get_policy_detail(&policy_id);
    assert!(
        detail_opt.is_some(),
        "Detail must be found for known policy ID"
    );
    let detail = detail_opt.unwrap();

    assert_eq!(detail.policy.policy_id, policy_id);
    assert_eq!(
        detail.policy.scope,
        PolicyScope::SpecificTargets(vec![target_ip])
    );
    assert!(
        detail.provider_verification_available,
        "Verification must be available for active provider"
    );
    assert!(
        detail.provider_verification_status.contains("mock"),
        "Status must cite provider ID"
    );
    assert!(
        !detail.audit_events.is_empty(),
        "Audit events must contain execution history"
    );
    assert_eq!(detail.audit_events[0].operation, "apply");

    // Rendering detail view must succeed without panic
    render_router_policy_detail(&detail);

    // Query detail for unknown ID
    let unknown_detail = engine.get_policy_detail("nonexistent-policy-id-99999");
    assert!(
        unknown_detail.is_none(),
        "Unknown policy ID must return None"
    );
}

#[test]
fn test_recovery_status_representation() {
    let now = 1700000000;

    // 1. Indefinite policy -> NotApplicable
    let indefinite_status = ActivePolicyStatus::new(
        "pol-indef",
        PolicyScope::NetworkWide,
        now,
        None,
        false,
        "Firewall",
        false,
    );
    let entry_indef = UnifiedPolicyEntry::from_active_policy(
        &indefinite_status,
        "mock",
        PolicyConfirmationState::ProviderConfirmed,
    );
    assert_eq!(
        entry_indef.recovery_status,
        PolicyRecoveryStatus::NotApplicable
    );

    // 2. OpenWrt Watchdog confirmed
    let mut openwrt_status = ActivePolicyStatus::new(
        "pol-openwrt",
        PolicyScope::NetworkWide,
        now,
        Some(now + 300),
        true,
        "UCI Firewall",
        true,
    );
    openwrt_status.recovery_mechanism = Some("Router Watchdog".into());
    let entry_openwrt = UnifiedPolicyEntry::from_active_policy(
        &openwrt_status,
        "openwrt-http",
        PolicyConfirmationState::ProviderConfirmed,
    );
    assert_eq!(
        entry_openwrt.recovery_status,
        PolicyRecoveryStatus::InstalledAndConfirmed(RecoveryMechanism::RouterWatchdog)
    );

    // 3. MikroTik Scheduler confirmed
    let mut mikrotik_status = ActivePolicyStatus::new(
        "pol-mikrotik",
        PolicyScope::NetworkWide,
        now,
        Some(now + 600),
        true,
        "/ip firewall filter",
        true,
    );
    mikrotik_status.recovery_mechanism = Some("MikroTik Scheduler (/system scheduler)".into());
    let entry_mikrotik = UnifiedPolicyEntry::from_active_policy(
        &mikrotik_status,
        "mikrotik-rest",
        PolicyConfirmationState::ProviderConfirmed,
    );
    assert_eq!(
        entry_mikrotik.recovery_status,
        PolicyRecoveryStatus::InstalledAndConfirmed(RecoveryMechanism::MikroTikScheduler)
    );

    // 4. UniFi unsupported
    let unifi_status = ActivePolicyStatus::new(
        "pol-unifi",
        PolicyScope::NetworkWide,
        now,
        Some(now + 300),
        false,
        "Traffic Rules",
        false,
    );
    let entry_unifi = UnifiedPolicyEntry::from_active_policy(
        &unifi_status,
        "unifi-rest",
        PolicyConfirmationState::ProviderConfirmed,
    );
    assert_eq!(
        entry_unifi.recovery_status,
        PolicyRecoveryStatus::Unsupported
    );

    // 5. Failed policy
    let mut failed_status = ActivePolicyStatus::new(
        "pol-failed",
        PolicyScope::NetworkWide,
        now,
        Some(now + 300),
        false,
        "Firewall",
        false,
    );
    failed_status.lifecycle_state =
        PolicyLifecycleState::Failed("Watchdog script syntax error".into());
    let entry_failed = UnifiedPolicyEntry::from_active_policy(
        &failed_status,
        "openwrt-ssh",
        PolicyConfirmationState::LocallyRecordedFailed,
    );
    assert_eq!(
        entry_failed.recovery_status,
        PolicyRecoveryStatus::Failed("Watchdog script syntax error".into())
    );

    // 6. Unknown / Unverified local state
    let mut unverified_status = ActivePolicyStatus::new(
        "pol-unverified",
        PolicyScope::NetworkWide,
        now,
        Some(now + 300),
        true,
        "Firewall",
        true,
    );
    unverified_status.lifecycle_state = PolicyLifecycleState::Unknown;
    let entry_unverified = UnifiedPolicyEntry::from_active_policy(
        &unverified_status,
        "openwrt-http",
        PolicyConfirmationState::LocallyRecordedUnverified,
    );
    assert_eq!(
        entry_unverified.recovery_status,
        PolicyRecoveryStatus::UnknownOrUnverified
    );
}

#[test]
fn test_cached_versus_provider_confirmed_status() {
    let gateway_ip = Ipv4Addr::new(192, 168, 1, 1);
    let registry = Arc::new(RouterRegistry::new(gateway_ip));
    let engine = PolicyExecutionEngine::new(registry.clone());

    let mock = Arc::new(MockRouterAdminProvider::new(gateway_ip));
    registry
        .connect("mock", mock, "internal://mock")
        .expect("Connect mock");

    // Apply policy while connected
    let target_ip = Ipv4Addr::new(192, 168, 1, 150);
    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![target_ip]),
        PolicyDuration::Temporary(Duration::from_secs(300)),
        PolicyPersistence::RouterPersistent,
    );
    let applied = engine.apply_policy(&req).expect("Apply policy");

    // 1. While connected & authenticated: must be ProviderConfirmed and Active
    let connected_policies = engine.list_unified_policies();
    let pol = connected_policies
        .iter()
        .find(|p| p.policy_id == applied.policy_id);
    assert!(pol.is_some(), "Policy must be found in live listing");
    let p = pol.unwrap();
    assert_eq!(
        p.confirmation_state,
        PolicyConfirmationState::ProviderConfirmed
    );
    assert_eq!(p.lifecycle_state, PolicyLifecycleState::Active);

    // 2. Disconnect provider
    registry.disconnect();
    assert!(!registry.is_connected());

    // While disconnected: MUST NEVER claim to be Active or ProviderConfirmed!
    let disconnected_policies = engine.list_unified_policies();
    let disc_pol = disconnected_policies
        .iter()
        .find(|p| p.policy_id == applied.policy_id);
    assert!(
        disc_pol.is_some(),
        "Policy must be found in local store listing"
    );
    let dp = disc_pol.unwrap();
    assert_eq!(
        dp.confirmation_state,
        PolicyConfirmationState::LocallyRecordedUnverified,
        "Must be marked LocallyRecordedUnverified when disconnected"
    );
    assert_eq!(
        dp.lifecycle_state,
        PolicyLifecycleState::Unknown,
        "Must be marked Unknown rather than Active when disconnected"
    );
    assert!(
        dp.last_execution_result
            .as_deref()
            .unwrap_or("")
            .contains("disconnected"),
        "Result explanation must state that router provider is disconnected"
    );
}

#[test]
fn test_unsupported_operations_exposure() {
    let gateway_ip = Ipv4Addr::new(192, 168, 1, 1);
    let registry = Arc::new(RouterRegistry::new(gateway_ip));
    let engine = PolicyExecutionEngine::new(registry.clone());

    // 1. Connect UniFi provider (does not support autonomous timed recovery)
    let mock_transport = Box::new(MockUnifiTransport::default());
    let unifi = Arc::new(
        UnifiAdminProvider::new(gateway_ip, "https://192.168.1.1:443")
            .with_transport(mock_transport),
    );
    unifi.set_credentials(rustrict::gateway::admin::RouterCredentials::new(
        "admin",
        "admin_password",
    ));
    registry
        .connect("unifi-rest", unifi, "https://192.168.1.1:443")
        .expect("Connect UniFi");

    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![Ipv4Addr::new(192, 168, 1, 160)]),
        PolicyDuration::Temporary(Duration::from_secs(300)),
        PolicyPersistence::VolatileSession,
    );

    // Temporary policy on UniFi must be rejected before mutation with clear message
    match engine.apply_policy(&req) {
        Err(AdminError::UnsupportedOperation(msg)) => {
            assert!(
                msg.contains("does not support autonomous router-side timed recovery"),
                "Error must clearly state autonomous recovery is unsupported: {}",
                msg
            );
        }
        other => panic!("Expected UnsupportedOperation, got {:?}", other),
    }

    registry.disconnect();

    // 2. Connect OpenWrt provider (does not support device inventory)
    let openwrt_transport = Box::new(MockOpenWrtTransport::default());
    let openwrt = Arc::new(
        OpenWrtAdminProvider::new(gateway_ip, "http://192.168.1.1/ubus")
            .with_transport(openwrt_transport),
    );
    openwrt.set_credentials(rustrict::gateway::admin::RouterCredentials::new(
        "root",
        "admin_password",
    ));
    registry
        .connect("openwrt-http", openwrt, "http://192.168.1.1/ubus")
        .expect("Connect OpenWrt");

    // Device inventory on OpenWrt must return UnsupportedOperation without inventing fake endpoints
    match engine.list_devices() {
        Err(AdminError::UnsupportedOperation(msg)) => {
            assert!(
                msg.contains("OpenWrt") || msg.contains("does not support"),
                "Error must clearly state device inventory is unsupported: {}",
                msg
            );
        }
        other => panic!("Expected UnsupportedOperation, got {:?}", other),
    }
}

#[test]
fn test_provider_failures_and_sanitization() {
    let gateway_ip = Ipv4Addr::new(192, 168, 1, 1);
    let registry = Arc::new(RouterRegistry::new(gateway_ip));
    let engine = PolicyExecutionEngine::new(registry.clone());

    let mock = Arc::new(MockRouterAdminProvider::new(gateway_ip));
    registry
        .connect("mock", mock.clone(), "internal://mock")
        .expect("Connect mock");

    // Simulate transaction failure during mutation
    mock.set_simulate_transaction_failure(true);

    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![Ipv4Addr::new(192, 168, 1, 170)]),
        PolicyDuration::Indefinite,
        PolicyPersistence::VolatileSession,
    );

    let err = engine
        .apply_policy(&req)
        .expect_err("Should fail due to transaction failure");
    match err {
        AdminError::TransactionFailed(msg) => {
            assert!(msg.contains("Simulated transaction failure"));
        }
        other => panic!("Expected TransactionFailed, got {:?}", other),
    }

    // Check history: failure must be logged with sanitized error
    let records = engine.execution_history();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].operation, "apply");
    assert!(matches!(
        records[0].final_state,
        PolicyLifecycleState::Failed(_)
    ));
    assert!(records[0]
        .error
        .as_deref()
        .unwrap_or("")
        .contains("Simulated transaction failure"));

    // Also test secret sanitization in failure reporting
    let raw_error = "API error password=SuperSecretAdminPassword123! token=auth_tok_abcdef";
    let sanitized = rustrict::gateway::admin::sanitize_text(raw_error);
    assert!(!sanitized.contains("SuperSecretAdminPassword123!"));
    assert!(!sanitized.contains("auth_tok_abcdef"));
    assert!(sanitized.contains("[REDACTED]"));
}

#[test]
fn test_explicit_provider_selection_and_no_fallback() {
    let gateway_ip = Ipv4Addr::new(192, 168, 1, 1);
    let registry = Arc::new(RouterRegistry::new(gateway_ip));
    let engine = PolicyExecutionEngine::new(registry.clone());

    // 1. When disconnected, engine must fail closed
    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![Ipv4Addr::new(192, 168, 1, 180)]),
        PolicyDuration::Indefinite,
        PolicyPersistence::VolatileSession,
    );

    match engine.apply_policy(&req) {
        Err(AdminError::UnsupportedOperation(msg)) => {
            assert!(msg.contains("No router provider is currently connected"));
        }
        other => panic!(
            "Expected UnsupportedOperation when disconnected, got {:?}",
            other
        ),
    }

    // 2. Connect mock provider and verify operations route strictly to it
    let mock = Arc::new(MockRouterAdminProvider::new(gateway_ip));
    registry
        .connect("mock", mock, "internal://mock")
        .expect("Connect mock");

    assert_eq!(registry.active_provider_id().as_deref(), Some("mock"));
    let active = engine
        .apply_policy(&req)
        .expect("Apply on explicitly selected mock");
    assert!(active.policy_id.contains("mock"));

    // 3. Resume policy explicitly
    let resumed = engine.resume_policy(&req.scope).expect("Resume on mock");
    assert_eq!(resumed.len(), 1);
    assert_eq!(resumed[0], active.policy_id);
}
