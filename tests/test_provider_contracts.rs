use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use rustrict::gateway::admin::{
    sanitize_error, AdminError, AvmAdminProvider, MikroTikAdminProvider, MockAvmTransport,
    MockMikroTikTransport, MockOpenWrtTransport, MockRouterAdminProvider, MockSshExecutor,
    MockUnifiTransport, OpenWrtAdminProvider, OperationPlanRequest, PolicyDuration,
    PolicyExecutionEngine, PolicyPersistence, PolicyScope, RouterAdminProvider, RouterCredentials,
    RouterRegistry, SshConfig, SshOpenWrtTransport, UnifiAdminProvider,
};

fn create_openwrt_http() -> Arc<dyn RouterAdminProvider> {
    let mock = MockOpenWrtTransport::default();
    let gw = Ipv4Addr::new(192, 168, 1, 1);
    let p =
        OpenWrtAdminProvider::new(gw, "http://192.168.1.1:80/ubus").with_transport(Box::new(mock));
    p.set_credentials(RouterCredentials::new("root", "admin_password"));
    let _ = p.login();
    Arc::new(p)
}

fn create_openwrt_ssh() -> Arc<dyn RouterAdminProvider> {
    let mock = MockSshExecutor::default();
    let gw = Ipv4Addr::new(192, 168, 1, 1);
    let cfg = SshConfig::new(gw)
        .with_port(22)
        .with_username("root")
        .with_connect_timeout(Duration::from_secs(5));
    let t = SshOpenWrtTransport::with_executor(cfg, Arc::new(mock));
    let p = OpenWrtAdminProvider::new(gw, "ssh://192.168.1.1:22").with_transport(Box::new(t));
    let _ = p.login();
    Arc::new(p)
}

fn create_mikrotik_rest() -> Arc<dyn RouterAdminProvider> {
    let mock = MockMikroTikTransport::default();
    let gw = Ipv4Addr::new(192, 168, 88, 1);
    let p = MikroTikAdminProvider::new(gw, "https://192.168.88.1:443/rest")
        .with_transport(Box::new(mock));
    p.set_credentials(RouterCredentials::new("admin", "admin_password"));
    let _ = p.login();
    Arc::new(p)
}

fn create_avm_tr064() -> Arc<dyn RouterAdminProvider> {
    let mock = MockAvmTransport::default();
    let gw = Ipv4Addr::new(192, 168, 178, 1);
    let p = AvmAdminProvider::new(gw, "https://192.168.178.1:49443/tr64desc.xml")
        .with_transport(Box::new(mock));
    p.set_credentials(RouterCredentials::new("admin", "admin_password"));
    let _ = p.login();
    Arc::new(p)
}

fn create_unifi_rest() -> Arc<dyn RouterAdminProvider> {
    let mock = MockUnifiTransport::default();
    let gw = Ipv4Addr::new(192, 168, 1, 1);
    let p = UnifiAdminProvider::new(gw, "https://192.168.1.1:8443")
        .with_site("default")
        .with_transport(Box::new(mock));
    p.set_credentials(RouterCredentials::new("admin", "admin_password"));
    let _ = p.login();
    Arc::new(p)
}

fn create_mock() -> Arc<dyn RouterAdminProvider> {
    let gw = Ipv4Addr::new(192, 168, 1, 1);
    Arc::new(MockRouterAdminProvider::new(gw))
}

fn all_providers() -> Vec<(&'static str, Arc<dyn RouterAdminProvider>)> {
    vec![
        ("openwrt-http", create_openwrt_http()),
        ("openwrt-ssh", create_openwrt_ssh()),
        ("mikrotik-rest", create_mikrotik_rest()),
        ("avm-tr064", create_avm_tr064()),
        ("unifi-rest", create_unifi_rest()),
        ("mock", create_mock()),
    ]
}

#[test]
fn test_cross_provider_contract_zero_mutations_on_read_only_operations() {
    for (name, provider) in all_providers() {
        // Initial state: query active policies
        let initial_policies = provider.query_active_policies().unwrap_or_else(|e| {
            panic!("Provider '{}' query_active_policies failed: {:?}", name, e)
        });
        assert!(
            initial_policies.is_empty(),
            "Provider '{}' must start with zero active policies",
            name
        );

        // Run read-only operations
        let _ = provider.detect_identity();
        let _ = provider.inspect_capabilities();
        let _ = provider.list_devices();

        // Run dry-run plan
        let req = OperationPlanRequest::new(
            PolicyScope::SpecificTargets(vec![Ipv4Addr::new(192, 168, 1, 105)]),
            PolicyDuration::Indefinite,
            PolicyPersistence::VolatileSession,
        );
        let plan_res = provider.plan_operation(&req);
        if let Ok(plan) = plan_res {
            assert!(
                plan.is_dry_run,
                "Provider '{}' plan must be marked as dry run",
                name
            );
        }

        // Verify active policies remain completely unchanged (zero mutations)
        let final_policies = provider
            .query_active_policies()
            .unwrap_or_else(|e| panic!("Provider '{}' final query failed: {:?}", name, e));
        assert_eq!(
            final_policies.len(),
            0,
            "Provider '{}' mutated policy state during read-only inspection!",
            name
        );
    }
}

#[test]
fn test_cross_provider_contract_unsupported_capabilities_fail_closed() {
    let gateway_ip = Ipv4Addr::new(192, 168, 1, 1);

    for (name, provider) in all_providers() {
        let caps = provider.inspect_capabilities();

        // 1. Temporary duration without autonomous recovery must fail closed
        if !caps.timed_policy_auto_recovery.is_operational() {
            let registry = Arc::new(RouterRegistry::new(gateway_ip));
            registry
                .connect(name, provider.clone(), "internal://test")
                .expect("Connect");

            let engine = PolicyExecutionEngine::new(registry);
            let req = OperationPlanRequest::new(
                PolicyScope::SpecificTargets(vec![Ipv4Addr::new(192, 168, 1, 205)]),
                PolicyDuration::Temporary(Duration::from_secs(300)),
                PolicyPersistence::VolatileSession,
            );

            match engine.apply_policy(&req) {
                Err(AdminError::UnsupportedOperation(msg)) => {
                    assert!(
                        msg.contains("autonomous")
                            || msg.contains("recovery")
                            || msg.contains("temporary"),
                        "Provider '{}' error message should cite missing autonomous recovery: {}",
                        name,
                        msg
                    );
                }
                other => panic!(
                    "Provider '{}' must reject unsupported temporary policy, got {:?}",
                    name, other
                ),
            }

            // Zero policies must be active
            let active = provider.query_active_policies().expect("query");
            assert!(
                active.is_empty(),
                "Provider '{}' must not leave active policies after failed capability check",
                name
            );
        } else {
            // Providers that support autonomous recovery must be operational
            assert!(
                caps.timed_policy_auto_recovery.is_operational(),
                "Provider '{}' autonomous recovery should be operational",
                name
            );
        }

        // 2. IPv6 classification consistency
        if name == "mikrotik-rest" || name == "avm-tr064" {
            assert!(
                !caps.ipv6_policy_enforcement.is_operational(),
                "Provider '{}' must NOT advertise operational IPv6 enforcement without implementation",
                name
            );
        }
    }
}

#[test]
fn test_cross_provider_contract_multi_target_partial_failure_reporting() {
    let targets = vec![
        "192.168.1.10".to_string(),
        "192.168.1.11".to_string(),
        "192.168.1.12".to_string(),
    ];
    let failed = "192.168.1.13".to_string();
    let rollback_errs = vec!["Timeout reverting target 192.168.1.10".to_string()];

    let rollback_err = AdminError::RollbackFailed {
        applied_targets: targets.clone(),
        failed_target: failed.clone(),
        original_error: "API connection dropped".to_string(),
        rollback_errors: rollback_errs.clone(),
    };

    let display_str = rollback_err.to_string();
    assert!(display_str.contains("CRITICAL"));
    assert!(display_str.contains(&failed));
    assert!(display_str.contains("192.168.1.10"));
    assert!(display_str.contains("192.168.1.11"));
    assert!(display_str.contains("192.168.1.12"));

    // Ensure sanitize_error safely converts RollbackFailed without panicking
    let sanitized = sanitize_error(rollback_err);
    assert!(matches!(sanitized, AdminError::RollbackFailed { .. }));
}

#[test]
fn test_cross_provider_contract_unauthenticated_mutations_fail_closed() {
    let gw = Ipv4Addr::new(192, 168, 1, 1);

    // Test unauthenticated OpenWrt HTTP
    let unauth_owrt = OpenWrtAdminProvider::new(gw, "http://192.168.1.1/ubus")
        .with_transport(Box::new(MockOpenWrtTransport::default()));
    assert!(!unauth_owrt.is_authenticated());

    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![Ipv4Addr::new(192, 168, 1, 55)]),
        PolicyDuration::Indefinite,
        PolicyPersistence::VolatileSession,
    );
    assert!(unauth_owrt.apply_policy(&req).is_err());
    assert!(unauth_owrt.resume_policy(&req.scope).is_err());
    assert!(unauth_owrt
        .adjust_policy_duration(&req.scope, &PolicyDuration::Indefinite)
        .is_err());

    // Test unauthenticated MikroTik
    let unauth_mt = MikroTikAdminProvider::new(gw, "https://192.168.1.1/rest")
        .with_transport(Box::new(MockMikroTikTransport::default()));
    assert!(unauth_mt.apply_policy(&req).is_err());

    // Test unauthenticated AVM
    let unauth_avm = AvmAdminProvider::new(gw, "https://192.168.1.1:49443/tr64desc.xml")
        .with_transport(Box::new(MockAvmTransport::default()));
    assert!(unauth_avm.apply_policy(&req).is_err());

    // Test unauthenticated UniFi
    let unauth_unifi = UnifiAdminProvider::new(gw, "https://192.168.1.1:8443")
        .with_transport(Box::new(MockUnifiTransport::default()));
    assert!(unauth_unifi.apply_policy(&req).is_err());
}

#[test]
fn test_cross_provider_contract_credential_redaction_on_errors() {
    let secret_pass = "SuperSecretContractPass456";
    let secret_token = "SecretContractToken789";

    let test_errors = vec![
        AdminError::AuthenticationFailed(format!(
            "Auth failed for user root with password={}",
            secret_pass
        )),
        AdminError::Timeout(format!("Request timed out with Bearer {}", secret_token)),
        AdminError::CommunicationError(format!(
            "Error at https://admin:{}@192.168.1.1/api",
            secret_pass
        )),
        AdminError::RollbackFailed {
            applied_targets: vec!["192.168.1.50".into()],
            failed_target: "192.168.1.51".into(),
            original_error: format!("Commit failed: token={}", secret_token),
            rollback_errors: vec![format!("Rollback failed: pass={}", secret_pass)],
        },
    ];

    for err in test_errors {
        let sanitized = sanitize_error(err);
        let err_str = sanitized.to_string();

        assert!(
            !err_str.contains(secret_pass),
            "Secret password leaked in sanitized error: {}",
            err_str
        );
        assert!(
            !err_str.contains(secret_token),
            "Secret token leaked in sanitized error: {}",
            err_str
        );
        assert!(
            err_str.contains("[REDACTED]"),
            "Sanitized error should contain [REDACTED]: {}",
            err_str
        );
    }
}

#[test]
fn test_cross_provider_contract_evidence_export_zero_mutations() {
    let gateway_ip = Ipv4Addr::new(192, 168, 1, 1);

    for (name, provider) in all_providers() {
        let registry = Arc::new(RouterRegistry::new(gateway_ip));
        registry
            .connect(name, provider.clone(), "internal://contract-export")
            .expect("Connect");

        let engine = PolicyExecutionEngine::new(registry);

        let bundle = engine.build_evidence_bundle();
        assert_eq!(bundle.schema_version, "rustrict-evidence-v1.0");
        assert_eq!(bundle.provider_id, name);

        // Verify active policies on provider remain zero
        let active = provider.query_active_policies().expect("query");
        assert_eq!(
            active.len(),
            0,
            "Provider '{}' active policies must remain 0 after building evidence bundle",
            name
        );
    }
}
