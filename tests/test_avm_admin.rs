use std::net::Ipv4Addr;
use std::sync::atomic::Ordering;
use std::time::Duration;

use rustrict::gateway::admin::{
    calculate_digest_response, md5_digest, AdminError, AvmAdminProvider, AvmTransport,
    CapabilityClassification, MockAvmTransport, OperationPlanRequest, PolicyDuration,
    PolicyPersistence, PolicyScope, RouterAdminProvider, RouterCredentials,
};

fn create_mock_avm() -> (AvmAdminProvider, MockAvmTransport) {
    let mock_transport = MockAvmTransport::default();
    let gw_ip = Ipv4Addr::new(192, 168, 178, 1);
    let provider = AvmAdminProvider::new(gw_ip, "https://192.168.178.1:49443/tr64desc.xml")
        .with_transport(Box::new(mock_transport.clone()));
    provider.set_credentials(RouterCredentials::new("admin", "admin_password"));
    (provider, mock_transport)
}

#[test]
fn test_avm_md5_rfc_vectors() {
    // Official RFC 1321 test vectors
    assert_eq!(md5_digest(b""), "d41d8cd98f00b204e9800998ecf8427e");
    assert_eq!(md5_digest(b"a"), "0cc175b9c0f1b6a831c399e269772661");
    assert_eq!(md5_digest(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
    assert_eq!(
        md5_digest(b"message digest"),
        "f96b697d7cb7938d525a2f31aaf161d0"
    );

    // HTTP Digest response calculation verification
    let resp = calculate_digest_response(
        "admin",
        "FRITZ!Box",
        "secret",
        "POST",
        "/upnp/control/x_hostfilter",
        "nonce1234",
        Some("auth"),
        "00000001",
        "clientnonce5678",
    );
    assert_eq!(resp.len(), 32);
    assert!(resp.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_avm_service_description_parsing() {
    let (provider, _transport) = create_mock_avm();

    provider
        .ensure_services_discovered()
        .expect("Device description parsing should succeed");

    let ctrl_deviceinfo = provider
        .get_service_control_url("DeviceInfo:1")
        .expect("DeviceInfo service should be discovered");
    assert!(ctrl_deviceinfo.contains("/upnp/control/deviceinfo"));

    let ctrl_hosts = provider
        .get_service_control_url("Hosts:1")
        .expect("Hosts service should be discovered");
    assert!(ctrl_hosts.contains("/upnp/control/hosts"));

    let ctrl_hostfilter = provider
        .get_service_control_url("X_AVM-DE_HostFilter:1")
        .expect("HostFilter service should be discovered");
    assert!(ctrl_hostfilter.contains("/upnp/control/x_hostfilter"));
}

#[test]
fn test_avm_digest_auth_success() {
    let (provider, _transport) = create_mock_avm();

    assert!(provider.is_authenticated());
    let login_res = provider.login();
    assert!(
        login_res.is_ok(),
        "Login should succeed with valid credentials"
    );
    assert!(provider.is_authenticated());
}

#[test]
fn test_avm_digest_auth_failure() {
    let mock_transport = MockAvmTransport::default();
    let gw_ip = Ipv4Addr::new(192, 168, 178, 1);
    let provider = AvmAdminProvider::new(gw_ip, "https://192.168.178.1:49443/tr64desc.xml")
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
fn test_avm_identity_verification_and_mismatch() {
    let (provider, transport) = create_mock_avm();

    let identity = provider
        .detect_identity()
        .expect("Identity probe should succeed");
    assert_eq!(identity.ip, Ipv4Addr::new(192, 168, 178, 1));
    assert_eq!(identity.manufacturer.as_deref(), Some("AVM"));
    assert_eq!(identity.model_name.as_deref(), Some("FRITZ!Box 7590"));
    assert_eq!(identity.firmware_version.as_deref(), Some("154.07.57"));
    assert_eq!(identity.serial_number.as_deref(), Some("CCCE1E000001"));

    // Mismatched non-AVM manufacturer
    transport.simulate_non_avm.store(true, Ordering::SeqCst);
    let mismatch_provider = AvmAdminProvider::new(
        Ipv4Addr::new(192, 168, 178, 1),
        "https://192.168.178.1:49443/tr64desc.xml",
    )
    .with_transport(Box::new(transport));
    mismatch_provider.set_credentials(RouterCredentials::new("admin", "admin_password"));

    let err = mismatch_provider
        .detect_identity()
        .expect_err("Should reject non-AVM device");
    assert!(
        matches!(err, AdminError::IdentityMismatch(_)),
        "Expected IdentityMismatch error, got: {:?}",
        err
    );
}

#[test]
fn test_avm_soap_success_and_fault_handling() {
    let (provider, transport) = create_mock_avm();

    // Enable SOAP Fault simulation (e.g. 714 NoSuchEntryInArray)
    transport.simulate_soap_fault.store(true, Ordering::SeqCst);

    let ctrl_url = provider.get_service_control_url("DeviceInfo:1").unwrap();
    let resp = transport
        .execute_soap(
            &ctrl_url,
            "urn:dslforum-org:service:DeviceInfo:1",
            "GetInfo",
            "",
            Some(&RouterCredentials::new("admin", "admin_password")),
        )
        .unwrap();

    let err = provider
        .check_soap_fault(&resp)
        .expect_err("Should detect SOAP fault");
    assert!(
        matches!(err, AdminError::PolicyNotFound(_)),
        "Expected PolicyNotFound for fault 714, got: {:?}",
        err
    );
}

#[test]
fn test_avm_missing_hostfilter_service() {
    let mock_transport = MockAvmTransport::default();
    mock_transport
        .simulate_missing_hostfilter
        .store(true, Ordering::SeqCst);

    let gw_ip = Ipv4Addr::new(192, 168, 178, 1);
    let provider = AvmAdminProvider::new(gw_ip, "https://192.168.178.1:49443/tr64desc.xml")
        .with_transport(Box::new(mock_transport));
    provider.set_credentials(RouterCredentials::new("admin", "admin_password"));

    provider.ensure_services_discovered().unwrap();
    let caps = provider.inspect_capabilities();

    // HostFilter missing: IPv4 policy enforcement must be classified as NotImplemented
    assert_eq!(
        caps.ipv4_policy_enforcement,
        CapabilityClassification::NotImplemented
    );
    assert_eq!(
        caps.per_device_access_policy,
        CapabilityClassification::NotImplemented
    );

    // Attempting to apply policy must fail cleanly
    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![Ipv4Addr::new(192, 168, 178, 20)]),
        PolicyDuration::Indefinite,
        PolicyPersistence::RouterPersistent,
    );
    let err = provider
        .apply_policy(&req)
        .expect_err("Should fail when HostFilter service is missing");
    assert!(
        matches!(err, AdminError::UnsupportedOperation(_)),
        "Expected UnsupportedOperation, got: {:?}",
        err
    );
}

#[test]
fn test_avm_per_device_pause_and_resume() {
    let (provider, transport) = create_mock_avm();

    let target_ip = Ipv4Addr::new(192, 168, 178, 20);
    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![target_ip]),
        PolicyDuration::Indefinite,
        PolicyPersistence::RouterPersistent,
    );

    // 1. Pause device
    let active = provider.apply_policy(&req).expect("Pause should succeed");
    assert_eq!(active.scope, req.scope);

    // Verify router mock state
    assert!(transport.active_disallowed_ips.read().contains(&target_ip));

    // Reconcile policies confirms active policy
    let policies = provider
        .reconcile_policies()
        .expect("Reconcile should succeed");
    assert_eq!(policies.len(), 1);

    // 2. Resume device
    let resumed = provider
        .resume_policy(&req.scope)
        .expect("Resume should succeed");
    assert_eq!(resumed.len(), 1);
    assert_eq!(resumed[0], "192.168.178.20");

    // Verify router mock state is cleared
    assert!(!transport.active_disallowed_ips.read().contains(&target_ip));
}

#[test]
fn test_avm_asynchronous_policy_verification_success() {
    let (provider, transport) = create_mock_avm();

    // Simulate 2-cycle propagation delay before router commits the filter state
    transport.async_delay_cycles.store(2, Ordering::SeqCst);

    let target_ip = Ipv4Addr::new(192, 168, 178, 30);
    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![target_ip]),
        PolicyDuration::Indefinite,
        PolicyPersistence::RouterPersistent,
    );

    // Apply policy will poll GetWANAccessByIP until the state converges
    let active = provider
        .apply_policy(&req)
        .expect("Asynchronous verification should succeed");
    assert_eq!(active.scope, req.scope);
    assert!(transport.active_disallowed_ips.read().contains(&target_ip));
}

#[test]
fn test_avm_asynchronous_policy_verification_timeout() {
    let (provider, transport) = create_mock_avm();

    // Simulate permanent non-convergence
    transport.async_delay_cycles.store(999999, Ordering::SeqCst);

    let target_ip = Ipv4Addr::new(192, 168, 178, 40);

    // Bounded polling timeout must trigger Timeout error
    let err = provider
        .poll_verify_wan_access(target_ip, true, Duration::from_millis(150))
        .expect_err("Should time out when state never converges");

    assert!(
        matches!(err, AdminError::Timeout(_)),
        "Expected Timeout, got: {:?}",
        err
    );
}

#[test]
fn test_avm_ipv4_and_ipv6_capability_classification() {
    let (provider, _transport) = create_mock_avm();
    provider.ensure_services_discovered().unwrap();

    let caps = provider.inspect_capabilities();

    assert_eq!(
        caps.ipv4_policy_enforcement,
        CapabilityClassification::Implemented
    );
    assert_eq!(
        caps.per_device_access_policy,
        CapabilityClassification::Implemented
    );
    // Explicitly classified limitations
    assert!(matches!(
        caps.ipv6_policy_enforcement,
        CapabilityClassification::Conditional(_)
    ));
    assert_eq!(
        caps.timed_policy_auto_recovery,
        CapabilityClassification::NotImplemented
    );
}

#[test]
fn test_avm_unsafe_control_url_rejection() {
    let (provider, _transport) = create_mock_avm();

    // 1. External malicious host
    let err1 = provider
        .validate_control_url("http://attacker.com/upnp/control/x_hostfilter")
        .expect_err("External host must be rejected to prevent SSRF");
    assert!(matches!(err1, AdminError::SecurityViolation(_)));

    // 2. Different internal IP
    let err2 = provider
        .validate_control_url("http://10.0.0.99:49000/upnp/control/x_hostfilter")
        .expect_err("Different IP must be rejected to prevent SSRF");
    assert!(matches!(err2, AdminError::SecurityViolation(_)));

    // 3. Valid relative control URL
    let valid_rel = provider
        .validate_control_url("/upnp/control/x_hostfilter")
        .expect("Relative control URL must be accepted");
    assert_eq!(
        valid_rel,
        "https://192.168.178.1:49443/upnp/control/x_hostfilter"
    );

    // 4. Valid absolute control URL matching router
    let valid_abs = provider
        .validate_control_url("https://192.168.178.1:49443/upnp/control/x_hostfilter")
        .expect("Matching router control URL must be accepted");
    assert_eq!(
        valid_abs,
        "https://192.168.178.1:49443/upnp/control/x_hostfilter"
    );
}

#[test]
fn test_avm_lockout_prevention() {
    let (provider, _transport) = create_mock_avm();

    let router_ip = Ipv4Addr::new(192, 168, 178, 1);
    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![router_ip]),
        PolicyDuration::Indefinite,
        PolicyPersistence::RouterPersistent,
    );

    // Dry-run plan must reject targeting router IP
    let plan_err = provider
        .plan_operation(&req)
        .expect_err("Should prevent lockout during planning");
    assert!(matches!(plan_err, AdminError::LockoutPrevented(_)));

    // Execution must reject targeting router IP
    let apply_err = provider
        .apply_policy(&req)
        .expect_err("Should prevent lockout during execution");
    assert!(matches!(apply_err, AdminError::LockoutPrevented(_)));
}

#[test]
fn test_avm_unsupported_autonomous_recovery() {
    let (provider, transport) = create_mock_avm();

    let target_ip = Ipv4Addr::new(192, 168, 178, 50);
    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![target_ip]),
        PolicyDuration::Temporary(Duration::from_secs(300)),
        PolicyPersistence::RouterPersistent,
    );

    // Must fail closed because AVM TR-064 lacks a router-resident autonomous scheduler
    let err = provider
        .apply_policy(&req)
        .expect_err("Temporary policies must be rejected when autonomous recovery is unsupported");

    assert!(
        matches!(err, AdminError::UnsupportedOperation(_)),
        "Expected UnsupportedOperation, got: {:?}",
        err
    );

    // Verify no restrictions were leaked
    assert!(transport.active_disallowed_ips.read().is_empty());
}

#[test]
fn test_avm_network_wide_policy_lifecycle() {
    let (provider, transport) = create_mock_avm();

    let req = OperationPlanRequest::new(
        PolicyScope::NetworkWide,
        PolicyDuration::Indefinite,
        PolicyPersistence::RouterPersistent,
    );

    // Network-wide plan outlines individual host policies and risks
    let plan = provider.plan_operation(&req).expect("Plan should succeed");
    assert_eq!(plan.target_scope, PolicyScope::NetworkWide);
    assert!(plan.expected_wan_impact.contains("AVM HostFilter"));
    assert!(plan.management_plane_safe);

    // Apply network-wide policy
    let active = provider
        .apply_policy(&req)
        .expect("Network-wide pause should succeed");
    assert_eq!(active.scope, PolicyScope::NetworkWide);

    // Verify all enumerated LAN hosts are disallowed
    {
        let disallowed = transport.active_disallowed_ips.read();
        assert!(disallowed.contains(&Ipv4Addr::new(192, 168, 178, 20)));
        assert!(disallowed.contains(&Ipv4Addr::new(192, 168, 178, 30)));
        assert!(!disallowed.contains(&Ipv4Addr::new(192, 168, 178, 1))); // Router IP never blocked
    }

    // Resume network-wide
    let resumed = provider
        .resume_policy(&PolicyScope::NetworkWide)
        .expect("Resume should succeed");
    assert_eq!(resumed.len(), 2);
    assert!(transport.active_disallowed_ips.read().is_empty());
}

#[test]
fn test_avm_tls_cert_error_rejection() {
    let (provider, transport) = create_mock_avm();

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
fn test_avm_preserves_unrelated_hosts_and_settings() {
    let (provider, transport) = create_mock_avm();

    let target_ip = Ipv4Addr::new(192, 168, 178, 20);
    let unmanaged_ip = Ipv4Addr::new(192, 168, 178, 30);

    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![target_ip]),
        PolicyDuration::Indefinite,
        PolicyPersistence::RouterPersistent,
    );

    provider.apply_policy(&req).expect("Apply should succeed");

    // Only target_ip is disallowed; unmanaged_ip remains untouched
    assert!(transport.active_disallowed_ips.read().contains(&target_ip));
    assert!(!transport
        .active_disallowed_ips
        .read()
        .contains(&unmanaged_ip));
}

#[test]
fn test_avm_curl_transport_payload_isolation_and_cleanup() {
    use rustrict::gateway::admin::AutoCleanFile;

    let soap_payload = b"<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><Test/></s:Body></s:Envelope>";
    let file_path;
    {
        let guard = AutoCleanFile::create("rustrict_avm_test", ".xml", soap_payload)
            .expect("Failed to create temporary SOAP payload file");
        file_path = guard.path().to_path_buf();
        assert!(file_path.exists());
        let read = std::fs::read(&file_path).unwrap();
        assert_eq!(read, soap_payload);
    }
    // Verifies RAII cleanup on drop
    assert!(
        !file_path.exists(),
        "Payload temporary file must be cleanly deleted on drop"
    );
}

#[test]
fn test_avm_multi_target_policy_enforcement_and_recovery() {
    let (provider, transport) = create_mock_avm();

    let target1 = Ipv4Addr::new(192, 168, 178, 51);
    let target2 = Ipv4Addr::new(192, 168, 178, 52);
    let target3 = Ipv4Addr::new(192, 168, 178, 53);
    let targets = vec![target1, target2, target3];

    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(targets.clone()),
        PolicyDuration::Indefinite,
        PolicyPersistence::RouterPersistent,
    );

    let active = provider
        .apply_policy(&req)
        .expect("Multi-target policy application must succeed on AVM");
    assert_eq!(active.policy_id, "avm_pause_multi_192_168_178_51");

    // Verify all 3 targets are marked disallowed
    {
        let disallowed = transport.active_disallowed_ips.read();
        assert!(disallowed.contains(&target1));
        assert!(disallowed.contains(&target2));
        assert!(disallowed.contains(&target3));
    }

    // Resume all 3 targets
    let resumed = provider
        .resume_policy(&PolicyScope::SpecificTargets(targets))
        .expect("Resume must succeed");
    assert_eq!(resumed.len(), 3);

    // Verify all 3 targets restored
    {
        let disallowed = transport.active_disallowed_ips.read();
        assert!(!disallowed.contains(&target1));
        assert!(!disallowed.contains(&target2));
        assert!(!disallowed.contains(&target3));
    }
}

#[test]
fn test_avm_rollback_failure_reporting() {
    use rustrict::gateway::admin::avm::AvmTransport;

    struct AvmRollbackFailTransport {
        inner: MockAvmTransport,
    }
    impl AvmTransport for AvmRollbackFailTransport {
        fn transport_name(&self) -> &'static str {
            "Mock-AvmRollbackFail"
        }
        fn fetch_description(
            &self,
            description_url: &str,
            credentials: Option<&RouterCredentials>,
        ) -> Result<String, AdminError> {
            self.inner.fetch_description(description_url, credentials)
        }
        fn execute_soap(
            &self,
            control_url: &str,
            service_urn: &str,
            action: &str,
            args_xml: &str,
            creds: Option<&RouterCredentials>,
        ) -> Result<String, AdminError> {
            if action == "DisallowWANAccessByIP" {
                if args_xml.contains("<NewDisallow>1</NewDisallow>") {
                    let disallowed = self.inner.active_disallowed_ips.read().len();
                    if disallowed >= 1 {
                        return Err(AdminError::CommunicationError(
                            "Target 2 disallow failed".into(),
                        ));
                    }
                } else if args_xml.contains("<NewDisallow>0</NewDisallow>") {
                    return Err(AdminError::CommunicationError(
                        "Rollback re-allow failed over SOAP".into(),
                    ));
                }
            }
            self.inner
                .execute_soap(control_url, service_urn, action, args_xml, creds)
        }
    }

    let fail_transport = AvmRollbackFailTransport {
        inner: MockAvmTransport::default(),
    };
    let fail_provider = AvmAdminProvider::new(
        Ipv4Addr::new(192, 168, 178, 1),
        "http://192.168.178.1:49000",
    )
    .with_transport(Box::new(fail_transport));
    fail_provider.set_credentials(RouterCredentials::new("admin", "admin_password"));

    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![
            Ipv4Addr::new(192, 168, 178, 10),
            Ipv4Addr::new(192, 168, 178, 20),
        ]),
        PolicyDuration::Indefinite,
        PolicyPersistence::VolatileSession,
    );

    let err = fail_provider
        .apply_policy(&req)
        .expect_err("Must report AVM rollback failure");
    match err {
        AdminError::RollbackFailed {
            applied_targets,
            failed_target,
            original_error,
            rollback_errors,
        } => {
            assert_eq!(applied_targets, vec!["192.168.178.10".to_string()]);
            assert_eq!(failed_target, "192.168.178.20");
            assert!(original_error.contains("Target 2 disallow failed"));
            assert_eq!(rollback_errors.len(), 1);
            assert!(rollback_errors[0].contains("Rollback re-allow failed over SOAP"));
        }
        other => panic!("Expected RollbackFailed, got: {:?}", other),
    }
}
