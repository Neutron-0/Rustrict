mod support;

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use rustrict::gateway::admin::{
    avm::classify_avm_action, execute_with_operation_retry, mikrotik::classify_mikrotik_operation,
    unifi::classify_unifi_operation, AdminError, AvmAdminProvider, HttpOpenWrtTransport,
    HttpsMikroTikTransport, MikroTikAdminProvider, MikroTikTransport, MockSshExecutor,
    OpenWrtAdminProvider, OperationPlanRequest, OperationSemantics, PolicyDuration,
    PolicyExecutionEngine, PolicyLifecycleState, PolicyPersistence, PolicyScope, PolicyStore,
    RouterAdminProvider, RouterCredentials, RouterRegistry, SshConfig, SshOpenWrtTransport,
    UnifiAdminProvider,
};
use serde_json::{json, Value};
use support::{FailMode, RouterEmulator, TestTempDir};

#[test]
fn test_router_emulator_lifecycle() {
    let emulator = RouterEmulator::start();
    assert!(emulator.port() > 0);
    assert!(emulator.endpoint().starts_with("http://127.0.0.1:"));
}

#[test]
fn test_openwrt_http_full_protocol_flow() {
    let emulator = RouterEmulator::start();
    let gw_ip = Ipv4Addr::new(127, 0, 0, 1);
    let ubus_url = format!("{}/ubus", emulator.endpoint());

    let provider = OpenWrtAdminProvider::new(gw_ip, &ubus_url);
    provider.set_credentials(RouterCredentials::new("root", "admin_password"));

    // 1. Detect Identity via ubus system.board
    let identity = provider.detect_identity().expect("Detect OpenWrt identity");
    assert_eq!(identity.manufacturer.as_deref(), Some("OpenWrt Community"));
    assert_eq!(identity.model_name.as_deref(), Some("OpenWrt One"));
    assert_eq!(identity.firmware_version.as_deref(), Some("23.05.2"));

    // 2. Multi-Target Policy Application
    let target1 = Ipv4Addr::new(192, 168, 1, 100);
    let target2 = Ipv4Addr::new(192, 168, 1, 101);
    let req = OperationPlanRequest {
        scope: PolicyScope::SpecificTargets(vec![target1, target2]),
        duration: PolicyDuration::Temporary(Duration::from_secs(1800)),
        persistence: PolicyPersistence::VolatileSession,
        target_macs: Vec::new(),
    };

    let status = provider
        .apply_policy(&req)
        .expect("Apply multi-target policy");
    assert_eq!(
        status.lifecycle_state,
        rustrict::gateway::admin::PolicyLifecycleState::Active
    );
    assert!(status.policy_id.starts_with("rustrict_pause_"));

    // Verify rules were added to the emulator state
    let state = emulator.state();
    assert_eq!(state.openwrt_rules.len(), 2);

    // 3. Query Active Policies
    let active = provider
        .query_active_policies()
        .expect("Query active policies");
    assert_eq!(active.len(), 2);

    // 4. Revoke / Resume Policy
    let resumed = provider
        .resume_policy(&PolicyScope::SpecificTargets(vec![target1, target2]))
        .expect("Resume policy");
    assert!(!resumed.is_empty());

    // Verify rules removed from emulator state
    let state_after = emulator.state();
    assert_eq!(state_after.openwrt_rules.len(), 0);

    // 5. Inspect recorded requests and ensure authorization was sanitized
    let requests = emulator.recorded_requests();
    assert!(!requests.is_empty());
    for r in requests {
        assert_eq!(r.method, "POST");
        assert_eq!(r.path, "/ubus");
        assert!(
            !r.body.contains("admin_password"),
            "Password leaked in recorded request body!"
        );
    }
}

#[test]
fn test_openwrt_http_failure_modes() {
    let emulator = RouterEmulator::start();
    let gw_ip = Ipv4Addr::new(127, 0, 0, 1);
    let ubus_url = format!("{}/ubus", emulator.endpoint());

    // 1. Timeout failure mode
    emulator.set_fail_mode(Some(FailMode::Timeout(Duration::from_millis(500))));
    let provider = OpenWrtAdminProvider::new(gw_ip, &ubus_url).with_transport(Box::new(
        HttpOpenWrtTransport {
            timeout: Duration::from_millis(80),
        },
    ));
    provider.set_credentials(RouterCredentials::new("root", "admin_password"));
    let err = provider.detect_identity().unwrap_err();
    assert!(
        matches!(
            err,
            AdminError::Timeout(_) | AdminError::CommunicationError(_)
        ),
        "Expected timeout or communication error, got: {:?}",
        err
    );

    // 2. Malformed JSON failure mode
    emulator.set_fail_mode(Some(FailMode::MalformedJson));
    let provider = OpenWrtAdminProvider::new(gw_ip, &ubus_url);
    provider.set_credentials(RouterCredentials::new("root", "admin_password"));
    let err = provider.detect_identity().unwrap_err();
    assert!(
        matches!(err, AdminError::CommunicationError(_)),
        "Expected communication error on malformed JSON, got: {:?}",
        err
    );

    // 3. Oversized Response failure mode
    emulator.set_fail_mode(Some(FailMode::OversizedResponse(3 * 1024 * 1024)));
    let provider = OpenWrtAdminProvider::new(gw_ip, &ubus_url);
    provider.set_credentials(RouterCredentials::new("root", "admin_password"));
    let err = provider.detect_identity().unwrap_err();
    assert!(
        matches!(err, AdminError::CommunicationError(_)),
        "Expected communication error on oversized response, got: {:?}",
        err
    );

    // 4. Redirect rejection failure mode (HTTP 302 must NOT be silently followed)
    emulator.set_fail_mode(Some(FailMode::Redirect(
        "http://evil-attacker.local/ubus".into(),
    )));
    let provider = OpenWrtAdminProvider::new(gw_ip, &ubus_url);
    provider.set_credentials(RouterCredentials::new("root", "admin_password"));
    let err = provider.detect_identity().unwrap_err();
    assert!(
        matches!(
            err,
            AdminError::SecurityViolation(_) | AdminError::CommunicationError(_)
        ),
        "Expected security violation or communication error on redirect response, got: {:?}",
        err
    );
}

#[test]
fn test_openwrt_multi_target_partial_failure_rollback() {
    let emulator = RouterEmulator::start();
    let gw_ip = Ipv4Addr::new(127, 0, 0, 1);
    let ubus_url = format!("{}/ubus", emulator.endpoint());

    let provider = OpenWrtAdminProvider::new(gw_ip, &ubus_url);
    provider.set_credentials(RouterCredentials::new("root", "admin_password"));

    // Inject partial failure: allow session login and watchdog, but fail during the 2nd target addition
    // First target addition succeeds (1st target mutation), 2nd target addition fails
    emulator.set_fail_mode(Some(FailMode::MultiTargetPartialFail {
        succeed_targets: 1,
    }));

    let target1 = Ipv4Addr::new(192, 168, 1, 10);
    let target2 = Ipv4Addr::new(192, 168, 1, 11);
    let req = OperationPlanRequest {
        scope: PolicyScope::SpecificTargets(vec![target1, target2]),
        duration: PolicyDuration::Indefinite,
        persistence: PolicyPersistence::RouterPersistent,
        target_macs: Vec::new(),
    };

    let result = provider.apply_policy(&req);
    assert!(
        result.is_err(),
        "Multi-target policy with failure must return Err"
    );

    // Verify rollback: zero residual rules in emulator state
    let state = emulator.state();
    assert_eq!(
        state.openwrt_rules.len(),
        0,
        "Rollback must remove first target's rule if second target fails: {:?}",
        state.openwrt_rules
    );
}

#[test]
fn test_avm_tr064_full_protocol_flow() {
    let emulator = RouterEmulator::start();
    let gw_ip = Ipv4Addr::new(127, 0, 0, 1);
    let desc_url = format!("{}/tr64desc.xml", emulator.endpoint());

    let provider = AvmAdminProvider::new(gw_ip, &desc_url);
    provider.set_credentials(RouterCredentials::new("admin", "fritz_pass"));

    // 1. Detect Identity via TR-064 DeviceInfo:GetInfo
    let identity = provider.detect_identity().expect("Detect AVM identity");
    assert_eq!(identity.manufacturer.as_deref(), Some("AVM"));
    assert_eq!(identity.model_name.as_deref(), Some("FRITZ!Box 7590"));
    assert_eq!(identity.firmware_version.as_deref(), Some("7.57"));

    // 2. Discover Devices via Hosts:GetGenericHostEntry
    let devices = provider.list_devices().expect("List AVM devices");
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].ip, Some(Ipv4Addr::new(192, 168, 178, 20)));

    // 3. Multi-Target Policy Application (DisallowWANAccessByIP)
    let target1 = Ipv4Addr::new(192, 168, 178, 20);
    let target2 = Ipv4Addr::new(192, 168, 178, 21);
    let req = OperationPlanRequest {
        scope: PolicyScope::SpecificTargets(vec![target1, target2]),
        duration: PolicyDuration::Indefinite,
        persistence: PolicyPersistence::RouterPersistent,
        target_macs: Vec::new(),
    };

    let status = provider
        .apply_policy(&req)
        .expect("Apply multi-target AVM policy");
    assert!(status.policy_id.contains("avm_pause_"));

    let state = emulator.state();
    assert!(state.avm_blocked_ips.contains(&target1));
    assert!(state.avm_blocked_ips.contains(&target2));

    // 4. Revoke Policy (AllowWANAccessByIP)
    let resumed = provider
        .resume_policy(&PolicyScope::SpecificTargets(vec![target1, target2]))
        .expect("Resume AVM policy");
    assert_eq!(resumed.len(), 2);

    let state_after = emulator.state();
    assert!(!state_after.avm_blocked_ips.contains(&target1));
    assert!(!state_after.avm_blocked_ips.contains(&target2));
}

#[test]
fn test_avm_tr064_soap_fault_and_malformed() {
    let emulator = RouterEmulator::start();
    let gw_ip = Ipv4Addr::new(127, 0, 0, 1);
    let desc_url = format!("{}/tr64desc.xml", emulator.endpoint());

    // 1. SOAP Fault injection
    emulator.set_fail_mode(Some(FailMode::SoapFault {
        code: "s:Client".into(),
        message: "UPnPError: Action not authorized".into(),
    }));
    let provider = AvmAdminProvider::new(gw_ip, &desc_url);
    provider.set_credentials(RouterCredentials::new("admin", "fritz_pass"));
    let err = provider.detect_identity().unwrap_err();
    assert!(
        matches!(
            err,
            AdminError::TransactionFailed(_) | AdminError::CommunicationError(_)
        ),
        "Expected transaction or communication error on SOAP fault, got: {:?}",
        err
    );

    // 2. Malformed XML injection
    emulator.set_fail_mode(Some(FailMode::MalformedXml));
    let provider = AvmAdminProvider::new(gw_ip, &desc_url);
    provider.set_credentials(RouterCredentials::new("admin", "fritz_pass"));
    let err = provider.detect_identity().unwrap_err();
    assert!(
        matches!(
            err,
            AdminError::CommunicationError(_) | AdminError::TransactionFailed(_)
        ),
        "Expected error on malformed XML, got: {:?}",
        err
    );
}

#[test]
fn test_unifi_rest_protocol_flow() {
    let emulator = RouterEmulator::start();
    let gw_ip = Ipv4Addr::new(127, 0, 0, 1);

    let provider = UnifiAdminProvider::new(gw_ip, emulator.endpoint());
    provider.set_credentials(RouterCredentials::new("admin", "admin_password"));

    // 1. Authenticate & Discover Identity
    provider.login().expect("Authenticate UniFi controller");
    let identity = provider.detect_identity().expect("Detect UniFi identity");
    assert_eq!(identity.manufacturer.as_deref(), Some("Ubiquiti Networks"));
    assert_eq!(
        identity.model_name.as_deref(),
        Some("UniFi Network Application")
    );
    assert_eq!(identity.firmware_version.as_deref(), Some("8.0.28"));

    // 2. Query Client Inventory
    let devices = provider.list_devices().expect("List UniFi client devices");
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].ip, Some(Ipv4Addr::new(192, 168, 1, 100)));

    // 3. Multi-Target Policy Application (Traffic Rules)
    let target1 = Ipv4Addr::new(192, 168, 1, 100);
    let target2 = Ipv4Addr::new(192, 168, 1, 101);
    let req = OperationPlanRequest {
        scope: PolicyScope::SpecificTargets(vec![target1, target2]),
        duration: PolicyDuration::Indefinite,
        persistence: PolicyPersistence::RouterPersistent,
        target_macs: Vec::new(),
    };

    let status = provider
        .apply_policy(&req)
        .expect("Apply multi-target UniFi traffic rule");
    assert!(status.policy_id.starts_with("rustrict_pause_"));

    let state = emulator.state();
    assert_eq!(state.unifi_rules.len(), 1);

    // 4. Query Active Policies
    let active = provider
        .query_active_policies()
        .expect("Query active UniFi policies");
    assert_eq!(active.len(), 1);

    // 5. Revoke Policy
    let resumed = provider
        .resume_policy(&PolicyScope::SpecificTargets(vec![target1, target2]))
        .expect("Resume UniFi traffic rule");
    assert_eq!(resumed.len(), 1);

    let state_after = emulator.state();
    assert_eq!(state_after.unifi_rules.len(), 0);
}

#[test]
fn test_unifi_invalid_credentials_rejected() {
    let emulator = RouterEmulator::start();
    let gw_ip = Ipv4Addr::new(127, 0, 0, 1);

    let provider = UnifiAdminProvider::new(gw_ip, emulator.endpoint());
    provider.set_credentials(RouterCredentials::new("admin", "wrong_password"));

    let err = provider.login().unwrap_err();
    match err {
        AdminError::AuthenticationFailed(msg) => {
            assert!(
                msg.contains("Invalid") || msg.contains("401"),
                "Error was: {}",
                msg
            );
        }
        other => panic!("Expected AuthenticationFailed, got: {:?}", other),
    }
}

#[test]
fn test_mikrotik_rejects_unencrypted_http() {
    let transport = HttpsMikroTikTransport::default();
    let creds = RouterCredentials::new("admin", "mikrotik_pass");

    // Strict security assertion: HttpsMikroTikTransport must refuse unencrypted HTTP
    let result = transport.request(
        "http://127.0.0.1:8728",
        "GET",
        "/rest/system/resource",
        None,
        Some(&creds),
    );

    match result {
        Err(AdminError::SecurityViolation(msg)) => {
            assert!(
                msg.contains("Unencrypted HTTP is strictly prohibited"),
                "Expected unencrypted HTTP warning, got: {}",
                msg
            );
        }
        other => panic!(
            "Expected SecurityViolation for unencrypted HTTP, got: {:?}",
            other
        ),
    }
}

/// Loopback test transport for verifying MikroTik REST request construction and parsing
struct LoopbackMikroTikTransport;

impl MikroTikTransport for LoopbackMikroTikTransport {
    fn request(
        &self,
        endpoint: &str,
        method: &str,
        path: &str,
        body: Option<Value>,
        credentials: Option<&RouterCredentials>,
    ) -> Result<Value, AdminError> {
        let semantics = classify_mikrotik_operation(method, path);
        execute_with_operation_retry(semantics, path, |_attempt| {
            let clean = endpoint.trim_start_matches("http://");
            let (host, port_str) = clean.split_once(':').unwrap_or((clean, "80"));
            let port: u16 = port_str.parse().unwrap_or(80);
            let mut stream = TcpStream::connect((host, port)).map_err(|e| {
                AdminError::CommunicationError(format!("Loopback connect failed: {}", e))
            })?;

            let body_str = body.as_ref().map(|b| b.to_string()).unwrap_or_default();
            let mut req = format!(
                "{} {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
                method, path, clean, body_str.len()
            );
            if let Some(creds) = credentials {
                let auth = rustrict::gateway::admin::mikrotik::base64_encode(
                    format!("{}:{}", creds.username, creds.password.expose()).as_bytes(),
                );
                req.push_str(&format!("Authorization: Basic {}\r\n", auth));
            }
            req.push_str("\r\n");
            req.push_str(&body_str);

            stream
                .write_all(req.as_bytes())
                .map_err(|e| AdminError::CommunicationError(format!("Write failed: {}", e)))?;

            let mut resp_bytes = Vec::new();
            stream
                .read_to_end(&mut resp_bytes)
                .map_err(|e| AdminError::CommunicationError(format!("Read failed: {}", e)))?;

            let resp_str = String::from_utf8_lossy(&resp_bytes);
            if let Some((headers, body)) = resp_str.split_once("\r\n\r\n") {
                let status_line = headers.lines().next().unwrap_or("");
                if status_line.contains("401") {
                    return Err(AdminError::AuthenticationFailed(
                        "MikroTik 401 Unauthorized".into(),
                    ));
                }
                if status_line.contains("500") {
                    return Err(AdminError::TransactionFailed("MikroTik 500 Error".into()));
                }
                if body.trim().is_empty() || status_line.contains("204") {
                    return Ok(json!({}));
                }
                serde_json::from_str(body)
                    .map_err(|e| AdminError::CommunicationError(format!("Invalid JSON: {}", e)))
            } else {
                Err(AdminError::CommunicationError(
                    "Invalid HTTP response (connection closed before complete response)".into(),
                ))
            }
        })
    }
}

#[test]
fn test_mikrotik_loopback_rest_flow() {
    let emulator = RouterEmulator::start();
    let gw_ip = Ipv4Addr::new(127, 0, 0, 1);

    let provider = MikroTikAdminProvider::new(gw_ip, emulator.endpoint())
        .with_transport(Box::new(LoopbackMikroTikTransport));
    provider.set_credentials(RouterCredentials::new("admin", "mikrotik_pass"));

    // 1. Detect Identity
    let identity = provider
        .detect_identity()
        .expect("Detect MikroTik identity");
    assert_eq!(identity.manufacturer.as_deref(), Some("MikroTik"));
    assert_eq!(identity.model_name.as_deref(), Some("hEX S"));
    assert_eq!(identity.firmware_version.as_deref(), Some("7.14.1"));

    // 2. Discover Devices (MikroTik provider correctly reports UnsupportedOperation for device inventory)
    let dev_res = provider.list_devices();
    assert!(
        matches!(dev_res, Err(AdminError::UnsupportedOperation(_))),
        "MikroTik provider must report UnsupportedOperation for device inventory"
    );

    // 3. Multi-Target Policy Application
    let target1 = Ipv4Addr::new(192, 168, 88, 50);
    let target2 = Ipv4Addr::new(192, 168, 88, 51);
    let req = OperationPlanRequest {
        scope: PolicyScope::SpecificTargets(vec![target1, target2]),
        duration: PolicyDuration::Indefinite,
        persistence: PolicyPersistence::RouterPersistent,
        target_macs: Vec::new(),
    };

    let status = provider
        .apply_policy(&req)
        .expect("Apply multi-target MikroTik policy");
    assert!(status.policy_id.contains("multi"));

    let state = emulator.state();
    assert_eq!(state.mikrotik_rules.len(), 2);

    // 4. Revoke Policy
    let resumed = provider
        .resume_policy(&PolicyScope::SpecificTargets(vec![target1, target2]))
        .expect("Resume MikroTik policy");
    assert_eq!(resumed.len(), 2);

    let state_after = emulator.state();
    assert_eq!(state_after.mikrotik_rules.len(), 0);
}

#[test]
fn test_ssh_openwrt_contract_and_pipes() {
    let mock_executor = MockSshExecutor::default();
    let gw_ip = Ipv4Addr::new(192, 168, 1, 1);
    let ssh_config = SshConfig::new(gw_ip)
        .with_port(2222)
        .with_username("admin_ssh")
        .with_connect_timeout(Duration::from_secs(4));

    let transport =
        SshOpenWrtTransport::with_executor(ssh_config.clone(), Arc::new(mock_executor.clone()));
    let provider = OpenWrtAdminProvider::new(gw_ip, "ssh://192.168.1.1:2222")
        .with_transport(Box::new(transport));

    // Execute an operation and verify argument construction
    let req = OperationPlanRequest {
        scope: PolicyScope::SpecificTargets(vec![Ipv4Addr::new(192, 168, 1, 55)]),
        duration: PolicyDuration::Indefinite,
        persistence: PolicyPersistence::RouterPersistent,
        target_macs: Vec::new(),
    };

    let status = provider.apply_policy(&req).expect("Apply SSH policy");
    assert!(status.policy_id.contains("192_168_1_55"));

    // Verify remote commands executed via SSH
    let recorded = mock_executor.executed_commands.read();
    assert!(!recorded.is_empty());
    assert!(recorded.iter().any(|c| c.contains("id -u")));
    assert!(mock_executor
        .firewall_rules
        .read()
        .values()
        .any(|r| { r.to_string().contains("192.168.1.55") }));

    // Verify fail-closed security behavior on fresh connection: non-root access rejected
    let non_root_executor = MockSshExecutor::default();
    non_root_executor
        .simulate_non_root
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let non_root_provider =
        OpenWrtAdminProvider::new(gw_ip, "ssh://192.168.1.1:2222").with_transport(Box::new(
            SshOpenWrtTransport::with_executor(ssh_config.clone(), Arc::new(non_root_executor)),
        ));
    let err = non_root_provider.detect_identity().unwrap_err();
    assert!(
        matches!(err, AdminError::AuthenticationFailed(_)),
        "Expected AuthenticationFailed when SSH user is not root, got: {:?}",
        err
    );

    // Verify fail-closed security behavior: host key mismatch rejected
    let spoof_executor = MockSshExecutor::default();
    spoof_executor
        .simulate_host_key_mismatch
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let spoof_provider =
        OpenWrtAdminProvider::new(gw_ip, "ssh://192.168.1.1:2222").with_transport(Box::new(
            SshOpenWrtTransport::with_executor(ssh_config, Arc::new(spoof_executor)),
        ));
    let err2 = spoof_provider.detect_identity().unwrap_err();
    assert!(
        matches!(err2, AdminError::AuthenticationFailed(_)),
        "Expected AuthenticationFailed on spoofed host key, got: {:?}",
        err2
    );
}

#[test]
fn test_transport_operation_classification_and_retry_matrix() {
    // 1. AVM TR-064 classification
    let avm_get = classify_avm_action("urn:dslforum-org:service:Hosts:1", "GetGenericHostEntry");
    assert_eq!(avm_get, OperationSemantics::ReadOnly);
    assert_eq!(avm_get.max_attempts(), 2);
    assert!(avm_get.allows_retry());

    let avm_info = classify_avm_action("urn:dslforum-org:service:DeviceInfo:1", "GetInfo");
    assert_eq!(avm_info, OperationSemantics::ReadOnly);

    let avm_mutate = classify_avm_action(
        "urn:dslforum-org:service:X_AVM-DE_HostFilter:1",
        "DisallowWANAccessByIP",
    );
    assert_eq!(avm_mutate, OperationSemantics::StateChanging);
    assert_eq!(avm_mutate.max_attempts(), 1);
    assert!(!avm_mutate.allows_retry());

    let avm_unknown = classify_avm_action("urn:dslforum-org:service:Custom:1", "RebootRouter");
    assert_eq!(avm_unknown, OperationSemantics::Unknown);
    assert_eq!(avm_unknown.max_attempts(), 1);
    assert!(!avm_unknown.allows_retry());

    // 2. UniFi REST classification
    let unifi_get =
        classify_unifi_operation("GET", "/proxy/network/api/s/default/rest/firewallrule");
    assert_eq!(unifi_get, OperationSemantics::ReadOnly);
    assert_eq!(unifi_get.max_attempts(), 2);
    assert!(unifi_get.allows_retry());

    let unifi_auth = classify_unifi_operation("POST", "/api/auth/login");
    assert_eq!(unifi_auth, OperationSemantics::ReadOnly);

    let unifi_post =
        classify_unifi_operation("POST", "/proxy/network/api/s/default/rest/firewallrule");
    assert_eq!(unifi_post, OperationSemantics::StateChanging);
    assert_eq!(unifi_post.max_attempts(), 1);
    assert!(!unifi_post.allows_retry());

    let unifi_delete = classify_unifi_operation(
        "DELETE",
        "/proxy/network/api/s/default/rest/firewallrule/rule123",
    );
    assert_eq!(unifi_delete, OperationSemantics::StateChanging);

    let unifi_unknown =
        classify_unifi_operation("OPTIONS", "/proxy/network/api/s/default/rest/firewallrule");
    assert_eq!(unifi_unknown, OperationSemantics::Unknown);
    assert_eq!(unifi_unknown.max_attempts(), 1);

    // 3. MikroTik REST classification
    let mikrotik_get = classify_mikrotik_operation("GET", "/rest/ip/firewall/filter");
    assert_eq!(mikrotik_get, OperationSemantics::ReadOnly);
    assert_eq!(mikrotik_get.max_attempts(), 2);
    assert!(mikrotik_get.allows_retry());

    let mikrotik_post = classify_mikrotik_operation("POST", "/rest/ip/firewall/filter");
    assert_eq!(mikrotik_post, OperationSemantics::StateChanging);
    assert_eq!(mikrotik_post.max_attempts(), 1);
    assert!(!mikrotik_post.allows_retry());

    let mikrotik_delete = classify_mikrotik_operation("DELETE", "/rest/ip/firewall/filter/*1");
    assert_eq!(mikrotik_delete, OperationSemantics::StateChanging);

    let mikrotik_unknown = classify_mikrotik_operation("HEAD", "/rest/ip/firewall/filter");
    assert_eq!(mikrotik_unknown, OperationSemantics::Unknown);
    assert_eq!(mikrotik_unknown.max_attempts(), 1);
}

#[test]
fn test_execute_with_operation_retry_isolation() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    // 1. StateChanging: failure must not retry (exactly 1 invocation)
    let call_count = AtomicUsize::new(0);
    let res: Result<(), AdminError> = execute_with_operation_retry(
        OperationSemantics::StateChanging,
        "test_mutate",
        |_attempt| {
            call_count.fetch_add(1, Ordering::SeqCst);
            Err(AdminError::CommunicationError("Connection dropped".into()))
        },
    );
    assert!(res.is_err());
    assert_eq!(call_count.load(Ordering::SeqCst), 1);

    // 2. Unknown: failure must not retry (strictly 1 invocation)
    let call_count = AtomicUsize::new(0);
    let res: Result<(), AdminError> =
        execute_with_operation_retry(OperationSemantics::Unknown, "test_unknown", |_attempt| {
            call_count.fetch_add(1, Ordering::SeqCst);
            Err(AdminError::Timeout("Timed out".into()))
        });
    assert!(res.is_err());
    assert_eq!(call_count.load(Ordering::SeqCst), 1);

    // 3. ReadOnly: transient communication error retries with fresh buffer isolation (2 invocations)
    let call_count = AtomicUsize::new(0);
    let res: Result<String, AdminError> = execute_with_operation_retry(
        OperationSemantics::ReadOnly,
        "test_read_transient",
        |attempt| {
            let prev = call_count.fetch_add(1, Ordering::SeqCst);
            if prev == 0 {
                assert_eq!(attempt, 1);
                Err(AdminError::CommunicationError("WSAECONNRESET 10054".into()))
            } else {
                assert_eq!(attempt, 2);
                Ok("clean_response_attempt_2".to_string())
            }
        },
    );
    assert_eq!(res.unwrap(), "clean_response_attempt_2");
    assert_eq!(call_count.load(Ordering::SeqCst), 2);

    // 4. ReadOnly: authentication failure must fail immediately without retrying
    let call_count = AtomicUsize::new(0);
    let res: Result<String, AdminError> = execute_with_operation_retry(
        OperationSemantics::ReadOnly,
        "test_read_auth_fail",
        |_attempt| {
            call_count.fetch_add(1, Ordering::SeqCst);
            Err(AdminError::AuthenticationFailed("Bad password".into()))
        },
    );
    assert!(res.is_err());
    assert_eq!(call_count.load(Ordering::SeqCst), 1);
}

#[test]
fn test_avm_mutation_response_dropped_uncertainty_and_no_retry() {
    let emulator = RouterEmulator::start();
    let temp_dir = TestTempDir::new("avm_uncertainty");
    let state_file = temp_dir.path().join("policy_store.json");

    let gateway_ip = Ipv4Addr::new(127, 0, 0, 1);
    let registry = Arc::new(RouterRegistry::new(gateway_ip));
    let store = Arc::new(PolicyStore::with_path(&state_file));
    let engine = PolicyExecutionEngine::with_store(registry.clone(), store.clone());

    let desc_url = format!("{}/tr64desc.xml", emulator.endpoint());
    let provider = Arc::new(AvmAdminProvider::new(gateway_ip, &desc_url));
    provider.set_credentials(RouterCredentials::new("admin", "fritz_pass"));

    registry
        .connect("avm-tr064", provider, &desc_url)
        .expect("Connect AVM provider");

    // Inject failure mode: Mutate router state, then drop TCP connection without response
    emulator.set_fail_mode(Some(FailMode::MutateThenDrop));
    emulator.clear_recorded_requests();

    let target_ip = Ipv4Addr::new(192, 168, 178, 88);
    let req = OperationPlanRequest {
        scope: PolicyScope::SpecificTargets(vec![target_ip]),
        duration: PolicyDuration::Indefinite,
        persistence: PolicyPersistence::RouterPersistent,
        target_macs: Vec::new(),
    };

    let apply_res = engine.apply_policy(&req);
    assert!(
        apply_res.is_err(),
        "Expected error when connection drops post-mutation"
    );
    let err = apply_res.err().unwrap();
    assert!(
        err.is_ambiguous_outcome(),
        "Transport drop post-dispatch must be recognized as ambiguous outcome: {:?}",
        err
    );

    // 1. Assert exactly ONE mutating request reached the emulator (NO automatic retry!)
    let reqs = emulator.recorded_requests();
    let mutate_reqs: Vec<&support::RecordedRequest> = reqs
        .iter()
        .filter(|r| r.body.contains("<NewIPv4Address>"))
        .collect();
    assert_eq!(
        mutate_reqs.len(),
        1,
        "StateChanging operation must not be retried automatically!"
    );

    // 2. Assert the router state DID change (the router received the mutation!)
    let state = emulator.state();
    assert!(
        state.avm_blocked_ips.contains(&target_ip),
        "Router in-memory state must reflect applied mutation despite lost response"
    );

    // 3. Assert persisted policy record is marked UNKNOWN rather than FALSELY FAILED or rolled back
    let history = store.historical_policies();
    let unconfirmed = history
        .iter()
        .find(|p| p.scope.conflicts_with(&req.scope))
        .expect("Must persist unconfirmed policy");
    assert_eq!(
        unconfirmed.lifecycle_state,
        PolicyLifecycleState::Unknown,
        "Policy state must accurately represent uncertainty"
    );

    // 4. Assert conflicting follow-up mutations on this scope are BLOCKED
    let conflicting_req = OperationPlanRequest {
        scope: PolicyScope::SpecificTargets(vec![target_ip]),
        duration: PolicyDuration::Indefinite,
        persistence: PolicyPersistence::RouterPersistent,
        target_macs: Vec::new(),
    };
    let block_res = engine.apply_policy(&conflicting_req);
    assert!(
        block_res.is_err(),
        "Conflicting mutation on unresolved policy must be rejected"
    );
    let block_err = block_res.err().unwrap();
    assert!(
        block_err
            .to_string()
            .contains("Mutation rejected: Conflicting policy"),
        "Expected conflict rejection error, got: {}",
        block_err
    );

    // Also assert NetworkWide mutation is BLOCKED
    let net_wide_req = OperationPlanRequest {
        scope: PolicyScope::NetworkWide,
        duration: PolicyDuration::Indefinite,
        persistence: PolicyPersistence::RouterPersistent,
        target_macs: Vec::new(),
    };
    let block_net_res = engine.apply_policy(&net_wide_req);
    assert!(block_net_res.is_err());

    // 5. Clear failure mode and verify operator resume recovers state
    emulator.set_fail_mode(None);
    let resume_res = engine.resume_policy(&PolicyScope::SpecificTargets(vec![target_ip]));
    assert!(resume_res.is_ok(), "Operator resume must succeed");

    let state_resumed = emulator.state();
    assert!(
        !state_resumed.avm_blocked_ips.contains(&target_ip),
        "Router state must be cleared after operator resume"
    );
}

#[test]
fn test_unifi_mutation_response_dropped_uncertainty_and_no_retry() {
    let emulator = RouterEmulator::start();
    let temp_dir = TestTempDir::new("unifi_uncertainty");
    let state_file = temp_dir.path().join("policy_store.json");

    let gateway_ip = Ipv4Addr::new(127, 0, 0, 1);
    let registry = Arc::new(RouterRegistry::new(gateway_ip));
    let store = Arc::new(PolicyStore::with_path(&state_file));
    let engine = PolicyExecutionEngine::with_store(registry.clone(), store.clone());

    let provider = Arc::new(UnifiAdminProvider::new(gateway_ip, emulator.endpoint()));
    provider.set_credentials(RouterCredentials::new("admin", "admin_password"));

    registry
        .connect("unifi-rest", provider, emulator.endpoint())
        .expect("Connect UniFi provider");

    // Inject failure mode: Mutate router state, then drop connection without sending response
    emulator.set_fail_mode(Some(FailMode::MutateThenDrop));
    emulator.clear_recorded_requests();

    let target_ip = Ipv4Addr::new(192, 168, 1, 99);
    let req = OperationPlanRequest {
        scope: PolicyScope::SpecificTargets(vec![target_ip]),
        duration: PolicyDuration::Indefinite,
        persistence: PolicyPersistence::RouterPersistent,
        target_macs: Vec::new(),
    };

    let apply_res = engine.apply_policy(&req);
    assert!(apply_res.is_err());
    let err = apply_res.err().unwrap();
    assert!(err.is_ambiguous_outcome());

    // Verify exactly 1 mutation request on emulator
    let reqs = emulator.recorded_requests();
    for r in &reqs {
        eprintln!(
            "AVM REQ: method={} soapaction={:?} body={}",
            r.method,
            r.headers.get("soapaction"),
            r.body
        );
    }
    let mutate_reqs: Vec<&support::RecordedRequest> = reqs
        .iter()
        .filter(|r| r.method == "POST" && r.path.contains("trafficrule"))
        .collect();
    assert_eq!(
        mutate_reqs.len(),
        1,
        "UniFi mutation request must not be retried automatically!"
    );

    // Verify router state DID change
    let state = emulator.state();
    assert_eq!(
        state.unifi_rules.len(),
        1,
        "UniFi rule must be present on simulated router"
    );

    // Verify persisted state is UNKNOWN
    let history = store.historical_policies();
    let unconfirmed = history
        .iter()
        .find(|p| p.scope.conflicts_with(&req.scope))
        .expect("Must persist unconfirmed policy");
    assert_eq!(unconfirmed.lifecycle_state, PolicyLifecycleState::Unknown);

    // Verify conflicting follow-up is blocked
    let conflict_res = engine.apply_policy(&req);
    assert!(conflict_res.is_err());
    let err = conflict_res.err().unwrap();
    assert!(err
        .to_string()
        .contains("Mutation rejected: Conflicting policy"));
}

#[test]
fn test_mikrotik_mutation_response_dropped_uncertainty_and_no_retry() {
    let emulator = RouterEmulator::start();
    let temp_dir = TestTempDir::new("mikrotik_uncertainty");
    let state_file = temp_dir.path().join("policy_store.json");

    let gateway_ip = Ipv4Addr::new(127, 0, 0, 1);
    let registry = Arc::new(RouterRegistry::new(gateway_ip));
    let store = Arc::new(PolicyStore::with_path(&state_file));
    let engine = PolicyExecutionEngine::with_store(registry.clone(), store.clone());

    let provider = Arc::new(
        MikroTikAdminProvider::new(gateway_ip, emulator.endpoint())
            .with_transport(Box::new(LoopbackMikroTikTransport)),
    );
    provider.set_credentials(RouterCredentials::new("admin", "mikrotik_pass"));

    registry
        .connect("mikrotik-rest", provider, emulator.endpoint())
        .expect("Connect MikroTik provider");

    // Inject failure mode: Mutate router state, then drop connection without sending response
    emulator.set_fail_mode(Some(FailMode::MutateThenDrop));
    emulator.clear_recorded_requests();

    let target_ip = Ipv4Addr::new(192, 168, 88, 77);
    let req = OperationPlanRequest {
        scope: PolicyScope::SpecificTargets(vec![target_ip]),
        duration: PolicyDuration::Indefinite,
        persistence: PolicyPersistence::RouterPersistent,
        target_macs: Vec::new(),
    };

    let apply_res = engine.apply_policy(&req);
    assert!(apply_res.is_err());
    let err = apply_res.err().unwrap();
    assert!(err.is_ambiguous_outcome());

    // Verify exactly 1 mutation request on emulator
    let reqs = emulator.recorded_requests();
    for r in &reqs {
        eprintln!(
            "AVM REQ: method={} soapaction={:?} body={}",
            r.method,
            r.headers.get("soapaction"),
            r.body
        );
    }
    let mutate_reqs: Vec<&support::RecordedRequest> = reqs
        .iter()
        .filter(|r| {
            (r.method == "POST" || r.method == "PUT")
                && r.path.starts_with("/rest/ip/firewall/filter")
        })
        .collect();
    assert_eq!(
        mutate_reqs.len(),
        1,
        "MikroTik mutation request must not be retried automatically!"
    );

    // Verify router state DID change
    let state = emulator.state();
    assert_eq!(
        state.mikrotik_rules.len(),
        1,
        "MikroTik rule must be present on simulated router"
    );

    // Verify persisted state is UNKNOWN
    let history = store.historical_policies();
    let unconfirmed = history
        .iter()
        .find(|p| p.scope.conflicts_with(&req.scope))
        .expect("Must persist unconfirmed policy");
    assert_eq!(unconfirmed.lifecycle_state, PolicyLifecycleState::Unknown);

    // Verify conflicting follow-up is blocked
    let conflict_res = engine.apply_policy(&req);
    assert!(conflict_res.is_err());
    let err = conflict_res.err().unwrap();
    assert!(err
        .to_string()
        .contains("Mutation rejected: Conflicting policy"));
}

#[test]
fn test_multi_target_partial_with_rollback_failure_reporting() {
    let emulator = RouterEmulator::start();
    let temp_dir = TestTempDir::new("avm_rb_fail");
    let state_file = temp_dir.path().join("policy_store.json");

    let gateway_ip = Ipv4Addr::new(127, 0, 0, 1);
    let registry = Arc::new(RouterRegistry::new(gateway_ip));
    let store = Arc::new(PolicyStore::with_path(&state_file));
    let engine = PolicyExecutionEngine::with_store(registry.clone(), store.clone());

    let desc_url = format!("{}/tr64desc.xml", emulator.endpoint());
    let provider = Arc::new(AvmAdminProvider::new(gateway_ip, &desc_url));
    provider.set_credentials(RouterCredentials::new("admin", "fritz_pass"));

    registry
        .connect("avm-tr064", provider, &desc_url)
        .expect("Connect AVM provider");

    // In multi-target: succeed target 1, fail target 2, and reject rollback of target 1
    emulator.set_fail_mode(Some(FailMode::MultiTargetPartialWithRollbackFail {
        succeed_targets: 1,
    }));
    emulator.reset_mutation_counter();

    let target1 = Ipv4Addr::new(192, 168, 178, 10);
    let target2 = Ipv4Addr::new(192, 168, 178, 11);
    let req = OperationPlanRequest {
        scope: PolicyScope::SpecificTargets(vec![target1, target2]),
        duration: PolicyDuration::Indefinite,
        persistence: PolicyPersistence::RouterPersistent,
        target_macs: Vec::new(),
    };

    let apply_res = engine.apply_policy(&req);
    assert!(apply_res.is_err());
    let err = apply_res.err().unwrap();

    // Verify typed RollbackFailed error is returned
    match &err {
        AdminError::RollbackFailed {
            applied_targets,
            failed_target,
            rollback_errors,
            ..
        } => {
            assert_eq!(applied_targets, &vec![target1.to_string()]);
            assert_eq!(failed_target, &target2.to_string());
            assert!(!rollback_errors.is_empty(), "Must record rollback failure");
        }
        _ => panic!("Expected AdminError::RollbackFailed, got: {:?}", err),
    }

    // Verify persisted state is PartialFailure
    let history = store.historical_policies();
    let unconfirmed = history
        .iter()
        .find(|p| p.scope.conflicts_with(&req.scope))
        .expect("Must persist unconfirmed partial failure");
    assert!(
        matches!(
            unconfirmed.lifecycle_state,
            PolicyLifecycleState::PartialFailure { .. }
        ),
        "Expected PartialFailure state, got: {:?}",
        unconfirmed.lifecycle_state
    );

    // Verify conflicting follow-up is blocked
    let conflict_res = engine.apply_policy(&req);
    assert!(conflict_res.is_err());
    let err = conflict_res.err().unwrap();
    assert!(err
        .to_string()
        .contains("Mutation rejected: Conflicting policy"));
}
