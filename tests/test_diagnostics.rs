use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustrict::gateway::admin::{
    sanitize_endpoint, AdminError, AvmAdminProvider, DataSource, DiagnosticResult,
    MockAvmTransport, MockRouterAdminProvider, MockUnifiTransport, OpenWrtAdminProvider,
    PolicyExecutionEngine, PolicyExecutionRecord, PolicyLifecycleState, PolicyStore,
    ProviderConnectionState, RouterAdminProvider, RouterCredentials, RouterRegistry,
    UnifiAdminProvider,
};
use rustrict::types::MacAddress;

struct TestTempDir {
    path: PathBuf,
}

impl TestTempDir {
    fn new(name: &str) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "rustrict_diag_{}_{}_{}",
            name,
            std::process::id(),
            now
        ));
        let _ = fs::create_dir_all(&path);
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestTempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[test]
fn test_endpoint_sanitization() {
    let clean = "https://192.168.1.1:443/ubus";
    assert_eq!(sanitize_endpoint(clean), "https://192.168.1.1:443/ubus");

    let embedded_user_pass = "https://admin:super_secret_password@192.168.1.1:443/api";
    let sanitized_up = sanitize_endpoint(embedded_user_pass);
    assert!(!sanitized_up.contains("super_secret_password"));
    assert!(sanitized_up.contains("[REDACTED]"));
    assert!(sanitized_up.contains("192.168.1.1:443/api"));

    let token_param = "https://192.168.1.1:8443/api?token=secret_token_12345&site=default";
    let sanitized_tok = sanitize_endpoint(token_param);
    assert!(!sanitized_tok.contains("secret_token_12345"));
    assert!(sanitized_tok.contains("[REDACTED]"));
    assert!(sanitized_tok.contains("site=default"));
}

#[test]
fn test_inventory_normalization_and_distinction_of_live_vs_cached() {
    let temp_dir = TestTempDir::new("inv_norm");
    let state_file = temp_dir.path().join("inv_test.json");

    let gateway_ip = Ipv4Addr::new(192, 168, 1, 1);
    let registry = Arc::new(RouterRegistry::new(gateway_ip));
    let store = Arc::new(PolicyStore::with_path(&state_file));

    // Seed a historical execution record for OpenWrt to test cached state
    let hist_record = PolicyExecutionRecord {
        execution_id: "exec_hist_1".into(),
        timestamp_unix: 1710000000,
        operation: "apply".into(),
        provider_id: "openwrt-http".into(),
        provider_name: "OpenWrt (HTTP/HTTPS JSON-RPC ubus)".into(),
        target_scope: rustrict::gateway::admin::PolicyScope::NetworkWide,
        initial_state: PolicyLifecycleState::PendingApplication,
        final_state: PolicyLifecycleState::Active,
        duration: rustrict::gateway::admin::PolicyDuration::Indefinite,
        persistence: rustrict::gateway::admin::PolicyPersistence::VolatileSession,
        autonomous_recovery_guaranteed: true,
        policy_id: Some("pol_openwrt_hist".into()),
        error: None,
    };
    store.append_record(&hist_record).expect("Append record");

    let engine = PolicyExecutionEngine::with_store(registry.clone(), store.clone());

    // 1. Check inventory while disconnected
    let inv_disconnected = engine.get_inventory();
    assert_eq!(
        inv_disconnected.len(),
        6,
        "All 6 built-in providers should be present"
    );

    let openwrt_item = inv_disconnected
        .iter()
        .find(|i| i.provider_id == "openwrt-http")
        .unwrap();
    assert_eq!(
        openwrt_item.connection_state,
        ProviderConnectionState::Disconnected
    );
    assert_eq!(openwrt_item.data_source, DataSource::LocallyCached);
    assert!(!openwrt_item.is_active_provider);
    assert_eq!(openwrt_item.last_contact_unix, Some(1710000000));
    assert!(openwrt_item
        .diagnostic_summary
        .as_ref()
        .unwrap()
        .contains("Locally cached"));

    let mikrotik_item = inv_disconnected
        .iter()
        .find(|i| i.provider_id == "mikrotik-rest")
        .unwrap();
    assert_eq!(
        mikrotik_item.connection_state,
        ProviderConnectionState::Disconnected
    );
    assert_eq!(mikrotik_item.data_source, DataSource::StaticDescriptor);
    assert!(!mikrotik_item.is_active_provider);
    assert_eq!(mikrotik_item.last_contact_unix, None);

    // 2. Connect mock provider and verify live distinction
    let mock = Arc::new(MockRouterAdminProvider::new(gateway_ip));
    registry
        .connect("mock", mock, "internal://mock")
        .expect("Connect mock");

    let inv_connected = engine.get_inventory();
    let mock_item = inv_connected
        .iter()
        .find(|i| i.provider_id == "mock")
        .unwrap();
    assert_eq!(
        mock_item.connection_state,
        ProviderConnectionState::Connected
    );
    assert_eq!(mock_item.data_source, DataSource::Live);
    assert!(mock_item.is_active_provider);
    assert!(mock_item.router_identity.is_some());
    assert_eq!(mock_item.firmware_version.as_deref(), Some("v2.4.0-test"));
    assert_eq!(mock_item.known_device_count, Some(2));
    assert!(mock_item.last_contact_unix.is_some());
}

#[test]
fn test_read_only_diagnostics_report_connected_and_read_only_enforcement() {
    let temp_dir = TestTempDir::new("diag_conn");
    let state_file = temp_dir.path().join("diag_test.json");

    let gateway_ip = Ipv4Addr::new(192, 168, 1, 1);
    let registry = Arc::new(RouterRegistry::new(gateway_ip));
    let mock = Arc::new(MockRouterAdminProvider::new(gateway_ip));
    registry
        .connect("mock", mock.clone(), "internal://mock")
        .expect("Connect mock");

    let store = Arc::new(PolicyStore::with_path(&state_file));
    let engine = PolicyExecutionEngine::with_store(registry.clone(), store.clone());

    // Record initial state of mock provider
    let initial_policies_count = mock.active_policies.read().len();

    // Execute read-only diagnostics
    let report = engine.run_diagnostics();

    assert_eq!(report.provider_id, "mock");
    assert_eq!(report.provider_name, "Mock Router Provider");

    // Connection diagnostic
    match &report.connection_status {
        DiagnosticResult::Supported(conn) => {
            assert!(conn.is_connected);
            assert!(conn.is_authenticated);
            assert_eq!(conn.transport_protocol, "Internal In-Memory Simulation");
            assert!(conn.response_latency_ms.is_some());
        }
        other => panic!("Expected Supported connection diagnostic, got {:?}", other),
    }

    // Identity and version
    match &report.identity_and_version {
        DiagnosticResult::Supported(id) => {
            assert_eq!(id.ip, gateway_ip);
            assert_eq!(id.manufacturer.as_deref(), Some("MockNetworks"));
            assert_eq!(id.model_name.as_deref(), Some("VirtualGateway-X1"));
            assert_eq!(id.firmware_version.as_deref(), Some("v2.4.0-test"));
        }
        other => panic!("Expected Supported identity, got {:?}", other),
    }

    // Client devices
    match &report.connected_devices {
        DiagnosticResult::Supported(devs) => {
            assert_eq!(devs.len(), 2);
            assert_eq!(devs[0].ip, Some(Ipv4Addr::new(192, 168, 1, 100)));
            assert_eq!(devs[0].hostname.as_deref(), Some("Mock-Desktop"));
        }
        other => panic!("Expected Supported connected devices, got {:?}", other),
    }

    // Capabilities
    match &report.capability_assessment {
        DiagnosticResult::Supported(caps) => {
            assert!(caps.read_only_discovery.is_operational());
        }
        other => panic!("Expected Supported capabilities, got {:?}", other),
    }

    // STRICT PROHIBITION VERIFICATION: Zero mutations took place
    assert_eq!(
        mock.active_policies.read().len(),
        initial_policies_count,
        "Read-only diagnostics must NEVER add or mutate router policy rules"
    );
    assert_eq!(
        store.records().len(),
        0,
        "Read-only diagnostics must not append policy mutation execution records"
    );
}

#[test]
fn test_read_only_diagnostics_report_disconnected() {
    let temp_dir = TestTempDir::new("diag_disconn");
    let state_file = temp_dir.path().join("diag_disconn.json");

    let gateway_ip = Ipv4Addr::new(192, 168, 1, 1);
    let registry = Arc::new(RouterRegistry::new(gateway_ip));
    let store = Arc::new(PolicyStore::with_path(&state_file));
    let engine = PolicyExecutionEngine::with_store(registry, store);

    let report = engine.run_diagnostics();

    match &report.connection_status {
        DiagnosticResult::Failed(msg) => {
            assert!(msg.contains("No router provider is currently connected"));
        }
        other => panic!(
            "Expected Failed connection status when disconnected, got {:?}",
            other
        ),
    }

    assert!(matches!(
        report.identity_and_version,
        DiagnosticResult::Unsupported(_)
    ));
    assert!(matches!(
        report.active_policies,
        DiagnosticResult::Unsupported(_)
    ));
    assert!(matches!(
        report.connected_devices,
        DiagnosticResult::Unsupported(_)
    ));
}

#[test]
fn test_device_inventory_support_on_unifi_and_avm() {
    let gateway_ip = Ipv4Addr::new(192, 168, 1, 1);

    // 1. UniFi Network Provider (Supported)
    let mock_unifi_transport = Box::new(MockUnifiTransport::default());
    let unifi = UnifiAdminProvider::new(gateway_ip, "https://192.168.1.1:443")
        .with_transport(mock_unifi_transport);
    unifi.set_credentials(RouterCredentials::new("admin", "admin_password"));

    let unifi_devices = unifi
        .list_devices()
        .expect("UniFi list_devices should succeed");
    assert!(
        !unifi_devices.is_empty(),
        "UniFi mock should return connected devices"
    );
    let dev0 = &unifi_devices[0];
    assert_eq!(dev0.ip, Some(Ipv4Addr::new(192, 168, 1, 100)));
    assert_eq!(
        dev0.mac,
        Some(MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
    );
    assert_eq!(dev0.hostname.as_deref(), Some("Workstation-Office"));
    assert_eq!(dev0.interface_type.as_deref(), Some("Wired (Ethernet)"));

    // 2. AVM FRITZ!Box Provider (Supported)
    let mock_avm_transport = Box::new(MockAvmTransport::default());
    let avm = AvmAdminProvider::new(gateway_ip, "https://192.168.1.1:49443/tr64desc.xml")
        .with_transport(mock_avm_transport);
    avm.set_credentials(RouterCredentials::new("admin", "admin_password"));

    let avm_devices = avm.list_devices().expect("AVM list_devices should succeed");
    assert!(
        !avm_devices.is_empty(),
        "AVM mock should return LAN host entries"
    );
    assert_eq!(avm_devices[0].ip, Some(Ipv4Addr::new(192, 168, 178, 20)));
    assert_eq!(avm_devices[0].hostname.as_deref(), Some("Desktop-PC"));

    // 3. OpenWrt HTTP Provider (Explicitly Unsupported)
    let openwrt = OpenWrtAdminProvider::new(gateway_ip, "http://192.168.1.1:80/ubus");
    match openwrt.list_devices() {
        Err(AdminError::UnsupportedOperation(msg)) => {
            assert!(
                msg.contains("does not support querying connected client device inventory"),
                "OpenWrt should report explicit unsupported operation without inventing endpoints"
            );
        }
        other => panic!(
            "Expected UnsupportedOperation for OpenWrt client devices, got {:?}",
            other
        ),
    }
}

#[test]
fn test_diagnostics_sanitizes_errors() {
    let temp_dir = TestTempDir::new("diag_sanit");
    let state_file = temp_dir.path().join("diag_sanit.json");

    let gateway_ip = Ipv4Addr::new(192, 168, 1, 1);
    let registry = Arc::new(RouterRegistry::new(gateway_ip));
    let mock = Arc::new(MockRouterAdminProvider::new(gateway_ip));
    registry
        .connect("mock", mock.clone(), "internal://mock")
        .expect("Connect mock");

    let store = Arc::new(PolicyStore::with_path(&state_file));

    // Append record with sensitive error text
    let error_record = PolicyExecutionRecord {
        execution_id: "exec_err_1".into(),
        timestamp_unix: 1715000000,
        operation: "apply".into(),
        provider_id: "mock".into(),
        provider_name: "Mock Provider".into(),
        target_scope: rustrict::gateway::admin::PolicyScope::NetworkWide,
        initial_state: PolicyLifecycleState::PendingApplication,
        final_state: PolicyLifecycleState::Failed("Auth error".into()),
        duration: rustrict::gateway::admin::PolicyDuration::Indefinite,
        persistence: rustrict::gateway::admin::PolicyPersistence::VolatileSession,
        autonomous_recovery_guaranteed: false,
        policy_id: None,
        error: Some("Failed with password=SecretPasswordXYZ and token=SecretToken987".into()),
    };
    store.append_record(&error_record).expect("Append record");

    let engine = PolicyExecutionEngine::with_store(registry, store);
    let report = engine.run_diagnostics();

    assert!(!report.recent_errors.is_empty());
    let err_msg = &report.recent_errors[0];
    assert!(
        !err_msg.contains("SecretPasswordXYZ"),
        "Diagnostic recent errors must be sanitized"
    );
    assert!(
        !err_msg.contains("SecretToken987"),
        "Diagnostic recent errors must be sanitized"
    );
    assert!(
        err_msg.contains("[REDACTED]"),
        "Diagnostic error must contain [REDACTED]"
    );
}

#[test]
fn test_no_provider_fallback_on_query_failure() {
    let gateway_ip = Ipv4Addr::new(192, 168, 1, 1);
    let registry = Arc::new(RouterRegistry::new(gateway_ip));

    let mock = Arc::new(MockRouterAdminProvider::new(gateway_ip));
    registry
        .connect("mock", mock.clone(), "internal://mock")
        .expect("Connect mock");

    // Force timeout after connection is established
    mock.set_force_timeout(true);

    let temp_dir = TestTempDir::new("no_fallback");
    let state_file = temp_dir.path().join("no_fallback.json");
    let store = Arc::new(PolicyStore::with_path(&state_file));
    let engine = PolicyExecutionEngine::with_store(registry, store);

    let report = engine.run_diagnostics();
    match &report.identity_and_version {
        DiagnosticResult::Failed(err) => {
            assert!(
                err.to_lowercase().contains("timed out"),
                "Should return failed result for selected provider without falling back to another"
            );
        }
        other => panic!("Expected Failed diagnostic result, got {:?}", other),
    }

    assert_eq!(
        report.provider_id, "mock",
        "Must remain on explicitly selected provider"
    );
}
