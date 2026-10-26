use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rustrict::gateway::admin::{
    atomic_write_file, ActivePolicyStatus, AdminError, MockRouterAdminProvider, MockUnifiTransport,
    OperationPlanRequest, PersistentPolicyState, PolicyDuration, PolicyExecutionEngine,
    PolicyExecutionRecord, PolicyLifecycleState, PolicyPersistence, PolicyScope, PolicyStore,
    RecoveryMechanism, RecoveryVerificationStatus, RouterRegistry, UnifiAdminProvider,
    CURRENT_SCHEMA_VERSION,
};

struct TestTempDir {
    path: PathBuf,
}

impl TestTempDir {
    fn new(name: &str) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("rustrict_{}_{}_{}", name, std::process::id(), now));
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
fn test_atomic_write_and_replace() {
    let temp_dir = TestTempDir::new("atomic_write");
    let target_file = temp_dir.path().join("atomic_policy_test.json");

    let data1 = b"{\"schema_version\": 1, \"content\": \"first write\"}";
    atomic_write_file(&target_file, data1).expect("First atomic write should succeed");
    assert!(target_file.exists());
    let read1 = fs::read_to_string(&target_file).expect("Read first write");
    assert_eq!(read1, String::from_utf8_lossy(data1));

    // Overwrite atomically
    let data2 = b"{\"schema_version\": 1, \"content\": \"second replaced write\"}";
    atomic_write_file(&target_file, data2).expect("Second atomic write should succeed");
    let read2 = fs::read_to_string(&target_file).expect("Read second write");
    assert_eq!(read2, String::from_utf8_lossy(data2));

    // Ensure no residual temp files remain
    let entries = fs::read_dir(temp_dir.path()).expect("Read dir");
    let temp_files: Vec<_> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
        .collect();
    assert!(temp_files.is_empty(), "Temporary files must be cleaned up");
}

#[test]
fn test_windows_path_handling_with_spaces() {
    let temp_dir = TestTempDir::new("spaces_test");
    let spaced_dir = temp_dir.path().join("Program Data Spaces");
    fs::create_dir_all(&spaced_dir).expect("Create spaced dir");
    let target_file = spaced_dir.join("router policies with space.json");

    let store = PolicyStore::with_path(&target_file);
    assert_eq!(store.records().len(), 0);

    let record = PolicyExecutionRecord {
        execution_id: "exec_space_test".into(),
        timestamp_unix: 1700000000,
        operation: "apply".into(),
        provider_id: "mock".into(),
        provider_name: "Mock Provider".into(),
        target_scope: PolicyScope::NetworkWide,
        initial_state: PolicyLifecycleState::PendingApplication,
        final_state: PolicyLifecycleState::Active,
        duration: PolicyDuration::Indefinite,
        persistence: PolicyPersistence::VolatileSession,
        autonomous_recovery_guaranteed: true,
        policy_id: Some("pol_space_1".into()),
        error: None,
    };

    store
        .append_record(&record)
        .expect("Append record should succeed in spaced path");
    assert!(target_file.exists());

    // Re-read with a second store instance
    let store2 = PolicyStore::with_path(&target_file);
    assert_eq!(store2.records().len(), 1);
    assert_eq!(store2.records()[0].execution_id, "exec_space_test");
}

#[test]
fn test_schema_versioning_and_malformed_state_handling() {
    let temp_dir = TestTempDir::new("corrupt_test");
    let corrupt_file = temp_dir.path().join("corrupted.json");

    // 1. Write garbage/malformed JSON
    fs::write(&corrupt_file, b"{ corrupted invalid json: [").expect("Write corrupt data");

    // Loading must not panic and must safely return fallback state
    let store = PolicyStore::with_path(&corrupt_file);
    assert_eq!(store.records().len(), 0);
    assert_eq!(store.historical_policies().len(), 0);
    assert_eq!(store.snapshot().schema_version, CURRENT_SCHEMA_VERSION);

    // 2. Truncated JSON
    let truncated_file = temp_dir.path().join("truncated.json");
    fs::write(&truncated_file, b"{\"schema_version\": 1, \"re").expect("Write truncated data");

    let store_trunc = PolicyStore::with_path(&truncated_file);
    assert_eq!(store_trunc.records().len(), 0);
    assert_eq!(store_trunc.historical_policies().len(), 0);
}

#[test]
fn test_safe_startup_reconciliation_marks_active_as_unknown() {
    let temp_dir = TestTempDir::new("reconciliation_test");
    let state_file = temp_dir.path().join("startup_reconciliation.json");

    // Manually create a persisted state with an ACTIVE policy
    let state = PersistentPolicyState {
        schema_version: 1,
        last_updated_unix: 1700000000,
        records: vec![],
        historical_policies: vec![ActivePolicyStatus::new(
            "policy_active_pre_reboot",
            PolicyScope::SpecificTargets(vec![Ipv4Addr::new(192, 168, 1, 150)]),
            1700000000,
            Some(1700003600),
            false,
            "Mock Provider",
            true,
        )],
    };
    let json = serde_json::to_string_pretty(&state).expect("Serialize");
    fs::write(&state_file, json).expect("Write state file");

    // Load state through PolicyStore (simulating Rustrict startup)
    let store = PolicyStore::with_path(&state_file);
    let policies = store.historical_policies();
    assert_eq!(policies.len(), 1);

    let policy = &policies[0];
    // Crucial requirement: Local Active state MUST NOT be assumed active on the router
    assert_eq!(
        policy.lifecycle_state,
        PolicyLifecycleState::Unknown,
        "Active policies from disk must transition to Unknown at startup"
    );
    assert!(
        policy
            .last_error
            .as_deref()
            .unwrap_or("")
            .contains("Startup reconciliation pending"),
        "Must record explanatory message for Unknown state"
    );
}

#[test]
fn test_secret_sanitization_on_disk() {
    let temp_dir = TestTempDir::new("secret_sanitization");
    let state_file = temp_dir.path().join("sanitized_state.json");

    let store = PolicyStore::with_path(&state_file);

    let sensitive_record = PolicyExecutionRecord {
        execution_id: "exec_leak_test".into(),
        timestamp_unix: 1700000000,
        operation: "apply".into(),
        provider_id: "openwrt".into(),
        provider_name: "OpenWrt HTTP".into(),
        target_scope: PolicyScope::NetworkWide,
        initial_state: PolicyLifecycleState::PendingApplication,
        final_state: PolicyLifecycleState::Failed("Auth error".into()),
        duration: PolicyDuration::Indefinite,
        persistence: PolicyPersistence::VolatileSession,
        autonomous_recovery_guaranteed: false,
        policy_id: None,
        error: Some("Failed authentication with password=SuperSecretPassword123 and Authorization: Bearer abc_topsecret_token_123".into()),
    };

    store
        .append_record(&sensitive_record)
        .expect("Append record");

    let raw_content = fs::read_to_string(&state_file).expect("Read saved state");
    assert!(
        !raw_content.contains("SuperSecretPassword123"),
        "Passwords must never be written to persistent storage"
    );
    assert!(
        !raw_content.contains("abc_topsecret_token_123"),
        "Tokens must never be written to persistent storage"
    );
    assert!(
        raw_content.contains("[REDACTED]"),
        "Sanitized text should contain [REDACTED]"
    );
}

#[test]
fn test_engine_integration_persists_audit_records_and_updates() {
    let temp_dir = TestTempDir::new("engine_integration");
    let state_file = temp_dir.path().join("engine_audit.json");

    let gateway_ip = Ipv4Addr::new(192, 168, 1, 1);
    let registry = Arc::new(RouterRegistry::new(gateway_ip));
    let mock = Arc::new(MockRouterAdminProvider::new(gateway_ip));
    registry
        .connect("mock", mock, "internal://mock")
        .expect("Connect mock");

    let store = Arc::new(PolicyStore::with_path(&state_file));
    let engine = PolicyExecutionEngine::with_store(registry.clone(), store.clone());

    let target_ip = Ipv4Addr::new(192, 168, 1, 120);
    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![target_ip]),
        PolicyDuration::Temporary(Duration::from_secs(300)),
        PolicyPersistence::VolatileSession,
    );

    // Apply policy
    let active = engine.apply_policy(&req).expect("Apply should succeed");
    assert_eq!(active.lifecycle_state, PolicyLifecycleState::Active);

    // Verify written to disk
    assert_eq!(store.records().len(), 1);
    assert_eq!(store.records()[0].operation, "apply");
    assert_eq!(store.records()[0].final_state, PolicyLifecycleState::Active);
    assert_eq!(store.historical_policies().len(), 1);
    assert_eq!(store.historical_policies()[0].policy_id, active.policy_id);

    // Resume policy
    let resumed = engine
        .resume_policy(&req.scope)
        .expect("Resume should succeed");
    assert_eq!(resumed.len(), 1);

    // Verify resume record written to disk
    assert_eq!(store.records().len(), 2);
    assert_eq!(store.records()[1].operation, "resume");
    assert_eq!(
        store.records()[1].final_state,
        PolicyLifecycleState::Recovered
    );
    assert_eq!(
        store.historical_policies()[0].lifecycle_state,
        PolicyLifecycleState::Recovered
    );

    // Verify safe startup reload from disk
    let loaded_store = PolicyStore::with_path(&state_file);
    assert_eq!(loaded_store.records().len(), 2);
    // Since it was already Recovered, it stays Recovered
    assert_eq!(
        loaded_store.historical_policies()[0].lifecycle_state,
        PolicyLifecycleState::Recovered
    );
}

#[test]
fn test_recovery_metadata_and_preflight_rejection() {
    let gateway_ip = Ipv4Addr::new(192, 168, 1, 1);
    let registry = Arc::new(RouterRegistry::new(gateway_ip));

    // Connect UniFi provider (which does NOT support autonomous timed recovery)
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

    let temp_dir = TestTempDir::new("recovery_preflight");
    let state_file = temp_dir.path().join("recovery_check.json");
    let store = Arc::new(PolicyStore::with_path(&state_file));
    let engine = PolicyExecutionEngine::with_store(registry, store.clone());

    let target_ip = Ipv4Addr::new(192, 168, 1, 180);
    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![target_ip]),
        PolicyDuration::Temporary(Duration::from_secs(600)),
        PolicyPersistence::VolatileSession,
    );

    // Attempting temporary policy on provider without autonomous recovery must fail closed BEFORE mutation
    match engine.apply_policy(&req) {
        Err(AdminError::UnsupportedOperation(msg)) => {
            assert!(
                msg.contains("does not support autonomous router-side timed recovery"),
                "Must reject temporary policy when timed recovery is unsupported"
            );
        }
        other => panic!("Expected UnsupportedOperation, got {:?}", other),
    }

    // Verify recovery mechanism display formatting
    let mech = RecoveryMechanism::OpenWrtCronScheduler;
    assert_eq!(format!("{}", mech), "OpenWrt Cron Scheduler");
    let status = RecoveryVerificationStatus::Confirmed(mech);
    assert_eq!(format!("{}", status), "Confirmed (OpenWrt Cron Scheduler)");
}

#[test]
fn test_cross_process_locking_contention_and_timeout() {
    use rustrict::gateway::admin::persistence::{PolicyStoreLockGuard, POLICY_STORE_LOCK_TIMEOUT};

    let temp_dir = TestTempDir::new("lock_contention");
    let lock_file = temp_dir.path().join("test_contention.json.lock");

    // Process 1 acquires lock
    let guard1 = PolicyStoreLockGuard::acquire(&lock_file, POLICY_STORE_LOCK_TIMEOUT)
        .expect("First lock acquisition must succeed");

    // Process 2 tries to acquire with short timeout; must timeout
    let start = std::time::Instant::now();
    let err = PolicyStoreLockGuard::acquire(&lock_file, Duration::from_millis(100))
        .expect_err("Second lock acquisition during contention must fail");
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    assert!(start.elapsed() >= Duration::from_millis(90));

    // Release lock 1
    drop(guard1);

    // Process 2 can now acquire lock immediately
    let guard2 = PolicyStoreLockGuard::acquire(&lock_file, Duration::from_millis(500));
    assert!(
        guard2.is_ok(),
        "Must acquire lock after previous holder released"
    );
}

#[test]
fn test_cross_process_concurrent_disjoint_writers() {
    use rustrict::gateway::admin::plan::{PolicyDuration, PolicyPersistence};

    let temp_dir = TestTempDir::new("concurrent_writers");
    let state_file = temp_dir.path().join("shared_policies.json");

    let num_writers = 4;
    let ops_per_writer = 10;
    let mut handles = Vec::new();

    for w_idx in 0..num_writers {
        let path = state_file.clone();
        handles.push(std::thread::spawn(move || {
            let store = PolicyStore::with_path(&path);
            for op in 0..ops_per_writer {
                let rec = PolicyExecutionRecord {
                    execution_id: format!("exec_{}_{}", w_idx, op),
                    timestamp_unix: 1000 + (w_idx * 100) as u64 + op as u64,
                    operation: "apply".to_string(),
                    provider_id: "test".to_string(),
                    provider_name: "Test Provider".to_string(),
                    target_scope: PolicyScope::SpecificTargets(vec![Ipv4Addr::new(
                        192,
                        168,
                        1,
                        10 + w_idx as u8,
                    )]),
                    initial_state: PolicyLifecycleState::Planned,
                    final_state: PolicyLifecycleState::Active,
                    duration: PolicyDuration::Indefinite,
                    persistence: PolicyPersistence::VolatileSession,
                    autonomous_recovery_guaranteed: false,
                    policy_id: Some(format!("pol_{}_{}", w_idx, op)),
                    error: None,
                };
                store
                    .append_record(&rec)
                    .expect("Append must succeed under lock");
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    let final_store = PolicyStore::with_path(&state_file);
    let records = final_store.records();
    assert_eq!(
        records.len(),
        (num_writers * ops_per_writer) as usize,
        "All disjoint writes from concurrent processes must be preserved without loss"
    );
}
