use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rustrict::gateway::admin::{
    atomic_write_file, MockRouterAdminProvider, OperationPlanRequest, PersistentPolicyState,
    PolicyDuration, PolicyExecutionEngine, PolicyExecutionRecord, PolicyLifecycleState,
    PolicyPersistence, PolicyScope, PolicyStore, RouterRegistry, CURRENT_SCHEMA_VERSION,
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
        let path = std::env::temp_dir().join(format!(
            "rustrict_rel_{}_{}_{}",
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
fn test_atomic_write_resilience_and_cleanup() {
    let temp_dir = TestTempDir::new("atomic_resilience");
    let target_file = temp_dir.path().join("policy_store.json");

    // First write valid content
    let content1 = b"{\"schema_version\": 1, \"records\": []}";
    atomic_write_file(&target_file, content1).expect("initial write succeeds");
    assert!(target_file.exists());

    // Subsequent write succeeds and replaces
    let content2 = b"{\"schema_version\": 1, \"records\": [\"updated\"]}";
    atomic_write_file(&target_file, content2).expect("replacement write succeeds");
    let read_back = fs::read_to_string(&target_file).expect("read replaced");
    assert_eq!(read_back, String::from_utf8_lossy(content2));

    // Verify temp files and backup files are cleaned up
    let entries = fs::read_dir(temp_dir.path()).unwrap();
    let file_names: Vec<String> = entries
        .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().to_string()))
        .collect();
    assert_eq!(file_names, vec!["policy_store.json"]);
}

#[test]
fn test_schema_versioning_and_corrupt_files() {
    let temp_dir = TestTempDir::new("schema_corrupt");
    let file_path = temp_dir.path().join("corrupt_or_future.json");

    // 1. Empty file should load default empty state without error or panic
    fs::write(&file_path, b"").expect("write empty file");
    let store_empty = PolicyStore::with_path(&file_path);
    assert_eq!(
        store_empty.snapshot().schema_version,
        CURRENT_SCHEMA_VERSION
    );
    assert!(store_empty.records().is_empty());

    // 2. Corrupt / invalid JSON should fallback safely without panic
    fs::write(&file_path, b"not valid json at all {{{").expect("write garbage");
    let store_corrupt = PolicyStore::with_path(&file_path);
    assert_eq!(
        store_corrupt.snapshot().schema_version,
        CURRENT_SCHEMA_VERSION
    );
    assert!(store_corrupt.records().is_empty());

    // 3. Schema version 0 migration to CURRENT_SCHEMA_VERSION
    let legacy_json = b"{\"schema_version\": 0, \"last_updated_unix\": 1000, \"records\": [], \"historical_policies\": []}";
    fs::write(&file_path, legacy_json).expect("write legacy schema");
    let store_legacy = PolicyStore::with_path(&file_path);
    assert_eq!(
        store_legacy.snapshot().schema_version,
        CURRENT_SCHEMA_VERSION
    );
}

#[test]
fn test_secret_sanitization_in_persistent_state() {
    let mut state = PersistentPolicyState::new();
    let record = PolicyExecutionRecord {
        execution_id: "rec-test-1".into(),
        timestamp_unix: 1700000000,
        operation: "apply".into(),
        provider_id: "openwrt-ssh".into(),
        provider_name: "OpenWrt SSH".into(),
        target_scope: PolicyScope::NetworkWide,
        initial_state: PolicyLifecycleState::PendingApplication,
        final_state: PolicyLifecycleState::Failed("Auth error".into()),
        duration: PolicyDuration::Indefinite,
        persistence: PolicyPersistence::VolatileSession,
        autonomous_recovery_guaranteed: false,
        policy_id: None,
        error: Some("SSH error: password=SuperSecretPass123 auth token=top_secret_tok".into()),
    };
    state.records.push(record);

    state.sanitize_all_secrets();

    // Verify password parameter was redacted
    let sanitized_err = state.records[0].error.as_deref().unwrap();
    assert!(sanitized_err.contains("[REDACTED]"));
    assert!(!sanitized_err.contains("SuperSecretPass123"));
}

#[test]
fn test_multi_instance_concurrent_sync() {
    let temp_dir = TestTempDir::new("multi_instance_sync");
    let store_path = temp_dir.path().join("shared_store.json");

    // Create Instance A and Instance B pointing to same path
    let store_a = PolicyStore::with_path(&store_path);
    let store_b = PolicyStore::with_path(&store_path);

    let rec_a = PolicyExecutionRecord {
        execution_id: "exec-from-a".into(),
        timestamp_unix: 1700000000,
        operation: "apply".into(),
        provider_id: "openwrt".into(),
        provider_name: "OpenWrt".into(),
        target_scope: PolicyScope::NetworkWide,
        initial_state: PolicyLifecycleState::PendingApplication,
        final_state: PolicyLifecycleState::Active,
        duration: PolicyDuration::Indefinite,
        persistence: PolicyPersistence::VolatileSession,
        autonomous_recovery_guaranteed: false,
        policy_id: Some("pol-a".into()),
        error: None,
    };

    let rec_b = PolicyExecutionRecord {
        execution_id: "exec-from-b".into(),
        timestamp_unix: 1700000100,
        operation: "apply".into(),
        provider_id: "mikrotik".into(),
        provider_name: "MikroTik".into(),
        target_scope: PolicyScope::NetworkWide,
        initial_state: PolicyLifecycleState::PendingApplication,
        final_state: PolicyLifecycleState::Active,
        duration: PolicyDuration::Indefinite,
        persistence: PolicyPersistence::VolatileSession,
        autonomous_recovery_guaranteed: false,
        policy_id: Some("pol-b".into()),
        error: None,
    };

    // Store A writes record A to disk
    store_a.append_record(&rec_a).expect("append rec_a");

    // Store B appends record B and persists, which performs sync_from_disk_if_present
    store_b.append_record(&rec_b).expect("append rec_b");

    // Now Store A syncs from disk
    store_a.sync_from_disk_if_present();

    // Both stores should now have both record A and record B!
    let a_records = store_a.records();
    let b_records = store_b.records();

    assert_eq!(
        a_records.len(),
        2,
        "Store A should contain both records after sync"
    );
    assert_eq!(
        b_records.len(),
        2,
        "Store B should contain both records after sync"
    );

    let a_ids: Vec<&str> = a_records.iter().map(|r| r.execution_id.as_str()).collect();
    assert!(a_ids.contains(&"exec-from-a"));
    assert!(a_ids.contains(&"exec-from-b"));
}

#[test]
fn test_engine_persistence_error_tracking() {
    let temp_dir = TestTempDir::new("engine_persistence_err");
    // Point the store to an unwritable path (e.g. invalid subpath inside a file)
    let invalid_dir_file = temp_dir.path().join("cannot_be_a_dir");
    fs::write(&invalid_dir_file, b"regular file").unwrap();
    let unwritable_path = invalid_dir_file.join("sub").join("store.json");

    let store = Arc::new(PolicyStore::with_path(&unwritable_path));

    let gateway_ip = Ipv4Addr::new(192, 168, 1, 1);
    let registry = Arc::new(RouterRegistry::new(gateway_ip));
    let provider = Arc::new(MockRouterAdminProvider::new(gateway_ip));
    registry
        .connect("mock", provider, "internal://mock")
        .unwrap();

    let engine = PolicyExecutionEngine::with_store(registry, store);

    // Initial state: no persistence error
    assert_eq!(engine.last_persistence_error(), None);

    // Apply a policy plan
    let req = OperationPlanRequest::new(
        PolicyScope::SpecificTargets(vec![Ipv4Addr::new(192, 168, 1, 80)]),
        PolicyDuration::Temporary(Duration::from_secs(300)),
        PolicyPersistence::VolatileSession,
    );

    let active = engine
        .apply_policy(&req)
        .expect("apply policy succeeds in memory");
    assert_eq!(active.lifecycle_state, PolicyLifecycleState::Active);

    // Policy applied, but disk persistence failed because the path is unwritable!
    let last_err = engine.last_persistence_error();
    assert!(
        last_err.is_some(),
        "Engine should track persistence failure"
    );
    let err_str = last_err.unwrap();
    assert!(
        err_str.contains("Failed to write")
            || err_str.contains("directory")
            || err_str.contains("create")
            || err_str.contains("path")
    );
}

#[test]
fn test_credential_hygiene_and_protected_buffer_zeroing() {
    use rustrict::gateway::admin::{
        dpapi_decrypt, dpapi_encrypt, zero_slice, ProtectedBuffer, ProtectedString,
        RouterCredentials,
    };

    // 1. Redaction in Debug and Display
    let secret = "SuperSecretPassword123!";
    let pstr = ProtectedString::new(secret);
    assert_eq!(format!("{:?}", pstr), "[REDACTED]");
    assert_eq!(format!("{}", pstr), "[REDACTED]");
    assert_eq!(pstr.expose(), secret);

    let creds = RouterCredentials::new("admin_operator", secret);
    let creds_debug = format!("{:?}", creds);
    assert!(!creds_debug.contains(secret));
    assert!(creds_debug.contains("[REDACTED]"));
    assert!(creds_debug.contains("admin_operator"));

    // 2. ProtectedBuffer redaction and zeroing
    let mut pbuf = ProtectedBuffer::new(secret.as_bytes().to_vec());
    let buf_debug = format!("{:?}", pbuf);
    assert!(!buf_debug.contains(secret));
    assert!(buf_debug.contains("[REDACTED_BUFFER"));
    assert_eq!(format!("{}", pbuf), "[REDACTED]");
    assert_eq!(&*pbuf, secret.as_bytes());

    pbuf.clear();
    assert_eq!(pbuf.len(), 0);

    // 3. Volatile zero slice verification
    let mut sensitive_bytes = *b"SensitiveIntermediateTokenBuffer";
    zero_slice(&mut sensitive_bytes);
    assert!(sensitive_bytes.iter().all(|&b| b == 0));

    // 4. DPAPI roundtrip returns ProtectedBuffer with redaction
    let encrypted = dpapi_encrypt(secret.as_bytes()).expect("DPAPI encrypt succeeds");
    assert_ne!(encrypted, secret.as_bytes());

    let decrypted = dpapi_decrypt(&encrypted).expect("DPAPI decrypt succeeds");
    assert_eq!(decrypted, secret.as_bytes());
    assert_eq!(
        format!("{:?}", decrypted),
        format!("[REDACTED_BUFFER (len={})]", secret.len())
    );
    assert_eq!(format!("{}", decrypted), "[REDACTED]");
}

#[test]
fn test_protected_credentials_file_roundtrip_with_zeroization() {
    use rustrict::gateway::admin::{
        load_protected_credentials, save_protected_credentials, RouterCredentials,
    };

    let temp_dir = TestTempDir::new("dpapi_creds_test");
    let creds_path = temp_dir.path().join("router_auth.dat");

    let creds = RouterCredentials::new("sec_admin", "UltraStrongPassphrase!#492");
    save_protected_credentials(&creds_path, &creds).expect("save protected credentials succeeds");

    // File on disk must NOT contain plaintext password
    let on_disk_bytes = fs::read(&creds_path).expect("read raw credentials file");
    let raw_str = String::from_utf8_lossy(&on_disk_bytes);
    assert!(!raw_str.contains("UltraStrongPassphrase!#492"));

    // Loading credentials succeeds and exposes expected password
    let loaded =
        load_protected_credentials(&creds_path).expect("load protected credentials succeeds");
    assert_eq!(loaded.username, "sec_admin");
    assert_eq!(loaded.password.expose(), "UltraStrongPassphrase!#492");
}

#[test]
fn test_protected_buffer_clone_and_zeroize_independence() {
    use rustrict::gateway::admin::{ProtectedBuffer, ProtectedString};
    use zeroize::Zeroize;

    let secret = "IndependentSecretKey999";
    let mut pbuf1 = ProtectedBuffer::new(secret.as_bytes().to_vec());
    let mut pbuf2 = pbuf1.clone();

    assert_eq!(&*pbuf1, &*pbuf2);
    assert_eq!(&*pbuf1, secret.as_bytes());

    // Zeroizing pbuf1 independently must not corrupt pbuf2
    pbuf1.zeroize();
    assert!(pbuf1.iter().all(|&b| b == 0));
    assert_eq!(&*pbuf2, secret.as_bytes());

    pbuf2.clear();
    assert_eq!(pbuf2.len(), 0);

    // ProtectedString clone isolation
    let mut pstr1 = ProtectedString::new(secret);
    let pstr2 = pstr1.clone();

    assert_eq!(pstr1.expose(), pstr2.expose());
    pstr1.zeroize();
    assert_ne!(pstr1.expose(), secret);
    assert_eq!(pstr2.expose(), secret);
}

#[test]
fn test_dpapi_decrypt_corrupted_data_fails_safely() {
    use rustrict::gateway::admin::{dpapi_decrypt, AdminError};

    let corrupt_ciphertext = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04];
    let res = dpapi_decrypt(&corrupt_ciphertext);
    assert!(res.is_err(), "Decrypting corrupted ciphertext must fail");
    match res {
        Err(AdminError::AuthenticationFailed(msg)) => {
            assert!(
                msg.contains("Failed to decrypt") || msg.contains("DPAPI"),
                "Error message must be sanitized: {}",
                msg
            );
        }
        other => panic!("Expected AuthenticationFailed, got {:?}", other),
    }
}
