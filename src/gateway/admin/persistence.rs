use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fs2::FileExt;
use serde::{Deserialize, Serialize};

use crate::gateway::admin::engine::{sanitize_text, PolicyExecutionRecord};
use crate::gateway::admin::plan::{ActivePolicyStatus, PolicyLifecycleState, PolicyScope};

/// Maximum duration to wait when acquiring a cross-process policy store lock.
pub const POLICY_STORE_LOCK_TIMEOUT: Duration = Duration::from_secs(5);

/// Cross-process lockfile guard that releases the OS-level exclusive file lock upon drop.
#[derive(Debug)]
pub struct PolicyStoreLockGuard {
    _file: File,
    _path: PathBuf,
}

impl PolicyStoreLockGuard {
    /// Attempts to acquire an exclusive cross-process lock on the specified lockfile.
    /// Retries boundedly until `timeout` expires, preventing indefinite hangs or deadlocks.
    pub fn acquire(lock_path: &Path, timeout: Duration) -> io::Result<Self> {
        if let Some(parent) = lock_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)?;

        let start = Instant::now();
        loop {
            match file.try_lock_exclusive() {
                Ok(()) => {
                    return Ok(Self {
                        _file: file,
                        _path: lock_path.to_path_buf(),
                    });
                }
                Err(err) => {
                    // On Windows, OS error 33 (ERROR_LOCK_VIOLATION) or WouldBlock indicates the lock is currently held.
                    let is_contended =
                        err.kind() == io::ErrorKind::WouldBlock || err.raw_os_error() == Some(33);

                    if is_contended {
                        if start.elapsed() >= timeout {
                            return Err(io::Error::new(
                                io::ErrorKind::TimedOut,
                                format!(
                                    "Timed out after {:?} waiting for policy store lock '{}'",
                                    timeout,
                                    lock_path.display()
                                ),
                            ));
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    } else {
                        return Err(err);
                    }
                }
            }
        }
    }
}

impl Drop for PolicyStoreLockGuard {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self._file);
    }
}

/// Current schema version of the persistent router policy state file
pub const CURRENT_SCHEMA_VERSION: u32 = 1;

/// Autonomous recovery mechanism type identified on the router
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryMechanism {
    RouterWatchdog,
    OpenWrtCronScheduler,
    MikroTikScheduler,
    None,
}

impl std::fmt::Display for RecoveryMechanism {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RouterWatchdog => write!(f, "Router Watchdog"),
            Self::OpenWrtCronScheduler => write!(f, "OpenWrt Cron Scheduler"),
            Self::MikroTikScheduler => write!(f, "MikroTik Scheduler"),
            Self::None => write!(f, "None"),
        }
    }
}

/// Recovery verification status of a policy
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryVerificationStatus {
    Supported(RecoveryMechanism),
    Attempted,
    Confirmed(RecoveryMechanism),
    Failed(String),
    Uncertain,
    Unsupported,
}

impl std::fmt::Display for RecoveryVerificationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Supported(m) => write!(f, "Supported ({})", m),
            Self::Attempted => write!(f, "Attempted"),
            Self::Confirmed(m) => write!(f, "Confirmed ({})", m),
            Self::Failed(err) => write!(f, "Failed: {}", err),
            Self::Uncertain => write!(f, "Uncertain"),
            Self::Unsupported => write!(f, "Unsupported"),
        }
    }
}

/// Root data model for versioned, crash-safe router policy state persistence
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistentPolicyState {
    pub schema_version: u32,
    pub last_updated_unix: u64,
    pub records: Vec<PolicyExecutionRecord>,
    pub historical_policies: Vec<ActivePolicyStatus>,
}

impl Default for PersistentPolicyState {
    fn default() -> Self {
        Self {
            schema_version: CURRENT_SCHEMA_VERSION,
            last_updated_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            records: Vec::new(),
            historical_policies: Vec::new(),
        }
    }
}

impl PersistentPolicyState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reconciles startup state according to safe offline principles:
    ///
    /// Persisted policy records represent historical controller evidence, NOT guaranteed
    /// live state on the physical router.
    ///
    /// Any policy marked `PolicyLifecycleState::Active` in the local file MUST be
    /// transitioned to `PolicyLifecycleState::Unknown` with an explanatory message,
    /// without sending any network mutations to the router.
    pub fn reconcile_startup_state(&mut self) {
        for policy in &mut self.historical_policies {
            if policy.lifecycle_state == PolicyLifecycleState::Active {
                policy.lifecycle_state = PolicyLifecycleState::Unknown;
                policy.last_error = Some(
                    "Startup reconciliation pending: local state not yet verified against live router"
                        .to_string(),
                );
            }
        }
    }

    /// Sanitizes all string fields across records and policies before disk persistence
    pub fn sanitize_all_secrets(&mut self) {
        for record in &mut self.records {
            if let Some(ref err) = record.error {
                record.error = Some(sanitize_text(err));
            }
        }
        for policy in &mut self.historical_policies {
            if let Some(ref err) = policy.last_error {
                policy.last_error = Some(sanitize_text(err));
            }
        }
    }

    /// Migrates an older schema version forward to CURRENT_SCHEMA_VERSION
    pub fn migrate_schema(mut self) -> Self {
        if self.schema_version < CURRENT_SCHEMA_VERSION {
            self.schema_version = CURRENT_SCHEMA_VERSION;
        }
        self
    }
}

/// Resolves standard durable router policy state file path on Windows
/// Checks %RUSTRICT_STORE_PATH%, %APPDATA%\Rustrict, %LOCALAPPDATA%\Rustrict,
/// %ProgramData%\Rustrict, or directory alongside executable.
pub fn default_policy_store_path() -> PathBuf {
    if let Ok(store_path) = std::env::var("RUSTRICT_STORE_PATH") {
        if !store_path.trim().is_empty() {
            return PathBuf::from(store_path.trim());
        }
    }
    if let Ok(appdata) = std::env::var("APPDATA") {
        let dir = PathBuf::from(appdata).join("Rustrict");
        return dir.join("router_policies.json");
    }
    if let Ok(localappdata) = std::env::var("LOCALAPPDATA") {
        let dir = PathBuf::from(localappdata).join("Rustrict");
        return dir.join("router_policies.json");
    }
    if let Ok(progdata) = std::env::var("ProgramData") {
        let dir = PathBuf::from(progdata).join("Rustrict");
        return dir.join("router_policies.json");
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            return dir.join("router_policies.json");
        }
    }
    PathBuf::from("router_policies.json")
}

struct TempFileGuard<'a>(&'a Path, bool);
impl<'a> TempFileGuard<'a> {
    fn new(path: &'a Path) -> Self {
        Self(path, true)
    }
    fn disarm(&mut self) {
        self.1 = false;
    }
}
impl<'a> Drop for TempFileGuard<'a> {
    fn drop(&mut self) {
        if self.1 {
            let _ = fs::remove_file(self.0);
        }
    }
}

struct BackupFileGuard<'a>(&'a Path, &'a Path, bool);
impl<'a> BackupFileGuard<'a> {
    fn new(backup: &'a Path, orig: &'a Path) -> Self {
        Self(backup, orig, true)
    }
    fn disarm_and_cleanup(mut self) {
        self.2 = false;
        let _ = fs::remove_file(self.0);
    }
}
impl<'a> Drop for BackupFileGuard<'a> {
    fn drop(&mut self) {
        if self.2 {
            let _ = fs::rename(self.0, self.1);
        }
    }
}

fn rename_with_retry(from: &Path, to: &Path, max_retries: usize) -> io::Result<()> {
    let mut last_err = io::Error::other("Unknown rename error");
    for attempt in 0..=max_retries {
        match fs::rename(from, to) {
            Ok(()) => return Ok(()),
            Err(e) => {
                last_err = e;
                if attempt < max_retries {
                    std::thread::sleep(std::time::Duration::from_millis(10 * (attempt as u64 + 1)));
                }
            }
        }
    }
    Err(last_err)
}

/// Performs an atomic, crash-safe file write on Windows.
///
/// 1. Writes to a temporary file in the same directory (handling paths with spaces)
/// 2. Flushes buffers and syncs all metadata to physical disk
/// 3. Safely backs up existing target destination before replacement
/// 4. Rolls back to previous valid state if replacement fails
/// 5. Automatically cleans up temporary files on error via RAII guards
pub fn atomic_write_file(path: &Path, content: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let file_stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("state");
    let pid = std::process::id();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temp_name = format!(".{}_{}_{}.tmp", file_stem, pid, now);

    let temp_path = match path.parent() {
        Some(p) => p.join(temp_name),
        None => PathBuf::from(temp_name),
    };

    let mut temp_guard = TempFileGuard::new(&temp_path);

    // Write content and flush to disk
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temp_path)?;
        file.write_all(content)?;
        file.sync_all()?;
    }

    // Atomic replacement preserving existing file on failure
    if path.exists() {
        let backup_name = format!(".{}_{}_{}.bak", file_stem, pid, now);
        let backup_path = match path.parent() {
            Some(p) => p.join(backup_name),
            None => PathBuf::from(backup_name),
        };

        rename_with_retry(path, &backup_path, 3)?;
        let backup_guard = BackupFileGuard::new(&backup_path, path);

        rename_with_retry(&temp_path, path, 5)?;
        temp_guard.disarm();
        backup_guard.disarm_and_cleanup();
    } else {
        rename_with_retry(&temp_path, path, 5)?;
        temp_guard.disarm();
    }

    Ok(())
}

/// Thread-safe persistence store for router policies and audit records
#[derive(Debug, Clone)]
pub struct PolicyStore {
    path: Option<PathBuf>,
    state: Arc<RwLock<PersistentPolicyState>>,
}

impl Default for PolicyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyStore {
    /// Constructs a persistent store using the default Windows platform path
    pub fn new() -> Self {
        Self::with_path(default_policy_store_path())
    }

    /// Constructs a persistent store with a custom target path (supporting overrides and spaces)
    pub fn with_path<P: Into<PathBuf>>(path: P) -> Self {
        let path = path.into();
        let state = Self::load_from_path(&path);
        Self {
            path: Some(path),
            state: Arc::new(RwLock::new(state)),
        }
    }

    /// Constructs an isolated in-memory store without writing to physical disk
    pub fn in_memory() -> Self {
        Self {
            path: None,
            state: Arc::new(RwLock::new(PersistentPolicyState::new())),
        }
    }

    /// Accesses the target storage path, if configured
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Loads and parses persistent state from the given path without panicking.
    ///
    /// Malformed JSON, truncated files, or schema discrepancies are handled gracefully.
    /// In all cases, `reconcile_startup_state` is executed so that unverified historical
    /// policies are marked `Unknown`.
    fn load_from_path(path: &Path) -> PersistentPolicyState {
        if !path.exists() {
            let mut state = PersistentPolicyState::new();
            state.reconcile_startup_state();
            return state;
        }

        match fs::read_to_string(path) {
            Ok(content) => {
                let trimmed = content.trim();
                if trimmed.is_empty() {
                    eprintln!(
                        "[WARN] Empty policy state file '{}'. Initializing safe fallback state.",
                        path.display()
                    );
                    let mut state = PersistentPolicyState::new();
                    state.reconcile_startup_state();
                    return state;
                }

                match serde_json::from_str::<PersistentPolicyState>(trimmed) {
                    Ok(mut state) => {
                        if state.schema_version > CURRENT_SCHEMA_VERSION {
                            eprintln!(
                                "[WARN] Policy state file '{}' has schema version {} newer than supported version {}. Preserving state without destructive downgrade.",
                                path.display(),
                                state.schema_version,
                                CURRENT_SCHEMA_VERSION
                            );
                        } else if state.schema_version < CURRENT_SCHEMA_VERSION {
                            state = state.migrate_schema();
                        }
                        // Safe startup reconciliation: mark unverified active policies as Unknown
                        state.reconcile_startup_state();
                        state
                    }
                    Err(err) => {
                        eprintln!(
                            "[WARN] Corrupt or incompatible policy state file '{}': {}. Initializing safe fallback state.",
                            path.display(),
                            err
                        );
                        let mut state = PersistentPolicyState::new();
                        state.reconcile_startup_state();
                        state
                    }
                }
            }
            Err(err) => {
                eprintln!(
                    "[WARN] Failed to read policy state file '{}': {}. Initializing safe fallback state.",
                    path.display(),
                    err
                );
                let mut state = PersistentPolicyState::new();
                state.reconcile_startup_state();
                state
            }
        }
    }

    /// Syncs and merges in-memory state with any concurrent updates from disk
    pub fn sync_from_disk_if_present(&self) {
        if let Some(path) = &self.path {
            if path.exists() {
                if let Ok(content) = fs::read_to_string(path) {
                    if let Ok(disk_state) = serde_json::from_str::<PersistentPolicyState>(&content)
                    {
                        let mut lock = self.state.write().unwrap();
                        for rec in disk_state.records {
                            if !lock
                                .records
                                .iter()
                                .any(|r| r.execution_id == rec.execution_id)
                            {
                                lock.records.push(rec);
                            }
                        }
                        lock.records.sort_by_key(|r| r.timestamp_unix);

                        for p in disk_state.historical_policies {
                            if let Some(pos) = lock
                                .historical_policies
                                .iter()
                                .position(|hp| hp.policy_id == p.policy_id)
                            {
                                let current = &lock.historical_policies[pos];
                                if (p.lifecycle_state == PolicyLifecycleState::Recovered
                                    && current.lifecycle_state != PolicyLifecycleState::Recovered)
                                    || p.applied_at_unix > current.applied_at_unix
                                {
                                    lock.historical_policies[pos] = p;
                                }
                            } else {
                                lock.historical_policies.push(p);
                            }
                        }
                    }
                }
            }
        }
    }

    /// Resolves the companion lockfile path for cross-process synchronization.
    pub fn lock_path(&self) -> Option<PathBuf> {
        self.path.as_ref().map(|p| {
            let mut lock_name = p
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("policy_store")
                .to_string();
            lock_name.push_str(".lock");
            match p.parent() {
                Some(parent) => parent.join(lock_name),
                None => PathBuf::from(lock_name),
            }
        })
    }

    /// Acquires an exclusive cross-process lock for the duration of a store transaction.
    /// In-memory stores return `Ok(None)`.
    pub fn acquire_lock(&self) -> Result<Option<PolicyStoreLockGuard>, String> {
        if let Some(lock_path) = self.lock_path() {
            PolicyStoreLockGuard::acquire(&lock_path, POLICY_STORE_LOCK_TIMEOUT)
                .map(Some)
                .map_err(|e| format!("Failed to acquire cross-process policy store lock: {}", e))
        } else {
            Ok(None)
        }
    }

    /// Atomically persists the in-memory state to disk, merging concurrent on-disk changes
    fn persist_internal(&self, state: &mut PersistentPolicyState) -> Result<(), String> {
        state.sanitize_all_secrets();
        if let Some(path) = &self.path {
            if path.exists() {
                if let Ok(content) = fs::read_to_string(path) {
                    if let Ok(disk_state) = serde_json::from_str::<PersistentPolicyState>(&content)
                    {
                        for rec in disk_state.records {
                            if !state
                                .records
                                .iter()
                                .any(|r| r.execution_id == rec.execution_id)
                            {
                                state.records.push(rec);
                            }
                        }
                        state.records.sort_by_key(|r| r.timestamp_unix);

                        for p in disk_state.historical_policies {
                            if let Some(pos) = state
                                .historical_policies
                                .iter()
                                .position(|hp| hp.policy_id == p.policy_id)
                            {
                                let current = &state.historical_policies[pos];
                                if (p.lifecycle_state == PolicyLifecycleState::Recovered
                                    && current.lifecycle_state != PolicyLifecycleState::Recovered)
                                    || p.applied_at_unix > current.applied_at_unix
                                {
                                    state.historical_policies[pos] = p;
                                }
                            } else {
                                state.historical_policies.push(p);
                            }
                        }
                    }
                }
            }

            let json = serde_json::to_string_pretty(state)
                .map_err(|e| format!("Serialization error: {}", e))?;

            atomic_write_file(path, json.as_bytes())
                .map_err(|e| format!("Failed to write state file '{}': {}", path.display(), e))
        } else {
            Ok(())
        }
    }

    /// Appends a sanitized execution record and persists to disk under cross-process locking
    pub fn append_record(&self, record: &PolicyExecutionRecord) -> Result<(), String> {
        let _proc_lock = self.acquire_lock()?;
        self.sync_from_disk_if_present();
        let mut sanitized = record.clone();
        if let Some(err) = &sanitized.error {
            sanitized.error = Some(sanitize_text(err));
        }

        let mut lock = self.state.write().unwrap();
        lock.records.push(sanitized);
        lock.last_updated_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.persist_internal(&mut lock)
    }

    /// Inserts or updates an active policy status in historical records and persists to disk under cross-process locking
    pub fn update_policy_status(&self, policy: &ActivePolicyStatus) -> Result<(), String> {
        let _proc_lock = self.acquire_lock()?;
        self.sync_from_disk_if_present();
        let mut sanitized = policy.clone();
        if let Some(err) = &sanitized.last_error {
            sanitized.last_error = Some(sanitize_text(err));
        }

        let mut lock = self.state.write().unwrap();
        if let Some(pos) = lock
            .historical_policies
            .iter()
            .position(|p| p.policy_id == sanitized.policy_id)
        {
            lock.historical_policies[pos] = sanitized;
        } else {
            lock.historical_policies.push(sanitized);
        }

        lock.last_updated_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.persist_internal(&mut lock)
    }

    /// Updates historical policies based on live provider reconciliation results under cross-process locking
    pub fn update_policies_from_reconcile(
        &self,
        live_policies: &[ActivePolicyStatus],
    ) -> Result<(), String> {
        let _proc_lock = self.acquire_lock()?;
        self.sync_from_disk_if_present();
        let mut lock = self.state.write().unwrap();

        // Update or add confirmed live policies
        for live in live_policies {
            let mut sanitized = live.clone();
            if let Some(err) = &sanitized.last_error {
                sanitized.last_error = Some(sanitize_text(err));
            }

            if let Some(pos) = lock
                .historical_policies
                .iter()
                .position(|p| p.policy_id == sanitized.policy_id)
            {
                lock.historical_policies[pos] = sanitized;
            } else {
                lock.historical_policies.push(sanitized);
            }
        }

        // If a previously recorded policy is no longer in live rules, mark it Recovered
        for hist in &mut lock.historical_policies {
            if !live_policies
                .iter()
                .any(|lp| lp.policy_id == hist.policy_id)
                && (hist.lifecycle_state == PolicyLifecycleState::Active
                    || hist.lifecycle_state == PolicyLifecycleState::Unknown)
            {
                hist.lifecycle_state = PolicyLifecycleState::Recovered;
                hist.last_error = Some("Rule verified absent on live router.".to_string());
            }
        }

        lock.last_updated_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.persist_internal(&mut lock)
    }

    /// Marks matching historical policies as recovered when resumed under cross-process locking
    pub fn mark_scope_recovered(&self, scope: &PolicyScope) -> Result<(), String> {
        let _proc_lock = self.acquire_lock()?;
        self.sync_from_disk_if_present();
        let mut lock = self.state.write().unwrap();
        for policy in &mut lock.historical_policies {
            let matched = match (&policy.scope, scope) {
                (PolicyScope::NetworkWide, PolicyScope::NetworkWide) => true,
                (PolicyScope::SpecificTargets(p_ips), PolicyScope::SpecificTargets(s_ips)) => {
                    p_ips.iter().any(|ip| s_ips.contains(ip))
                }
                _ => false,
            };
            if matched {
                policy.lifecycle_state = PolicyLifecycleState::Recovered;
                policy.last_error = None;
            }
        }
        lock.last_updated_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.persist_internal(&mut lock)
    }

    /// Returns a copy of all audit execution records
    pub fn records(&self) -> Vec<PolicyExecutionRecord> {
        self.sync_from_disk_if_present();
        self.state.read().unwrap().records.clone()
    }

    /// Returns a copy of all historical policy statuses
    pub fn historical_policies(&self) -> Vec<ActivePolicyStatus> {
        self.sync_from_disk_if_present();
        self.state.read().unwrap().historical_policies.clone()
    }

    /// Reads snapshot of current persistent policy state
    pub fn snapshot(&self) -> PersistentPolicyState {
        self.state.read().unwrap().clone()
    }

    /// Clears execution history and historical policies, persisting an empty state under cross-process locking
    pub fn clear(&self) -> Result<(), String> {
        let _proc_lock = self.acquire_lock()?;
        let mut lock = self.state.write().unwrap();
        lock.records.clear();
        lock.historical_policies.clear();
        lock.last_updated_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.persist_internal(&mut lock)
    }
}
