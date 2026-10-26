use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::gateway::admin::capabilities::RouterCapabilityMatrix;
use crate::gateway::admin::diagnostics::{
    sanitize_endpoint, unix_to_iso8601, ConnectionDiagnostic, DataSource, DiagnosticResult,
    NormalizedRouterInventoryItem, ProviderConnectionState, RouterDeviceEntry,
    RouterDiagnosticReport, RouterEvidenceBundle,
};
use crate::gateway::admin::persistence::PolicyStore;
use crate::gateway::admin::plan::{
    ActivePolicyStatus, AdminError, OperationPlan, OperationPlanRequest, PolicyDuration,
    PolicyLifecycleState, PolicyPersistence, PolicyScope, RouterIdentity,
};
use crate::gateway::admin::provider::RouterAdminProvider;
use crate::gateway::admin::registry::RouterRegistry;
use crate::gateway::admin::views::{
    PolicyConfirmationState, PolicyDetailView, PolicyRecoveryStatus, UnifiedPolicyEntry,
};

/// Sanitizes text strings by redacting potential passwords, authorization headers, tokens, and keys
/// while preserving exact UTF-8 byte boundaries and non-secret Unicode content.
pub fn sanitize_text(text: &str) -> String {
    let mut out = text.to_string();
    sanitize_urls_in_place(&mut out);
    sanitize_auth_headers_in_place(&mut out);
    sanitize_key_values_in_place(&mut out);
    out
}

fn sanitize_urls_in_place(out: &mut String) {
    let mut search_from = 0;
    while search_from < out.len() {
        let bytes = out.as_bytes();
        let proto_match = bytes[search_from..].windows(3).position(|w| w == b"://");

        let pos = match proto_match {
            Some(p) => search_from + p,
            None => break,
        };

        let auth_start = pos + 3;
        if auth_start >= out.len() {
            break;
        }

        let auth_len = out[auth_start..]
            .find(|c: char| c == '/' || c == '?' || c == '#' || c.is_whitespace())
            .unwrap_or(out[auth_start..].len());
        let auth_end = auth_start + auth_len;

        if let Some(at_rel) = out[auth_start..auth_end].find('@') {
            let at_idx = auth_start + at_rel;
            let userinfo = &out[auth_start..at_idx];
            if let Some(colon_rel) = userinfo.find(':') {
                let pass_start = auth_start + colon_rel + 1;
                let pass_end = at_idx;
                if pass_start < pass_end && &out[pass_start..pass_end] != "[REDACTED]" {
                    out.replace_range(pass_start..pass_end, "[REDACTED]");
                    search_from = pass_start + "[REDACTED]".len();
                    continue;
                }
            }
        }

        search_from = auth_end;
    }
}

fn sanitize_auth_headers_in_place(out: &mut String) {
    const AUTH_PREFIXES: &[&[u8]] = &[b"bearer ", b"basic "];

    let mut search_from = 0;
    'outer: while search_from < out.len() {
        let lower_bytes: Vec<u8> = out.as_bytes()[search_from..]
            .iter()
            .map(|b| b.to_ascii_lowercase())
            .collect();

        // Find the earliest matching prefix among all prefixes
        let mut earliest: Option<(usize, usize)> = None;
        for prefix in AUTH_PREFIXES {
            if let Some(pos) = lower_bytes.windows(prefix.len()).position(|w| w == *prefix) {
                match earliest {
                    Some((min_pos, _)) if pos < min_pos => {
                        earliest = Some((pos, prefix.len()));
                    }
                    None => {
                        earliest = Some((pos, prefix.len()));
                    }
                    _ => {}
                }
            }
        }

        let (rel_pos, pat_len) = match earliest {
            Some(m) => m,
            None => break,
        };

        let actual_pos = search_from + rel_pos;

        // Ensure boundary before prefix (not preceded by alphanumeric)
        if actual_pos > 0 {
            let prev = out.as_bytes()[actual_pos - 1];
            if prev.is_ascii_alphanumeric() {
                search_from = actual_pos + pat_len;
                continue 'outer;
            }
        }

        let val_start_candidate = actual_pos + pat_len;
        if val_start_candidate >= out.len() {
            break 'outer;
        }

        // Trim leading spaces
        let trimmed_spaces = out[val_start_candidate..]
            .find(|c: char| !c.is_ascii_whitespace())
            .unwrap_or(out[val_start_candidate..].len());
        let val_start = val_start_candidate + trimmed_spaces;
        if val_start >= out.len() {
            search_from = out.len();
            continue 'outer;
        }

        let first_char = out.as_bytes()[val_start];
        if first_char == b'"' || first_char == b'\'' {
            let quote = first_char as char;
            let inner_start = val_start + 1;
            let rel_end = out[inner_start..]
                .find([quote, '\n'])
                .unwrap_or(out[inner_start..].len());
            let inner_end = inner_start + rel_end;
            if inner_start < inner_end && &out[inner_start..inner_end] != "[REDACTED]" {
                out.replace_range(inner_start..inner_end, "[REDACTED]");
                search_from = inner_start + "[REDACTED]".len();
                continue 'outer;
            } else {
                search_from = inner_end
                    + if inner_end < out.len() && out.as_bytes()[inner_end] == first_char {
                        1
                    } else {
                        0
                    };
                continue 'outer;
            }
        } else if out[val_start..].starts_with("[REDACTED]") {
            search_from = val_start + "[REDACTED]".len();
            continue 'outer;
        } else {
            let val_len = out[val_start..]
                .char_indices()
                .find(|&(_, c)| {
                    c.is_whitespace()
                        || c == '"'
                        || c == '\''
                        || c == ','
                        || c == ';'
                        || c == '}'
                        || c == ']'
                })
                .map(|(i, _)| i)
                .unwrap_or(out[val_start..].len());
            let val_end = val_start + val_len;
            if val_start < val_end && &out[val_start..val_end] != "[REDACTED]" {
                out.replace_range(val_start..val_end, "[REDACTED]");
                search_from = val_start + "[REDACTED]".len();
                continue 'outer;
            } else {
                search_from = if val_end > val_start {
                    val_end
                } else {
                    val_start + 1
                };
                continue 'outer;
            }
        }
    }
}

fn sanitize_key_values_in_place(out: &mut String) {
    const SECRET_PATTERNS: &[&[u8]] = &[
        b"password",
        b"passwd",
        b"pwd",
        b"pass",
        b"token",
        b"secret",
        b"api_key",
        b"apikey",
        b"api-key",
    ];

    let mut search_from = 0;
    'outer: while search_from < out.len() {
        let lower_bytes: Vec<u8> = out.as_bytes()[search_from..]
            .iter()
            .map(|b| b.to_ascii_lowercase())
            .collect();

        // Find the earliest matching pattern
        let mut earliest: Option<(usize, usize)> = None;
        for pattern in SECRET_PATTERNS {
            if let Some(pos) = lower_bytes
                .windows(pattern.len())
                .position(|w| w == *pattern)
            {
                match earliest {
                    Some((min_pos, _)) if pos < min_pos => {
                        earliest = Some((pos, pattern.len()));
                    }
                    None => {
                        earliest = Some((pos, pattern.len()));
                    }
                    _ => {}
                }
            }
        }

        let (rel_pos, pat_len) = match earliest {
            Some(m) => m,
            None => break,
        };

        let pat_start = search_from + rel_pos;
        let pat_end = pat_start + pat_len;

        // 1. Boundary check before pat_start
        if pat_start > 0 {
            let prev = out.as_bytes()[pat_start - 1];
            if prev.is_ascii_alphanumeric() {
                search_from = pat_end;
                continue 'outer;
            }
        }

        // 2. Boundary check after pat_end
        if pat_end < out.len() {
            let next = out.as_bytes()[pat_end];
            if next.is_ascii_alphanumeric() || next == b'_' || next == b'-' {
                search_from = pat_end;
                continue 'outer;
            }
        }

        // 3. Scan for delimiter = or :
        let mut scan = pat_end;
        if scan < out.len() && (out.as_bytes()[scan] == b'"' || out.as_bytes()[scan] == b'\'') {
            scan += 1;
        }
        while scan < out.len() && (out.as_bytes()[scan] == b' ' || out.as_bytes()[scan] == b'\t') {
            scan += 1;
        }

        if scan >= out.len() || (out.as_bytes()[scan] != b'=' && out.as_bytes()[scan] != b':') {
            search_from = pat_end;
            continue 'outer;
        }

        scan += 1; // skip delimiter

        while scan < out.len() && (out.as_bytes()[scan] == b' ' || out.as_bytes()[scan] == b'\t') {
            scan += 1;
        }

        if scan >= out.len() {
            search_from = out.len();
            continue 'outer;
        }

        // 4. Value extraction
        let first_byte = out.as_bytes()[scan];
        let val_start = if first_byte == b'"' || first_byte == b'\'' {
            scan + 1
        } else {
            scan
        };

        if first_byte == b'"' || first_byte == b'\'' {
            let quote = first_byte as char;
            let rel_end = out[val_start..]
                .find([quote, '\n'])
                .unwrap_or(out[val_start..].len());
            let val_end = val_start + rel_end;

            if val_start < val_end && &out[val_start..val_end] != "[REDACTED]" {
                out.replace_range(val_start..val_end, "[REDACTED]");
                search_from = val_start + "[REDACTED]".len();
                continue 'outer;
            } else {
                search_from = val_end
                    + if val_end < out.len() && out.as_bytes()[val_end] == first_byte {
                        1
                    } else {
                        0
                    };
                continue 'outer;
            }
        } else if out[val_start..].starts_with("[REDACTED]") {
            search_from = val_start + "[REDACTED]".len();
            continue 'outer;
        } else {
            let val_len = out[val_start..]
                .char_indices()
                .find(|&(_, c)| {
                    c.is_whitespace()
                        || c == '&'
                        || c == ','
                        || c == '"'
                        || c == '\''
                        || c == '}'
                        || c == ']'
                        || c == ';'
                        || c == '#'
                })
                .map(|(i, _)| i)
                .unwrap_or(out[val_start..].len());
            let val_end = val_start + val_len;

            if val_start < val_end && &out[val_start..val_end] != "[REDACTED]" {
                out.replace_range(val_start..val_end, "[REDACTED]");
                search_from = val_start + "[REDACTED]".len();
                continue 'outer;
            } else {
                search_from = if val_end > val_start {
                    val_end
                } else {
                    val_start + 1
                };
                continue 'outer;
            }
        }
    }
}

/// Sanitizes strongly typed errors to ensure sensitive authentication credentials are never exposed
pub fn sanitize_error(err: AdminError) -> AdminError {
    match err {
        AdminError::UnsupportedOperation(msg) => {
            AdminError::UnsupportedOperation(sanitize_text(&msg))
        }
        AdminError::AuthenticationFailed(msg) => {
            AdminError::AuthenticationFailed(sanitize_text(&msg))
        }
        AdminError::SessionExpired(msg) => AdminError::SessionExpired(sanitize_text(&msg)),
        AdminError::IdentityMismatch(msg) => AdminError::IdentityMismatch(sanitize_text(&msg)),
        AdminError::Timeout(msg) => AdminError::Timeout(sanitize_text(&msg)),
        AdminError::CommunicationError(msg) => AdminError::CommunicationError(sanitize_text(&msg)),
        AdminError::ScopeViolation(msg) => AdminError::ScopeViolation(sanitize_text(&msg)),
        AdminError::LockoutPrevented(msg) => AdminError::LockoutPrevented(sanitize_text(&msg)),
        AdminError::DuplicatePolicy(msg) => AdminError::DuplicatePolicy(sanitize_text(&msg)),
        AdminError::PolicyNotFound(msg) => AdminError::PolicyNotFound(sanitize_text(&msg)),
        AdminError::TransactionFailed(msg) => AdminError::TransactionFailed(sanitize_text(&msg)),
        AdminError::RollbackFailed {
            applied_targets,
            failed_target,
            original_error,
            rollback_errors,
        } => AdminError::RollbackFailed {
            applied_targets: applied_targets
                .into_iter()
                .map(|t| sanitize_text(&t))
                .collect(),
            failed_target: sanitize_text(&failed_target),
            original_error: sanitize_text(&original_error),
            rollback_errors: rollback_errors
                .into_iter()
                .map(|e| sanitize_text(&e))
                .collect(),
        },
        AdminError::SecurityViolation(msg) => AdminError::SecurityViolation(sanitize_text(&msg)),
    }
}

/// Persistent audit record documenting a policy execution event
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyExecutionRecord {
    pub execution_id: String,
    pub timestamp_unix: u64,
    pub operation: String,
    pub provider_id: String,
    pub provider_name: String,
    pub target_scope: PolicyScope,
    pub initial_state: PolicyLifecycleState,
    pub final_state: PolicyLifecycleState,
    pub duration: PolicyDuration,
    pub persistence: PolicyPersistence,
    pub autonomous_recovery_guaranteed: bool,
    pub policy_id: Option<String>,
    pub error: Option<String>,
}

/// Preflight evaluation report prior to executing a router firewall mutation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutationPreflightReport {
    pub provider_name: String,
    pub router_identity: RouterIdentity,
    pub target_scope: PolicyScope,
    pub target_count: usize,
    pub duration: PolicyDuration,
    pub persistence: PolicyPersistence,
    pub recovery_mechanism: String,
    pub has_unreconciled_partial_failure: bool,
    pub prior_failures: Vec<String>,
    pub target_overlaps: Vec<String>,
    pub warnings: Vec<String>,
}

/// Unified, capability-driven policy execution engine.
///
/// Dispatches administrative network control requests through a common,
/// hardened execution path:
/// 1. Resolves explicitly selected provider from `RouterRegistry`
/// 2. Validates targets and enforces router/controller lockout protection
/// 3. Pre-validates provider capabilities (rejecting unsupported temporary policies before mutation)
/// 4. Rejects duplicate active policies
/// 5. Transitions lifecycle state from `PendingApplication` to `Active` (or `Failed`)
/// 6. Redacts sensitive credentials from errors and execution logs
#[derive(Clone)]
pub struct PolicyExecutionEngine {
    registry: Arc<RouterRegistry>,
    store: Arc<PolicyStore>,
    last_persistence_error: Arc<parking_lot::RwLock<Option<String>>>,
}

fn is_test_environment() -> bool {
    if cfg!(test) {
        return true;
    }
    if let Ok(exe) = std::env::current_exe() {
        let path_str = exe.to_string_lossy();
        if path_str.contains("deps")
            || exe
                .file_name()
                .and_then(|f| f.to_str())
                .is_some_and(|name| name.starts_with("test_"))
        {
            return true;
        }
    }
    false
}

impl PolicyExecutionEngine {
    /// Constructs a new unified policy execution engine bound to a router registry
    pub fn new(registry: Arc<RouterRegistry>) -> Self {
        if is_test_environment() {
            Self::with_store(registry, Arc::new(PolicyStore::in_memory()))
        } else {
            Self::with_store(registry, Arc::new(PolicyStore::new()))
        }
    }

    /// Constructs a new unified policy execution engine with a custom persistent store
    pub fn with_store(registry: Arc<RouterRegistry>, store: Arc<PolicyStore>) -> Self {
        Self {
            registry,
            store,
            last_persistence_error: Arc::new(parking_lot::RwLock::new(None)),
        }
    }

    /// Accesses the last observed persistence error, if one occurred
    pub fn last_persistence_error(&self) -> Option<String> {
        self.last_persistence_error.read().clone()
    }

    /// Records persistence operation outcomes to surface disk failures
    fn record_persistence_result(&self, res: Result<(), String>) {
        match res {
            Ok(()) => {
                *self.last_persistence_error.write() = None;
            }
            Err(e) => {
                eprintln!("[WARN] Policy persistence error: {}", e);
                *self.last_persistence_error.write() = Some(e);
            }
        }
    }

    /// Accesses the underlying router provider registry
    pub fn registry(&self) -> &Arc<RouterRegistry> {
        &self.registry
    }

    /// Accesses the underlying persistent policy store
    pub fn store(&self) -> &Arc<PolicyStore> {
        &self.store
    }

    /// Returns a copy of the execution audit history
    pub fn execution_history(&self) -> Vec<PolicyExecutionRecord> {
        self.store.records()
    }

    /// Clears execution history records
    pub fn clear_history(&self) {
        let _ = self.store.clear();
    }

    /// Plans a dry-run policy operation through capability and safety checks
    pub fn plan_policy(&self, req: &OperationPlanRequest) -> Result<OperationPlan, AdminError> {
        let active_id = self.registry.active_provider_id().ok_or_else(|| {
            AdminError::UnsupportedOperation(
                "No router provider is currently connected. Establish a connection first with 'router connect <provider>'."
                    .into(),
            )
        })?;
        let active_provider = self.registry.active_provider().ok_or_else(|| {
            AdminError::UnsupportedOperation(
                "No active router provider available in registry.".into(),
            )
        })?;
        let desc = self.registry.get_descriptor(&active_id).ok_or_else(|| {
            AdminError::UnsupportedOperation(format!(
                "Descriptor not found for provider '{}'",
                active_id
            ))
        })?;

        // Lockout protection
        self.registry.validate_scope_safety(&req.scope)?;

        // Capability pre-check for dry-run
        let caps = active_provider.inspect_capabilities();
        match &req.scope {
            PolicyScope::NetworkWide => {
                if !caps.network_wide_access_policy.is_operational() {
                    return Err(AdminError::UnsupportedOperation(format!(
                        "Selected router provider '{}' ({}) does not support network-wide access policies (capability status: {}).",
                        desc.id, desc.name, caps.network_wide_access_policy
                    )));
                }
            }
            PolicyScope::SpecificTargets(targets) => {
                if targets.is_empty() {
                    return Err(AdminError::ScopeViolation(
                        "Target list cannot be empty for per-device access policy.".into(),
                    ));
                }
                if !caps.per_device_access_policy.is_operational() {
                    return Err(AdminError::UnsupportedOperation(format!(
                        "Selected router provider '{}' ({}) does not support per-device access policies (capability status: {}).",
                        desc.id, desc.name, caps.per_device_access_policy
                    )));
                }
            }
        }

        let mut plan = active_provider.plan_operation(req)?;
        plan.is_dry_run = true;

        // Check for prior unresolved partial failures or unknown states from store
        for p in self.store.historical_policies() {
            match &p.lifecycle_state {
                PolicyLifecycleState::PartialFailure {
                    applied_targets,
                    failed_target,
                    rollback_errors,
                } => {
                    plan.uncertainties_and_risks.push(format!(
                        "PRIOR UNRESOLVED PARTIAL FAILURE: Policy '{}' failed on target '{}' (applied: {:?}, rollback errors: {:?}). Firewall may be in an inconsistent state.",
                        p.policy_id, failed_target, applied_targets, rollback_errors
                    ));
                }
                PolicyLifecycleState::Unknown => {
                    plan.uncertainties_and_risks.push(format!(
                        "PRIOR UNKNOWN STATE: Policy '{}' has unknown lifecycle state on the router. Reconciliation is recommended before mutating.",
                        p.policy_id
                    ));
                }
                _ => {}
            }
        }

        // Check for target overlap or conflicts with active policies
        let active_policies: Vec<_> = self
            .store
            .historical_policies()
            .into_iter()
            .filter(|p| p.lifecycle_state == PolicyLifecycleState::Active)
            .collect();

        match &req.scope {
            PolicyScope::NetworkWide => {
                for ap in &active_policies {
                    plan.uncertainties_and_risks.push(format!(
                        "TARGET OVERLAP: Network-wide policy will overlap with existing active policy '{}' (scope: {})",
                        ap.policy_id, ap.scope
                    ));
                }
            }
            PolicyScope::SpecificTargets(targets) => {
                for target in targets {
                    for ap in &active_policies {
                        match &ap.scope {
                            PolicyScope::NetworkWide => {
                                plan.uncertainties_and_risks.push(format!(
                                    "TARGET OVERLAP: Target {} is already covered by active Network-Wide policy '{}'",
                                    target, ap.policy_id
                                ));
                            }
                            PolicyScope::SpecificTargets(existing_targets) => {
                                if existing_targets.contains(target) {
                                    plan.uncertainties_and_risks.push(format!(
                                        "TARGET OVERLAP: Target {} is already subject to active policy '{}'",
                                        target, ap.policy_id
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(plan)
    }

    /// Checks the policy store and router history for any unresolved partial failures or unknown states
    pub fn check_unreconciled_failures(&self) -> Vec<String> {
        let mut warnings = Vec::new();
        for p in self.store.historical_policies() {
            match &p.lifecycle_state {
                PolicyLifecycleState::PartialFailure {
                    applied_targets,
                    failed_target,
                    rollback_errors,
                } => {
                    warnings.push(format!(
                        "Policy '{}' has unresolved partial failure (failed target: {}, applied: {:?}, rollback errors: {:?})",
                        p.policy_id, failed_target, applied_targets, rollback_errors
                    ));
                }
                PolicyLifecycleState::Unknown => {
                    warnings.push(format!(
                        "Policy '{}' is in an ambiguous/unknown lifecycle state",
                        p.policy_id
                    ));
                }
                _ => {}
            }
        }
        warnings
    }

    /// Performs preflight inspection for a policy mutation, returning a structured summary of risks and conflicts
    pub fn preflight_mutation(
        &self,
        req: &OperationPlanRequest,
    ) -> Result<MutationPreflightReport, AdminError> {
        let plan = self.plan_policy(req)?;
        let unreconciled = self.check_unreconciled_failures();
        let mut target_overlaps = Vec::new();
        for risk in &plan.uncertainties_and_risks {
            if risk.starts_with("TARGET OVERLAP:") {
                target_overlaps.push(risk.clone());
            }
        }

        Ok(MutationPreflightReport {
            provider_name: plan.provider_name,
            router_identity: plan.router_identity,
            target_scope: plan.target_scope,
            target_count: plan.target_count,
            duration: plan.duration,
            persistence: plan.persistence,
            recovery_mechanism: plan.recovery_mechanism,
            has_unreconciled_partial_failure: !unreconciled.is_empty(),
            prior_failures: unreconciled,
            target_overlaps,
            warnings: plan.uncertainties_and_risks,
        })
    }

    /// Applies a network access policy through the capability-driven execution pipeline
    pub fn apply_policy(
        &self,
        req: &OperationPlanRequest,
    ) -> Result<ActivePolicyStatus, AdminError> {
        let active_id = self.registry.active_provider_id().ok_or_else(|| {
            AdminError::UnsupportedOperation(
                "No router provider is currently connected. Establish a connection first with 'router connect <provider>'."
                    .into(),
            )
        })?;
        let active_provider = self.registry.active_provider().ok_or_else(|| {
            AdminError::UnsupportedOperation(
                "No active router provider available in registry.".into(),
            )
        })?;
        let desc = self.registry.get_descriptor(&active_id).ok_or_else(|| {
            AdminError::UnsupportedOperation(format!(
                "Descriptor not found for provider '{}'",
                active_id
            ))
        })?;

        // 1. Authentication check
        if !active_provider.is_authenticated() {
            return Err(AdminError::AuthenticationFailed(format!(
                "Selected router provider '{}' ({}) is not authenticated. Configure credentials or run 'router connect' first.",
                desc.id, desc.name
            )));
        }

        // 2. Lockout protection for router gateway IP and controller host IP
        self.registry.validate_scope_safety(&req.scope)?;

        // 3. Pre-validate declared provider capabilities BEFORE mutation
        let caps = active_provider.inspect_capabilities();

        match &req.scope {
            PolicyScope::NetworkWide => {
                if !caps.network_wide_access_policy.is_operational() {
                    return Err(AdminError::UnsupportedOperation(format!(
                        "Selected router provider '{}' ({}) does not support network-wide access policies (capability status: {}).",
                        desc.id, desc.name, caps.network_wide_access_policy
                    )));
                }
            }
            PolicyScope::SpecificTargets(targets) => {
                if targets.is_empty() {
                    return Err(AdminError::ScopeViolation(
                        "Target list cannot be empty for per-device access policy.".into(),
                    ));
                }
                if !caps.per_device_access_policy.is_operational() {
                    return Err(AdminError::UnsupportedOperation(format!(
                        "Selected router provider '{}' ({}) does not support per-device access policies (capability status: {}).",
                        desc.id, desc.name, caps.per_device_access_policy
                    )));
                }
            }
        }

        // Autonomous timed recovery pre-validation: reject temporary policies if unsupported
        if let PolicyDuration::Temporary(dur) = &req.duration {
            if !caps.timed_policy_auto_recovery.is_operational() {
                return Err(AdminError::UnsupportedOperation(format!(
                    "Selected router provider '{}' ({}) does not support autonomous router-side timed recovery (capability status: {}). Temporary policy of {} seconds rejected to prevent unrecoverable network restrictions. Use indefinite duration with explicit resume, or connect an autonomous recovery provider (e.g. OpenWrt or MikroTik RouterOS).",
                    desc.id, desc.name, caps.timed_policy_auto_recovery, dur.as_secs()
                )));
            }
        }

        // Persistence capability check
        if req.persistence == PolicyPersistence::RouterPersistent
            && !caps.persistence_after_app_exit.is_operational()
        {
            return Err(AdminError::UnsupportedOperation(format!(
                "Selected router provider '{}' ({}) does not support persistent policies surviving application exit (capability status: {}).",
                desc.id, desc.name, caps.persistence_after_app_exit
            )));
        }

        // 4. Duplicate policy check
        self.registry.check_duplicate_policy(&req.scope)?;

        // 4b. Check and warn on active partial failure or unknown states before mutating
        for p in self.store.historical_policies() {
            if matches!(
                p.lifecycle_state,
                PolicyLifecycleState::PartialFailure { .. } | PolicyLifecycleState::Unknown
            ) {
                eprintln!(
                    "[WARN] Active partial failure or unknown router state detected for policy '{}'. Proceeding with mutation may compound router state divergence.",
                    p.policy_id
                );
            }
        }

        // 5. Track state transition: PendingApplication
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let execution_id = format!("exec_{}_{}", active_id, now);

        // 6. Execute policy application on router provider
        let result = active_provider.apply_policy(req);

        match result {
            Ok(status) => {
                let router_identity_summary = self
                    .registry
                    .get_status()
                    .verified_identity
                    .map(|id| id.display_summary())
                    .unwrap_or_else(|| "Unknown Router".to_string());

                let active_status = status
                    .with_state(PolicyLifecycleState::Active)
                    .with_provider(desc.name.clone())
                    .with_router_identity(router_identity_summary);

                let record = PolicyExecutionRecord {
                    execution_id,
                    timestamp_unix: now,
                    operation: "apply".to_string(),
                    provider_id: desc.id.clone(),
                    provider_name: desc.name.clone(),
                    target_scope: req.scope.clone(),
                    initial_state: PolicyLifecycleState::PendingApplication,
                    final_state: PolicyLifecycleState::Active,
                    duration: req.duration.clone(),
                    persistence: req.persistence.clone(),
                    autonomous_recovery_guaranteed: active_status.autonomous_recovery,
                    policy_id: Some(active_status.policy_id.clone()),
                    error: None,
                };
                let res1 = self.store.update_policy_status(&active_status);
                self.record_persistence_result(res1);
                let res2 = self.store.append_record(&record);
                self.record_persistence_result(res2);

                Ok(active_status)
            }
            Err(e) => {
                let sanitized_err = sanitize_error(e);
                let final_state = match &sanitized_err {
                    AdminError::RollbackFailed {
                        applied_targets,
                        failed_target,
                        rollback_errors,
                        ..
                    } => PolicyLifecycleState::PartialFailure {
                        applied_targets: applied_targets.clone(),
                        failed_target: failed_target.clone(),
                        rollback_errors: rollback_errors.clone(),
                    },
                    _ => PolicyLifecycleState::Failed(sanitized_err.to_string()),
                };

                let record = PolicyExecutionRecord {
                    execution_id,
                    timestamp_unix: now,
                    operation: "apply".to_string(),
                    provider_id: desc.id.clone(),
                    provider_name: desc.name.clone(),
                    target_scope: req.scope.clone(),
                    initial_state: PolicyLifecycleState::PendingApplication,
                    final_state,
                    duration: req.duration.clone(),
                    persistence: req.persistence.clone(),
                    autonomous_recovery_guaranteed: false,
                    policy_id: None,
                    error: Some(sanitized_err.to_string()),
                };
                let res = self.store.append_record(&record);
                self.record_persistence_result(res);

                Err(sanitized_err)
            }
        }
    }

    /// Resumes normal network transit by removing policy rules matching the given scope
    pub fn resume_policy(&self, scope: &PolicyScope) -> Result<Vec<String>, AdminError> {
        let active_id = self.registry.active_provider_id().ok_or_else(|| {
            AdminError::UnsupportedOperation(
                "No router provider is currently connected. Establish a connection first with 'router connect <provider>'."
                    .into(),
            )
        })?;
        let active_provider = self.registry.active_provider().ok_or_else(|| {
            AdminError::UnsupportedOperation(
                "No active router provider available in registry.".into(),
            )
        })?;
        let desc = self.registry.get_descriptor(&active_id).ok_or_else(|| {
            AdminError::UnsupportedOperation(format!(
                "Descriptor not found for provider '{}'",
                active_id
            ))
        })?;

        if !active_provider.is_authenticated() {
            return Err(AdminError::AuthenticationFailed(format!(
                "Selected router provider '{}' ({}) is not authenticated.",
                desc.id, desc.name
            )));
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let execution_id = format!("resume_{}_{}", active_id, now);

        match active_provider.resume_policy(scope) {
            Ok(ids) => {
                let record = PolicyExecutionRecord {
                    execution_id,
                    timestamp_unix: now,
                    operation: "resume".to_string(),
                    provider_id: desc.id.clone(),
                    provider_name: desc.name.clone(),
                    target_scope: scope.clone(),
                    initial_state: PolicyLifecycleState::RecoveryInProgress,
                    final_state: PolicyLifecycleState::Recovered,
                    duration: PolicyDuration::Indefinite,
                    persistence: PolicyPersistence::VolatileSession,
                    autonomous_recovery_guaranteed: false,
                    policy_id: ids.first().cloned(),
                    error: None,
                };
                let res1 = self.store.mark_scope_recovered(scope);
                self.record_persistence_result(res1);
                let res2 = self.store.append_record(&record);
                self.record_persistence_result(res2);

                Ok(ids)
            }
            Err(e) => {
                let sanitized_err = sanitize_error(e);
                let record = PolicyExecutionRecord {
                    execution_id,
                    timestamp_unix: now,
                    operation: "resume".to_string(),
                    provider_id: desc.id.clone(),
                    provider_name: desc.name.clone(),
                    target_scope: scope.clone(),
                    initial_state: PolicyLifecycleState::RecoveryInProgress,
                    final_state: PolicyLifecycleState::Failed(sanitized_err.to_string()),
                    duration: PolicyDuration::Indefinite,
                    persistence: PolicyPersistence::VolatileSession,
                    autonomous_recovery_guaranteed: false,
                    policy_id: None,
                    error: Some(sanitized_err.to_string()),
                };
                let res = self.store.append_record(&record);
                self.record_persistence_result(res);

                Err(sanitized_err)
            }
        }
    }

    /// Adjusts an existing policy's duration through capability pre-validation
    pub fn adjust_policy_duration(
        &self,
        scope: &PolicyScope,
        new_duration: &PolicyDuration,
    ) -> Result<ActivePolicyStatus, AdminError> {
        let active_id = self.registry.active_provider_id().ok_or_else(|| {
            AdminError::UnsupportedOperation(
                "No router provider is currently connected. Establish a connection first with 'router connect <provider>'."
                    .into(),
            )
        })?;
        let active_provider = self.registry.active_provider().ok_or_else(|| {
            AdminError::UnsupportedOperation(
                "No active router provider available in registry.".into(),
            )
        })?;
        let desc = self.registry.get_descriptor(&active_id).ok_or_else(|| {
            AdminError::UnsupportedOperation(format!(
                "Descriptor not found for provider '{}'",
                active_id
            ))
        })?;

        if !active_provider.is_authenticated() {
            return Err(AdminError::AuthenticationFailed(format!(
                "Selected router provider '{}' ({}) is not authenticated.",
                desc.id, desc.name
            )));
        }

        // Capability check for temporary duration
        let caps = active_provider.inspect_capabilities();
        if let PolicyDuration::Temporary(dur) = new_duration {
            if !caps.timed_policy_auto_recovery.is_operational() {
                return Err(AdminError::UnsupportedOperation(format!(
                    "Selected router provider '{}' ({}) does not support autonomous router-side timed recovery (capability status: {}). Cannot adjust policy to a temporary duration of {} seconds.",
                    desc.id, desc.name, caps.timed_policy_auto_recovery, dur.as_secs()
                )));
            }
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let execution_id = format!("adjust_{}_{}", active_id, now);

        match active_provider.adjust_policy_duration(scope, new_duration) {
            Ok(status) => {
                let router_identity_summary = self
                    .registry
                    .get_status()
                    .verified_identity
                    .map(|id| id.display_summary())
                    .unwrap_or_else(|| "Unknown Router".to_string());

                let active_status = status
                    .with_state(PolicyLifecycleState::Active)
                    .with_provider(desc.name.clone())
                    .with_router_identity(router_identity_summary);

                let record = PolicyExecutionRecord {
                    execution_id,
                    timestamp_unix: now,
                    operation: "adjust".to_string(),
                    provider_id: desc.id.clone(),
                    provider_name: desc.name.clone(),
                    target_scope: scope.clone(),
                    initial_state: PolicyLifecycleState::Active,
                    final_state: PolicyLifecycleState::Active,
                    duration: new_duration.clone(),
                    persistence: if active_status.is_persistent {
                        PolicyPersistence::RouterPersistent
                    } else {
                        PolicyPersistence::VolatileSession
                    },
                    autonomous_recovery_guaranteed: active_status.autonomous_recovery,
                    policy_id: Some(active_status.policy_id.clone()),
                    error: None,
                };
                let res1 = self.store.update_policy_status(&active_status);
                self.record_persistence_result(res1);
                let res2 = self.store.append_record(&record);
                self.record_persistence_result(res2);

                Ok(active_status)
            }
            Err(e) => {
                let sanitized_err = sanitize_error(e);
                let record = PolicyExecutionRecord {
                    execution_id,
                    timestamp_unix: now,
                    operation: "adjust".to_string(),
                    provider_id: desc.id.clone(),
                    provider_name: desc.name.clone(),
                    target_scope: scope.clone(),
                    initial_state: PolicyLifecycleState::Active,
                    final_state: PolicyLifecycleState::Failed(sanitized_err.to_string()),
                    duration: new_duration.clone(),
                    persistence: PolicyPersistence::VolatileSession,
                    autonomous_recovery_guaranteed: false,
                    policy_id: None,
                    error: Some(sanitized_err.to_string()),
                };
                let res = self.store.append_record(&record);
                self.record_persistence_result(res);

                Err(sanitized_err)
            }
        }
    }

    /// Queries currently active policies residing on the router
    pub fn query_active_policies(&self) -> Result<Vec<ActivePolicyStatus>, AdminError> {
        let active_id = self.registry.active_provider_id().ok_or_else(|| {
            AdminError::UnsupportedOperation(
                "No router provider is currently connected. Establish a connection first with 'router connect <provider>'."
                    .into(),
            )
        })?;
        let active_provider = self.registry.active_provider().ok_or_else(|| {
            AdminError::UnsupportedOperation(
                "No active router provider available in registry.".into(),
            )
        })?;
        let desc = self.registry.get_descriptor(&active_id).ok_or_else(|| {
            AdminError::UnsupportedOperation(format!(
                "Descriptor not found for provider '{}'",
                active_id
            ))
        })?;

        let policies = active_provider.query_active_policies()?;
        let router_identity_summary = self
            .registry
            .get_status()
            .verified_identity
            .map(|id| id.display_summary())
            .unwrap_or_else(|| "Unknown Router".to_string());

        let enriched: Vec<ActivePolicyStatus> = policies
            .into_iter()
            .map(|mut p| {
                if p.provider_name.is_none() {
                    p.provider_name = Some(desc.name.clone());
                }
                if p.router_identity.is_none() {
                    p.router_identity = Some(router_identity_summary.clone());
                }
                p
            })
            .collect();
        Ok(enriched)
    }

    /// Reconciles router state by querying active rules and updating lifecycle states
    pub fn reconcile_policies(&self) -> Result<Vec<ActivePolicyStatus>, AdminError> {
        let active_id = self.registry.active_provider_id().ok_or_else(|| {
            AdminError::UnsupportedOperation(
                "No router provider is currently connected. Establish a connection first with 'router connect <provider>'."
                    .into(),
            )
        })?;
        let active_provider = self.registry.active_provider().ok_or_else(|| {
            AdminError::UnsupportedOperation(
                "No active router provider available in registry.".into(),
            )
        })?;
        let desc = self.registry.get_descriptor(&active_id).ok_or_else(|| {
            AdminError::UnsupportedOperation(format!(
                "Descriptor not found for provider '{}'",
                active_id
            ))
        })?;

        let policies = active_provider.reconcile_policies()?;
        let router_identity_summary = self
            .registry
            .get_status()
            .verified_identity
            .map(|id| id.display_summary())
            .unwrap_or_else(|| "Unknown Router".to_string());

        let enriched: Vec<ActivePolicyStatus> = policies
            .into_iter()
            .map(|mut p| {
                if p.provider_name.is_none() {
                    p.provider_name = Some(desc.name.clone());
                }
                if p.router_identity.is_none() {
                    p.router_identity = Some(router_identity_summary.clone());
                }
                p
            })
            .collect();
        let res = self.store.update_policies_from_reconcile(&enriched);
        self.record_persistence_result(res);
        Ok(enriched)
    }

    /// Queries connected client devices in a strictly read-only manner
    pub fn list_devices(&self) -> Result<Vec<RouterDeviceEntry>, AdminError> {
        let _active_id = self.registry.active_provider_id().ok_or_else(|| {
            AdminError::UnsupportedOperation(
                "No router provider is currently connected. Establish a connection first with 'router connect <provider>'."
                    .into(),
            )
        })?;
        let active_provider = self.registry.active_provider().ok_or_else(|| {
            AdminError::UnsupportedOperation(
                "No active router provider available in registry.".into(),
            )
        })?;
        active_provider.list_devices()
    }

    /// Returns a normalized, unified listing of router policies across providers,
    /// clearly distinguishing active provider-confirmed policies from locally cached
    /// historical records or unverified states.
    pub fn list_unified_policies(&self) -> Vec<UnifiedPolicyEntry> {
        let active_id = self.registry.active_provider_id();
        let is_connected = self.registry.is_connected();
        let is_authed = self.is_authenticated();

        let mut unified = Vec::new();
        let mut seen_ids = std::collections::HashSet::new();

        // 1. If connected and authenticated, query live physical router state
        if is_connected && is_authed {
            if let Ok(live_policies) = self.reconcile_policies() {
                let pid = active_id.clone().unwrap_or_else(|| "unknown".into());
                for live in &live_policies {
                    seen_ids.insert(live.policy_id.clone());
                    unified.push(UnifiedPolicyEntry::from_active_policy(
                        live,
                        &pid,
                        PolicyConfirmationState::ProviderConfirmed,
                    ));
                }
            }
        }

        // 2. Load historical policies from store
        let historical = self.store.historical_policies();
        for hist in historical {
            if seen_ids.contains(&hist.policy_id) {
                continue;
            }

            let pid = hist
                .provider_name
                .clone()
                .unwrap_or_else(|| "unknown".into());

            // If disconnected, or not confirmed on live router, determine confirmation state
            let conf_state = match hist.lifecycle_state {
                PolicyLifecycleState::Recovered => {
                    PolicyConfirmationState::LocallyRecordedRecovered
                }
                PolicyLifecycleState::Failed(_) => PolicyConfirmationState::LocallyRecordedFailed,
                _ => PolicyConfirmationState::LocallyRecordedUnverified,
            };

            let mut entry = UnifiedPolicyEntry::from_active_policy(&hist, &pid, conf_state);

            // Crucial safety rule: Never claim a policy is active merely because its local record says so!
            if (!is_connected || !is_authed)
                && entry.lifecycle_state == PolicyLifecycleState::Active
            {
                entry.lifecycle_state = PolicyLifecycleState::Unknown;
                entry.last_execution_result = Some(
                    "Local state unverified: router provider is currently disconnected".into(),
                );
            }

            unified.push(entry);
        }

        unified
    }

    /// Queries detailed inspection view for a specific policy ID
    pub fn get_policy_detail(&self, policy_id: &str) -> Option<PolicyDetailView> {
        let policies = self.list_unified_policies();
        let policy = policies
            .into_iter()
            .find(|p| p.policy_id == policy_id)
            .or_else(|| {
                // Also check raw execution records in case policy failed before status could be stored
                let records = self.store.records();
                let matching_rec = records
                    .iter()
                    .find(|r| r.policy_id.as_deref() == Some(policy_id))?;
                Some(UnifiedPolicyEntry {
                    policy_id: policy_id.to_string(),
                    provider_id: matching_rec.provider_id.clone(),
                    provider_name: matching_rec.provider_name.clone(),
                    scope: matching_rec.target_scope.clone(),
                    lifecycle_state: matching_rec.final_state.clone(),
                    duration: matching_rec.duration.clone(),
                    is_persistent: matching_rec.persistence == PolicyPersistence::RouterPersistent,
                    applied_at_unix: matching_rec.timestamp_unix,
                    expires_at_unix: match &matching_rec.duration {
                        PolicyDuration::Temporary(d) => {
                            Some(matching_rec.timestamp_unix + d.as_secs())
                        }
                        PolicyDuration::Indefinite => None,
                    },
                    enforcement_point: "Router Firewall".to_string(),
                    recovery_status: match &matching_rec.final_state {
                        PolicyLifecycleState::Failed(err) => {
                            PolicyRecoveryStatus::Failed(err.clone())
                        }
                        _ => PolicyRecoveryStatus::UnknownOrUnverified,
                    },
                    last_execution_result: matching_rec.error.clone(),
                    confirmation_state: PolicyConfirmationState::LocallyRecordedFailed,
                })
            })?;

        // Determine live verification capability
        let active_id = self.registry.active_provider_id();
        let is_connected = self.registry.is_connected();
        let is_authed = self.is_authenticated();

        let (can_verify, verify_status) = if is_connected && is_authed {
            if let Some(ref aid) = active_id {
                let aid_lower = aid.to_lowercase();
                let pol_prov_lower = policy.provider_id.to_lowercase();
                let matches = aid_lower == pol_prov_lower
                    || aid_lower.contains(&pol_prov_lower)
                    || pol_prov_lower.contains(&aid_lower);
                if matches {
                    (
                        true,
                        format!(
                            "YES — Connected provider '{}' is authenticated and actively verifying rules on router",
                            aid
                        ),
                    )
                } else {
                    (
                        false,
                        format!(
                            "NO — Connected provider '{}' differs from policy provider '{}'",
                            aid, policy.provider_id
                        ),
                    )
                }
            } else {
                (false, "NO — Provider identity unconfirmed".into())
            }
        } else if is_connected {
            (
                false,
                "NO — Router provider is connected but unauthenticated".into(),
            )
        } else {
            (
                false,
                "NO — Router provider is disconnected. Live hardware verification requires 'router connect <provider>'.".into(),
            )
        };

        let status = self.registry.get_status();
        let router_id = status.verified_identity.map(|id| id.display_summary());

        // Gather all historical audit execution records for this policy ID
        let all_records = self.store.records();
        let audit_events: Vec<PolicyExecutionRecord> = all_records
            .into_iter()
            .filter(|r| r.policy_id.as_deref() == Some(policy_id))
            .collect();

        Some(PolicyDetailView {
            policy,
            router_identity: router_id,
            provider_verification_available: can_verify,
            provider_verification_status: verify_status,
            audit_events,
        })
    }

    /// Returns a normalized inventory of all registered router providers,
    /// clearly distinguishing live connected data from locally cached historical state.
    pub fn get_inventory(&self) -> Vec<NormalizedRouterInventoryItem> {
        let providers = self.registry.list_providers();
        let active_id = self.registry.active_provider_id();
        let active_provider = self.registry.active_provider();
        let status = self.registry.get_status();
        let records = self.store.records();
        let historical_policies = self.store.historical_policies();

        let mut inventory = Vec::new();

        for desc in providers {
            let is_active = active_id.as_deref() == Some(&desc.id);

            if let (true, Some(p)) = (is_active, &active_provider) {
                let is_authed = p.is_authenticated();
                let conn_state = if is_authed {
                    ProviderConnectionState::Connected
                } else {
                    ProviderConnectionState::AuthenticationRequired
                };

                let identity = status
                    .verified_identity
                    .clone()
                    .or_else(|| p.detect_identity().ok());
                let fw = identity.as_ref().and_then(|id| id.firmware_version.clone());
                let endpoint = status.endpoint.as_deref().map(sanitize_endpoint);
                let pol_count = p
                    .query_active_policies()
                    .map(|policies| policies.len())
                    .ok();
                let dev_count = p.list_devices().map(|devs| devs.len()).ok();
                let caps = p.inspect_capabilities();

                let diag_summary = if is_authed {
                    "Live provider connected & authenticated (Hardware L3/L4)".to_string()
                } else {
                    "Live provider connected; authentication credentials required".to_string()
                };

                inventory.push(NormalizedRouterInventoryItem {
                    provider_id: desc.id,
                    display_name: desc.name,
                    vendor: desc.vendor,
                    connection_state: conn_state,
                    is_active_provider: true,
                    data_source: DataSource::Live,
                    router_identity: identity,
                    firmware_version: fw,
                    management_endpoint: endpoint,
                    last_contact_unix: status.last_contact_unix,
                    capabilities: caps,
                    active_policy_count: pol_count,
                    known_device_count: dev_count,
                    diagnostic_summary: Some(diag_summary),
                    last_error: None,
                });
            } else {
                // Provider is disconnected
                let provider_records: Vec<_> = records
                    .iter()
                    .filter(|r| r.provider_id == desc.id)
                    .collect();

                if let Some(latest) = provider_records.iter().max_by_key(|r| r.timestamp_unix) {
                    let matching_hist_count = historical_policies
                        .iter()
                        .filter(|pol| pol.provider_name.as_deref() == Some(&desc.name))
                        .count();

                    inventory.push(NormalizedRouterInventoryItem {
                        provider_id: desc.id,
                        display_name: desc.name,
                        vendor: desc.vendor,
                        connection_state: ProviderConnectionState::Disconnected,
                        is_active_provider: false,
                        data_source: DataSource::LocallyCached,
                        router_identity: None,
                        firmware_version: None,
                        management_endpoint: None,
                        last_contact_unix: Some(latest.timestamp_unix),
                        capabilities: desc.capabilities,
                        active_policy_count: Some(matching_hist_count),
                        known_device_count: None, // Never invented
                        diagnostic_summary: Some(format!(
                            "Disconnected (Locally cached history present, last activity: unix {})",
                            latest.timestamp_unix
                        )),
                        last_error: latest.error.clone(),
                    });
                } else {
                    inventory.push(NormalizedRouterInventoryItem {
                        provider_id: desc.id,
                        display_name: desc.name,
                        vendor: desc.vendor,
                        connection_state: ProviderConnectionState::Disconnected,
                        is_active_provider: false,
                        data_source: DataSource::StaticDescriptor,
                        router_identity: None,
                        firmware_version: None,
                        management_endpoint: None,
                        last_contact_unix: None,
                        capabilities: desc.capabilities,
                        active_policy_count: None,
                        known_device_count: None,
                        diagnostic_summary: Some(
                            "Disconnected (Descriptor registered, not configured)".into(),
                        ),
                        last_error: None,
                    });
                }
            }
        }

        inventory
    }

    /// Runs a comprehensive read-only diagnostic check without mutating router configuration
    pub fn run_diagnostics(&self) -> RouterDiagnosticReport {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let active_id = self.registry.active_provider_id();
        let active_provider = self.registry.active_provider();
        let reg_status = self.registry.get_status();

        let recent_errors = self
            .store
            .records()
            .iter()
            .filter(|r| {
                active_id
                    .as_deref()
                    .map(|id| id == r.provider_id)
                    .unwrap_or(false)
            })
            .filter_map(|r| r.error.clone())
            .map(|e| sanitize_text(&e))
            .rev()
            .take(5)
            .collect();

        if active_id.is_none() || active_provider.is_none() {
            return RouterDiagnosticReport {
                provider_id: "none".to_string(),
                provider_name: "No Provider Connected".to_string(),
                endpoint: None,
                timestamp_unix: now,
                connection_status: DiagnosticResult::Failed(
                    "No router provider is currently connected. Establish a connection first with 'router connect <provider>'.".into(),
                ),
                identity_and_version: DiagnosticResult::Unsupported(
                    "Cannot query router identity when disconnected".into(),
                ),
                active_policies: DiagnosticResult::Unsupported(
                    "Cannot query active policies when disconnected".into(),
                ),
                connected_devices: DiagnosticResult::Unsupported(
                    "Cannot query connected devices when disconnected".into(),
                ),
                capability_assessment: DiagnosticResult::Unsupported(
                    "Cannot inspect live capabilities when disconnected".into(),
                ),
                recent_errors,
            };
        }

        let pid = active_id.unwrap();
        let provider = active_provider.unwrap();
        let desc = self.registry.get_descriptor(&pid).unwrap_or_else(|| {
            crate::gateway::admin::registry::ProviderDescriptor::new(
                pid.clone(),
                provider.name(),
                "Unknown Vendor",
                "TCP/IP",
                0,
                "",
                "Unsupported",
                RouterCapabilityMatrix::unsupported(),
            )
        });

        // 1. Connection Diagnostic (Read-Only)
        let is_authed = provider.is_authenticated();
        let ping_start = std::time::Instant::now();
        let _ = provider.is_authenticated();
        let latency_ms = ping_start.elapsed().as_millis() as u64;

        let conn_diag = ConnectionDiagnostic {
            is_connected: true,
            is_authenticated: is_authed,
            transport_protocol: desc.protocols.clone(),
            response_latency_ms: Some(latency_ms),
        };

        // 2. Identity and Version Diagnostic (Read-Only)
        let id_diag = match provider.detect_identity() {
            Ok(id) => DiagnosticResult::Supported(id),
            Err(e) => DiagnosticResult::Failed(sanitize_error(e).to_string()),
        };

        // 3. Active Policy Inspection (Read-Only)
        let pol_diag = match provider.query_active_policies() {
            Ok(policies) => DiagnosticResult::Supported(policies),
            Err(e) => DiagnosticResult::Failed(sanitize_error(e).to_string()),
        };

        // 4. Connected Client Device Inventory (Read-Only)
        let dev_diag = match provider.list_devices() {
            Ok(devices) => DiagnosticResult::Supported(devices),
            Err(AdminError::UnsupportedOperation(msg)) => DiagnosticResult::Unsupported(msg),
            Err(e) => DiagnosticResult::Failed(sanitize_error(e).to_string()),
        };

        // 5. Capability Assessment (Read-Only)
        let caps = provider.inspect_capabilities();
        let caps_diag = DiagnosticResult::Supported(caps);

        let endpoint_str = reg_status.endpoint.as_deref().map(sanitize_endpoint);

        RouterDiagnosticReport {
            provider_id: pid,
            provider_name: desc.name,
            endpoint: endpoint_str,
            timestamp_unix: now,
            connection_status: DiagnosticResult::Supported(conn_diag),
            identity_and_version: id_diag,
            active_policies: pol_diag,
            connected_devices: dev_diag,
            capability_assessment: caps_diag,
            recent_errors,
        }
    }

    /// Constructs a complete, sanitized read-only diagnostic evidence bundle
    pub fn build_evidence_bundle(&self) -> RouterEvidenceBundle {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let iso8601 = unix_to_iso8601(now);

        let diag_report = self.run_diagnostics();
        let active_policies = match &diag_report.active_policies {
            DiagnosticResult::Supported(p) => p.clone(),
            _ => Vec::new(),
        };
        let device_inventory = match &diag_report.connected_devices {
            DiagnosticResult::Supported(d) => d.clone(),
            _ => Vec::new(),
        };
        let router_identity = match &diag_report.identity_and_version {
            DiagnosticResult::Supported(id) => Some(id.clone()),
            _ => self.registry.get_status().verified_identity,
        };
        let caps = match &diag_report.capability_assessment {
            DiagnosticResult::Supported(c) => c.clone(),
            _ => RouterCapabilityMatrix::unsupported(),
        };

        let historical_policies = self.store.historical_policies();
        let execution_records = self.store.records();
        let sanitized_errors = diag_report.recent_errors.clone();

        let raw_bundle = RouterEvidenceBundle {
            schema_version: "rustrict-evidence-v1.0".to_string(),
            generated_at_unix: now,
            generated_at_iso8601: iso8601,
            provider_id: diag_report.provider_id.clone(),
            provider_name: diag_report.provider_name.clone(),
            endpoint: diag_report.endpoint.clone(),
            connection_status: diag_report.connection_status.clone(),
            router_identity,
            capability_matrix: caps,
            diagnostic_report: diag_report,
            active_policies,
            historical_policies,
            execution_records,
            device_inventory,
            sanitized_errors,
        };

        // Redact any credentials from all sections of the bundle
        let json_str = serde_json::to_string_pretty(&raw_bundle).unwrap_or_default();
        let sanitized_json = sanitize_text(&json_str);
        serde_json::from_str(&sanitized_json).unwrap_or(raw_bundle)
    }

    /// Exports the sanitized evidence bundle to a JSON file on disk atomically
    pub fn export_evidence_bundle(
        &self,
        path: &Path,
        overwrite: bool,
    ) -> Result<RouterEvidenceBundle, AdminError> {
        if path.exists() && !overwrite {
            return Err(AdminError::SecurityViolation(format!(
                "Refusing to overwrite existing evidence bundle at '{}' without explicit overwrite flag.",
                path.display()
            )));
        }

        let bundle = self.build_evidence_bundle();
        let json_str = serde_json::to_string_pretty(&bundle).map_err(|e| {
            AdminError::CommunicationError(format!("Failed to serialize evidence bundle: {}", e))
        })?;
        let sanitized_json = sanitize_text(&json_str);

        crate::gateway::admin::persistence::atomic_write_file(path, sanitized_json.as_bytes())
            .map_err(|e| {
                AdminError::CommunicationError(format!(
                    "Failed to write evidence bundle to '{}': {}",
                    path.display(),
                    e
                ))
            })?;

        Ok(bundle)
    }
}

impl RouterAdminProvider for PolicyExecutionEngine {
    fn name(&self) -> &'static str {
        "PolicyExecutionEngine"
    }

    fn detect_identity(&self) -> Result<RouterIdentity, AdminError> {
        let active_provider = self.registry.active_provider().ok_or_else(|| {
            AdminError::UnsupportedOperation(
                "No router provider is currently connected. Connect a provider first using 'router connect <provider>'."
                    .into(),
            )
        })?;
        active_provider.detect_identity()
    }

    fn inspect_capabilities(&self) -> RouterCapabilityMatrix {
        if let Some(active_provider) = self.registry.active_provider() {
            active_provider.inspect_capabilities()
        } else {
            RouterCapabilityMatrix::unsupported()
        }
    }

    fn plan_operation(&self, req: &OperationPlanRequest) -> Result<OperationPlan, AdminError> {
        self.plan_policy(req)
    }

    fn query_active_policies(&self) -> Result<Vec<ActivePolicyStatus>, AdminError> {
        self.query_active_policies()
    }

    fn is_authenticated(&self) -> bool {
        if let Some(active_provider) = self.registry.active_provider() {
            active_provider.is_authenticated()
        } else {
            false
        }
    }

    fn apply_policy(&self, req: &OperationPlanRequest) -> Result<ActivePolicyStatus, AdminError> {
        self.apply_policy(req)
    }

    fn resume_policy(&self, scope: &PolicyScope) -> Result<Vec<String>, AdminError> {
        self.resume_policy(scope)
    }

    fn reconcile_policies(&self) -> Result<Vec<ActivePolicyStatus>, AdminError> {
        self.reconcile_policies()
    }

    fn adjust_policy_duration(
        &self,
        scope: &PolicyScope,
        new_duration: &PolicyDuration,
    ) -> Result<ActivePolicyStatus, AdminError> {
        self.adjust_policy_duration(scope, new_duration)
    }

    fn resume_all(&self) -> Result<Vec<String>, AdminError> {
        self.resume_policy(&PolicyScope::NetworkWide)
    }

    fn list_devices(&self) -> Result<Vec<RouterDeviceEntry>, AdminError> {
        self.list_devices()
    }
}
