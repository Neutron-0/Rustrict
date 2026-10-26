use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::Ipv4Addr;
use std::time::Duration;

/// Detailed metadata describing the detected router hardware and software identity
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouterIdentity {
    pub ip: Ipv4Addr,
    pub manufacturer: Option<String>,
    pub model_name: Option<String>,
    pub model_number: Option<String>,
    pub firmware_version: Option<String>,
    pub hardware_version: Option<String>,
    pub serial_number: Option<String>,
    pub interface_name: Option<String>,
}

impl RouterIdentity {
    pub fn new(ip: Ipv4Addr) -> Self {
        Self {
            ip,
            manufacturer: None,
            model_name: None,
            model_number: None,
            firmware_version: None,
            hardware_version: None,
            serial_number: None,
            interface_name: None,
        }
    }

    pub fn display_summary(&self) -> String {
        let mfg = self.manufacturer.as_deref().unwrap_or("Unknown Vendor");
        let model = self.model_name.as_deref().unwrap_or("Unknown Model");
        let fw = self.firmware_version.as_deref().unwrap_or("Unknown FW");
        format!("{} {} (FW: {}) at {}", mfg, model, fw, self.ip)
    }
}

/// Target scope for an administrative policy
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyScope {
    /// Enforces policy globally across all devices on the network
    NetworkWide,
    /// Enforces policy selectively targeting specific client IPv4 addresses
    SpecificTargets(Vec<Ipv4Addr>),
}

impl fmt::Display for PolicyScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NetworkWide => write!(f, "Network-Wide (All Connected Devices)"),
            Self::SpecificTargets(targets) => {
                write!(f, "Selective ({} Device(s): {:?})", targets.len(), targets)
            }
        }
    }
}

/// Temporal duration for an administrative policy
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyDuration {
    /// Temporary policy with a definitive duration before auto-recovery
    Temporary(Duration),
    /// Indefinite policy running until explicitly revoked by an administrator
    Indefinite,
}

impl fmt::Display for PolicyDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Temporary(d) => write!(f, "Temporary ({:.1} minutes)", d.as_secs_f64() / 60.0),
            Self::Indefinite => write!(f, "Indefinite (Manual Revocation Required)"),
        }
    }
}

/// Persistence requirement for an administrative policy
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyPersistence {
    /// Volatile policy discarded when the controller exits or router reboots
    VolatileSession,
    /// Persistent policy stored in router configuration (surviving reboots and controller shutdown)
    RouterPersistent,
}

impl fmt::Display for PolicyPersistence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VolatileSession => write!(
                f,
                "Volatile Session (Discarded on Controller Exit / Reboot)"
            ),
            Self::RouterPersistent => {
                write!(f, "Router Persistent (Committed to Router NVRAM / Storage)")
            }
        }
    }
}

/// Request parameters for computing an administrative dry-run operation plan or executing policy
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationPlanRequest {
    pub scope: PolicyScope,
    pub duration: PolicyDuration,
    pub persistence: PolicyPersistence,
    #[serde(default)]
    pub target_macs: Vec<crate::types::MacAddress>,
}

impl OperationPlanRequest {
    pub fn new(
        scope: PolicyScope,
        duration: PolicyDuration,
        persistence: PolicyPersistence,
    ) -> Self {
        Self {
            scope,
            duration,
            persistence,
            target_macs: Vec::new(),
        }
    }

    pub fn with_macs(mut self, macs: Vec<crate::types::MacAddress>) -> Self {
        self.target_macs = macs;
        self
    }
}

/// Detailed dry-run operational plan outlining expected network effects without executing mutations
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationPlan {
    pub provider_name: String,
    pub router_identity: RouterIdentity,
    pub target_scope: PolicyScope,
    pub target_count: usize,
    pub duration: PolicyDuration,
    pub persistence: PolicyPersistence,
    pub discovered_services: Vec<String>,
    pub supported_capabilities: Vec<String>,
    pub unsupported_capabilities: Vec<String>,
    pub required_auth: String,
    pub auth_established: bool,
    pub expected_wan_impact: String,
    pub expected_lan_impact: String,
    pub management_plane_safe: bool,
    pub recovery_mechanism: String,
    pub uncertainties_and_risks: Vec<String>,
    pub is_dry_run: bool,
}

/// Detailed lifecycle state of a router-enforced administrative policy
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum PolicyLifecycleState {
    Planned,
    PendingApplication,
    #[default]
    Active,
    ExpiredPendingRecovery,
    RecoveryInProgress,
    Recovered,
    Failed(String),
    PartialFailure {
        applied_targets: Vec<String>,
        failed_target: String,
        rollback_errors: Vec<String>,
    },
    Unknown,
}

impl fmt::Display for PolicyLifecycleState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Planned => write!(f, "PLANNED"),
            Self::PendingApplication => write!(f, "PENDING APPLICATION"),
            Self::Active => write!(f, "ACTIVE"),
            Self::ExpiredPendingRecovery => write!(f, "EXPIRED (Pending Recovery)"),
            Self::RecoveryInProgress => write!(f, "RECOVERY IN PROGRESS"),
            Self::Recovered => write!(f, "RECOVERED"),
            Self::Failed(err) => write!(f, "FAILED: {}", err),
            Self::PartialFailure {
                applied_targets,
                failed_target,
                rollback_errors,
            } => {
                if rollback_errors.is_empty() {
                    write!(
                        f,
                        "PARTIAL FAILURE (Rolled back): target {} failed, {} prior targets rolled back",
                        failed_target,
                        applied_targets.len()
                    )
                } else {
                    write!(
                        f,
                        "CRITICAL PARTIAL FAILURE: target {} failed; ROLLBACK FAILED for {} target(s): {:?}",
                        failed_target,
                        rollback_errors.len(),
                        rollback_errors
                    )
                }
            }
            Self::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

/// Status of an active policy currently registered on the router
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivePolicyStatus {
    pub policy_id: String,
    pub scope: PolicyScope,
    pub applied_at_unix: u64,
    pub expires_at_unix: Option<u64>,
    pub is_persistent: bool,
    pub enforcement_point: String,
    #[serde(default)]
    pub autonomous_recovery: bool,
    #[serde(default)]
    pub lifecycle_state: PolicyLifecycleState,
    #[serde(default)]
    pub provider_name: Option<String>,
    #[serde(default)]
    pub router_identity: Option<String>,
    #[serde(default)]
    pub recovery_mechanism: Option<String>,
    #[serde(default)]
    pub last_error: Option<String>,
}

impl ActivePolicyStatus {
    pub fn new(
        policy_id: impl Into<String>,
        scope: PolicyScope,
        applied_at_unix: u64,
        expires_at_unix: Option<u64>,
        is_persistent: bool,
        enforcement_point: impl Into<String>,
        autonomous_recovery: bool,
    ) -> Self {
        Self {
            policy_id: policy_id.into(),
            scope,
            applied_at_unix,
            expires_at_unix,
            is_persistent,
            enforcement_point: enforcement_point.into(),
            autonomous_recovery,
            lifecycle_state: PolicyLifecycleState::Active,
            provider_name: None,
            router_identity: None,
            recovery_mechanism: None,
            last_error: None,
        }
    }

    pub fn with_provider(mut self, name: impl Into<String>) -> Self {
        self.provider_name = Some(name.into());
        self
    }

    pub fn with_router_identity(mut self, identity: impl Into<String>) -> Self {
        self.router_identity = Some(identity.into());
        self
    }

    pub fn with_recovery_mechanism(mut self, mechanism: impl Into<String>) -> Self {
        self.recovery_mechanism = Some(mechanism.into());
        self
    }

    pub fn with_state(mut self, state: PolicyLifecycleState) -> Self {
        self.lifecycle_state = state;
        self
    }

    pub fn with_error(mut self, error: impl Into<String>) -> Self {
        self.last_error = Some(error.into());
        self
    }

    pub fn is_expired(&self, current_unix: u64) -> bool {
        if let Some(exp) = self.expires_at_unix {
            current_unix >= exp
        } else {
            false
        }
    }
}

/// Strongly typed errors encountered during router administrative discovery or operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminError {
    UnsupportedOperation(String),
    AuthenticationFailed(String),
    SessionExpired(String),
    IdentityMismatch(String),
    Timeout(String),
    CommunicationError(String),
    ScopeViolation(String),
    LockoutPrevented(String),
    DuplicatePolicy(String),
    PolicyNotFound(String),
    TransactionFailed(String),
    RollbackFailed {
        applied_targets: Vec<String>,
        failed_target: String,
        original_error: String,
        rollback_errors: Vec<String>,
    },
    SecurityViolation(String),
}

impl fmt::Display for AdminError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedOperation(msg) => write!(f, "Unsupported Operation: {}", msg),
            Self::AuthenticationFailed(msg) => write!(f, "Authentication Failed: {}", msg),
            Self::SessionExpired(msg) => write!(f, "Session Expired: {}", msg),
            Self::IdentityMismatch(msg) => write!(f, "Router Identity Mismatch: {}", msg),
            Self::Timeout(msg) => write!(f, "Operation Timed Out: {}", msg),
            Self::CommunicationError(msg) => write!(f, "Communication Error: {}", msg),
            Self::ScopeViolation(msg) => write!(f, "Scope Violation: {}", msg),
            Self::LockoutPrevented(msg) => write!(f, "Lockout Prevented: {}", msg),
            Self::DuplicatePolicy(msg) => write!(f, "Duplicate Policy: {}", msg),
            Self::PolicyNotFound(msg) => write!(f, "Policy Not Found: {}", msg),
            Self::TransactionFailed(msg) => write!(f, "Transaction Failed: {}", msg),
            Self::RollbackFailed {
                applied_targets,
                failed_target,
                original_error,
                rollback_errors,
            } => {
                write!(
                    f,
                    "CRITICAL: Transaction failed for target '{}' ({}) AND rollback failed for {} target(s): {:?}. Manual verification required on physical router for applied targets: {:?}",
                    failed_target,
                    original_error,
                    rollback_errors.len(),
                    rollback_errors,
                    applied_targets
                )
            }
            Self::SecurityViolation(msg) => write!(f, "Security Violation: {}", msg),
        }
    }
}

impl std::error::Error for AdminError {}
