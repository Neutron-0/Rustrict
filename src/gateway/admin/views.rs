use serde::{Deserialize, Serialize};
use std::fmt;

use crate::gateway::admin::engine::PolicyExecutionRecord;
use crate::gateway::admin::persistence::RecoveryMechanism;
use crate::gateway::admin::plan::{
    ActivePolicyStatus, PolicyDuration, PolicyLifecycleState, PolicyScope,
};

/// Indicates whether a policy state has been actively verified against the physical router
/// or is loaded from local controller state records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyConfirmationState {
    /// Actively queried and confirmed present on the router by the connected provider
    ProviderConfirmed,
    /// Recorded in local controller state, but unverified against live router (e.g. disconnected)
    LocallyRecordedUnverified,
    /// Recorded in local controller state and verified recovered / absent from router
    LocallyRecordedRecovered,
    /// Policy application or recovery failed; recorded locally as failed
    LocallyRecordedFailed,
}

impl fmt::Display for PolicyConfirmationState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProviderConfirmed => write!(f, "Provider Confirmed (Live)"),
            Self::LocallyRecordedUnverified => write!(f, "Locally Recorded (Unverified)"),
            Self::LocallyRecordedRecovered => write!(f, "Locally Recorded (Recovered)"),
            Self::LocallyRecordedFailed => write!(f, "Locally Recorded (Failed)"),
        }
    }
}

/// Normalized autonomous recovery status for a router policy
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyRecoveryStatus {
    /// Provider does not support autonomous router-side timed recovery (e.g. UniFi, AVM)
    Unsupported,
    /// Policy duration is Indefinite, so autonomous recovery does not apply
    NotApplicable,
    /// Temporary policy is pending recovery mechanism installation
    Pending,
    /// Autonomous recovery mechanism is installed and confirmed on the router
    InstalledAndConfirmed(RecoveryMechanism),
    /// Autonomous recovery installation or execution failed
    Failed(String),
    /// Recovery status is unknown or unverified against the physical router
    UnknownOrUnverified,
}

impl fmt::Display for PolicyRecoveryStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => write!(f, "Unsupported"),
            Self::NotApplicable => write!(f, "Not Applicable"),
            Self::Pending => write!(f, "Pending"),
            Self::InstalledAndConfirmed(m) => write!(f, "Confirmed ({})", m),
            Self::Failed(err) => write!(f, "Failed: {}", err),
            Self::UnknownOrUnverified => write!(f, "Unknown / Unverified"),
        }
    }
}

/// Unified entry for displaying router policies across providers and lifecycle states
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnifiedPolicyEntry {
    pub policy_id: String,
    pub provider_id: String,
    pub provider_name: String,
    pub scope: PolicyScope,
    pub lifecycle_state: PolicyLifecycleState,
    pub duration: PolicyDuration,
    pub is_persistent: bool,
    pub applied_at_unix: u64,
    pub expires_at_unix: Option<u64>,
    pub enforcement_point: String,
    pub recovery_status: PolicyRecoveryStatus,
    pub last_execution_result: Option<String>,
    pub confirmation_state: PolicyConfirmationState,
}

impl UnifiedPolicyEntry {
    /// Constructs a unified policy entry from an active policy status and confirmation context
    pub fn from_active_policy(
        status: &ActivePolicyStatus,
        provider_id: impl Into<String>,
        confirmation_state: PolicyConfirmationState,
    ) -> Self {
        let pid = provider_id.into();
        let pname = status.provider_name.clone().unwrap_or_else(|| pid.clone());

        let duration = if let Some(exp) = status.expires_at_unix {
            let dur_secs = exp.saturating_sub(status.applied_at_unix);
            PolicyDuration::Temporary(std::time::Duration::from_secs(dur_secs))
        } else {
            PolicyDuration::Indefinite
        };

        // Determine recovery status using actual implementation evidence
        let recovery_status = match &status.lifecycle_state {
            PolicyLifecycleState::Failed(err) => PolicyRecoveryStatus::Failed(err.clone()),
            PolicyLifecycleState::Unknown => PolicyRecoveryStatus::UnknownOrUnverified,
            _ => {
                if status.expires_at_unix.is_none() {
                    PolicyRecoveryStatus::NotApplicable
                } else if confirmation_state == PolicyConfirmationState::LocallyRecordedUnverified {
                    PolicyRecoveryStatus::UnknownOrUnverified
                } else if status.autonomous_recovery {
                    let mech = if let Some(rec) = &status.recovery_mechanism {
                        let lower = rec.to_lowercase();
                        if lower.contains("scheduler") {
                            RecoveryMechanism::MikroTikScheduler
                        } else if lower.contains("cron") {
                            RecoveryMechanism::OpenWrtCronScheduler
                        } else {
                            RecoveryMechanism::RouterWatchdog
                        }
                    } else if pid.contains("mikrotik") {
                        RecoveryMechanism::MikroTikScheduler
                    } else if pid.contains("openwrt") {
                        RecoveryMechanism::OpenWrtCronScheduler
                    } else {
                        RecoveryMechanism::RouterWatchdog
                    };
                    PolicyRecoveryStatus::InstalledAndConfirmed(mech)
                } else if pid.contains("unifi") || pid.contains("avm") {
                    PolicyRecoveryStatus::Unsupported
                } else {
                    PolicyRecoveryStatus::Pending
                }
            }
        };

        let last_result = status
            .last_error
            .clone()
            .or_else(|| match status.lifecycle_state {
                PolicyLifecycleState::Active => Some("Active".to_string()),
                PolicyLifecycleState::Recovered => Some("Recovered".to_string()),
                PolicyLifecycleState::Failed(ref err) => Some(format!("Failed: {}", err)),
                PolicyLifecycleState::Unknown => Some("Unverified local state".to_string()),
                _ => None,
            });

        Self {
            policy_id: status.policy_id.clone(),
            provider_id: pid,
            provider_name: pname,
            scope: status.scope.clone(),
            lifecycle_state: status.lifecycle_state.clone(),
            duration,
            is_persistent: status.is_persistent,
            applied_at_unix: status.applied_at_unix,
            expires_at_unix: status.expires_at_unix,
            enforcement_point: status.enforcement_point.clone(),
            recovery_status,
            last_execution_result: last_result,
            confirmation_state,
        }
    }
}

/// Comprehensive detail view for a specific router policy
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDetailView {
    pub policy: UnifiedPolicyEntry,
    pub router_identity: Option<String>,
    pub provider_verification_available: bool,
    pub provider_verification_status: String,
    pub audit_events: Vec<PolicyExecutionRecord>,
}
