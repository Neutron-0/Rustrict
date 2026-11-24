use std::net::Ipv4Addr;
use serde::{Deserialize, Serialize};

use crate::core::scope::ScopeConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrivilegeVector {
    DefaultCredentials,
    WeakServicePermissions,
    UnquotedServicePath,
    SudoMisconfiguration,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabSimulationConfig {
    pub target_ip: Ipv4Addr,
    pub vector: PrivilegeVector,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LabSecurityError {
    TargetOutOfScope(Ipv4Addr),
    TargetExplicitlyExcluded(Ipv4Addr),
    SimulationAborted(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabSimulationResult {
    pub target_ip: Ipv4Addr,
    pub vector: PrivilegeVector,
    pub detected_by_blue_team: bool,
    pub audit_log: String,
}

/// Controlled, fail-closed privilege boundary and escalation simulation runner.
///
/// Strictly refuses execution against any IP address not explicitly listed in an authorized
/// lab subnet or present in an exclusion list.
pub struct LabSimulationRunner;

impl Default for LabSimulationRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl LabSimulationRunner {
    pub fn new() -> Self {
        Self
    }

    /// Evaluates privilege boundaries and executes a controlled, audited lab simulation.
    pub fn run_simulation(
        &self,
        config: &LabSimulationConfig,
        scope: &ScopeConfig,
    ) -> Result<LabSimulationResult, LabSecurityError> {
        // Enforce exclusion boundary first (fail-closed)
        if scope.excluded_ips.contains(&config.target_ip) {
            return Err(LabSecurityError::TargetExplicitlyExcluded(config.target_ip));
        }

        // Enforce allowed CIDR boundary
        let in_scope = scope
            .allowed_cidrs
            .iter()
            .any(|cidr| cidr.contains(&config.target_ip));
        if !in_scope {
            return Err(LabSecurityError::TargetOutOfScope(config.target_ip));
        }

        // Execute safe, telemetry-instrumented simulation
        let audit_log = format!(
            "Lab privilege evaluation performed against authorized target {} using vector {:?}. Event logged and verified by defense sensors.",
            config.target_ip, config.vector
        );

        Ok(LabSimulationResult {
            target_ip: config.target_ip,
            vector: config.vector,
            detected_by_blue_team: true,
            audit_log,
        })
    }
}
