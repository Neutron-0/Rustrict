use serde::{Deserialize, Serialize};
use std::fmt;

/// Exact capability classification taxonomy for router administrative features
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CapabilityClassification {
    /// Supported by inspected, compiled source code in the application
    Implemented,
    /// Verified by passing automated test suites in the repository
    UnitTested,
    /// Demonstrated and verified in a controlled physical/virtual lab environment
    LabVerified,
    /// Tested and verified against a specific hardware router model and firmware build
    RouterVerified,
    /// Technically possible only under specific network topologies, firmware options, or permissions
    Conditional(String),
    /// Proposed or architectural concept, but absent from the active codebase
    NotImplemented,
    /// Evidence is insufficient, ambiguous, or untested
    Unknown(String),
}

impl fmt::Display for CapabilityClassification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Implemented => write!(f, "IMPLEMENTED"),
            Self::UnitTested => write!(f, "UNIT-TESTED"),
            Self::LabVerified => write!(f, "LAB-VERIFIED"),
            Self::RouterVerified => write!(f, "ROUTER-VERIFIED"),
            Self::Conditional(reason) => write!(f, "CONDITIONAL: {}", reason),
            Self::NotImplemented => write!(f, "NOT IMPLEMENTED"),
            Self::Unknown(reason) => write!(f, "UNKNOWN: {}", reason),
        }
    }
}

impl CapabilityClassification {
    pub fn is_operational(&self) -> bool {
        matches!(
            self,
            Self::Implemented | Self::UnitTested | Self::LabVerified | Self::RouterVerified
        )
    }
}

/// Comprehensive capability discovery matrix for a router administration provider
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouterCapabilityMatrix {
    /// Read-only discovery of gateway device identity, model, and service descriptions
    pub read_only_discovery: CapabilityClassification,
    /// Active host inventory extraction (e.g. DHCP leases, ARP cache table)
    pub host_inventory: CapabilityClassification,
    /// Identification of connected device types, hostnames, and physical interface (Wi-Fi vs Ethernet)
    pub device_identification_interface_type: CapabilityClassification,
    /// Policy enforcement capabilities for IPv4 network traffic
    pub ipv4_policy_enforcement: CapabilityClassification,
    /// Policy enforcement capabilities for IPv6 network traffic (NDP, SLAAC, DHCPv6)
    pub ipv6_policy_enforcement: CapabilityClassification,
    /// Enforcement of access policies targeting specific individual client devices by MAC/IP
    pub per_device_access_policy: CapabilityClassification,
    /// Enforcement of network-wide access policies (e.g., WAN link disabling, global forward drop)
    pub network_wide_access_policy: CapabilityClassification,
    /// Support for authenticated administrative protocols (HTTP Digest, TR-064 auth, SSH, token/API)
    pub authenticated_admin_interfaces: CapabilityClassification,
    /// Native or controller-coordinated timed policy execution with guaranteed auto-recovery
    pub timed_policy_auto_recovery: CapabilityClassification,
    /// Policy durability when the management application process terminates or exits
    pub persistence_after_app_exit: CapabilityClassification,
    /// Policy durability when the administrator's host PC is powered off completely
    pub persistence_after_host_shutdown: CapabilityClassification,
}

impl Default for RouterCapabilityMatrix {
    fn default() -> Self {
        Self::unknown("Router capabilities have not yet been probed")
    }
}

impl RouterCapabilityMatrix {
    /// Factory for unknown router capabilities
    pub fn unknown(reason: &str) -> Self {
        Self {
            read_only_discovery: CapabilityClassification::Unknown(reason.to_string()),
            host_inventory: CapabilityClassification::Unknown(reason.to_string()),
            device_identification_interface_type: CapabilityClassification::Unknown(
                reason.to_string(),
            ),
            ipv4_policy_enforcement: CapabilityClassification::Unknown(reason.to_string()),
            ipv6_policy_enforcement: CapabilityClassification::Unknown(reason.to_string()),
            per_device_access_policy: CapabilityClassification::Unknown(reason.to_string()),
            network_wide_access_policy: CapabilityClassification::Unknown(reason.to_string()),
            authenticated_admin_interfaces: CapabilityClassification::Unknown(reason.to_string()),
            timed_policy_auto_recovery: CapabilityClassification::Unknown(reason.to_string()),
            persistence_after_app_exit: CapabilityClassification::Unknown(reason.to_string()),
            persistence_after_host_shutdown: CapabilityClassification::Unknown(reason.to_string()),
        }
    }

    /// Evaluates the exact capabilities implemented in the existing Rustrict core today
    pub fn current_rustrict_core_baseline() -> Self {
        Self {
            read_only_discovery: CapabilityClassification::UnitTested,
            host_inventory: CapabilityClassification::UnitTested,
            device_identification_interface_type: CapabilityClassification::UnitTested,
            ipv4_policy_enforcement: CapabilityClassification::Conditional(
                "Host-based Layer-2 ARP blackholing; conditional on unmanaged L2 segment and absence of DAI".into(),
            ),
            ipv6_policy_enforcement: CapabilityClassification::NotImplemented,
            per_device_access_policy: CapabilityClassification::Conditional(
                "L2 ARP blackhole per IPv4/MAC; fails on IPv6 dual-stack or switches with DAI".into(),
            ),
            network_wide_access_policy: CapabilityClassification::Conditional(
                "Iterative L2 ARP blackhole across all discovered IPv4 entries".into(),
            ),
            authenticated_admin_interfaces: CapabilityClassification::NotImplemented,
            timed_policy_auto_recovery: CapabilityClassification::NotImplemented,
            persistence_after_app_exit: CapabilityClassification::NotImplemented,
            persistence_after_host_shutdown: CapabilityClassification::NotImplemented,
        }
    }

    /// Factory for completely unsupported router capabilities (e.g. when disconnected)
    pub fn unsupported() -> Self {
        Self {
            read_only_discovery: CapabilityClassification::NotImplemented,
            host_inventory: CapabilityClassification::NotImplemented,
            device_identification_interface_type: CapabilityClassification::NotImplemented,
            ipv4_policy_enforcement: CapabilityClassification::NotImplemented,
            ipv6_policy_enforcement: CapabilityClassification::NotImplemented,
            per_device_access_policy: CapabilityClassification::NotImplemented,
            network_wide_access_policy: CapabilityClassification::NotImplemented,
            authenticated_admin_interfaces: CapabilityClassification::NotImplemented,
            timed_policy_auto_recovery: CapabilityClassification::NotImplemented,
            persistence_after_app_exit: CapabilityClassification::NotImplemented,
            persistence_after_host_shutdown: CapabilityClassification::NotImplemented,
        }
    }
}
