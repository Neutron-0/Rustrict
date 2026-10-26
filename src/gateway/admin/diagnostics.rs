use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::Ipv4Addr;

use crate::gateway::admin::capabilities::RouterCapabilityMatrix;
use crate::gateway::admin::engine::sanitize_text;
use crate::gateway::admin::plan::{ActivePolicyStatus, RouterIdentity};
use crate::types::MacAddress;

/// Normalized connection state of a router provider
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProviderConnectionState {
    Connected,
    Disconnected,
    AuthenticationRequired,
    Degraded(String),
    Error(String),
}

impl fmt::Display for ProviderConnectionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connected => write!(f, "Connected"),
            Self::Disconnected => write!(f, "Disconnected"),
            Self::AuthenticationRequired => write!(f, "Authentication Required"),
            Self::Degraded(msg) => write!(f, "Degraded: {}", msg),
            Self::Error(msg) => write!(f, "Error: {}", msg),
        }
    }
}

/// Provenance of router inventory and diagnostic data
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataSource {
    /// Actively queried from connected router hardware
    Live,
    /// Loaded from local controller state records
    LocallyCached,
    /// Discovered from static provider registration descriptor
    StaticDescriptor,
}

impl fmt::Display for DataSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Live => write!(f, "Live"),
            Self::LocallyCached => write!(f, "Cached"),
            Self::StaticDescriptor => write!(f, "Static"),
        }
    }
}

/// Normalized connected client device inventory entry
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouterDeviceEntry {
    pub ip: Option<Ipv4Addr>,
    pub mac: Option<MacAddress>,
    pub hostname: Option<String>,
    pub interface_type: Option<String>,
    pub is_active: Option<bool>,
    pub uptime_seconds: Option<u64>,
}

impl RouterDeviceEntry {
    pub fn new() -> Self {
        Self {
            ip: None,
            mac: None,
            hostname: None,
            interface_type: None,
            is_active: None,
            uptime_seconds: None,
        }
    }

    pub fn with_ip(mut self, ip: Ipv4Addr) -> Self {
        self.ip = Some(ip);
        self
    }

    pub fn with_mac(mut self, mac: MacAddress) -> Self {
        self.mac = Some(mac);
        self
    }

    pub fn with_hostname(mut self, hostname: impl Into<String>) -> Self {
        self.hostname = Some(hostname.into());
        self
    }

    pub fn with_interface(mut self, iface: impl Into<String>) -> Self {
        self.interface_type = Some(iface.into());
        self
    }

    pub fn with_active(mut self, active: bool) -> Self {
        self.is_active = Some(active);
        self
    }

    pub fn with_uptime(mut self, uptime_secs: u64) -> Self {
        self.uptime_seconds = Some(uptime_secs);
        self
    }
}

impl Default for RouterDeviceEntry {
    fn default() -> Self {
        Self::new()
    }
}

/// Typed result of an individual read-only diagnostic check
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiagnosticResult<T> {
    Supported(T),
    Unsupported(String),
    Failed(String),
}

impl<T> DiagnosticResult<T> {
    pub fn is_supported(&self) -> bool {
        matches!(self, Self::Supported(_))
    }

    pub fn as_option(&self) -> Option<&T> {
        match self {
            Self::Supported(v) => Some(v),
            _ => None,
        }
    }
}

/// Read-only connection health diagnostic details
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionDiagnostic {
    pub is_connected: bool,
    pub is_authenticated: bool,
    pub transport_protocol: String,
    pub response_latency_ms: Option<u64>,
}

/// Comprehensive read-only router diagnostic report
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouterDiagnosticReport {
    pub provider_id: String,
    pub provider_name: String,
    pub endpoint: Option<String>,
    pub timestamp_unix: u64,
    pub connection_status: DiagnosticResult<ConnectionDiagnostic>,
    pub identity_and_version: DiagnosticResult<RouterIdentity>,
    pub active_policies: DiagnosticResult<Vec<ActivePolicyStatus>>,
    pub connected_devices: DiagnosticResult<Vec<RouterDeviceEntry>>,
    pub capability_assessment: DiagnosticResult<RouterCapabilityMatrix>,
    pub recent_errors: Vec<String>,
}

/// Normalized provider inventory model exposing standard fields across router vendors
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedRouterInventoryItem {
    pub provider_id: String,
    pub display_name: String,
    pub vendor: String,
    pub connection_state: ProviderConnectionState,
    pub is_active_provider: bool,
    pub data_source: DataSource,
    pub router_identity: Option<RouterIdentity>,
    pub firmware_version: Option<String>,
    pub management_endpoint: Option<String>,
    pub last_contact_unix: Option<u64>,
    pub capabilities: RouterCapabilityMatrix,
    pub active_policy_count: Option<usize>,
    pub known_device_count: Option<usize>,
    pub diagnostic_summary: Option<String>,
    pub last_error: Option<String>,
}

/// Sanitizes management endpoints to ensure embedded user credentials or tokens are never leaked
pub fn sanitize_endpoint(endpoint: &str) -> String {
    let sanitized = sanitize_text(endpoint);
    if let Some(at_idx) = sanitized.find('@') {
        if let Some(proto_idx) = sanitized.find("://") {
            let prefix = &sanitized[..proto_idx + 3];
            let rest = &sanitized[at_idx + 1..];
            return format!("{}[REDACTED]@{}", prefix, rest);
        }
    }
    sanitized
}
