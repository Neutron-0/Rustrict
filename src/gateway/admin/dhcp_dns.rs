use std::net::Ipv4Addr;
use std::sync::Arc;
use serde::{Deserialize, Serialize};

use crate::gateway::admin::plan::AdminError;
use crate::gateway::admin::provider::RouterAdminProvider;
use crate::types::MacAddress;

/// Represents an active or static DHCP lease assigned by the router.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DhcpLease {
    pub ip: Ipv4Addr,
    pub mac: MacAddress,
    pub hostname: Option<String>,
    pub expires_at: Option<u64>,
    pub is_static: bool,
}

/// Represents a custom or local DNS forward / override rule on the router.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsForwardRule {
    pub domain: String,
    pub target_ip: Ipv4Addr,
    pub enabled: bool,
}

/// Unified manager for inspecting and controlling upstream router DHCP and DNS services.
pub struct RouterDhcpDnsManager {
    provider: Arc<dyn RouterAdminProvider>,
}

impl RouterDhcpDnsManager {
    pub fn new(provider: Arc<dyn RouterAdminProvider>) -> Self {
        Self { provider }
    }

    /// Queries all current DHCP leases (both dynamic and static reservations).
    pub fn list_dhcp_leases(&self) -> Result<Vec<DhcpLease>, AdminError> {
        self.provider.list_dhcp_leases()
    }

    /// Binds an IP and MAC address into a static DHCP reservation.
    pub fn add_static_lease(&self, lease: DhcpLease) -> Result<(), AdminError> {
        self.provider.add_static_lease(lease)
    }

    /// Queries local DNS forwarding rules and host overrides.
    pub fn list_dns_forward_rules(&self) -> Result<Vec<DnsForwardRule>, AdminError> {
        self.provider.list_dns_rules()
    }

    /// Configures a DNS forwarding rule / domain override.
    pub fn add_dns_forward_rule(&self, rule: DnsForwardRule) -> Result<(), AdminError> {
        self.provider.add_dns_rule(rule)
    }
}
