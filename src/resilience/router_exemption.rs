use std::net::Ipv4Addr;
use std::sync::Arc;

use crate::gateway::admin::plan::AdminError;
use crate::gateway::admin::provider::RouterAdminProvider;
use crate::types::MacAddress;

/// Manages router-level administrative bypass exemptions to prevent operators
/// from being isolated or rate-limited during network policy enforcement.
pub struct RouterExemptionManager {
    provider: Arc<dyn RouterAdminProvider>,
}

impl RouterExemptionManager {
    pub fn new(provider: Arc<dyn RouterAdminProvider>) -> Self {
        Self { provider }
    }

    /// Enforces an administrative bypass exemption on the upstream router/gateway
    pub fn enforce_exemption(&self, mac: MacAddress, ip: Ipv4Addr) -> Result<String, AdminError> {
        self.provider.apply_admin_exemption(mac, ip)
    }

    /// Checks if the given MAC is currently exempt at the router level
    pub fn is_exempt(&self, mac: MacAddress) -> bool {
        self.provider.has_admin_exemption(mac)
    }
}
