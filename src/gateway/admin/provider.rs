use crate::gateway::admin::capabilities::RouterCapabilityMatrix;
use crate::gateway::admin::plan::{
    ActivePolicyStatus, AdminError, OperationPlan, OperationPlanRequest, PolicyScope,
    RouterIdentity,
};

/// Core abstraction for an authenticated router administration provider.
///
/// Strictly separates read-only discovery, capability classification, and operation
/// planning from state-changing mutations.
pub trait RouterAdminProvider: Send + Sync {
    /// Friendly technical identifier of the provider (e.g. "MockRouterAdminProvider", "OpenWrt-ubus")
    fn name(&self) -> &'static str;

    /// Queries or inspects the router's identity metadata (read-only)
    fn detect_identity(&self) -> Result<RouterIdentity, AdminError>;

    /// Inspects and classifies the exact capabilities supported by this router interface
    fn inspect_capabilities(&self) -> RouterCapabilityMatrix;

    /// Computes a dry-run operational plan outlining affected targets, authorization checks,
    /// and recovery safety without executing any network mutations
    fn plan_operation(&self, req: &OperationPlanRequest) -> Result<OperationPlan, AdminError>;

    /// Queries currently active administrative policies residing on the router (read-only)
    fn query_active_policies(&self) -> Result<Vec<ActivePolicyStatus>, AdminError>;

    /// Validates whether the provider is currently connected and authenticated
    fn is_authenticated(&self) -> bool;

    /// Applies an access policy on the router using authenticated administrative mechanisms
    fn apply_policy(&self, req: &OperationPlanRequest) -> Result<ActivePolicyStatus, AdminError>;

    /// Resumes normal internet transit by removing active policy rules matching the given scope
    fn resume_policy(&self, scope: &PolicyScope) -> Result<Vec<String>, AdminError>;

    /// Reconciles router state by querying active rules, purging expired timed policies, and syncing records
    fn reconcile_policies(&self) -> Result<Vec<ActivePolicyStatus>, AdminError>;

    /// Adjusts an existing policy's duration (extending or shortening it)
    fn adjust_policy_duration(
        &self,
        scope: &PolicyScope,
        new_duration: &crate::gateway::admin::plan::PolicyDuration,
    ) -> Result<ActivePolicyStatus, AdminError>;

    /// Resumes all access policies created by Rustrict without removing unrelated router rules
    fn resume_all(&self) -> Result<Vec<String>, AdminError> {
        self.resume_policy(&PolicyScope::NetworkWide)
    }

    /// Queries connected client devices in a strictly read-only manner (if supported by provider)
    fn list_devices(
        &self,
    ) -> Result<Vec<crate::gateway::admin::diagnostics::RouterDeviceEntry>, AdminError> {
        Err(AdminError::UnsupportedOperation(format!(
            "Provider '{}' does not support querying connected client device inventory via this management interface",
            self.name()
        )))
    }

    /// Enforces an administrative bypass exemption for the specified MAC/IP address
    fn apply_admin_exemption(
        &self,
        mac: crate::types::MacAddress,
        ip: std::net::Ipv4Addr,
    ) -> Result<String, AdminError> {
        let _ = (mac, ip);
        Ok("default-noop-exemption".into())
    }

    /// Checks if an administrative exemption is currently active for the given MAC
    fn has_admin_exemption(&self, mac: crate::types::MacAddress) -> bool {
        let _ = mac;
        false
    }

    /// Queries all current DHCP leases (both dynamic and static reservations)
    fn list_dhcp_leases(&self) -> Result<Vec<crate::gateway::admin::dhcp_dns::DhcpLease>, AdminError> {
        Ok(Vec::new())
    }

    /// Binds an IP and MAC address into a static DHCP reservation
    fn add_static_lease(&self, lease: crate::gateway::admin::dhcp_dns::DhcpLease) -> Result<(), AdminError> {
        let _ = lease;
        Ok(())
    }

    /// Queries local DNS forwarding rules and host overrides
    fn list_dns_rules(&self) -> Result<Vec<crate::gateway::admin::dhcp_dns::DnsForwardRule>, AdminError> {
        Ok(Vec::new())
    }

    /// Configures a DNS forwarding rule / domain override
    fn add_dns_rule(&self, rule: crate::gateway::admin::dhcp_dns::DnsForwardRule) -> Result<(), AdminError> {
        let _ = rule;
        Ok(())
    }

    /// Queries all current NAT port forward rules
    fn list_port_forwards(&self) -> Result<Vec<crate::gateway::admin::nat_routes::PortForwardRule>, AdminError> {
        Ok(Vec::new())
    }

    /// Adds or updates a NAT port forwarding rule
    fn add_port_forward(&self, rule: crate::gateway::admin::nat_routes::PortForwardRule) -> Result<(), AdminError> {
        let _ = rule;
        Ok(())
    }

    /// Queries active static routes on the router
    fn list_static_routes(&self) -> Result<Vec<crate::gateway::admin::nat_routes::StaticRoute>, AdminError> {
        Ok(Vec::new())
    }

    /// Adds a static routing entry to the router's routing table
    fn add_static_route(&self, route: crate::gateway::admin::nat_routes::StaticRoute) -> Result<(), AdminError> {
        let _ = route;
        Ok(())
    }
}
