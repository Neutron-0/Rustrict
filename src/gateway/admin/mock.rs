use parking_lot::RwLock;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::gateway::admin::capabilities::{CapabilityClassification, RouterCapabilityMatrix};
use crate::gateway::admin::plan::{
    ActivePolicyStatus, AdminError, OperationPlan, OperationPlanRequest, PolicyDuration,
    PolicyPersistence, PolicyScope, RouterIdentity,
};
use crate::gateway::admin::provider::RouterAdminProvider;

/// A deterministic in-memory mock router administration provider for unit tests and offline dry-runs.
///
/// Sends zero network traffic. Simulates successes, failures, capability mismatches,
/// authentication errors, timeouts, and policy planning with absolute fidelity.
#[derive(Clone)]
pub struct MockRouterAdminProvider {
    pub name_str: &'static str,
    pub identity: RouterIdentity,
    pub capabilities: RouterCapabilityMatrix,
    pub authenticated: Arc<AtomicBool>,
    pub session_expired: Arc<AtomicBool>,
    pub force_timeout: Arc<AtomicBool>,
    pub force_unsupported: Arc<AtomicBool>,
    pub force_identity_mismatch: Arc<AtomicBool>,
    pub autonomous_recovery_supported: Arc<AtomicBool>,
    pub simulate_transaction_failure: Arc<AtomicBool>,
    pub active_policies: Arc<RwLock<Vec<ActivePolicyStatus>>>,
    pub discovered_services: Vec<String>,
    pub mock_devices: Arc<RwLock<Vec<crate::gateway::admin::diagnostics::RouterDeviceEntry>>>,
    pub exemptions: Arc<RwLock<std::collections::HashSet<crate::types::MacAddress>>>,
}

impl Default for MockRouterAdminProvider {
    fn default() -> Self {
        let mut id = RouterIdentity::new(Ipv4Addr::new(192, 168, 1, 1));
        id.manufacturer = Some("MockNetworks".to_string());
        id.model_name = Some("VirtualGateway-X1".to_string());
        id.model_number = Some("VG-100".to_string());
        id.firmware_version = Some("v2.4.0-test".to_string());

        let caps = RouterCapabilityMatrix {
            read_only_discovery: CapabilityClassification::UnitTested,
            host_inventory: CapabilityClassification::UnitTested,
            device_identification_interface_type: CapabilityClassification::UnitTested,
            ipv4_policy_enforcement: CapabilityClassification::UnitTested,
            ipv6_policy_enforcement: CapabilityClassification::UnitTested,
            per_device_access_policy: CapabilityClassification::UnitTested,
            network_wide_access_policy: CapabilityClassification::UnitTested,
            authenticated_admin_interfaces: CapabilityClassification::UnitTested,
            timed_policy_auto_recovery: CapabilityClassification::UnitTested,
            persistence_after_app_exit: CapabilityClassification::UnitTested,
            persistence_after_host_shutdown: CapabilityClassification::UnitTested,
        };

        Self {
            name_str: "MockRouterAdminProvider",
            identity: id,
            capabilities: caps,
            authenticated: Arc::new(AtomicBool::new(true)),
            session_expired: Arc::new(AtomicBool::new(false)),
            force_timeout: Arc::new(AtomicBool::new(false)),
            force_unsupported: Arc::new(AtomicBool::new(false)),
            force_identity_mismatch: Arc::new(AtomicBool::new(false)),
            autonomous_recovery_supported: Arc::new(AtomicBool::new(true)),
            simulate_transaction_failure: Arc::new(AtomicBool::new(false)),
            active_policies: Arc::new(RwLock::new(Vec::new())),
            discovered_services: vec![
                "urn:schemas-upnp-org:service:LANHostConfigManagement:1".to_string(),
                "urn:schemas-upnp-org:service:WANIPConnection:1".to_string(),
                "urn:mock-router:service:FirewallControl:1".to_string(),
            ],
            mock_devices: Arc::new(RwLock::new(vec![
                crate::gateway::admin::diagnostics::RouterDeviceEntry::new()
                    .with_ip(Ipv4Addr::new(192, 168, 1, 100))
                    .with_mac(crate::types::MacAddress([
                        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                    ]))
                    .with_hostname("Mock-Desktop")
                    .with_interface("Ethernet (Gigabit)")
                    .with_active(true)
                    .with_uptime(7200),
                crate::gateway::admin::diagnostics::RouterDeviceEntry::new()
                    .with_ip(Ipv4Addr::new(192, 168, 1, 101))
                    .with_mac(crate::types::MacAddress([
                        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
                    ]))
                    .with_hostname("Mock-Mobile-Phone")
                    .with_interface("Wi-Fi (5GHz)")
                    .with_active(true)
                    .with_uptime(1800),
            ])),
            exemptions: Arc::new(RwLock::new(std::collections::HashSet::new())),
        }
    }
}

impl MockRouterAdminProvider {
    pub fn new(ip: Ipv4Addr) -> Self {
        let mut s = Self::default();
        s.identity.ip = ip;
        s
    }

    pub fn with_unsupported_state(mut self) -> Self {
        self.capabilities.network_wide_access_policy = CapabilityClassification::NotImplemented;
        self.capabilities.per_device_access_policy = CapabilityClassification::NotImplemented;
        self.force_unsupported.store(true, Ordering::SeqCst);
        self
    }

    pub fn set_authenticated(&self, auth: bool) {
        self.authenticated.store(auth, Ordering::SeqCst);
    }

    pub fn set_session_expired(&self, expired: bool) {
        self.session_expired.store(expired, Ordering::SeqCst);
    }

    pub fn set_force_timeout(&self, timeout: bool) {
        self.force_timeout.store(timeout, Ordering::SeqCst);
    }

    pub fn set_force_identity_mismatch(&self, mismatch: bool) {
        self.force_identity_mismatch
            .store(mismatch, Ordering::SeqCst);
    }

    pub fn set_autonomous_recovery_supported(&self, supported: bool) {
        self.autonomous_recovery_supported
            .store(supported, Ordering::SeqCst);
    }

    pub fn set_simulate_transaction_failure(&self, fail: bool) {
        self.simulate_transaction_failure
            .store(fail, Ordering::SeqCst);
    }

    pub fn add_mock_active_policy(&self, policy: ActivePolicyStatus) {
        self.active_policies.write().push(policy);
    }

    pub fn set_mock_devices(
        &self,
        devices: Vec<crate::gateway::admin::diagnostics::RouterDeviceEntry>,
    ) {
        *self.mock_devices.write() = devices;
    }
}

impl RouterAdminProvider for MockRouterAdminProvider {
    fn name(&self) -> &'static str {
        self.name_str
    }

    fn detect_identity(&self) -> Result<RouterIdentity, AdminError> {
        if self.force_timeout.load(Ordering::SeqCst) {
            return Err(AdminError::Timeout(
                "Mock gateway failed to respond to identity probe within 500ms".into(),
            ));
        }

        if self.force_identity_mismatch.load(Ordering::SeqCst) {
            return Err(AdminError::IdentityMismatch(
                "Configured provider target does not match discovered gateway MAC/identity".into(),
            ));
        }

        Ok(self.identity.clone())
    }

    fn inspect_capabilities(&self) -> RouterCapabilityMatrix {
        self.capabilities.clone()
    }

    fn plan_operation(&self, req: &OperationPlanRequest) -> Result<OperationPlan, AdminError> {
        if self.force_timeout.load(Ordering::SeqCst) {
            return Err(AdminError::Timeout(
                "Communication with router timed out during planning phase".into(),
            ));
        }

        if self.force_identity_mismatch.load(Ordering::SeqCst) {
            return Err(AdminError::IdentityMismatch(
                "Configured provider target does not match discovered gateway MAC/identity".into(),
            ));
        }

        if self.session_expired.load(Ordering::SeqCst) {
            return Err(AdminError::SessionExpired(
                "Administrative session expired; re-authentication required".into(),
            ));
        }

        if !self.authenticated.load(Ordering::SeqCst) {
            return Err(AdminError::AuthenticationFailed(
                "Missing or invalid administrative credentials for target router".into(),
            ));
        }

        if self.force_unsupported.load(Ordering::SeqCst) {
            return Err(AdminError::UnsupportedOperation(
                "Target router firmware does not expose an authorized administrative policy API"
                    .into(),
            ));
        }

        let target_count = match &req.scope {
            PolicyScope::NetworkWide => 0, // Applies to all connected clients
            PolicyScope::SpecificTargets(list) => list.len(),
        };

        let mut supported_caps = Vec::new();
        let mut unsupported_caps = Vec::new();

        if self
            .capabilities
            .network_wide_access_policy
            .is_operational()
        {
            supported_caps.push("Network-Wide WAN Transit Policy".into());
        } else {
            unsupported_caps.push("Network-Wide WAN Transit Policy".into());
        }

        if self.capabilities.per_device_access_policy.is_operational() {
            supported_caps.push("Selective Per-Device MAC/IP Forwarding Rules".into());
        } else {
            unsupported_caps.push("Selective Per-Device MAC/IP Forwarding Rules".into());
        }

        if self.capabilities.ipv6_policy_enforcement.is_operational() {
            supported_caps.push("Dual-Stack IPv4 + IPv6 Enforcement".into());
        } else {
            unsupported_caps
                .push("Dual-Stack IPv6 Policy Enforcement (IPv6 Traffic Unfiltered)".into());
        }

        let recovery = match &req.duration {
            PolicyDuration::Temporary(d) => format!(
                "Router-side auto-expiration scheduled via kernel watchdog ({:.1} min)",
                d.as_secs_f64() / 60.0
            ),
            PolicyDuration::Indefinite => {
                "Manual administrative invocation required (CLI: 'router resume')".into()
            }
        };

        let risks = match (&req.scope, &req.persistence) {
            (PolicyScope::NetworkWide, PolicyPersistence::RouterPersistent) => vec![
                "WARNING: Network-wide persistent policy will cut internet for all devices including administration PC.".into(),
                "Router web management (port 80/443) will remain active, but cloud/external services will be unreachable.".into(),
            ],
            (PolicyScope::NetworkWide, PolicyPersistence::VolatileSession) => vec![
                "Network-wide policy will temporarily pause all client internet access.".into(),
                "Local LAN file shares, printing, and router web administration remain preserved.".into(),
            ],
            (PolicyScope::SpecificTargets(_), _) => vec![
                "Selective policy targets specified IP endpoints without affecting remainder of LAN.".into(),
            ],
        };

        Ok(OperationPlan {
            provider_name: self.name_str.to_string(),
            router_identity: self.identity.clone(),
            target_scope: req.scope.clone(),
            target_count,
            duration: req.duration.clone(),
            persistence: req.persistence.clone(),
            discovered_services: self.discovered_services.clone(),
            supported_capabilities: supported_caps,
            unsupported_capabilities: unsupported_caps,
            required_auth: "Router Admin HTTP Digest / Token Session".into(),
            auth_established: self.authenticated.load(Ordering::SeqCst),
            expected_wan_impact: "Outbound internet access halted; external sockets receive ICMP Admin Prohibited".into(),
            expected_lan_impact: "Local intra-subnet LAN communication and router management plane (HTTP/HTTPS) remain 100% accessible".into(),
            management_plane_safe: true,
            recovery_mechanism: recovery,
            uncertainties_and_risks: risks,
            is_dry_run: true,
        })
    }

    fn query_active_policies(&self) -> Result<Vec<ActivePolicyStatus>, AdminError> {
        if self.force_timeout.load(Ordering::SeqCst) {
            return Err(AdminError::Timeout(
                "Query active policies timed out".into(),
            ));
        }
        Ok(self.active_policies.read().clone())
    }

    fn is_authenticated(&self) -> bool {
        self.authenticated.load(Ordering::SeqCst)
    }

    fn apply_policy(&self, req: &OperationPlanRequest) -> Result<ActivePolicyStatus, AdminError> {
        // Run pre-checks identical to plan_operation
        let _ = self.plan_operation(req)?;

        if self.simulate_transaction_failure.load(Ordering::SeqCst) {
            return Err(AdminError::TransactionFailed(
                "Simulated transaction failure during policy commit; changes rolled back".into(),
            ));
        }

        if let PolicyDuration::Temporary(_) = req.duration {
            if !self.autonomous_recovery_supported.load(Ordering::SeqCst) {
                return Err(AdminError::UnsupportedOperation(
                    "Autonomous router-side recovery could not be established on this endpoint. Timed operations rejected to prevent unrecoverable network restriction. Use persistent/indefinite policy or enable router crontab access.".into()
                ));
            }
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let expires_at_unix = match req.duration {
            PolicyDuration::Temporary(d) => Some(now + d.as_secs()),
            PolicyDuration::Indefinite => None,
        };

        let policy_id = format!("pol-mock-{}", now);
        let status = ActivePolicyStatus::new(
            policy_id,
            req.scope.clone(),
            now,
            expires_at_unix,
            req.persistence == PolicyPersistence::RouterPersistent,
            "MockRouterUciFirewall",
            self.autonomous_recovery_supported.load(Ordering::SeqCst),
        );

        self.active_policies.write().push(status.clone());
        Ok(status)
    }

    fn resume_policy(&self, scope: &PolicyScope) -> Result<Vec<String>, AdminError> {
        if self.force_timeout.load(Ordering::SeqCst) {
            return Err(AdminError::Timeout(
                "Resume policy operation timed out".into(),
            ));
        }

        let mut lock = self.active_policies.write();
        let mut resumed = Vec::new();
        lock.retain(|p| {
            let matches = match (scope, &p.scope) {
                (PolicyScope::NetworkWide, PolicyScope::NetworkWide) => true,
                (
                    PolicyScope::SpecificTargets(targets),
                    PolicyScope::SpecificTargets(policy_targets),
                ) => targets.iter().any(|t| policy_targets.contains(t)),
                (PolicyScope::SpecificTargets(_), PolicyScope::NetworkWide) => false,
                (PolicyScope::NetworkWide, PolicyScope::SpecificTargets(_)) => true,
            };
            if matches {
                resumed.push(p.policy_id.clone());
                false
            } else {
                true
            }
        });

        if resumed.is_empty() {
            return Err(AdminError::PolicyNotFound(
                "No active router policy matched specified target".into(),
            ));
        }

        Ok(resumed)
    }

    fn reconcile_policies(&self) -> Result<Vec<ActivePolicyStatus>, AdminError> {
        if self.force_timeout.load(Ordering::SeqCst) {
            return Err(AdminError::Timeout("Reconciliation timed out".into()));
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut lock = self.active_policies.write();
        lock.retain(|p| !p.is_expired(now));
        Ok(lock.clone())
    }

    fn adjust_policy_duration(
        &self,
        scope: &PolicyScope,
        new_duration: &PolicyDuration,
    ) -> Result<ActivePolicyStatus, AdminError> {
        if self.force_timeout.load(Ordering::SeqCst) {
            return Err(AdminError::Timeout(
                "Adjust policy duration timed out".into(),
            ));
        }

        if let PolicyDuration::Temporary(_) = new_duration {
            if !self.autonomous_recovery_supported.load(Ordering::SeqCst) {
                return Err(AdminError::UnsupportedOperation(
                    "Autonomous router-side recovery could not be established on this endpoint. Timed duration adjustment rejected.".into()
                ));
            }
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let new_expires_at = match new_duration {
            PolicyDuration::Temporary(d) => Some(now + d.as_secs()),
            PolicyDuration::Indefinite => None,
        };

        let mut lock = self.active_policies.write();
        let policy = lock.iter_mut().find(|p| match (scope, &p.scope) {
            (PolicyScope::NetworkWide, PolicyScope::NetworkWide) => true,
            (PolicyScope::SpecificTargets(t1), PolicyScope::SpecificTargets(t2)) => {
                t1.iter().any(|t| t2.contains(t))
            }
            _ => false,
        });

        if let Some(p) = policy {
            p.expires_at_unix = new_expires_at;
            Ok(p.clone())
        } else {
            Err(AdminError::PolicyNotFound(
                "No active router policy matched specified target for duration adjustment".into(),
            ))
        }
    }

    fn list_devices(
        &self,
    ) -> Result<Vec<crate::gateway::admin::diagnostics::RouterDeviceEntry>, AdminError> {
        if self.force_timeout.load(Ordering::SeqCst) {
            return Err(AdminError::Timeout(
                "Mock gateway failed to respond to device query within 500ms".into(),
            ));
        }

        if self.force_unsupported.load(Ordering::SeqCst) {
            return Err(AdminError::UnsupportedOperation(
                "Mock router device inventory unsupported".into(),
            ));
        }

        Ok(self.mock_devices.read().clone())
    }

    fn apply_admin_exemption(
        &self,
        mac: crate::types::MacAddress,
        _ip: std::net::Ipv4Addr,
    ) -> Result<String, AdminError> {
        self.exemptions.write().insert(mac);
        Ok(format!("mock-exemption-{}", mac))
    }

    fn has_admin_exemption(&self, mac: crate::types::MacAddress) -> bool {
        self.exemptions.read().contains(&mac)
    }
}
