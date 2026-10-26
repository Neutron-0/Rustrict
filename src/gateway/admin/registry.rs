use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};

use crate::gateway::admin::capabilities::{CapabilityClassification, RouterCapabilityMatrix};
use crate::gateway::admin::plan::{
    ActivePolicyStatus, AdminError, OperationPlan, OperationPlanRequest, PolicyDuration,
    PolicyLifecycleState, PolicyScope, RouterIdentity,
};
use crate::gateway::admin::provider::RouterAdminProvider;

/// Metadata describing a registered router administration provider
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderDescriptor {
    pub id: String,
    pub name: String,
    pub vendor: String,
    pub protocols: String,
    pub default_port: u16,
    pub description: String,
    pub autonomous_recovery_support: String,
    pub capabilities: RouterCapabilityMatrix,
}

impl ProviderDescriptor {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        vendor: impl Into<String>,
        protocols: impl Into<String>,
        default_port: u16,
        description: impl Into<String>,
        autonomous_recovery_support: impl Into<String>,
        capabilities: RouterCapabilityMatrix,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            vendor: vendor.into(),
            protocols: protocols.into(),
            default_port,
            description: description.into(),
            autonomous_recovery_support: autonomous_recovery_support.into(),
            capabilities,
        }
    }
}

/// Currently active router connection details
#[derive(Clone)]
pub struct ActiveConnection {
    pub provider_id: String,
    pub provider: Arc<dyn RouterAdminProvider>,
    pub endpoint: String,
    pub identity: RouterIdentity,
    pub last_contact_unix: u64,
}

/// Status summary of the central router registry connection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryStatus {
    pub is_connected: bool,
    pub provider_id: Option<String>,
    pub provider_name: Option<String>,
    pub endpoint: Option<String>,
    pub verified_identity: Option<RouterIdentity>,
    pub is_authenticated: bool,
    pub last_contact_unix: Option<u64>,
}

/// Centralized registry for router administration providers.
///
/// Dispatches administrative commands to explicitly selected, authenticated
/// providers while enforcing lockout prevention, scope validation, duplicate
/// policy rejection, and safe disconnection semantics.
#[derive(Clone)]
pub struct RouterRegistry {
    gateway_ip: Ipv4Addr,
    controller_ip: Arc<RwLock<Option<Ipv4Addr>>>,
    descriptors: Arc<RwLock<HashMap<String, ProviderDescriptor>>>,
    active_connection: Arc<RwLock<Option<ActiveConnection>>>,
}

impl RouterRegistry {
    /// Creates a new router registry initialized with all supported built-in providers
    pub fn new(gateway_ip: Ipv4Addr) -> Self {
        let registry = Self {
            gateway_ip,
            controller_ip: Arc::new(RwLock::new(None)),
            descriptors: Arc::new(RwLock::new(HashMap::new())),
            active_connection: Arc::new(RwLock::new(None)),
        };

        registry.register_builtin_providers();
        registry
    }

    /// Sets the controller host IP for lockout prevention checks
    pub fn set_controller_ip(&self, ip: Ipv4Addr) {
        *self.controller_ip.write().unwrap() = Some(ip);
    }

    /// Registers a provider descriptor
    pub fn register_descriptor(&self, descriptor: ProviderDescriptor) {
        let mut descs = self.descriptors.write().unwrap();
        descs.insert(descriptor.id.clone(), descriptor);
    }

    /// Lists all registered provider descriptors sorted by ID
    pub fn list_providers(&self) -> Vec<ProviderDescriptor> {
        let descs = self.descriptors.read().unwrap();
        let mut list: Vec<ProviderDescriptor> = descs.values().cloned().collect();
        list.sort_by(|a, b| a.id.cmp(&b.id));
        list
    }

    /// Retrieves a provider descriptor by ID
    pub fn get_descriptor(&self, id: &str) -> Option<ProviderDescriptor> {
        let descs = self.descriptors.read().unwrap();
        descs.get(id).cloned()
    }

    /// Returns the currently active connection status
    pub fn get_status(&self) -> RegistryStatus {
        let guard = self.active_connection.read().unwrap();
        if let Some(conn) = guard.as_ref() {
            RegistryStatus {
                is_connected: true,
                provider_id: Some(conn.provider_id.clone()),
                provider_name: Some(conn.provider.name().to_string()),
                endpoint: Some(conn.endpoint.clone()),
                verified_identity: Some(conn.identity.clone()),
                is_authenticated: conn.provider.is_authenticated(),
                last_contact_unix: Some(conn.last_contact_unix),
            }
        } else {
            RegistryStatus {
                is_connected: false,
                provider_id: None,
                provider_name: None,
                endpoint: None,
                verified_identity: None,
                is_authenticated: false,
                last_contact_unix: None,
            }
        }
    }

    /// Updates the last successful contact timestamp on the active connection
    pub fn touch_contact(&self) {
        if let Some(conn) = self.active_connection.write().unwrap().as_mut() {
            conn.last_contact_unix = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
        }
    }

    /// Checks if a router provider is currently connected
    pub fn is_connected(&self) -> bool {
        self.active_connection.read().unwrap().is_some()
    }

    /// Retrieves the ID of the currently active provider
    pub fn active_provider_id(&self) -> Option<String> {
        self.active_connection
            .read()
            .unwrap()
            .as_ref()
            .map(|c| c.provider_id.clone())
    }

    /// Retrieves the active provider reference
    pub fn active_provider(&self) -> Option<Arc<dyn RouterAdminProvider>> {
        self.active_connection
            .read()
            .unwrap()
            .as_ref()
            .map(|c| c.provider.clone())
    }

    /// Connects and verifies an authenticated router provider
    pub fn connect(
        &self,
        provider_id: &str,
        provider: Arc<dyn RouterAdminProvider>,
        endpoint: impl Into<String>,
    ) -> Result<RouterIdentity, AdminError> {
        let ep = endpoint.into();
        // Verify provider descriptor exists
        let desc = {
            let descs = self.descriptors.read().unwrap();
            descs.get(provider_id).cloned().ok_or_else(|| {
                AdminError::UnsupportedOperation(format!(
                    "Unrecognized provider ID '{}'. Use 'router providers' to list supported providers.",
                    provider_id
                ))
            })?
        };

        // Query and verify router identity
        let identity = provider.detect_identity()?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut guard = self.active_connection.write().unwrap();
        *guard = Some(ActiveConnection {
            provider_id: desc.id,
            provider,
            endpoint: ep,
            identity: identity.clone(),
            last_contact_unix: now,
        });

        Ok(identity)
    }

    /// Cleanly disconnects the active provider without falling back to another provider or ARP poisoning
    pub fn disconnect(&self) {
        let mut guard = self.active_connection.write().unwrap();
        *guard = None;
    }

    /// Validates that target scope does not isolate the controller or router management plane
    pub fn validate_scope_safety(&self, scope: &PolicyScope) -> Result<(), AdminError> {
        let controller_ip = *self.controller_ip.read().unwrap();
        match scope {
            PolicyScope::SpecificTargets(targets) => {
                for target in targets {
                    if *target == self.gateway_ip {
                        return Err(AdminError::LockoutPrevented(format!(
                            "Target IP '{}' matches the router gateway management interface ({}); operation halted to prevent administrative lockout",
                            target, self.gateway_ip
                        )));
                    }
                    if let Some(ctrl_ip) = controller_ip {
                        if *target == ctrl_ip {
                            return Err(AdminError::LockoutPrevented(format!(
                                "Target IP '{}' matches the controller host IP ({}); operation halted to prevent controller isolation",
                                target, ctrl_ip
                            )));
                        }
                    }
                }
            }
            PolicyScope::NetworkWide => {
                // Network-wide policies are verified by individual providers to preserve intra-LAN management access
            }
        }
        Ok(())
    }

    /// Checks if a policy for the requested scope is already active, rejecting duplicates
    pub fn check_duplicate_policy(&self, scope: &PolicyScope) -> Result<(), AdminError> {
        if let Some(conn) = self.active_connection.read().unwrap().as_ref() {
            let active_policies = conn.provider.query_active_policies()?;
            for p in active_policies {
                if &p.scope == scope && p.lifecycle_state == PolicyLifecycleState::Active {
                    return Err(AdminError::DuplicatePolicy(format!(
                        "A policy for scope '{}' is already active on the router (policy ID: '{}'); duplicate operation rejected to avoid redundant rules",
                        scope, p.policy_id
                    )));
                }
            }
        }
        Ok(())
    }

    fn register_builtin_providers(&self) {
        // 1. OpenWrt HTTP JSON-RPC
        self.register_descriptor(ProviderDescriptor::new(
            "openwrt-http",
            "OpenWrt (HTTP/HTTPS JSON-RPC ubus)",
            "OpenWrt",
            "JSON-RPC 2.0 over HTTP/HTTPS (uhttpd / rpcd)",
            80,
            "Administrative integration for OpenWrt via ubus JSON-RPC API. Controls iptables/nftables firewall chains.",
            "Full (crond watchdog script autonomous recovery)",
            RouterCapabilityMatrix {
                read_only_discovery: CapabilityClassification::Implemented,
                host_inventory: CapabilityClassification::Implemented,
                device_identification_interface_type: CapabilityClassification::Implemented,
                ipv4_policy_enforcement: CapabilityClassification::Implemented,
                ipv6_policy_enforcement: CapabilityClassification::Implemented,
                per_device_access_policy: CapabilityClassification::Implemented,
                network_wide_access_policy: CapabilityClassification::Implemented,
                authenticated_admin_interfaces: CapabilityClassification::Implemented,
                timed_policy_auto_recovery: CapabilityClassification::Implemented,
                persistence_after_app_exit: CapabilityClassification::Implemented,
                persistence_after_host_shutdown: CapabilityClassification::Implemented,
            },
        ));

        // 2. OpenWrt SSH CLI
        self.register_descriptor(ProviderDescriptor::new(
            "openwrt-ssh",
            "OpenWrt (SSH CLI Transport)",
            "OpenWrt",
            "SSH over TCP",
            22,
            "Administrative integration for OpenWrt using secure shell commands. Manages uci firewall rules and crond watchdog directly.",
            "Full (crond watchdog script autonomous recovery)",
            RouterCapabilityMatrix {
                read_only_discovery: CapabilityClassification::Implemented,
                host_inventory: CapabilityClassification::Implemented,
                device_identification_interface_type: CapabilityClassification::Implemented,
                ipv4_policy_enforcement: CapabilityClassification::Implemented,
                ipv6_policy_enforcement: CapabilityClassification::Implemented,
                per_device_access_policy: CapabilityClassification::Implemented,
                network_wide_access_policy: CapabilityClassification::Implemented,
                authenticated_admin_interfaces: CapabilityClassification::Implemented,
                timed_policy_auto_recovery: CapabilityClassification::Implemented,
                persistence_after_app_exit: CapabilityClassification::Implemented,
                persistence_after_host_shutdown: CapabilityClassification::Implemented,
            },
        ));

        // 3. MikroTik RouterOS REST
        self.register_descriptor(ProviderDescriptor::new(
            "mikrotik-rest",
            "MikroTik RouterOS (REST API)",
            "MikroTik",
            "HTTPS REST API (RouterOS v7.1+)",
            443,
            "Administrative integration for MikroTik RouterOS v7 via native REST interface. Manages /ip/firewall/filter.",
            "Full (/system/scheduler and /system/script autonomous watchdog)",
            RouterCapabilityMatrix {
                read_only_discovery: CapabilityClassification::Implemented,
                host_inventory: CapabilityClassification::Implemented,
                device_identification_interface_type: CapabilityClassification::Implemented,
                ipv4_policy_enforcement: CapabilityClassification::Implemented,
                ipv6_policy_enforcement: CapabilityClassification::NotImplemented,
                per_device_access_policy: CapabilityClassification::Implemented,
                network_wide_access_policy: CapabilityClassification::Implemented,
                authenticated_admin_interfaces: CapabilityClassification::Implemented,
                timed_policy_auto_recovery: CapabilityClassification::Implemented,
                persistence_after_app_exit: CapabilityClassification::Implemented,
                persistence_after_host_shutdown: CapabilityClassification::Implemented,
            },
        ));

        // 4. AVM FRITZ!Box TR-064
        self.register_descriptor(ProviderDescriptor::new(
            "avm-tr064",
            "AVM FRITZ!Box (TR-064 SOAP)",
            "AVM",
            "TR-064 SOAP over HTTP/HTTPS",
            49000,
            "Administrative integration for AVM FRITZ!Box routers via standardized TR-064 services (X_AVM-DE_HostFilter). IPv4 only.",
            "Unsupported (FRITZ!OS lacks router-resident autonomous scheduler)",
            RouterCapabilityMatrix {
                read_only_discovery: CapabilityClassification::Implemented,
                host_inventory: CapabilityClassification::Implemented,
                device_identification_interface_type: CapabilityClassification::Implemented,
                ipv4_policy_enforcement: CapabilityClassification::Implemented,
                ipv6_policy_enforcement: CapabilityClassification::NotImplemented,
                per_device_access_policy: CapabilityClassification::Implemented,
                network_wide_access_policy: CapabilityClassification::Implemented,
                authenticated_admin_interfaces: CapabilityClassification::Implemented,
                timed_policy_auto_recovery: CapabilityClassification::NotImplemented,
                persistence_after_app_exit: CapabilityClassification::Implemented,
                persistence_after_host_shutdown: CapabilityClassification::Implemented,
            },
        ));

        // 5. Ubiquiti UniFi Network REST
        self.register_descriptor(ProviderDescriptor::new(
            "unifi-rest",
            "Ubiquiti UniFi Network (REST API)",
            "Ubiquiti",
            "HTTPS REST API (UniFi Controller / Cloud Gateway v7+ / v8+)",
            8443,
            "Administrative integration for Ubiquiti UniFi Network application via Traffic Rules engine. Controls wired and wireless LAN devices.",
            "Unsupported (UniFi Controller lacks router-resident autonomous scheduler; requires controller-driven recovery)",
            RouterCapabilityMatrix {
                read_only_discovery: CapabilityClassification::Implemented,
                host_inventory: CapabilityClassification::Implemented,
                device_identification_interface_type: CapabilityClassification::Implemented,
                ipv4_policy_enforcement: CapabilityClassification::Implemented,
                ipv6_policy_enforcement: CapabilityClassification::Implemented,
                per_device_access_policy: CapabilityClassification::Implemented,
                network_wide_access_policy: CapabilityClassification::Implemented,
                authenticated_admin_interfaces: CapabilityClassification::Implemented,
                timed_policy_auto_recovery: CapabilityClassification::NotImplemented,
                persistence_after_app_exit: CapabilityClassification::Implemented,
                persistence_after_host_shutdown: CapabilityClassification::Implemented,
            },
        ));

        // 6. Mock In-Memory Provider
        self.register_descriptor(ProviderDescriptor::new(
            "mock",
            "Mock Router Provider",
            "Rustrict Mock",
            "Internal In-Memory Simulation",
            0,
            "Deterministic test provider simulating router state, firewall rules, and autonomous expiry without live hardware.",
            "Simulated (In-memory clock expiry)",
            RouterCapabilityMatrix {
                read_only_discovery: CapabilityClassification::Implemented,
                host_inventory: CapabilityClassification::Implemented,
                device_identification_interface_type: CapabilityClassification::Implemented,
                ipv4_policy_enforcement: CapabilityClassification::Implemented,
                ipv6_policy_enforcement: CapabilityClassification::Implemented,
                per_device_access_policy: CapabilityClassification::Implemented,
                network_wide_access_policy: CapabilityClassification::Implemented,
                authenticated_admin_interfaces: CapabilityClassification::Implemented,
                timed_policy_auto_recovery: CapabilityClassification::Implemented,
                persistence_after_app_exit: CapabilityClassification::Implemented,
                persistence_after_host_shutdown: CapabilityClassification::Implemented,
            },
        ));
    }
}

impl RouterAdminProvider for RouterRegistry {
    fn name(&self) -> &'static str {
        "RouterRegistry"
    }

    fn detect_identity(&self) -> Result<RouterIdentity, AdminError> {
        let guard = self.active_connection.read().unwrap();
        let conn = guard.as_ref().ok_or_else(|| {
            AdminError::UnsupportedOperation(
                "No router provider is currently connected. Connect a provider first using 'router connect <provider>'."
                    .into(),
            )
        })?;
        conn.provider.detect_identity()
    }

    fn inspect_capabilities(&self) -> RouterCapabilityMatrix {
        let guard = self.active_connection.read().unwrap();
        if let Some(conn) = guard.as_ref() {
            conn.provider.inspect_capabilities()
        } else {
            RouterCapabilityMatrix::unsupported()
        }
    }

    fn plan_operation(&self, req: &OperationPlanRequest) -> Result<OperationPlan, AdminError> {
        let guard = self.active_connection.read().unwrap();
        let conn = guard.as_ref().ok_or_else(|| {
            AdminError::UnsupportedOperation(
                "No router provider is currently connected. Connect a provider first using 'router connect <provider>'."
                    .into(),
            )
        })?;
        self.validate_scope_safety(&req.scope)?;
        conn.provider.plan_operation(req)
    }

    fn query_active_policies(&self) -> Result<Vec<ActivePolicyStatus>, AdminError> {
        let guard = self.active_connection.read().unwrap();
        let conn = guard.as_ref().ok_or_else(|| {
            AdminError::UnsupportedOperation(
                "No router provider is currently connected. Connect a provider first using 'router connect <provider>'."
                    .into(),
            )
        })?;
        let policies = conn.provider.query_active_policies()?;
        let enriched = policies
            .into_iter()
            .map(|mut p| {
                if p.provider_name.is_none() {
                    p.provider_name = Some(conn.provider.name().to_string());
                }
                if p.router_identity.is_none() {
                    p.router_identity = Some(conn.identity.display_summary());
                }
                p
            })
            .collect();
        Ok(enriched)
    }

    fn is_authenticated(&self) -> bool {
        let guard = self.active_connection.read().unwrap();
        if let Some(conn) = guard.as_ref() {
            conn.provider.is_authenticated()
        } else {
            false
        }
    }

    fn apply_policy(&self, req: &OperationPlanRequest) -> Result<ActivePolicyStatus, AdminError> {
        let guard = self.active_connection.read().unwrap();
        let conn = guard.as_ref().ok_or_else(|| {
            AdminError::UnsupportedOperation(
                "No router provider is currently connected. Connect a provider first using 'router connect <provider>'."
                    .into(),
            )
        })?;
        self.validate_scope_safety(&req.scope)?;

        // Capability pre-validation
        let caps = conn.provider.inspect_capabilities();
        if let PolicyDuration::Temporary(dur) = &req.duration {
            if !caps.timed_policy_auto_recovery.is_operational() {
                return Err(AdminError::UnsupportedOperation(format!(
                    "Selected router provider '{}' does not support autonomous router-side timed recovery (capability status: {}). Temporary policy of {} seconds rejected to prevent unrecoverable network restrictions.",
                    conn.provider_id, caps.timed_policy_auto_recovery, dur.as_secs()
                )));
            }
        }

        self.check_duplicate_policy(&req.scope)?;
        let mut status = conn.provider.apply_policy(req)?;
        if status.provider_name.is_none() {
            status.provider_name = Some(conn.provider.name().to_string());
        }
        if status.router_identity.is_none() {
            status.router_identity = Some(conn.identity.display_summary());
        }
        Ok(status)
    }

    fn resume_policy(&self, scope: &PolicyScope) -> Result<Vec<String>, AdminError> {
        let guard = self.active_connection.read().unwrap();
        let conn = guard.as_ref().ok_or_else(|| {
            AdminError::UnsupportedOperation(
                "No router provider is currently connected. Connect a provider first using 'router connect <provider>'."
                    .into(),
            )
        })?;
        conn.provider.resume_policy(scope)
    }

    fn reconcile_policies(&self) -> Result<Vec<ActivePolicyStatus>, AdminError> {
        let guard = self.active_connection.read().unwrap();
        let conn = guard.as_ref().ok_or_else(|| {
            AdminError::UnsupportedOperation(
                "No router provider is currently connected. Connect a provider first using 'router connect <provider>'."
                    .into(),
            )
        })?;
        conn.provider.reconcile_policies()
    }

    fn adjust_policy_duration(
        &self,
        scope: &PolicyScope,
        new_duration: &PolicyDuration,
    ) -> Result<ActivePolicyStatus, AdminError> {
        let guard = self.active_connection.read().unwrap();
        let conn = guard.as_ref().ok_or_else(|| {
            AdminError::UnsupportedOperation(
                "No router provider is currently connected. Connect a provider first using 'router connect <provider>'."
                    .into(),
            )
        })?;

        // Capability pre-validation
        let caps = conn.provider.inspect_capabilities();
        if let PolicyDuration::Temporary(dur) = new_duration {
            if !caps.timed_policy_auto_recovery.is_operational() {
                return Err(AdminError::UnsupportedOperation(format!(
                    "Selected router provider '{}' does not support autonomous router-side timed recovery (capability status: {}). Cannot adjust policy to temporary duration of {} seconds.",
                    conn.provider_id, caps.timed_policy_auto_recovery, dur.as_secs()
                )));
            }
        }

        let mut status = conn.provider.adjust_policy_duration(scope, new_duration)?;
        if status.provider_name.is_none() {
            status.provider_name = Some(conn.provider.name().to_string());
        }
        if status.router_identity.is_none() {
            status.router_identity = Some(conn.identity.display_summary());
        }
        Ok(status)
    }

    fn resume_all(&self) -> Result<Vec<String>, AdminError> {
        let guard = self.active_connection.read().unwrap();
        let conn = guard.as_ref().ok_or_else(|| {
            AdminError::UnsupportedOperation(
                "No router provider is currently connected. Connect a provider first using 'router connect <provider>'."
                    .into(),
            )
        })?;
        conn.provider.resume_all()
    }

    fn list_devices(
        &self,
    ) -> Result<Vec<crate::gateway::admin::diagnostics::RouterDeviceEntry>, AdminError> {
        let guard = self.active_connection.read().unwrap();
        let conn = guard.as_ref().ok_or_else(|| {
            AdminError::UnsupportedOperation(
                "No router provider is currently connected. Connect a provider first using 'router connect <provider>'."
                    .into(),
            )
        })?;
        let res = conn.provider.list_devices();
        if res.is_ok() {
            drop(guard);
            self.touch_contact();
        }
        res
    }
}
