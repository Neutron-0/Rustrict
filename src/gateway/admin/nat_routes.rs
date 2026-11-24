use std::net::Ipv4Addr;
use std::sync::Arc;
use serde::{Deserialize, Serialize};

use crate::gateway::admin::plan::AdminError;
use crate::gateway::admin::provider::RouterAdminProvider;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ForwardProtocol {
    Tcp,
    Udp,
    Both,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortForwardRule {
    pub name: String,
    pub proto: ForwardProtocol,
    pub external_port: u16,
    pub internal_ip: Ipv4Addr,
    pub internal_port: u16,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticRoute {
    pub destination: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub interface: Option<String>,
    pub metric: u32,
}

/// Unified manager for inspecting and controlling upstream router NAT port forwards and static routes.
pub struct RouterNatRouteManager {
    provider: Arc<dyn RouterAdminProvider>,
}

impl RouterNatRouteManager {
    pub fn new(provider: Arc<dyn RouterAdminProvider>) -> Self {
        Self { provider }
    }

    /// Queries all current NAT port forward rules.
    pub fn list_port_forwards(&self) -> Result<Vec<PortForwardRule>, AdminError> {
        self.provider.list_port_forwards()
    }

    /// Adds or updates a NAT port forwarding rule.
    pub fn add_port_forward(&self, rule: PortForwardRule) -> Result<(), AdminError> {
        self.provider.add_port_forward(rule)
    }

    /// Queries active static routes on the router.
    pub fn list_static_routes(&self) -> Result<Vec<StaticRoute>, AdminError> {
        self.provider.list_static_routes()
    }

    /// Adds a static routing entry to the router's routing table.
    pub fn add_static_route(&self, route: StaticRoute) -> Result<(), AdminError> {
        self.provider.add_static_route(route)
    }
}
