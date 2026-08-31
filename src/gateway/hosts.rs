use std::net::Ipv4Addr;
use crate::types::MacAddress;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayHostEntry {
    pub ip: Ipv4Addr,
    pub mac: MacAddress,
    pub hostname: String,
    pub interface_type: String,
    pub active: bool,
}

impl GatewayHostEntry {
    pub fn new(
        ip: Ipv4Addr,
        mac: MacAddress,
        hostname: String,
        interface_type: String,
        active: bool,
    ) -> Self {
        Self {
            ip,
            mac,
            hostname,
            interface_type,
            active,
        }
    }
}
