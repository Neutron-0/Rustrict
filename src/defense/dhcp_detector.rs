use std::net::Ipv4Addr;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DhcpAlert {
    RogueServerDetected {
        rogue_ip: Ipv4Addr,
        expected_ip: Ipv4Addr,
    },
}

/// Rogue DHCP server detector that alerts when an unauthorized gateway/server attempts to offer leases.
pub struct RogueDhcpDetector {
    authorized_server_ip: Ipv4Addr,
}

impl RogueDhcpDetector {
    pub fn new(authorized_server_ip: Ipv4Addr) -> Self {
        Self {
            authorized_server_ip,
        }
    }

    /// Evaluates a received DHCP offer / ACK message.
    pub fn process_dhcp_offer(&self, server_ip: Ipv4Addr) -> Option<DhcpAlert> {
        if server_ip != self.authorized_server_ip {
            Some(DhcpAlert::RogueServerDetected {
                rogue_ip: server_ip,
                expected_ip: self.authorized_server_ip,
            })
        } else {
            None
        }
    }
}
