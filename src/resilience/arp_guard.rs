use crate::spoofer::craft_arp_reply;
use crate::types::MacAddress;
use std::net::Ipv4Addr;

pub struct ArpGuard {
    pub gateway_ip: Ipv4Addr,
    pub gateway_mac: MacAddress,
}

impl ArpGuard {
    pub fn new(gateway_ip: Ipv4Addr, gateway_mac: MacAddress) -> Self {
        Self {
            gateway_ip,
            gateway_mac,
        }
    }

    pub fn format_netsh_lock_command(&self, iface_name: &str) -> String {
        let mac_str = format!(
            "{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}",
            self.gateway_mac.0[0],
            self.gateway_mac.0[1],
            self.gateway_mac.0[2],
            self.gateway_mac.0[3],
            self.gateway_mac.0[4],
            self.gateway_mac.0[5]
        );
        format!(
            "netsh interface ipv4 add neighbors \"{}\" {} {} store=active",
            iface_name, self.gateway_ip, mac_str
        )
    }

    pub fn format_netsh_unlock_command(&self, iface_name: &str) -> String {
        format!(
            "netsh interface ipv4 delete neighbors \"{}\" {}",
            iface_name, self.gateway_ip
        )
    }

    pub fn is_cache_healthy(&self, cache: &[(Ipv4Addr, MacAddress)]) -> bool {
        for (ip, mac) in cache {
            if *ip == self.gateway_ip {
                return *mac == self.gateway_mac;
            }
        }
        // If not found in cache, considered not explicitly poisoned
        true
    }

    pub fn craft_healing_garp_reply(&self) -> Vec<u8> {
        // Gratuitous ARP reply: Sender IP = gateway_ip, Target IP = gateway_ip,
        // Sender MAC = gateway_mac, Target MAC = Broadcast
        craft_arp_reply(
            MacAddress::BROADCAST,
            self.gateway_mac,
            self.gateway_ip,
            self.gateway_mac,
            self.gateway_ip,
            MacAddress::BROADCAST,
        )
        .to_vec()
    }
}
