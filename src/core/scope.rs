use crate::types::MacAddress;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ipv4Cidr {
    pub network: Ipv4Addr,
    pub prefix: u8,
}

impl Ipv4Cidr {
    pub fn new(network: Ipv4Addr, prefix: u8) -> Result<Self, String> {
        if prefix > 32 {
            return Err("CIDR prefix must be between 0 and 32".into());
        }
        let mask = if prefix == 0 {
            0
        } else {
            !((1u32 << (32 - prefix)) - 1)
        };
        let normalized = Ipv4Addr::from(u32::from(network) & mask);
        Ok(Self {
            network: normalized,
            prefix,
        })
    }

    pub fn contains(&self, ip: &Ipv4Addr) -> bool {
        let mask = if self.prefix == 0 {
            0
        } else {
            !((1u32 << (32 - self.prefix)) - 1)
        };
        (u32::from(*ip) & mask) == (u32::from(self.network) & mask)
    }

    /// Returns the subnet network identifier address.
    pub fn network_address(&self) -> Ipv4Addr {
        self.network
    }

    /// Returns the directed broadcast address for this CIDR if applicable.
    ///
    /// Per RFC 3021, prefixes >= 31 (/31 point-to-point links and /32 host routes)
    /// do not have directed broadcast addresses.
    pub fn broadcast_address(&self) -> Option<Ipv4Addr> {
        if self.prefix >= 31 {
            None
        } else if self.prefix == 0 {
            Some(Ipv4Addr::new(255, 255, 255, 255))
        } else {
            let host_mask = (1u32 << (32 - self.prefix)) - 1;
            Some(Ipv4Addr::from(u32::from(self.network) | host_mask))
        }
    }

    /// Checks if `ip` is the network identifier for this subnet.
    ///
    /// In subnets with prefix <= 30, the all-zeros host identifier is reserved as the network address.
    /// In /31 (RFC 3021) and /32 subnets, this does not apply.
    pub fn is_network_address(&self, ip: &Ipv4Addr) -> bool {
        if self.prefix <= 30 {
            *ip == self.network
        } else {
            false
        }
    }

    /// Checks if `ip` is the directed broadcast address for this subnet.
    ///
    /// In subnets with prefix <= 30, the all-ones host identifier is the directed broadcast.
    /// In /31 (RFC 3021) and /32 subnets, there is no directed broadcast.
    pub fn is_directed_broadcast(&self, ip: &Ipv4Addr) -> bool {
        if let Some(bcast) = self.broadcast_address() {
            *ip == bcast
        } else {
            false
        }
    }

    /// Checks whether `ip` is a valid host target within this CIDR.
    ///
    /// Returns `true` if `ip` is contained in this CIDR and is neither the network address
    /// nor the directed broadcast address (for prefixes <= 30). For /31 and /32 prefixes,
    /// all contained addresses are valid host endpoints.
    pub fn is_valid_host_ip(&self, ip: &Ipv4Addr) -> bool {
        if !self.contains(ip) {
            return false;
        }
        if self.prefix <= 30 {
            !self.is_network_address(ip) && !self.is_directed_broadcast(ip)
        } else {
            true
        }
    }
}

impl FromStr for Ipv4Cidr {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let clean = s.trim();
        if let Some((net_str, prefix_str)) = clean.split_once('/') {
            let net = net_str
                .parse::<Ipv4Addr>()
                .map_err(|e| format!("Invalid IP in CIDR: {}", e))?;
            let prefix = prefix_str
                .parse::<u8>()
                .map_err(|e| format!("Invalid prefix in CIDR: {}", e))?;
            Self::new(net, prefix)
        } else {
            let net = clean
                .parse::<Ipv4Addr>()
                .map_err(|e| format!("Invalid IP address: {}", e))?;
            Self::new(net, 32)
        }
    }
}

impl std::fmt::Display for Ipv4Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeManager {
    pub allowed_cidrs: Vec<Ipv4Cidr>,
    pub excluded_ips: HashSet<Ipv4Addr>,
    pub excluded_macs: HashSet<MacAddress>,
    pub strict_mode: bool,
}

pub type ScopeConfig = ScopeManager;

impl Default for ScopeManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ScopeManager {
    pub fn new() -> Self {
        Self {
            allowed_cidrs: Vec::new(),
            excluded_ips: HashSet::new(),
            excluded_macs: HashSet::new(),
            strict_mode: false,
        }
    }

    pub fn add_cidr(&mut self, cidr_str: &str) -> Result<Ipv4Cidr, String> {
        let cidr = Ipv4Cidr::from_str(cidr_str)?;
        self.add_cidr_direct(cidr.clone());
        Ok(cidr)
    }

    pub fn add_cidr_direct(&mut self, cidr: Ipv4Cidr) {
        if !self.allowed_cidrs.contains(&cidr) {
            self.allowed_cidrs.push(cidr);
        }
    }

    pub fn remove_cidr(&mut self, cidr_str: &str) -> Result<bool, String> {
        let cidr = Ipv4Cidr::from_str(cidr_str)?;
        Ok(self.remove_cidr_direct(&cidr))
    }

    pub fn remove_cidr_direct(&mut self, cidr: &Ipv4Cidr) -> bool {
        let initial_len = self.allowed_cidrs.len();
        self.allowed_cidrs.retain(|c| c != cidr);
        self.allowed_cidrs.len() < initial_len
    }

    pub fn set_strict(&mut self, strict: bool) {
        self.strict_mode = strict;
    }

    pub fn exclude_ip(&mut self, ip: Ipv4Addr) {
        self.excluded_ips.insert(ip);
    }

    pub fn unexclude_ip(&mut self, ip: &Ipv4Addr) -> bool {
        self.excluded_ips.remove(ip)
    }

    pub fn exclude_mac(&mut self, mac: MacAddress) {
        self.excluded_macs.insert(mac);
    }

    pub fn is_allowed(&self, ip: &Ipv4Addr, mac: Option<&MacAddress>) -> bool {
        self.validate_target(ip, mac).is_ok()
    }

    /// Validates target host IP and optional MAC against operational boundaries, explicit exclusions,
    /// and IPv4 host validity rules (rejecting unspecified, loopback, broadcast, multicast,
    /// and subnet network or directed-broadcast addresses).
    ///
    /// Intended Semantics for Overlapping / Multiple CIDRs:
    /// Evaluation is conservative: if an IP address constitutes a network identifier or directed
    /// broadcast address for ANY configured CIDR range with prefix <= 30 containing it, it is rejected.
    /// This prevents directed-broadcast amplification, subnet-wide broadcast storms, or targeting network
    /// identifiers on any configured subnet segment, even if an enclosing supernet CIDR would otherwise
    /// treat it as an interior address.
    pub fn validate_target(&self, ip: &Ipv4Addr, mac: Option<&MacAddress>) -> Result<(), String> {
        // 1. Unspecified address
        if ip.is_unspecified() {
            return Err("Unspecified IP 0.0.0.0 is not a valid target".into());
        }

        // 2. Loopback address
        if ip.is_loopback() {
            return Err(format!("Loopback IP {} is invalid for LAN enforcement", ip));
        }

        // 3. Limited / Global broadcast
        if ip.is_broadcast() {
            return Err(format!(
                "Broadcast IP {} cannot be an enforcement target",
                ip
            ));
        }

        // 4. Multicast
        if ip.is_multicast() {
            return Err(format!(
                "Multicast IP {} cannot be an enforcement target",
                ip
            ));
        }

        // 5. Explicit IP exclusions
        if self.excluded_ips.contains(ip) {
            return Err(format!(
                "Target IP {} is explicitly excluded from assessment scope.",
                ip
            ));
        }

        // 6. MAC syntax & unicast validity (if provided)
        if let Some(m) = mac {
            if m.is_zero() {
                return Err("Zero MAC 00:00:00:00:00:00 is not routable".into());
            }
            if m.is_broadcast() {
                return Err(
                    "Broadcast MAC FF:FF:FF:FF:FF:FF cannot be an enforcement target".into(),
                );
            }
            if m.0[0] & 1 != 0 {
                return Err(format!(
                    "Multicast MAC {} cannot be an enforcement target",
                    m
                ));
            }
            if self.excluded_macs.contains(m) {
                return Err(format!(
                    "Target MAC {} is explicitly excluded from assessment scope.",
                    m
                ));
            }
        }

        // 7. Subnet Network and Directed Broadcast Validation (Conservative overlapping CIDRs)
        // If an IP matches the network identifier or directed broadcast of ANY configured CIDR
        // with prefix <= 30 containing it, it is rejected to prevent broadcast storms, packet loops,
        // or targeting network wire identifiers.
        for cidr in &self.allowed_cidrs {
            if cidr.contains(ip) {
                if cidr.is_network_address(ip) {
                    return Err(format!(
                        "Target IP {} is the subnet network identifier for {} and cannot be an enforcement target",
                        ip, cidr
                    ));
                }
                if cidr.is_directed_broadcast(ip) {
                    return Err(format!(
                        "Target IP {} is the directed broadcast address for {} and cannot be an enforcement target",
                        ip, cidr
                    ));
                }
            }
        }

        // 8. Strict mode boundary check
        if self.strict_mode {
            if self.allowed_cidrs.is_empty() {
                return Err("Target rejected: Strict mode is enabled but no authorized CIDR ranges are defined.".into());
            }
            if !self.allowed_cidrs.iter().any(|c| c.contains(ip)) {
                return Err(format!(
                    "Target IP {} is out of authorized scope CIDR definitions (strict mode enabled).",
                    ip
                ));
            }
        }

        Ok(())
    }

    /// Sanitizes scope configuration loaded from untrusted storage or external input.
    /// Retains only valid, routable unicast CIDR boundaries and valid exclusion entries.
    pub fn sanitize(&mut self) {
        self.allowed_cidrs.retain(|c| {
            c.prefix > 0
                && c.prefix <= 32
                && !c.network.is_unspecified()
                && !c.network.is_loopback()
                && !c.network.is_broadcast()
                && !c.network.is_multicast()
        });
        self.excluded_ips.retain(|ip| {
            !ip.is_unspecified() && !ip.is_loopback() && !ip.is_broadcast() && !ip.is_multicast()
        });
        self.excluded_macs
            .retain(|mac| !mac.is_zero() && !mac.is_broadcast() && (mac.0[0] & 1 == 0));
    }

    pub fn clear(&mut self) {
        self.allowed_cidrs.clear();
        self.excluded_ips.clear();
        self.excluded_macs.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cidr_network_and_broadcast_addresses() {
        let cidr24 = Ipv4Cidr::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap();
        assert_eq!(cidr24.network_address(), Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(
            cidr24.broadcast_address(),
            Some(Ipv4Addr::new(192, 168, 1, 255))
        );
        assert!(cidr24.is_network_address(&Ipv4Addr::new(192, 168, 1, 0)));
        assert!(cidr24.is_directed_broadcast(&Ipv4Addr::new(192, 168, 1, 255)));
        assert!(!cidr24.is_valid_host_ip(&Ipv4Addr::new(192, 168, 1, 0)));
        assert!(!cidr24.is_valid_host_ip(&Ipv4Addr::new(192, 168, 1, 255)));
        assert!(cidr24.is_valid_host_ip(&Ipv4Addr::new(192, 168, 1, 50)));

        // RFC 3021 /31 point-to-point link
        let cidr31 = Ipv4Cidr::new(Ipv4Addr::new(192, 168, 1, 0), 31).unwrap();
        assert_eq!(cidr31.broadcast_address(), None);
        assert!(!cidr31.is_network_address(&Ipv4Addr::new(192, 168, 1, 0)));
        assert!(!cidr31.is_directed_broadcast(&Ipv4Addr::new(192, 168, 1, 1)));
        assert!(cidr31.is_valid_host_ip(&Ipv4Addr::new(192, 168, 1, 0)));
        assert!(cidr31.is_valid_host_ip(&Ipv4Addr::new(192, 168, 1, 1)));

        // /32 host route
        let cidr32 = Ipv4Cidr::new(Ipv4Addr::new(192, 168, 1, 42), 32).unwrap();
        assert_eq!(cidr32.broadcast_address(), None);
        assert!(!cidr32.is_network_address(&Ipv4Addr::new(192, 168, 1, 42)));
        assert!(cidr32.is_valid_host_ip(&Ipv4Addr::new(192, 168, 1, 42)));
    }

    #[test]
    fn test_scope_rejects_subnet_network_and_broadcast() {
        let mut scope = ScopeManager::new();
        let cidr = Ipv4Cidr::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap();
        scope.add_cidr_direct(cidr);

        // Network ID rejected
        let net_res = scope.validate_target(&Ipv4Addr::new(192, 168, 1, 0), None);
        assert!(net_res.is_err());
        assert!(net_res.unwrap_err().contains("subnet network identifier"));

        // Directed broadcast rejected
        let bcast_res = scope.validate_target(&Ipv4Addr::new(192, 168, 1, 255), None);
        assert!(bcast_res.is_err());
        assert!(bcast_res
            .unwrap_err()
            .contains("directed broadcast address"));

        // Valid host accepted
        let host_res = scope.validate_target(&Ipv4Addr::new(192, 168, 1, 1), None);
        assert!(host_res.is_ok());

        // Global broadcast rejected
        let glob_res = scope.validate_target(&Ipv4Addr::new(255, 255, 255, 255), None);
        assert!(glob_res.is_err());
        assert!(glob_res.unwrap_err().contains("Broadcast IP"));

        // Multicast rejected
        let multi_res = scope.validate_target(&Ipv4Addr::new(224, 0, 0, 1), None);
        assert!(multi_res.is_err());
        assert!(multi_res.unwrap_err().contains("Multicast IP"));

        // Unspecified rejected
        let unspec_res = scope.validate_target(&Ipv4Addr::new(0, 0, 0, 0), None);
        assert!(unspec_res.is_err());
        assert!(unspec_res.unwrap_err().contains("Unspecified IP"));

        // Loopback rejected
        let loop_res = scope.validate_target(&Ipv4Addr::new(127, 0, 0, 1), None);
        assert!(loop_res.is_err());
        assert!(loop_res.unwrap_err().contains("Loopback IP"));
    }

    #[test]
    fn test_scope_conservative_overlapping_cidrs() {
        let mut scope = ScopeManager::new();
        scope.add_cidr_direct(Ipv4Cidr::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap());
        scope.add_cidr_direct(Ipv4Cidr::new(Ipv4Addr::new(10, 1, 2, 0), 24).unwrap());

        // 10.1.2.0 is network for /24 -> must be rejected even though interior to /8
        let res1 = scope.validate_target(&Ipv4Addr::new(10, 1, 2, 0), None);
        assert!(res1.is_err());
        assert!(res1.unwrap_err().contains("subnet network identifier"));

        // 10.1.2.255 is broadcast for /24 -> must be rejected even though interior to /8
        let res2 = scope.validate_target(&Ipv4Addr::new(10, 1, 2, 255), None);
        assert!(res2.is_err());
        assert!(res2.unwrap_err().contains("directed broadcast address"));

        // 10.1.2.50 is valid host for both
        assert!(scope
            .validate_target(&Ipv4Addr::new(10, 1, 2, 50), None)
            .is_ok());

        // 10.0.0.0 is network for /8 -> rejected
        assert!(scope
            .validate_target(&Ipv4Addr::new(10, 0, 0, 0), None)
            .is_err());

        // 10.255.255.255 is broadcast for /8 -> rejected
        assert!(scope
            .validate_target(&Ipv4Addr::new(10, 255, 255, 255), None)
            .is_err());
    }

    #[test]
    fn test_scope_preserves_31_and_32_valid_endpoints() {
        let mut scope = ScopeManager::new();
        scope.add_cidr_direct(Ipv4Cidr::new(Ipv4Addr::new(172, 16, 0, 0), 31).unwrap());
        scope.add_cidr_direct(Ipv4Cidr::new(Ipv4Addr::new(172, 16, 0, 10), 32).unwrap());

        // /31 endpoints both valid
        assert!(scope
            .validate_target(&Ipv4Addr::new(172, 16, 0, 0), None)
            .is_ok());
        assert!(scope
            .validate_target(&Ipv4Addr::new(172, 16, 0, 1), None)
            .is_ok());

        // /32 single host valid
        assert!(scope
            .validate_target(&Ipv4Addr::new(172, 16, 0, 10), None)
            .is_ok());
    }

    #[test]
    fn test_scope_sanitize_filters_invalid_untrusted_entries() {
        let mut scope = ScopeManager::new();
        // Insert invalid CIDRs manually
        scope.allowed_cidrs.push(Ipv4Cidr {
            network: Ipv4Addr::new(0, 0, 0, 0),
            prefix: 0,
        });
        scope.allowed_cidrs.push(Ipv4Cidr {
            network: Ipv4Addr::new(127, 0, 0, 0),
            prefix: 8,
        });
        scope.allowed_cidrs.push(Ipv4Cidr {
            network: Ipv4Addr::new(224, 0, 0, 0),
            prefix: 4,
        });
        scope.allowed_cidrs.push(Ipv4Cidr {
            network: Ipv4Addr::new(255, 255, 255, 255),
            prefix: 32,
        });
        scope.allowed_cidrs.push(Ipv4Cidr {
            network: Ipv4Addr::new(192, 168, 1, 0),
            prefix: 24,
        });

        scope.excluded_ips.insert(Ipv4Addr::new(0, 0, 0, 0));
        scope.excluded_ips.insert(Ipv4Addr::new(127, 0, 0, 1));
        scope.excluded_ips.insert(Ipv4Addr::new(192, 168, 1, 200));

        scope.excluded_macs.insert(MacAddress::ZERO);
        scope.excluded_macs.insert(MacAddress::BROADCAST);
        scope
            .excluded_macs
            .insert("00:11:22:33:44:55".parse().unwrap());

        scope.sanitize();

        assert_eq!(scope.allowed_cidrs.len(), 1);
        assert_eq!(
            scope.allowed_cidrs[0],
            Ipv4Cidr::new(Ipv4Addr::new(192, 168, 1, 0), 24).unwrap()
        );
        assert_eq!(scope.excluded_ips.len(), 1);
        assert!(scope
            .excluded_ips
            .contains(&Ipv4Addr::new(192, 168, 1, 200)));
        assert_eq!(scope.excluded_macs.len(), 1);
        assert!(scope
            .excluded_macs
            .contains(&"00:11:22:33:44:55".parse().unwrap()));
    }
}
