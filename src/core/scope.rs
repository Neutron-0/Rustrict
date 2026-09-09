use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::str::FromStr;
use serde::{Deserialize, Serialize};
use crate::types::MacAddress;

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
        let mask = if prefix == 0 { 0 } else { !((1u32 << (32 - prefix)) - 1) };
        let normalized = Ipv4Addr::from(u32::from(network) & mask);
        Ok(Self { network: normalized, prefix })
    }

    pub fn contains(&self, ip: &Ipv4Addr) -> bool {
        let mask = if self.prefix == 0 { 0 } else { !((1u32 << (32 - self.prefix)) - 1) };
        (u32::from(*ip) & mask) == (u32::from(self.network) & mask)
    }
}

impl FromStr for Ipv4Cidr {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let clean = s.trim();
        if let Some((net_str, prefix_str)) = clean.split_once('/') {
            let net = net_str.parse::<Ipv4Addr>().map_err(|e| format!("Invalid IP in CIDR: {}", e))?;
            let prefix = prefix_str.parse::<u8>().map_err(|e| format!("Invalid prefix in CIDR: {}", e))?;
            Self::new(net, prefix)
        } else {
            let net = clean.parse::<Ipv4Addr>().map_err(|e| format!("Invalid IP address: {}", e))?;
            Self::new(net, 32)
        }
    }
}

impl std::fmt::Display for Ipv4Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeManager {
    pub allowed_cidrs: Vec<Ipv4Cidr>,
    pub excluded_ips: HashSet<Ipv4Addr>,
    pub excluded_macs: HashSet<MacAddress>,
    pub strict_mode: bool,
}

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
        if self.excluded_ips.contains(ip) {
            return false;
        }
        if let Some(m) = mac {
            if self.excluded_macs.contains(m) {
                return false;
            }
        }
        if self.strict_mode && !self.allowed_cidrs.is_empty() {
            return self.allowed_cidrs.iter().any(|c| c.contains(ip));
        }
        true
    }

    pub fn validate_target(&self, ip: &Ipv4Addr, mac: Option<&MacAddress>) -> Result<(), String> {
        if self.excluded_ips.contains(ip) {
            return Err(format!("Target IP {} is explicitly excluded from assessment scope.", ip));
        }
        if let Some(m) = mac {
            if self.excluded_macs.contains(m) {
                return Err(format!("Target MAC {} is explicitly excluded from assessment scope.", m));
            }
        }
        if self.strict_mode && !self.allowed_cidrs.is_empty() && !self.allowed_cidrs.iter().any(|c| c.contains(ip)) {
            return Err(format!("Target IP {} is out of authorized scope CIDR definitions (strict mode enabled).", ip));
        }
        Ok(())
    }


    pub fn clear(&mut self) {
        self.allowed_cidrs.clear();
        self.excluded_ips.clear();
        self.excluded_macs.clear();
    }
}
